import type {
  AlertSeverity,
  ComponentHeartbeatRow,
  ComponentLayer,
  ComponentStatus,
  OperationalAlertRow,
} from './types';

export const HEARTBEAT_THRESHOLDS_SECONDS = {
  infrastructure_degraded: 300, // 5 minutes
  infrastructure_offline: 900, // 15 minutes
  endpoint_stale: 86400, // 24 hours
  endpoint_offline: 259200, // 72 hours
} as const;

export function isEndpointLayer(layer: ComponentLayer): boolean {
  return layer === 'ENDPOINT_AGENT';
}

export function computeEffectiveStatus(
  layer: ComponentLayer,
  reportedStatus: ComponentStatus,
  lastHeartbeatAt: string,
  now: Date
): { status: ComponentStatus; ageSeconds: number; reason: string } {
  const lastMs = Date.parse(lastHeartbeatAt);
  const ageSeconds = Number.isFinite(lastMs)
    ? Math.max(0, Math.floor((now.getTime() - lastMs) / 1000))
    : Number.MAX_SAFE_INTEGER;

  if (isEndpointLayer(layer)) {
    if (ageSeconds > HEARTBEAT_THRESHOLDS_SECONDS.endpoint_offline) {
      return {
        status: 'OFFLINE',
        ageSeconds,
        reason: `Endpoint sin reporte por ${Math.round(ageSeconds / 3600)}h (> 72h límite)`,
      };
    }
    if (reportedStatus === 'OFFLINE') {
      return { status: 'OFFLINE', ageSeconds, reason: 'Estado reportado OFFLINE por el agente' };
    }
    if (ageSeconds > HEARTBEAT_THRESHOLDS_SECONDS.endpoint_stale) {
      return {
        status: 'STALE',
        ageSeconds,
        reason: `Endpoint sin reporte por ${Math.round(ageSeconds / 3600)}h (> 24h límite)`,
      };
    }
    return {
      status: reportedStatus,
      ageSeconds,
      reason: `Heartbeat reportado ${reportedStatus}`,
    };
  }

  // Infrastructure layers
  if (ageSeconds > HEARTBEAT_THRESHOLDS_SECONDS.infrastructure_offline) {
    return {
      status: 'OFFLINE',
      ageSeconds,
      reason: `Sin heartbeat por ${Math.round(ageSeconds / 60)}m (> 15m límite)`,
    };
  }
  if (reportedStatus === 'OFFLINE') {
    return { status: 'OFFLINE', ageSeconds, reason: 'Componente reportó estado OFFLINE' };
  }
  if (ageSeconds > HEARTBEAT_THRESHOLDS_SECONDS.infrastructure_degraded) {
    return {
      status: 'DEGRADED',
      ageSeconds,
      reason: `Heartbeat retrasado ${Math.round(ageSeconds / 60)}m (> 5m límite)`,
    };
  }
  return {
    status: reportedStatus,
    ageSeconds,
    reason: `Heartbeat reportado ${reportedStatus}`,
  };
}

function severityForUnhealthyComponent(
  layer: ComponentLayer,
  status: ComponentStatus
): AlertSeverity {
  if (status === 'OFFLINE') {
    return isEndpointLayer(layer) ? 'HIGH' : 'CRITICAL';
  }
  if (status === 'DEGRADED') {
    return 'HIGH';
  }
  return 'MEDIUM';
}

export interface HealthSyncResult {
  evaluated: number;
  statusUpdates: number;
  alertsCreated: number;
  alertsResolved: number;
}

/**
 * Evaluates staleness & reported status across `component_heartbeats` (and `endpoints`),
 * updates `computed_status`, opens alerts for DEGRADED/OFFLINE/STALE components without
 * an active alert, and auto-resolves open/acknowledged alerts when components recover to ONLINE.
 */
export async function evaluateAndSyncHealth(
  db: D1Database,
  tenantId?: string | null,
  now: Date = new Date()
): Promise<HealthSyncResult> {
  const nowIso = now.toISOString();

  const heartbeatsQuery = tenantId
    ? db
        .prepare(
          'SELECT * FROM component_heartbeats WHERE tenant_id = ? ORDER BY component_layer, component_id'
        )
        .bind(tenantId)
    : db.prepare('SELECT * FROM component_heartbeats ORDER BY tenant_id, component_layer, component_id');

  const { results: heartbeats } = await heartbeatsQuery.all<ComponentHeartbeatRow>();

  let statusUpdates = 0;
  let alertsCreated = 0;
  let alertsResolved = 0;

  for (const hb of heartbeats ?? []) {
    const computed = computeEffectiveStatus(
      hb.component_layer,
      hb.reported_status,
      hb.last_heartbeat_at,
      now
    );

    if (computed.status !== hb.computed_status) {
      await db
        .prepare(
          'UPDATE component_heartbeats SET computed_status = ?, updated_at = ? WHERE id = ?'
        )
        .bind(computed.status, nowIso, hb.id)
        .run();
      statusUpdates += 1;
    }

    const activeAlert = await db
      .prepare(
        `SELECT * FROM operational_alerts
         WHERE tenant_id = ? AND component_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED')
         ORDER BY triggered_at DESC LIMIT 1`
      )
      .bind(hb.tenant_id, hb.component_id)
      .first<OperationalAlertRow>();

    if (computed.status === 'ONLINE') {
      if (activeAlert) {
        await db
          .prepare(
            `UPDATE operational_alerts
             SET status = 'RESOLVED', resolved_at = ?
             WHERE tenant_id = ? AND component_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED')`
          )
          .bind(nowIso, hb.tenant_id, hb.component_id)
          .run();
        alertsResolved += 1;
      }
    } else {
      const severity = severityForUnhealthyComponent(hb.component_layer, computed.status);
      const title = `[${hb.component_layer}] ${hb.display_name} en estado ${computed.status}`;
      const details = [
        computed.reason,
        hb.last_error ? `Último error: ${hb.last_error}` : null,
        `Último heartbeat: ${hb.last_heartbeat_at}`,
      ]
        .filter(Boolean)
        .join(' | ');

      if (!activeAlert) {
        const alertId = crypto.randomUUID();
        await db
          .prepare(
            `INSERT INTO operational_alerts
             (id, tenant_id, component_id, component_layer, severity, status, title, details, triggered_at)
             VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)`
          )
          .bind(
            alertId,
            hb.tenant_id,
            hb.component_id,
            hb.component_layer,
            severity,
            title,
            details,
            nowIso
          )
          .run();
        alertsCreated += 1;
      } else if (activeAlert.severity !== severity && severity === 'CRITICAL') {
        await db
          .prepare(
            `UPDATE operational_alerts SET severity = ?, title = ?, details = ? WHERE id = ?`
          )
          .bind(severity, title, details, activeAlert.id)
          .run();
      }
    }
  }

  // Also synchronize endpoint table staleness (>24h STALE, >72h OFFLINE)
  const endpointsQuery = tenantId
    ? db.prepare('SELECT id, last_seen_at, status FROM endpoints WHERE tenant_id = ?').bind(tenantId)
    : db.prepare('SELECT id, last_seen_at, status FROM endpoints');

  const { results: endpoints } = await endpointsQuery.all<{
    id: string;
    last_seen_at: string;
    status: ComponentStatus;
  }>();

  for (const ep of endpoints ?? []) {
    const computed = computeEffectiveStatus('ENDPOINT_AGENT', 'ONLINE', ep.last_seen_at, now);
    if (computed.status !== ep.status) {
      await db
        .prepare('UPDATE endpoints SET status = ? WHERE id = ?')
        .bind(computed.status, ep.id)
        .run();
    }
  }

  return {
    evaluated: (heartbeats ?? []).length,
    statusUpdates,
    alertsCreated,
    alertsResolved,
  };
}
