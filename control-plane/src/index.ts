import { Hono, type Context } from 'hono';
import { z } from 'zod';
import {
  authMiddleware,
  corsMiddleware,
  requireRoles,
  sha256Hex,
  verifyPayloadTenantAccess,
} from './auth';
import { evaluateAndSyncHealth } from './health-monitor';
import {
  addPanamaBusinessDays,
  businessDaysRemaining,
  getDsarSlaBusinessDays,
} from './panama-calendar';
import {
  computeEndpointRiskScore,
  evaluateCisoRisk,
  getRegulatoryProfileContext,
} from './scoring';
import { seedDemoEnvironment } from './seed';
import type {
  AppVariables,
  BreachIncidentRow,
  CasbEventRow,
  ComponentHeartbeatRow,
  ComponentLayer,
  DataTransferRow,
  DsarRequestRow,
  EndpointRow,
  Env,
  FichaTecnicaSnapshotRow,
  LogpushBatchRow,
  OperationalAlertRow,
  RiskHistoryRow,
  ScanFindingRow,
  ShadowAiEventRow,
  TenantRow,
} from './types';

const ComponentLayerEnum = z.enum([
  'CONTROL_PLANE',
  'TUNNEL',
  'ONPREM_COLLECTOR',
  'ADGUARD_DNS',
  'ENDPOINT_AGENT',
  'DB_CONNECTOR',
  'SMB_CONNECTOR',
  'WAZUH_FIM',
  'CLOUDFLARE_DLP',
  'CLOUDFLARE_CASB',
  'LOGPUSH',
]);

const ComponentStatusEnum = z.enum(['ONLINE', 'DEGRADED', 'OFFLINE', 'STALE']);
const RegulatoryProfileEnum = z.enum(['ANTAI_LEY81', 'SBP_001_2022', 'SALUD_LEY68']);
const AlertSeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const ArcoRightEnum = z.enum([
  'ACCESO',
  'RECTIFICACION',
  'CANCELACION',
  'OPOSICION',
  'PORTABILIDAD',
]);
const EntityTypeEnum = z.enum([
  'PA_IDENTIDAD_NATURAL',
  'PA_PASAPORTE',
  'PA_DATO_SENSIBLE_SALUD',
  'PA_TARJETA_PAGO',
  'PA_SWIFT_PA',
  'EMAIL_PERSONAL',
]);
const SourceTypeEnum = z.enum(['SMB', 'SQL_DB', 'OCR_IMAGE', 'CASB', 'DLP_EDGE']);

const HeartbeatSchema = z.object({
  tenant_id: z.string().min(1),
  component_layer: ComponentLayerEnum,
  component_id: z.string().min(1),
  display_name: z.string().min(1),
  status: ComponentStatusEnum,
  latency_ms: z.number().nonnegative().optional(),
  version: z.string().optional(),
  cpu_pct: z.number().min(0).max(100).optional(),
  ram_mb: z.number().nonnegative().optional(),
  uptime_pct_24h: z.number().min(0).max(100).optional(),
  last_error: z.string().nullable().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  timestamp: z.string().optional(),
});

const SimulateOutageSchema = z.object({
  tenant_id: z.string().min(1),
  component_id: z.string().min(1),
  target_status: ComponentStatusEnum.optional().default('OFFLINE'),
  backdate_minutes: z.number().int().min(0).max(10080).optional().default(0),
  error_message: z.string().optional(),
});

const TenantCreateSchema = z.object({
  id: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9-]+$/),
  name: z.string().min(1).max(200),
  industry: z.string().min(1).max(120).optional().default('General'),
  regulatory_profile: RegulatoryProfileEnum,
  dpo_name: z.string().nullable().optional(),
  dpo_email: z.string().email().nullable().optional(),
  dpo_antai_registered: z.boolean().optional().default(false),
  dpo_antai_reg_ref: z.string().nullable().optional(),
});

const TenantPatchSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  industry: z.string().min(1).max(120).optional(),
  regulatory_profile: RegulatoryProfileEnum.optional(),
  dpo_name: z.string().nullable().optional(),
  dpo_email: z.string().email().nullable().optional(),
  dpo_antai_registered: z.boolean().optional(),
  dpo_antai_reg_ref: z.string().nullable().optional(),
  active: z.boolean().optional(),
});

const EndpointIngestSchema = z.object({
  tenant_id: z.string().min(1),
  hostname: z.string().min(1).max(128),
  username: z.string().min(1).max(128),
  ip_address: z.string().nullable().optional(),
  os_version: z.string().optional().default('Windows 11 Pro'),
  agent_version: z.string().optional().default('2.0.0'),
  shadow_ai_dns_hits: z
    .array(
      z.object({
        domain: z.string().min(1),
        count: z.number().int().min(0),
        category: z.string().min(1),
        last_timestamp: z.string().optional(),
      })
    )
    .default([]),
  risky_extensions: z
    .array(
      z.object({
        extension_id: z.string().min(1),
        name: z.string().min(1),
        browser: z.string().min(1),
        version: z.string().optional(),
        permissions: z.array(z.string()).default([]),
        has_all_urls: z.boolean(),
      })
    )
    .default([]),
  box_audit: z.object({
    provider: z.string().default('BoxDrive'),
    installed: z.boolean(),
    sync_path: z.string().nullable().optional(),
    total_synced_files: z.number().int().min(0),
    sensitive_files_count: z.number().int().min(0),
    dlp_enabled: z.boolean(),
    sample_files_masked: z.array(z.string()).default([]),
  }),
  onedrive_audit: z
    .object({
      provider: z.string().default('OneDrive'),
      installed: z.boolean(),
      sync_path: z.string().nullable().optional(),
      total_synced_files: z.number().int().min(0),
      sensitive_files_count: z.number().int().min(0),
      dlp_enabled: z.boolean(),
      sample_files_masked: z.array(z.string()).default([]),
    })
    .nullable()
    .optional(),
  timestamp: z.string().optional(),
});

const FindingBatchSchema = z.object({
  tenant_id: z.string().min(1),
  scan_id: z.string().min(1),
  scanner_layer: z.enum(['SMB_CONNECTOR', 'DB_CONNECTOR', 'ONPREM_COLLECTOR']),
  is_simulated: z.boolean().default(false),
  total_assets_scanned: z.number().int().min(0),
  scan_duration_ms: z.number().int().min(0),
  findings: z.array(
    z.object({
      source_type: SourceTypeEnum,
      repository_name: z.string().min(1),
      location_path: z.string().min(1),
      entity_type: EntityTypeEnum,
      masked_sample: z.string().min(1),
      value_sha256: z.string().min(1),
      match_count: z.number().int().min(1),
      is_sensitive: z.boolean(),
      severity: AlertSeverityEnum,
      retention_age_days: z.number().int().min(0).nullable().optional(),
      retention_violation: z.boolean().optional(),
      detected_at: z.string().optional(),
    })
  ),
});

const ShadowAiBatchSchema = z.object({
  tenant_id: z.string().min(1),
  source: z.enum(['ADGUARD_DNS', 'ENDPOINT_AGENT', 'AI_GATEWAY']),
  total_queries_inspected: z.number().int().min(0),
  events: z.array(
    z.object({
      client_ip: z.string().min(1),
      hostname: z.string().optional(),
      domain: z.string().min(1),
      category: z.string().min(1),
      hits: z.number().int().min(1),
      blocked: z.boolean().optional().default(false),
      timestamp: z.string().optional(),
    })
  ),
});

const CasbWebhookSchema = z.object({
  tenant_id: z.string().min(1),
  event_id: z.string().min(1),
  saas_app: z.string().min(1),
  resource_name: z.string().min(1),
  finding_type: z.string().min(1),
  exposure_level: z.enum(['PUBLIC_LINK', 'EXTERNAL_SHARE', 'OAUTH_RISKY', 'PII_DETECTED']),
  remediated_automatically: z.boolean(),
  remediation_action: z.string().optional(),
  severity: AlertSeverityEnum,
  detected_at: z.string().min(1),
  remediated_at: z.string().nullable().optional(),
});

const LogpushBatchSchema = z.object({
  tenant_id: z.string().min(1),
  dataset: z.enum(['gateway_http', 'dlp_forensic', 'casb_findings', 'audit_logs']),
  records_count: z.number().int().min(0),
  lag_seconds: z.number().min(0),
  encrypted_with_customer_key: z.boolean(),
  r2_object_key: z.string().optional(),
  summary_counts: z.record(z.string(), z.number()).default({}),
});

const DsarCreateSchema = z.object({
  tenant_id: z.string().min(1),
  requester_name: z.string().min(1),
  requester_id_masked: z.string().min(1),
  right_type: ArcoRightEnum,
  target_systems: z.array(z.string()).default([]),
  notes: z.string().optional(),
  received_at: z.string().optional(),
});

const DsarPatchSchema = z.object({
  status: z.enum(['PENDING', 'OPEN', 'IN_PROGRESS', 'COMPLETED', 'REJECTED']).optional(),
  notes: z.string().optional(),
  target_systems: z.array(z.string()).optional(),
  evidence: z.record(z.string(), z.unknown()).optional(),
  completed_at: z.string().nullable().optional(),
});

const BreachCreateSchema = z.object({
  tenant_id: z.string().min(1),
  title: z.string().min(1),
  severity: AlertSeverityEnum,
  what_happened: z.string().min(1),
  compromised_data_types: z.array(z.string()).min(1),
  affected_records_estimate: z.number().int().min(0),
  measures_adopted: z.string().min(1),
  titular_actions: z.string().min(1),
  contact_point: z.string().min(1),
  detected_at: z.string().optional(),
});

const BreachPatchSchema = z.object({
  status: z.enum(['DETECTED', 'CONTAINING', 'NOTIFIED_ANTAI', 'CLOSED']).optional(),
  severity: AlertSeverityEnum.optional(),
  what_happened: z.string().min(1).optional(),
  compromised_data_types: z.array(z.string()).optional(),
  affected_records_estimate: z.number().int().min(0).optional(),
  measures_adopted: z.string().min(1).optional(),
  titular_actions: z.string().min(1).optional(),
  contact_point: z.string().min(1).optional(),
  antai_notified_at: z.string().nullable().optional(),
});

const TransferCreateSchema = z.object({
  tenant_id: z.string().min(1),
  recipient_name: z.string().min(1),
  destination_country: z.string().min(2),
  is_cross_border: z.boolean(),
  purpose: z.string().min(1),
  data_categories: z.array(z.string()).default([]),
  legal_basis: z.string().min(1),
  dpa_contract_active: z.boolean(),
  max_retention_days: z.number().int().min(1),
  destructor_verified: z.boolean().optional().default(false),
});

const TransferPatchSchema = z.object({
  purpose: z.string().min(1).optional(),
  legal_basis: z.string().min(1).optional(),
  dpa_contract_active: z.boolean().optional(),
  max_retention_days: z.number().int().min(1).optional(),
  destructor_verified: z.boolean().optional(),
  data_categories: z.array(z.string()).optional(),
});

const FichaGenerateSchema = z.object({
  tenant_id: z.string().min(1).optional(),
  generated_by: z.string().min(1).optional(),
});

type AppContext = Context<{ Bindings: Env; Variables: AppVariables }>;

async function parseJson<T>(
  c: AppContext,
  schema: z.ZodType<T>
): Promise<{ data: T } | { errorResponse: Response }> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    return {
      errorResponse: c.json({ error: 'Bad Request', message: 'Invalid JSON request body' }, 400),
    };
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    return {
      errorResponse: c.json(
        {
          error: 'Validation Error',
          message: 'Request body failed schema validation',
          issues: parsed.error.issues,
        },
        400
      ),
    };
  }
  return { data: parsed.data };
}

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function getTenantById(db: D1Database, tenantId: string): Promise<TenantRow | null> {
  return db
    .prepare('SELECT * FROM tenants WHERE id = ? LIMIT 1')
    .bind(tenantId)
    .first<TenantRow>();
}

async function resolveTenantOrError(
  c: AppContext,
  explicitTenantId?: string | null
): Promise<{ tenant: TenantRow } | { errorResponse: Response }> {
  const targetId = explicitTenantId ?? c.get('resolvedTenantId');
  let tenant: TenantRow | null = null;

  if (targetId) {
    tenant = await getTenantById(c.env.DB, targetId);
    if (!tenant) {
      return {
        errorResponse: c.json(
          { error: 'Not Found', message: `Tenant '${targetId}' does not exist` },
          404
        ),
      };
    }
  } else {
    tenant = await c.env.DB.prepare(
      'SELECT * FROM tenants WHERE active = 1 ORDER BY created_at ASC LIMIT 1'
    ).first<TenantRow>();
    if (!tenant) {
      return {
        errorResponse: c.json(
          {
            error: 'Not Found',
            message: 'No active tenant found. Create a tenant or seed demo data first.',
          },
          404
        ),
      };
    }
  }

  return { tenant };
}

async function loadTenantDataset(db: D1Database, tenantId: string) {
  const [
    heartbeatsRes,
    alertsRes,
    endpointsRes,
    findingsRes,
    shadowAiRes,
    casbRes,
    logpushRes,
    dsarsRes,
    breachesRes,
    transfersRes,
  ] = await Promise.all([
    db
      .prepare('SELECT * FROM component_heartbeats WHERE tenant_id = ? ORDER BY component_layer, component_id')
      .bind(tenantId)
      .all<ComponentHeartbeatRow>(),
    db
      .prepare('SELECT * FROM operational_alerts WHERE tenant_id = ? ORDER BY triggered_at DESC')
      .bind(tenantId)
      .all<OperationalAlertRow>(),
    db
      .prepare('SELECT * FROM endpoints WHERE tenant_id = ? ORDER BY endpoint_risk_score DESC, hostname ASC')
      .bind(tenantId)
      .all<EndpointRow>(),
    db
      .prepare('SELECT * FROM scan_findings WHERE tenant_id = ? ORDER BY detected_at DESC')
      .bind(tenantId)
      .all<ScanFindingRow>(),
    db
      .prepare('SELECT * FROM shadow_ai_events WHERE tenant_id = ? ORDER BY recorded_at DESC')
      .bind(tenantId)
      .all<ShadowAiEventRow>(),
    db
      .prepare('SELECT * FROM casb_events WHERE tenant_id = ? ORDER BY detected_at DESC')
      .bind(tenantId)
      .all<CasbEventRow>(),
    db
      .prepare('SELECT * FROM logpush_batches WHERE tenant_id = ? ORDER BY ingested_at DESC')
      .bind(tenantId)
      .all<LogpushBatchRow>(),
    db
      .prepare('SELECT * FROM dsar_requests WHERE tenant_id = ? ORDER BY due_at ASC')
      .bind(tenantId)
      .all<DsarRequestRow>(),
    db
      .prepare('SELECT * FROM breach_incidents WHERE tenant_id = ? ORDER BY detected_at DESC')
      .bind(tenantId)
      .all<BreachIncidentRow>(),
    db
      .prepare('SELECT * FROM data_transfers WHERE tenant_id = ? ORDER BY created_at DESC')
      .bind(tenantId)
      .all<DataTransferRow>(),
  ]);

  return {
    heartbeats: heartbeatsRes.results ?? [],
    alerts: alertsRes.results ?? [],
    endpoints: endpointsRes.results ?? [],
    findings: findingsRes.results ?? [],
    shadowAiEvents: shadowAiRes.results ?? [],
    casbEvents: casbRes.results ?? [],
    logpushBatches: logpushRes.results ?? [],
    dsars: dsarsRes.results ?? [],
    breaches: breachesRes.results ?? [],
    transfers: transfersRes.results ?? [],
  };
}

const ALL_LAYERS_ORDER: ComponentLayer[] = [
  'CONTROL_PLANE',
  'TUNNEL',
  'ONPREM_COLLECTOR',
  'ADGUARD_DNS',
  'ENDPOINT_AGENT',
  'DB_CONNECTOR',
  'SMB_CONNECTOR',
  'WAZUH_FIM',
  'CLOUDFLARE_DLP',
  'CLOUDFLARE_CASB',
  'LOGPUSH',
];

export const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

app.use('/api/v2/*', corsMiddleware());
app.use('/api/v2/*', authMiddleware());

// ---------------------------------------------------------------------------
// 1. Health & Operational Telemetry
// ---------------------------------------------------------------------------

app.get('/api/v2/health/ping', async (c) => {
  let dbOk = true;
  try {
    if (c.env?.DB) {
      await c.env.DB.prepare('SELECT 1 AS ok').first();
    }
  } catch {
    dbOk = false;
  }
  return c.json({
    ok: dbOk,
    service: 'vektor81-control-plane',
    version: '2.0.0',
    environment: c.env?.ENVIRONMENT ?? 'development',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/v2/health/heartbeat', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, HeartbeatSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const hbAt = data.timestamp ?? nowIso;

  await c.env.DB.prepare(
    `INSERT INTO component_heartbeats
     (id, tenant_id, component_layer, component_id, display_name, reported_status, computed_status, latency_ms, version, cpu_pct, ram_mb, uptime_pct_24h, last_error, metadata_json, last_heartbeat_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(tenant_id, component_id) DO UPDATE SET
       component_layer = excluded.component_layer,
       display_name = excluded.display_name,
       reported_status = excluded.reported_status,
       latency_ms = excluded.latency_ms,
       version = excluded.version,
       cpu_pct = excluded.cpu_pct,
       ram_mb = excluded.ram_mb,
       uptime_pct_24h = COALESCE(excluded.uptime_pct_24h, component_heartbeats.uptime_pct_24h),
       last_error = excluded.last_error,
       metadata_json = excluded.metadata_json,
       last_heartbeat_at = excluded.last_heartbeat_at,
       updated_at = excluded.updated_at`
  )
    .bind(
      crypto.randomUUID(),
      data.tenant_id,
      data.component_layer,
      data.component_id,
      data.display_name,
      data.status,
      data.status,
      data.latency_ms ?? null,
      data.version ?? null,
      data.cpu_pct ?? null,
      data.ram_mb ?? null,
      data.uptime_pct_24h ?? 100.0,
      data.last_error ?? null,
      JSON.stringify(data.metadata ?? {}),
      hbAt,
      nowIso
    )
    .run();

  const sync = await evaluateAndSyncHealth(c.env.DB, data.tenant_id, now);
  const updated = await c.env.DB.prepare(
    'SELECT * FROM component_heartbeats WHERE tenant_id = ? AND component_id = ? LIMIT 1'
  )
    .bind(data.tenant_id, data.component_id)
    .first<ComponentHeartbeatRow>();

  return c.json({
    ok: true,
    component: updated,
    sync,
  });
});

app.get(
  '/api/v2/health/overview',
  requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'),
  async (c) => {
    const tenantId = c.get('resolvedTenantId');
    const sync = await evaluateAndSyncHealth(c.env.DB, tenantId);

    const compQuery = tenantId
      ? c.env.DB.prepare(
          'SELECT * FROM component_heartbeats WHERE tenant_id = ? ORDER BY component_layer, component_id'
        ).bind(tenantId)
      : c.env.DB.prepare(
          'SELECT * FROM component_heartbeats ORDER BY tenant_id, component_layer, component_id'
        );
    const alertQuery = tenantId
      ? c.env.DB.prepare(
          `SELECT * FROM operational_alerts WHERE tenant_id = ?
           ORDER BY CASE status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END, triggered_at DESC`
        ).bind(tenantId)
      : c.env.DB.prepare(
          `SELECT * FROM operational_alerts
           ORDER BY CASE status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END, triggered_at DESC`
        );

    const [compRes, alertRes] = await Promise.all([
      compQuery.all<ComponentHeartbeatRow>(),
      alertQuery.all<OperationalAlertRow>(),
    ]);
    const components = compRes.results ?? [];
    const alerts = alertRes.results ?? [];

    const summary = {
      total_components: components.length,
      online: components.filter((x) => x.computed_status === 'ONLINE').length,
      degraded: components.filter((x) => x.computed_status === 'DEGRADED').length,
      offline: components.filter((x) => x.computed_status === 'OFFLINE').length,
      stale: components.filter((x) => x.computed_status === 'STALE').length,
      open_alerts: alerts.filter((a) => a.status === 'OPEN').length,
      acknowledged_alerts: alerts.filter((a) => a.status === 'ACKNOWLEDGED').length,
      resolved_alerts: alerts.filter((a) => a.status === 'RESOLVED').length,
      critical_alerts: alerts.filter((a) => a.status !== 'RESOLVED' && a.severity === 'CRITICAL')
        .length,
    };

    return c.json({
      tenant_id: tenantId,
      summary,
      components,
      alerts,
      sync,
    });
  }
);

app.post('/api/v2/health/alerts/:id/ack', requireRoles('MSSP_ADMIN', 'CISO'), async (c) => {
  const id = c.req.param('id');
  const alert = await c.env.DB.prepare('SELECT * FROM operational_alerts WHERE id = ? LIMIT 1')
    .bind(id)
    .first<OperationalAlertRow>();

  if (!alert) {
    return c.json({ error: 'Not Found', message: 'Alert not found' }, 404);
  }
  const auth = c.get('auth');
  if (auth.tenantId !== null && alert.tenant_id !== auth.tenantId) {
    return c.json({ error: 'Forbidden', message: 'Cross-tenant alert access denied' }, 403);
  }

  const nowIso = new Date().toISOString();
  await c.env.DB.prepare(
    `UPDATE operational_alerts
     SET status = CASE WHEN status = 'RESOLVED' THEN 'RESOLVED' ELSE 'ACKNOWLEDGED' END,
         acknowledged_at = COALESCE(acknowledged_at, ?)
     WHERE id = ?`
  )
    .bind(nowIso, id)
    .run();

  const updated = await c.env.DB.prepare('SELECT * FROM operational_alerts WHERE id = ? LIMIT 1')
    .bind(id)
    .first<OperationalAlertRow>();

  return c.json({ ok: true, alert: updated });
});

app.post('/api/v2/health/alerts/:id/resolve', requireRoles('MSSP_ADMIN', 'CISO'), async (c) => {
  const id = c.req.param('id');
  const alert = await c.env.DB.prepare('SELECT * FROM operational_alerts WHERE id = ? LIMIT 1')
    .bind(id)
    .first<OperationalAlertRow>();

  if (!alert) {
    return c.json({ error: 'Not Found', message: 'Alert not found' }, 404);
  }
  const auth = c.get('auth');
  if (auth.tenantId !== null && alert.tenant_id !== auth.tenantId) {
    return c.json({ error: 'Forbidden', message: 'Cross-tenant alert access denied' }, 403);
  }

  const nowIso = new Date().toISOString();
  await c.env.DB.prepare(
    `UPDATE operational_alerts
     SET status = 'RESOLVED', resolved_at = COALESCE(resolved_at, ?)
     WHERE id = ?`
  )
    .bind(nowIso, id)
    .run();

  const updated = await c.env.DB.prepare('SELECT * FROM operational_alerts WHERE id = ? LIMIT 1')
    .bind(id)
    .first<OperationalAlertRow>();

  return c.json({ ok: true, alert: updated });
});

app.post('/api/v2/health/simulate-outage', requireRoles('MSSP_ADMIN', 'CISO'), async (c) => {
  if (c.env.ENABLE_DEMO_TOOLS !== 'true') {
    return c.json(
      { error: 'Forbidden', message: 'Demo outage simulation is disabled in this environment' },
      403
    );
  }

  const parsed = await parseJson(c, SimulateOutageSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const existing = await c.env.DB.prepare(
    'SELECT * FROM component_heartbeats WHERE tenant_id = ? AND component_id = ? LIMIT 1'
  )
    .bind(data.tenant_id, data.component_id)
    .first<ComponentHeartbeatRow>();

  if (!existing) {
    return c.json(
      { error: 'Not Found', message: `Component '${data.component_id}' not found for tenant` },
      404
    );
  }

  const now = new Date();
  const hbIso = new Date(now.getTime() - data.backdate_minutes * 60_000).toISOString();

  await c.env.DB.prepare(
    `UPDATE component_heartbeats
     SET reported_status = ?, last_heartbeat_at = ?, last_error = ?, updated_at = ?
     WHERE id = ?`
  )
    .bind(
      data.target_status,
      hbIso,
      data.error_message ??
        (data.target_status === 'ONLINE'
          ? null
          : `Simulated ${data.target_status} outage triggered via demo tools`),
      now.toISOString(),
      existing.id
    )
    .run();

  const sync = await evaluateAndSyncHealth(c.env.DB, data.tenant_id, now);
  const [component, alertsRes] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM component_heartbeats WHERE id = ? LIMIT 1')
      .bind(existing.id)
      .first<ComponentHeartbeatRow>(),
    c.env.DB.prepare(
      'SELECT * FROM operational_alerts WHERE tenant_id = ? AND component_id = ? ORDER BY triggered_at DESC'
    )
      .bind(data.tenant_id, data.component_id)
      .all<OperationalAlertRow>(),
  ]);

  return c.json({
    ok: true,
    component,
    sync,
    alerts: alertsRes.results ?? [],
  });
});

// ---------------------------------------------------------------------------
// 2. Tenants Management
// ---------------------------------------------------------------------------

app.get('/api/v2/tenants', requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'), async (c) => {
  const auth = c.get('auth');
  const query = auth.tenantId
    ? c.env.DB.prepare('SELECT * FROM tenants WHERE id = ? LIMIT 1').bind(auth.tenantId)
    : c.env.DB.prepare('SELECT * FROM tenants ORDER BY created_at ASC');
  const res = await query.all<TenantRow>();
  return c.json({ tenants: res.results ?? [] });
});

app.post('/api/v2/tenants', requireRoles('MSSP_ADMIN'), async (c) => {
  const auth = c.get('auth');
  if (auth.tenantId !== null) {
    return c.json(
      { error: 'Forbidden', message: 'Tenant-scoped tokens cannot create new tenants' },
      403
    );
  }

  const parsed = await parseJson(c, TenantCreateSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const existing = await getTenantById(c.env.DB, data.id);
  if (existing) {
    return c.json({ error: 'Conflict', message: `Tenant '${data.id}' already exists` }, 409);
  }

  const nowIso = new Date().toISOString();
  await c.env.DB.prepare(
    `INSERT INTO tenants
     (id, name, industry, regulatory_profile, dpo_name, dpo_email, dpo_antai_registered, dpo_antai_reg_ref, active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
  )
    .bind(
      data.id,
      data.name,
      data.industry,
      data.regulatory_profile,
      data.dpo_name ?? null,
      data.dpo_email ?? null,
      data.dpo_antai_registered ? 1 : 0,
      data.dpo_antai_reg_ref ?? null,
      nowIso
    )
    .run();

  const tenant = await getTenantById(c.env.DB, data.id);
  return c.json({ ok: true, tenant }, 201);
});

app.patch('/api/v2/tenants/:id', requireRoles('MSSP_ADMIN', 'DPO'), async (c) => {
  const id = c.req.param('id') ?? '';
  if (!id) {
    return c.json({ error: 'Bad Request', message: 'Missing tenant id' }, 400);
  }
  const auth = c.get('auth');
  if (auth.tenantId !== null && auth.tenantId !== id) {
    return c.json({ error: 'Forbidden', message: 'Cross-tenant modification denied' }, 403);
  }

  const existing = await getTenantById(c.env.DB, id);
  if (!existing) {
    return c.json({ error: 'Not Found', message: `Tenant '${id}' not found` }, 404);
  }

  const parsed = await parseJson(c, TenantPatchSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  await c.env.DB.prepare(
    `UPDATE tenants SET
       name = ?,
       industry = ?,
       regulatory_profile = ?,
       dpo_name = ?,
       dpo_email = ?,
       dpo_antai_registered = ?,
       dpo_antai_reg_ref = ?,
       active = ?
     WHERE id = ?`
  )
    .bind(
      data.name ?? existing.name,
      data.industry ?? existing.industry,
      data.regulatory_profile ?? existing.regulatory_profile,
      data.dpo_name !== undefined ? data.dpo_name : existing.dpo_name,
      data.dpo_email !== undefined ? data.dpo_email : existing.dpo_email,
      data.dpo_antai_registered !== undefined
        ? data.dpo_antai_registered
          ? 1
          : 0
        : existing.dpo_antai_registered,
      data.dpo_antai_reg_ref !== undefined ? data.dpo_antai_reg_ref : existing.dpo_antai_reg_ref,
      data.active !== undefined ? (data.active ? 1 : 0) : existing.active,
      id
    )
    .run();

  const tenant = await getTenantById(c.env.DB, id);
  return c.json({ ok: true, tenant });
});

// ---------------------------------------------------------------------------
// 3. Telemetry Ingestion Endpoints
// ---------------------------------------------------------------------------

app.post('/api/v2/ingest/endpoint', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, EndpointIngestSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const nowIso = data.timestamp ?? new Date().toISOString();
  const dnsHitsCount = data.shadow_ai_dns_hits.reduce((sum, item) => sum + item.count, 0);
  const allUrlsCount = data.risky_extensions.filter((e) => e.has_all_urls).length;
  const riskyExtCount = Math.max(allUrlsCount, data.risky_extensions.length);
  const boxExposed = data.box_audit.installed ? data.box_audit.sensitive_files_count : 0;
  const onedriveExposed = data.onedrive_audit?.installed
    ? data.onedrive_audit.sensitive_files_count
    : 0;

  const riskScore = computeEndpointRiskScore({
    dnsHitsCount,
    allUrlsExtensionsCount: allUrlsCount,
    boxInstalled: data.box_audit.installed,
    boxDlpEnabled: data.box_audit.dlp_enabled,
    boxSensitiveFiles: data.box_audit.sensitive_files_count,
    onedriveInstalled: data.onedrive_audit?.installed,
    onedriveDlpEnabled: data.onedrive_audit?.dlp_enabled,
    onedriveSensitiveFiles: data.onedrive_audit?.sensitive_files_count,
  });

  const epId = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO endpoints
     (id, tenant_id, hostname, username, ip_address, os_version, agent_version, dns_hits_count, risky_extensions_count, box_exposed_files, box_dlp_active, onedrive_exposed_files, endpoint_risk_score, status, last_seen_at, details_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?)
     ON CONFLICT(tenant_id, hostname) DO UPDATE SET
       username = excluded.username,
       ip_address = excluded.ip_address,
       os_version = excluded.os_version,
       agent_version = excluded.agent_version,
       dns_hits_count = excluded.dns_hits_count,
       risky_extensions_count = excluded.risky_extensions_count,
       box_exposed_files = excluded.box_exposed_files,
       box_dlp_active = excluded.box_dlp_active,
       onedrive_exposed_files = excluded.onedrive_exposed_files,
       endpoint_risk_score = excluded.endpoint_risk_score,
       status = 'ONLINE',
       last_seen_at = excluded.last_seen_at,
       details_json = excluded.details_json`
  )
    .bind(
      epId,
      data.tenant_id,
      data.hostname,
      data.username,
      data.ip_address ?? null,
      data.os_version,
      data.agent_version,
      dnsHitsCount,
      riskyExtCount,
      boxExposed,
      data.box_audit.dlp_enabled ? 1 : 0,
      onedriveExposed,
      riskScore,
      nowIso,
      JSON.stringify({
        risky_extensions: data.risky_extensions,
        box_audit: data.box_audit,
        onedrive_audit: data.onedrive_audit ?? null,
      })
    )
    .run();

  for (const hit of data.shadow_ai_dns_hits) {
    await c.env.DB.prepare(
      `INSERT INTO shadow_ai_events
       (id, tenant_id, source, client_ip, hostname, domain, category, hits, blocked, recorded_at)
       VALUES (?, ?, 'ENDPOINT_AGENT', ?, ?, ?, ?, ?, 0, ?)`
    )
      .bind(
        crypto.randomUUID(),
        data.tenant_id,
        data.ip_address ?? '0.0.0.0',
        data.hostname,
        hit.domain,
        hit.category,
        hit.count,
        hit.last_timestamp ?? nowIso
      )
      .run();
  }

  return c.json({
    ok: true,
    hostname: data.hostname,
    endpoint_risk_score: riskScore,
    dns_hits_count: dnsHitsCount,
  });
});

app.post('/api/v2/ingest/findings', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, FindingBatchSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const nowIso = new Date().toISOString();
  for (const f of data.findings) {
    await c.env.DB.prepare(
      `INSERT INTO scan_findings
       (id, tenant_id, scan_id, source_type, repository_name, location_path, entity_type, masked_sample, value_sha256, match_count, is_sensitive, severity, retention_age_days, retention_violation, is_simulated, detected_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        crypto.randomUUID(),
        data.tenant_id,
        data.scan_id,
        f.source_type,
        f.repository_name,
        f.location_path,
        f.entity_type,
        f.masked_sample,
        f.value_sha256,
        f.match_count,
        f.is_sensitive ? 1 : 0,
        f.severity,
        f.retention_age_days ?? null,
        f.retention_violation ? 1 : 0,
        data.is_simulated ? 1 : 0,
        f.detected_at ?? nowIso
      )
      .run();
  }

  return c.json({
    ok: true,
    scan_id: data.scan_id,
    scanner_layer: data.scanner_layer,
    inserted: data.findings.length,
    total_assets_scanned: data.total_assets_scanned,
  });
});

app.post('/api/v2/ingest/shadow-ai', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, ShadowAiBatchSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const nowIso = new Date().toISOString();
  for (const ev of data.events) {
    await c.env.DB.prepare(
      `INSERT INTO shadow_ai_events
       (id, tenant_id, source, client_ip, hostname, domain, category, hits, blocked, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        crypto.randomUUID(),
        data.tenant_id,
        data.source,
        ev.client_ip,
        ev.hostname ?? null,
        ev.domain,
        ev.category,
        ev.hits,
        ev.blocked ? 1 : 0,
        ev.timestamp ?? nowIso
      )
      .run();
  }

  return c.json({
    ok: true,
    source: data.source,
    inserted: data.events.length,
    total_queries_inspected: data.total_queries_inspected,
  });
});

app.post('/api/v2/ingest/casb-webhook', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, CasbWebhookSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  await c.env.DB.prepare(
    `INSERT INTO casb_events
     (id, tenant_id, event_id, saas_app, resource_name, finding_type, exposure_level, remediated_automatically, remediation_action, severity, detected_at, remediated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(tenant_id, event_id) DO UPDATE SET
       saas_app = excluded.saas_app,
       resource_name = excluded.resource_name,
       finding_type = excluded.finding_type,
       exposure_level = excluded.exposure_level,
       remediated_automatically = excluded.remediated_automatically,
       remediation_action = excluded.remediation_action,
       severity = excluded.severity,
       detected_at = excluded.detected_at,
       remediated_at = excluded.remediated_at`
  )
    .bind(
      crypto.randomUUID(),
      data.tenant_id,
      data.event_id,
      data.saas_app,
      data.resource_name,
      data.finding_type,
      data.exposure_level,
      data.remediated_automatically ? 1 : 0,
      data.remediation_action ?? null,
      data.severity,
      data.detected_at,
      data.remediated_at ?? null
    )
    .run();

  return c.json({
    ok: true,
    event_id: data.event_id,
    remediated_automatically: data.remediated_automatically,
  });
});

app.post('/api/v2/ingest/logpush', requireRoles('MSSP_ADMIN', 'COLLECTOR'), async (c) => {
  const parsed = await parseJson(c, LogpushBatchSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const id = crypto.randomUUID();
  const nowIso = new Date().toISOString();

  await c.env.DB.prepare(
    `INSERT INTO logpush_batches
     (id, tenant_id, dataset, records_count, lag_seconds, encrypted_with_customer_key, r2_object_key, summary_json, ingested_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      data.tenant_id,
      data.dataset,
      data.records_count,
      data.lag_seconds,
      data.encrypted_with_customer_key ? 1 : 0,
      data.r2_object_key ?? null,
      JSON.stringify(data.summary_counts),
      nowIso
    )
    .run();

  return c.json({
    ok: true,
    id,
    dataset: data.dataset,
    records_count: data.records_count,
  });
});

// ---------------------------------------------------------------------------
// 4. Compliance: DSARs (ARCO), 72h Breaches, Cross-border Transfers, Ficha Técnica
// ---------------------------------------------------------------------------

function enrichDsar(row: DsarRequestRow, now: Date) {
  const daysRem = businessDaysRemaining(now, row.due_at);
  const isClosed = row.status === 'COMPLETED' || row.status === 'REJECTED';
  return {
    ...row,
    target_systems: safeJsonParse<string[]>(row.target_systems_json, []),
    evidence: safeJsonParse<Record<string, unknown>>(row.evidence_json, {}),
    business_days_remaining: isClosed ? 0 : daysRem,
    is_overdue: !isClosed && daysRem < 0,
  };
}

app.get(
  '/api/v2/compliance/dsar',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const now = new Date();
    const res = await c.env.DB.prepare(
      'SELECT * FROM dsar_requests WHERE tenant_id = ? ORDER BY due_at ASC'
    )
      .bind(tenant.id)
      .all<DsarRequestRow>();

    return c.json({
      tenant_id: tenant.id,
      dsars: (res.results ?? []).map((r) => enrichDsar(r, now)),
    });
  }
);

app.post('/api/v2/compliance/dsar', requireRoles('MSSP_ADMIN', 'DPO', 'CISO'), async (c) => {
  const parsed = await parseJson(c, DsarCreateSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const now = new Date();
  const receivedDate = data.received_at ? new Date(data.received_at) : now;
  if (Number.isNaN(receivedDate.getTime())) {
    return c.json({ error: 'Bad Request', message: 'Invalid received_at timestamp' }, 400);
  }

  const slaDays = getDsarSlaBusinessDays(data.right_type);
  const dueAt = addPanamaBusinessDays(receivedDate, slaDays);
  const id = crypto.randomUUID();

  await c.env.DB.prepare(
    `INSERT INTO dsar_requests
     (id, tenant_id, requester_name, requester_id_masked, right_type, sla_business_days, received_at, due_at, status, target_systems_json, notes, completed_at, evidence_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, NULL, '{}')`
  )
    .bind(
      id,
      data.tenant_id,
      data.requester_name,
      data.requester_id_masked,
      data.right_type,
      slaDays,
      receivedDate.toISOString(),
      dueAt.toISOString(),
      JSON.stringify(data.target_systems),
      data.notes ?? null
    )
    .run();

  const row = await c.env.DB.prepare('SELECT * FROM dsar_requests WHERE id = ? LIMIT 1')
    .bind(id)
    .first<DsarRequestRow>();

  return c.json({ ok: true, dsar: row ? enrichDsar(row, now) : null }, 201);
});

app.patch('/api/v2/compliance/dsar/:id', requireRoles('MSSP_ADMIN', 'DPO', 'CISO'), async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT * FROM dsar_requests WHERE id = ? LIMIT 1')
    .bind(id)
    .first<DsarRequestRow>();

  if (!existing) {
    return c.json({ error: 'Not Found', message: 'DSAR request not found' }, 404);
  }

  const auth = c.get('auth');
  if (auth.tenantId !== null && existing.tenant_id !== auth.tenantId) {
    return c.json({ error: 'Forbidden', message: 'Cross-tenant DSAR access denied' }, 403);
  }

  const parsed = await parseJson(c, DsarPatchSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const now = new Date();
  const nextStatus = data.status ?? existing.status;
  const completedAt =
    data.completed_at !== undefined
      ? data.completed_at
      : nextStatus === 'COMPLETED' && !existing.completed_at
        ? now.toISOString()
        : existing.completed_at;

  await c.env.DB.prepare(
    `UPDATE dsar_requests SET
       status = ?,
       notes = ?,
       target_systems_json = ?,
       evidence_json = ?,
       completed_at = ?
     WHERE id = ?`
  )
    .bind(
      nextStatus,
      data.notes !== undefined ? data.notes : existing.notes,
      data.target_systems ? JSON.stringify(data.target_systems) : existing.target_systems_json,
      data.evidence ? JSON.stringify(data.evidence) : existing.evidence_json,
      completedAt,
      id
    )
    .run();

  const updated = await c.env.DB.prepare('SELECT * FROM dsar_requests WHERE id = ? LIMIT 1')
    .bind(id)
    .first<DsarRequestRow>();

  return c.json({ ok: true, dsar: updated ? enrichDsar(updated, now) : null });
});

app.get(
  '/api/v2/compliance/dsar/:id/export',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const id = c.req.param('id');
    const dsar = await c.env.DB.prepare('SELECT * FROM dsar_requests WHERE id = ? LIMIT 1')
      .bind(id)
      .first<DsarRequestRow>();

    if (!dsar) {
      return c.json({ error: 'Not Found', message: 'DSAR request not found' }, 404);
    }

    const auth = c.get('auth');
    if (auth.tenantId !== null && dsar.tenant_id !== auth.tenantId) {
      return c.json({ error: 'Forbidden', message: 'Cross-tenant DSAR export denied' }, 403);
    }

    const [tenant, findingsRes] = await Promise.all([
      getTenantById(c.env.DB, dsar.tenant_id),
      c.env.DB.prepare(
        'SELECT source_type, repository_name, location_path, entity_type, masked_sample, severity, detected_at FROM scan_findings WHERE tenant_id = ? LIMIT 100'
      )
        .bind(dsar.tenant_id)
        .all(),
    ]);

    const now = new Date();
    const pkg = {
      export_type: 'LEY_81_ARCO_EVIDENCE_PACKAGE',
      exported_at: now.toISOString(),
      legal_framework: 'Ley 81 de 2019 y Decreto Ejecutivo 285 de 2021 (República de Panamá)',
      tenant: tenant
        ? {
            id: tenant.id,
            name: tenant.name,
            regulatory_profile: tenant.regulatory_profile,
            dpo_name: tenant.dpo_name,
            dpo_email: tenant.dpo_email,
          }
        : null,
      dsar: enrichDsar(dsar, now),
      correlated_repositories: findingsRes.results ?? [],
    };
    const digest = await sha256Hex(JSON.stringify(pkg));

    return c.json({
      ...pkg,
      sha256_integrity: digest,
    });
  }
);

function enrichBreach(row: BreachIncidentRow, now: Date) {
  const compromisedTypes = safeJsonParse<string[]>(row.compromised_data_types_json, []);
  const deadlineMs = Date.parse(row.deadline_72h_at);
  const diffMs = Number.isFinite(deadlineMs) ? deadlineMs - now.getTime() : 0;
  const hoursRemaining = Math.round((diffMs / 3600_000) * 10) / 10;
  const isClosedOrNotified = row.status === 'NOTIFIED_ANTAI' || row.status === 'CLOSED';
  const missingElements: string[] = [];
  if (!row.what_happened.trim()) missingElements.push('what_happened');
  if (compromisedTypes.length === 0) missingElements.push('compromised_data_types');
  if (!row.measures_adopted.trim()) missingElements.push('measures_adopted');
  if (!row.titular_actions.trim()) missingElements.push('titular_actions');
  if (!row.contact_point.trim()) missingElements.push('contact_point');

  return {
    ...row,
    compromised_data_types: compromisedTypes,
    hours_remaining_72h: hoursRemaining,
    is_overdue_72h: !isClosedOrNotified && diffMs < 0,
    art37_complete: missingElements.length === 0,
    missing_art37_elements: missingElements,
  };
}

app.get(
  '/api/v2/compliance/breaches',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const now = new Date();
    const res = await c.env.DB.prepare(
      'SELECT * FROM breach_incidents WHERE tenant_id = ? ORDER BY detected_at DESC'
    )
      .bind(tenant.id)
      .all<BreachIncidentRow>();

    return c.json({
      tenant_id: tenant.id,
      breaches: (res.results ?? []).map((b) => enrichBreach(b, now)),
    });
  }
);

app.post('/api/v2/compliance/breaches', requireRoles('MSSP_ADMIN', 'DPO', 'CISO'), async (c) => {
  const parsed = await parseJson(c, BreachCreateSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const now = new Date();
  const detectedDate = data.detected_at ? new Date(data.detected_at) : now;
  if (Number.isNaN(detectedDate.getTime())) {
    return c.json({ error: 'Bad Request', message: 'Invalid detected_at timestamp' }, 400);
  }
  const deadline72h = new Date(detectedDate.getTime() + 72 * 3600_000);
  const id = crypto.randomUUID();

  await c.env.DB.prepare(
    `INSERT INTO breach_incidents
     (id, tenant_id, title, severity, status, what_happened, compromised_data_types_json, affected_records_estimate, measures_adopted, titular_actions, contact_point, detected_at, deadline_72h_at, antai_notified_at)
     VALUES (?, ?, ?, ?, 'DETECTED', ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
  )
    .bind(
      id,
      data.tenant_id,
      data.title,
      data.severity,
      data.what_happened,
      JSON.stringify(data.compromised_data_types),
      data.affected_records_estimate,
      data.measures_adopted,
      data.titular_actions,
      data.contact_point,
      detectedDate.toISOString(),
      deadline72h.toISOString()
    )
    .run();

  const row = await c.env.DB.prepare('SELECT * FROM breach_incidents WHERE id = ? LIMIT 1')
    .bind(id)
    .first<BreachIncidentRow>();

  return c.json({ ok: true, breach: row ? enrichBreach(row, now) : null }, 201);
});

app.patch(
  '/api/v2/compliance/breaches/:id',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO'),
  async (c) => {
    const id = c.req.param('id');
    const existing = await c.env.DB.prepare('SELECT * FROM breach_incidents WHERE id = ? LIMIT 1')
      .bind(id)
      .first<BreachIncidentRow>();

    if (!existing) {
      return c.json({ error: 'Not Found', message: 'Breach incident not found' }, 404);
    }

    const auth = c.get('auth');
    if (auth.tenantId !== null && existing.tenant_id !== auth.tenantId) {
      return c.json({ error: 'Forbidden', message: 'Cross-tenant breach access denied' }, 403);
    }

    const parsed = await parseJson(c, BreachPatchSchema);
    if ('errorResponse' in parsed) return parsed.errorResponse;
    const data = parsed.data;

    const now = new Date();
    const nextStatus = data.status ?? existing.status;
    const antaiNotifiedAt =
      data.antai_notified_at !== undefined
        ? data.antai_notified_at
        : nextStatus === 'NOTIFIED_ANTAI' && !existing.antai_notified_at
          ? now.toISOString()
          : existing.antai_notified_at;

    await c.env.DB.prepare(
      `UPDATE breach_incidents SET
         status = ?,
         severity = ?,
         what_happened = ?,
         compromised_data_types_json = ?,
         affected_records_estimate = ?,
         measures_adopted = ?,
         titular_actions = ?,
         contact_point = ?,
         antai_notified_at = ?
       WHERE id = ?`
    )
      .bind(
        nextStatus,
        data.severity ?? existing.severity,
        data.what_happened ?? existing.what_happened,
        data.compromised_data_types
          ? JSON.stringify(data.compromised_data_types)
          : existing.compromised_data_types_json,
        data.affected_records_estimate ?? existing.affected_records_estimate,
        data.measures_adopted ?? existing.measures_adopted,
        data.titular_actions ?? existing.titular_actions,
        data.contact_point ?? existing.contact_point,
        antaiNotifiedAt,
        id
      )
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM breach_incidents WHERE id = ? LIMIT 1')
      .bind(id)
      .first<BreachIncidentRow>();

    return c.json({ ok: true, breach: updated ? enrichBreach(updated, now) : null });
  }
);

app.get(
  '/api/v2/compliance/breaches/:id/antai-draft',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const id = c.req.param('id');
    const breach = await c.env.DB.prepare('SELECT * FROM breach_incidents WHERE id = ? LIMIT 1')
      .bind(id)
      .first<BreachIncidentRow>();

    if (!breach) {
      return c.json({ error: 'Not Found', message: 'Breach incident not found' }, 404);
    }

    const auth = c.get('auth');
    if (auth.tenantId !== null && breach.tenant_id !== auth.tenantId) {
      return c.json({ error: 'Forbidden', message: 'Cross-tenant breach draft access denied' }, 403);
    }

    const tenant = await getTenantById(c.env.DB, breach.tenant_id);
    const now = new Date();
    const enriched = enrichBreach(breach, now);
    const deadlineMs = Date.parse(breach.deadline_72h_at);
    const remainingMs = Number.isFinite(deadlineMs) ? deadlineMs - now.getTime() : 0;

    return c.json({
      document_type: 'NOTIFICACION_BRECHA_SEGURIDAD_ANTAI',
      legal_basis: 'Decreto Ejecutivo 285 de 2021, Art. 37 y Art. 48.3 (Ley 81 de 2019)',
      generated_at: now.toISOString(),
      incident_id: breach.id,
      title: breach.title,
      severity: breach.severity,
      status: breach.status,
      detected_at: breach.detected_at,
      deadline_72h_at: breach.deadline_72h_at,
      countdown: {
        hours_remaining: enriched.hours_remaining_72h,
        minutes_remaining: Math.round(remainingMs / 60_000),
        is_overdue: enriched.is_overdue_72h,
      },
      tenant: tenant
        ? {
            id: tenant.id,
            name: tenant.name,
            regulatory_profile: tenant.regulatory_profile,
            dpo_name: tenant.dpo_name,
            dpo_email: tenant.dpo_email,
            dpo_antai_registered: Boolean(tenant.dpo_antai_registered),
            dpo_antai_reg_ref: tenant.dpo_antai_reg_ref,
          }
        : null,
      affected_records_estimate: breach.affected_records_estimate,
      five_required_elements: {
        what_happened: breach.what_happened,
        compromised_data_types: enriched.compromised_data_types,
        measures_adopted: breach.measures_adopted,
        titular_actions: breach.titular_actions,
        contact_point: breach.contact_point,
      },
      ready_for_submission: enriched.art37_complete,
      missing_elements: enriched.missing_art37_elements,
    });
  }
);

function enrichTransfer(row: DataTransferRow) {
  return {
    ...row,
    is_cross_border: Boolean(row.is_cross_border),
    dpa_contract_active: Boolean(row.dpa_contract_active),
    destructor_verified: Boolean(row.destructor_verified),
    data_categories: safeJsonParse<string[]>(row.data_categories_json, []),
    dpa_gap: Boolean(row.is_cross_border) && !row.dpa_contract_active,
  };
}

app.get(
  '/api/v2/compliance/transfers',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const res = await c.env.DB.prepare(
      'SELECT * FROM data_transfers WHERE tenant_id = ? ORDER BY created_at DESC'
    )
      .bind(tenant.id)
      .all<DataTransferRow>();

    return c.json({
      tenant_id: tenant.id,
      transfers: (res.results ?? []).map(enrichTransfer),
    });
  }
);

app.post('/api/v2/compliance/transfers', requireRoles('MSSP_ADMIN', 'DPO', 'CISO'), async (c) => {
  const parsed = await parseJson(c, TransferCreateSchema);
  if ('errorResponse' in parsed) return parsed.errorResponse;
  const data = parsed.data;

  const tenantCheck = verifyPayloadTenantAccess(c, data.tenant_id);
  if (tenantCheck) return tenantCheck;

  const tenant = await getTenantById(c.env.DB, data.tenant_id);
  if (!tenant) {
    return c.json({ error: 'Not Found', message: `Tenant '${data.tenant_id}' not found` }, 404);
  }

  const id = crypto.randomUUID();
  const nowIso = new Date().toISOString();

  await c.env.DB.prepare(
    `INSERT INTO data_transfers
     (id, tenant_id, recipient_name, destination_country, is_cross_border, purpose, data_categories_json, legal_basis, dpa_contract_active, max_retention_days, destructor_verified, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      data.tenant_id,
      data.recipient_name,
      data.destination_country,
      data.is_cross_border ? 1 : 0,
      data.purpose,
      JSON.stringify(data.data_categories),
      data.legal_basis,
      data.dpa_contract_active ? 1 : 0,
      data.max_retention_days,
      data.destructor_verified ? 1 : 0,
      nowIso
    )
    .run();

  const row = await c.env.DB.prepare('SELECT * FROM data_transfers WHERE id = ? LIMIT 1')
    .bind(id)
    .first<DataTransferRow>();

  return c.json({ ok: true, transfer: row ? enrichTransfer(row) : null }, 201);
});

app.patch(
  '/api/v2/compliance/transfers/:id',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO'),
  async (c) => {
    const id = c.req.param('id');
    const existing = await c.env.DB.prepare('SELECT * FROM data_transfers WHERE id = ? LIMIT 1')
      .bind(id)
      .first<DataTransferRow>();

    if (!existing) {
      return c.json({ error: 'Not Found', message: 'Transfer record not found' }, 404);
    }

    const auth = c.get('auth');
    if (auth.tenantId !== null && existing.tenant_id !== auth.tenantId) {
      return c.json({ error: 'Forbidden', message: 'Cross-tenant transfer access denied' }, 403);
    }

    const parsed = await parseJson(c, TransferPatchSchema);
    if ('errorResponse' in parsed) return parsed.errorResponse;
    const data = parsed.data;

    await c.env.DB.prepare(
      `UPDATE data_transfers SET
         purpose = ?,
         legal_basis = ?,
         dpa_contract_active = ?,
         max_retention_days = ?,
         destructor_verified = ?,
         data_categories_json = ?
       WHERE id = ?`
    )
      .bind(
        data.purpose ?? existing.purpose,
        data.legal_basis ?? existing.legal_basis,
        data.dpa_contract_active !== undefined
          ? data.dpa_contract_active
            ? 1
            : 0
          : existing.dpa_contract_active,
        data.max_retention_days ?? existing.max_retention_days,
        data.destructor_verified !== undefined
          ? data.destructor_verified
            ? 1
            : 0
          : existing.destructor_verified,
        data.data_categories
          ? JSON.stringify(data.data_categories)
          : existing.data_categories_json,
        id
      )
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM data_transfers WHERE id = ? LIMIT 1')
      .bind(id)
      .first<DataTransferRow>();

    return c.json({ ok: true, transfer: updated ? enrichTransfer(updated) : null });
  }
);

app.post(
  '/api/v2/compliance/ficha-tecnica/generate',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO'),
  async (c) => {
    const bodyRaw = await c.req.text();
    let requestedTenantId: string | undefined;
    let generatedBy: string | undefined;

    if (bodyRaw.trim().length > 0) {
      let jsonVal: unknown;
      try {
        jsonVal = JSON.parse(bodyRaw);
      } catch {
        return c.json({ error: 'Bad Request', message: 'Invalid JSON request body' }, 400);
      }
      const parsed = FichaGenerateSchema.safeParse(jsonVal);
      if (!parsed.success) {
        return c.json(
          { error: 'Validation Error', issues: parsed.error.issues },
          400
        );
      }
      requestedTenantId = parsed.data.tenant_id;
      generatedBy = parsed.data.generated_by;
    }

    if (requestedTenantId) {
      const tenantCheck = verifyPayloadTenantAccess(c, requestedTenantId);
      if (tenantCheck) return tenantCheck;
    }

    const resolved = await resolveTenantOrError(c, requestedTenantId ?? null);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const now = new Date();
    await evaluateAndSyncHealth(c.env.DB, tenant.id, now);
    const dataset = await loadTenantDataset(c.env.DB, tenant.id);
    const risk = evaluateCisoRisk({ tenant, ...dataset, now });

    const maxVersionRow = await c.env.DB.prepare(
      'SELECT COALESCE(MAX(version_num), 0) AS max_ver FROM ficha_tecnica_snapshots WHERE tenant_id = ?'
    )
      .bind(tenant.id)
      .first<{ max_ver: number }>();
    const versionNum = (maxVersionRow?.max_ver ?? 0) + 1;

    const auth = c.get('auth');
    const actor = generatedBy ?? `${auth.role}:${auth.label}`;
    const generatedAt = now.toISOString();

    const document = {
      schema_version: '2.0.0',
      document_type: 'FICHA_TECNICA_LEY_81_PANAMA',
      version_num: versionNum,
      generated_at: generatedAt,
      generated_by: actor,
      tenant: {
        id: tenant.id,
        name: tenant.name,
        industry: tenant.industry,
        regulatory_profile: tenant.regulatory_profile,
        dpo_name: tenant.dpo_name,
        dpo_email: tenant.dpo_email,
        dpo_antai_registered: Boolean(tenant.dpo_antai_registered),
        dpo_antai_reg_ref: tenant.dpo_antai_reg_ref,
      },
      regulatory_framework: risk.regulatory_context,
      risk_posture: {
        global_score: risk.global_score,
        semaphore: risk.semaphore,
        vectors: risk.vectors,
        kpis: risk.kpis,
      },
      data_processing_inventory: {
        endpoints_count: dataset.endpoints.length,
        findings_count: dataset.findings.length,
        cross_border_transfers: dataset.transfers.map(enrichTransfer),
      },
      arco_dsar_summary: {
        total_requests: dataset.dsars.length,
        overdue_requests: risk.kpis.overdue_dsars,
        requests: dataset.dsars.map((d) => enrichDsar(d, now)),
      },
      breaches_72h_summary: {
        total_incidents: dataset.breaches.length,
        overdue_72h: risk.kpis.overdue_breaches_72h,
        incidents: dataset.breaches.map((b) => enrichBreach(b, now)),
      },
      legal_findings: risk.legal_findings,
    };

    const serialized = JSON.stringify(document, null, 2);
    const sha256Hash = await sha256Hex(serialized);
    const timestampSlug = generatedAt.replace(/[:.]/g, '-');
    const r2ObjectKey = `ficha-tecnica/${tenant.id}/v${versionNum}-${timestampSlug}.json`;

    await c.env.EVIDENCE_BUCKET.put(r2ObjectKey, serialized, {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        tenant_id: tenant.id,
        version_num: String(versionNum),
        sha256_hash: sha256Hash,
      },
    });

    const snapshotId = crypto.randomUUID();
    await c.env.DB.prepare(
      `INSERT INTO ficha_tecnica_snapshots
       (id, tenant_id, version_num, regulatory_profile, r2_object_key, sha256_hash, generated_by, generated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        snapshotId,
        tenant.id,
        versionNum,
        tenant.regulatory_profile,
        r2ObjectKey,
        sha256Hash,
        actor,
        generatedAt
      )
      .run();

    const snapshot = await c.env.DB.prepare(
      'SELECT * FROM ficha_tecnica_snapshots WHERE id = ? LIMIT 1'
    )
      .bind(snapshotId)
      .first<FichaTecnicaSnapshotRow>();

    return c.json(
      {
        ok: true,
        snapshot,
        sha256_hash: sha256Hash,
        r2_object_key: r2ObjectKey,
        document,
      },
      201
    );
  }
);

app.get(
  '/api/v2/compliance/ficha-tecnica',
  requireRoles('MSSP_ADMIN', 'DPO', 'CISO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const res = await c.env.DB.prepare(
      'SELECT * FROM ficha_tecnica_snapshots WHERE tenant_id = ? ORDER BY version_num DESC'
    )
      .bind(tenant.id)
      .all<FichaTecnicaSnapshotRow>();
    const snapshots = res.results ?? [];

    const snapshotIdParam = c.req.query('snapshot_id');
    const includeLatest = c.req.query('include_latest') === 'true';
    const targetSnapshot = snapshotIdParam
      ? snapshots.find((s) => s.id === snapshotIdParam) ?? null
      : includeLatest
        ? snapshots[0] ?? null
        : null;

    let document: Record<string, unknown> | null = null;
    let integrityVerified: boolean | null = null;

    if (targetSnapshot) {
      const obj = await c.env.EVIDENCE_BUCKET.get(targetSnapshot.r2_object_key);
      if (obj) {
        const text = await obj.text();
        const computedHash = await sha256Hex(text);
        integrityVerified = computedHash === targetSnapshot.sha256_hash;
        document = safeJsonParse<Record<string, unknown> | null>(text, null);
      }
    }

    return c.json({
      tenant_id: tenant.id,
      snapshots,
      selected_snapshot: targetSnapshot,
      integrity_verified: integrityVerified,
      document,
    });
  }
);

// ---------------------------------------------------------------------------
// 5. Role-Specific Dashboards: CISO, SOC Health, DPO, Assets
// ---------------------------------------------------------------------------

app.get(
  '/api/v2/dashboard/ciso',
  requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const now = new Date();
    await evaluateAndSyncHealth(c.env.DB, tenant.id, now);
    const dataset = await loadTenantDataset(c.env.DB, tenant.id);
    const risk = evaluateCisoRisk({ tenant, ...dataset, now });

    const historyRes = await c.env.DB.prepare(
      'SELECT * FROM risk_history WHERE tenant_id = ? ORDER BY recorded_date ASC LIMIT 30'
    )
      .bind(tenant.id)
      .all<RiskHistoryRow>();

    // Top Shadow AI domains
    const domainAgg = new Map<string, { domain: string; category: string; hits: number; blocked_hits: number }>();
    for (const ev of dataset.shadowAiEvents) {
      const cur = domainAgg.get(ev.domain) ?? {
        domain: ev.domain,
        category: ev.category,
        hits: 0,
        blocked_hits: 0,
      };
      cur.hits += ev.hits;
      if (ev.blocked) cur.blocked_hits += ev.hits;
      domainAgg.set(ev.domain, cur);
    }

    // Top Risky Repositories
    const repoAgg = new Map<
      string,
      { repository_name: string; source_type: string; findings_count: number; total_matches: number }
    >();
    for (const f of dataset.findings) {
      const key = `${f.source_type}::${f.repository_name}`;
      const cur = repoAgg.get(key) ?? {
        repository_name: f.repository_name,
        source_type: f.source_type,
        findings_count: 0,
        total_matches: 0,
      };
      cur.findings_count += 1;
      cur.total_matches += f.match_count;
      repoAgg.set(key, cur);
    }

    return c.json({
      tenant: {
        id: tenant.id,
        name: tenant.name,
        industry: tenant.industry,
        regulatory_profile: tenant.regulatory_profile,
        dpo_antai_registered: Boolean(tenant.dpo_antai_registered),
      },
      risk,
      risk_history: historyRes.results ?? [],
      top_shadow_ai_domains: Array.from(domainAgg.values())
        .sort((a, b) => b.hits - a.hits)
        .slice(0, 10),
      top_risky_repositories: Array.from(repoAgg.values())
        .sort((a, b) => b.total_matches - a.total_matches)
        .slice(0, 10),
    });
  }
);

app.get(
  '/api/v2/dashboard/soc-health',
  requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'),
  async (c) => {
    const tenantId = c.get('resolvedTenantId');
    const now = new Date();
    const sync = await evaluateAndSyncHealth(c.env.DB, tenantId, now);

    const compQuery = tenantId
      ? c.env.DB.prepare(
          'SELECT * FROM component_heartbeats WHERE tenant_id = ? ORDER BY component_layer, component_id'
        ).bind(tenantId)
      : c.env.DB.prepare(
          'SELECT * FROM component_heartbeats ORDER BY tenant_id, component_layer, component_id'
        );
    const alertQuery = tenantId
      ? c.env.DB.prepare(
          `SELECT * FROM operational_alerts WHERE tenant_id = ?
           ORDER BY CASE status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END, triggered_at DESC`
        ).bind(tenantId)
      : c.env.DB.prepare(
          `SELECT * FROM operational_alerts
           ORDER BY CASE status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END, triggered_at DESC`
        );
    const casbQuery = tenantId
      ? c.env.DB.prepare(
          'SELECT * FROM casb_events WHERE tenant_id = ? ORDER BY detected_at DESC LIMIT 50'
        ).bind(tenantId)
      : c.env.DB.prepare('SELECT * FROM casb_events ORDER BY detected_at DESC LIMIT 50');
    const logpushQuery = tenantId
      ? c.env.DB.prepare(
          'SELECT * FROM logpush_batches WHERE tenant_id = ? ORDER BY ingested_at DESC LIMIT 50'
        ).bind(tenantId)
      : c.env.DB.prepare('SELECT * FROM logpush_batches ORDER BY ingested_at DESC LIMIT 50');

    const [compRes, alertRes, casbRes, logpushRes] = await Promise.all([
      compQuery.all<ComponentHeartbeatRow>(),
      alertQuery.all<OperationalAlertRow>(),
      casbQuery.all<CasbEventRow>(),
      logpushQuery.all<LogpushBatchRow>(),
    ]);

    const components = compRes.results ?? [];
    const alerts = alertRes.results ?? [];
    const casbEvents = casbRes.results ?? [];
    const logpushBatches = logpushRes.results ?? [];

    const latencies = components
      .map((x) => x.latency_ms)
      .filter((v): v is number => typeof v === 'number' && v > 0);
    const avgLatencyMs =
      latencies.length > 0
        ? Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 10) / 10
        : 0;

    const layers = ALL_LAYERS_ORDER.map((layer) => {
      const items = components.filter((x) => x.component_layer === layer);
      const worst = items.some((x) => x.computed_status === 'OFFLINE')
        ? 'OFFLINE'
        : items.some((x) => x.computed_status === 'DEGRADED')
          ? 'DEGRADED'
          : items.some((x) => x.computed_status === 'STALE')
            ? 'STALE'
            : items.length > 0
              ? 'ONLINE'
              : 'OFFLINE';
      return {
        layer,
        count: items.length,
        online: items.filter((x) => x.computed_status === 'ONLINE').length,
        worst_status: worst,
        components: items,
      };
    });

    const autoRemCount = casbEvents.filter((e) => e.remediated_automatically === 1).length;
    const autoRemPct =
      casbEvents.length > 0 ? Math.round((autoRemCount / casbEvents.length) * 1000) / 10 : 0;

    const totalLogpushRecords = logpushBatches.reduce((s, b) => s + b.records_count, 0);
    const cmkBatches = logpushBatches.filter((b) => b.encrypted_with_customer_key === 1).length;
    const avgLagSeconds =
      logpushBatches.length > 0
        ? Math.round(
            (logpushBatches.reduce((s, b) => s + b.lag_seconds, 0) / logpushBatches.length) * 10
          ) / 10
        : 0;

    return c.json({
      tenant_id: tenantId,
      summary: {
        total_components: components.length,
        online: components.filter((x) => x.computed_status === 'ONLINE').length,
        degraded: components.filter((x) => x.computed_status === 'DEGRADED').length,
        offline: components.filter((x) => x.computed_status === 'OFFLINE').length,
        stale: components.filter((x) => x.computed_status === 'STALE').length,
        open_alerts: alerts.filter((a) => a.status === 'OPEN').length,
        acknowledged_alerts: alerts.filter((a) => a.status === 'ACKNOWLEDGED').length,
        resolved_alerts: alerts.filter((a) => a.status === 'RESOLVED').length,
        critical_alerts: alerts.filter((a) => a.status !== 'RESOLVED' && a.severity === 'CRITICAL')
          .length,
        avg_latency_ms: avgLatencyMs,
      },
      layers,
      components,
      alerts,
      casb_summary: {
        total_events: casbEvents.length,
        auto_remediated_count: autoRemCount,
        auto_remediation_pct: autoRemPct,
        recent_events: casbEvents,
      },
      logpush_summary: {
        total_batches: logpushBatches.length,
        total_records: totalLogpushRecords,
        avg_lag_seconds: avgLagSeconds,
        cmk_encrypted_pct:
          logpushBatches.length > 0
            ? Math.round((cmkBatches / logpushBatches.length) * 1000) / 10
            : 0,
        recent_batches: logpushBatches,
      },
      sync,
    });
  }
);

app.get(
  '/api/v2/dashboard/dpo',
  requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    const now = new Date();
    const [dsarsRes, breachesRes, transfersRes, findingsRes, fichaRes] = await Promise.all([
      c.env.DB.prepare('SELECT * FROM dsar_requests WHERE tenant_id = ? ORDER BY due_at ASC')
        .bind(tenant.id)
        .all<DsarRequestRow>(),
      c.env.DB.prepare(
        'SELECT * FROM breach_incidents WHERE tenant_id = ? ORDER BY detected_at DESC'
      )
        .bind(tenant.id)
        .all<BreachIncidentRow>(),
      c.env.DB.prepare('SELECT * FROM data_transfers WHERE tenant_id = ? ORDER BY created_at DESC')
        .bind(tenant.id)
        .all<DataTransferRow>(),
      c.env.DB.prepare('SELECT * FROM scan_findings WHERE tenant_id = ?')
        .bind(tenant.id)
        .all<ScanFindingRow>(),
      c.env.DB.prepare(
        'SELECT * FROM ficha_tecnica_snapshots WHERE tenant_id = ? ORDER BY version_num DESC'
      )
        .bind(tenant.id)
        .all<FichaTecnicaSnapshotRow>(),
    ]);

    const regCtx = getRegulatoryProfileContext(tenant.regulatory_profile);
    const findings = findingsRes.results ?? [];
    const findingsWithAge = findings.filter((f) => f.retention_age_days !== null);
    const retentionViolations = findings.filter((f) => {
      const isSaludClinicalProtected =
        tenant.regulatory_profile === 'SALUD_LEY68' &&
        f.entity_type === 'PA_DATO_SENSIBLE_SALUD' &&
        (f.retention_age_days ?? 0) < 7300;
      return f.retention_violation === 1 && !isSaludClinicalProtected;
    });

    return c.json({
      tenant: {
        id: tenant.id,
        name: tenant.name,
        industry: tenant.industry,
        regulatory_profile: tenant.regulatory_profile,
      },
      regulatory_context: regCtx,
      dpo_governance: {
        dpo_name: tenant.dpo_name,
        dpo_email: tenant.dpo_email,
        dpo_antai_registered: Boolean(tenant.dpo_antai_registered),
        dpo_antai_reg_ref: tenant.dpo_antai_reg_ref,
        compliant: Boolean(tenant.dpo_antai_registered && tenant.dpo_name && tenant.dpo_email),
      },
      dsars: (dsarsRes.results ?? []).map((r) => enrichDsar(r, now)),
      breaches: (breachesRes.results ?? []).map((b) => enrichBreach(b, now)),
      transfers: (transfersRes.results ?? []).map(enrichTransfer),
      retention_summary: {
        total_findings_with_age: findingsWithAge.length,
        violations_count: retentionViolations.length,
        max_age_days: findingsWithAge.reduce(
          (max, f) => Math.max(max, f.retention_age_days ?? 0),
          0
        ),
        rule_description: regCtx.retention_rule,
      },
      ficha_tecnica_snapshots: fichaRes.results ?? [],
    });
  }
);

app.get(
  '/api/v2/dashboard/assets',
  requireRoles('MSSP_ADMIN', 'CISO', 'DPO', 'AUDITOR'),
  async (c) => {
    const resolved = await resolveTenantOrError(c);
    if ('errorResponse' in resolved) return resolved.errorResponse;
    const { tenant } = resolved;

    await evaluateAndSyncHealth(c.env.DB, tenant.id);

    const sourceFilter = c.req.query('source_type');
    const entityFilter = c.req.query('entity_type');
    const severityFilter = c.req.query('severity');

    const [endpointsRes, findingsRes, shadowRes] = await Promise.all([
      c.env.DB.prepare(
        'SELECT * FROM endpoints WHERE tenant_id = ? ORDER BY endpoint_risk_score DESC, hostname ASC'
      )
        .bind(tenant.id)
        .all<EndpointRow>(),
      c.env.DB.prepare('SELECT * FROM scan_findings WHERE tenant_id = ? ORDER BY detected_at DESC')
        .bind(tenant.id)
        .all<ScanFindingRow>(),
      c.env.DB.prepare(
        'SELECT * FROM shadow_ai_events WHERE tenant_id = ? ORDER BY recorded_at DESC LIMIT 100'
      )
        .bind(tenant.id)
        .all<ShadowAiEventRow>(),
    ]);

    const endpoints = (endpointsRes.results ?? []).map((ep) => ({
      ...ep,
      box_dlp_active: Boolean(ep.box_dlp_active),
      details: safeJsonParse<Record<string, unknown>>(ep.details_json, {}),
    }));

    const allFindings = findingsRes.results ?? [];
    const filteredFindings = allFindings.filter((f) => {
      if (sourceFilter && f.source_type !== sourceFilter) return false;
      if (entityFilter && f.entity_type !== entityFilter) return false;
      if (severityFilter && f.severity !== severityFilter) return false;
      return true;
    });

    const shadowEvents = shadowRes.results ?? [];

    return c.json({
      tenant_id: tenant.id,
      summary: {
        endpoints_total: endpoints.length,
        endpoints_with_all_urls: endpoints.filter((e) => e.risky_extensions_count > 0).length,
        endpoints_box_unprotected: endpoints.filter(
          (e) => e.box_exposed_files > 0 && !e.box_dlp_active
        ).length,
        findings_total: filteredFindings.length,
        sensitive_findings_total: filteredFindings.filter((f) => f.is_sensitive === 1).length,
        shadow_ai_events_total: shadowEvents.length,
      },
      endpoints,
      findings: filteredFindings,
      shadow_ai_events: shadowEvents,
    });
  }
);

// ---------------------------------------------------------------------------
// 6. Demo Seeding (MSSP Admin)
// ---------------------------------------------------------------------------

app.post('/api/v2/admin/seed-demo', requireRoles('MSSP_ADMIN'), async (c) => {
  const auth = c.get('auth');
  if (auth.tenantId !== null) {
    return c.json(
      { error: 'Forbidden', message: 'Tenant-scoped tokens cannot seed global demo data' },
      403
    );
  }
  if (c.env.ENVIRONMENT === 'production' && c.env.ENABLE_DEMO_TOOLS !== 'true') {
    return c.json(
      { error: 'Forbidden', message: 'Demo seeding is disabled in production' },
      403
    );
  }

  const result = await seedDemoEnvironment(c.env.DB);
  return c.json({ ok: true, ...result });
});

export default {
  fetch: app.fetch,
  async scheduled(
    _controller: ScheduledController,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<void> {
    await evaluateAndSyncHealth(env.DB);
  },
};
