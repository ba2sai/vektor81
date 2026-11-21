import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Bell,
  Check,
  CheckCircle2,
  Clock,
  CloudCog,
  Cpu,
  Database,
  Flame,
  HardDrive,
  RefreshCw,
  ShieldCheck,
  WifiOff,
} from 'lucide-react';
import { apiClient, ApiError } from '../api/client';
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  cn,
} from '../components/ui/card';
import type {
  AlertStatus,
  ComponentHeartbeat,
  ComponentLayer,
  ComponentStatus,
  OperationalAlert,
  SocHealthDashboardResponse,
} from '../types';
import {
  ALL_LAYERS_ORDER,
  LAYER_LABELS,
  alertStatusBadgeVariant,
  formatDateTime,
  formatRelativeTime,
  severityBadgeVariant,
  statusBadgeVariant,
} from '../utils/format';

export interface SystemHealthPageProps {
  tenantId: string | null;
  refreshTrigger?: number;
  onHealthChanged?: () => void;
  initialData?: SocHealthDashboardResponse | null;
}

export function SystemHealthPage({
  tenantId,
  refreshTrigger = 0,
  onHealthChanged,
  initialData = null,
}: SystemHealthPageProps) {
  const [data, setData] = useState<SocHealthDashboardResponse | null>(initialData);
  const [loading, setLoading] = useState<boolean>(!initialData);
  const [error, setError] = useState<string | null>(null);
  const [alertFilter, setAlertFilter] = useState<'ALL' | AlertStatus>('ALL');
  const [busyAlertId, setBusyAlertId] = useState<string | null>(null);

  // Demo Outage Simulator state
  const [simComponentId, setSimComponentId] = useState<string>('');
  const [simTargetStatus, setSimTargetStatus] = useState<ComponentStatus>('OFFLINE');
  const [simBackdateMinutes, setSimBackdateMinutes] = useState<number>(20);
  const [simErrorMessage, setSimErrorMessage] = useState<string>('');
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simFeedback, setSimFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getSocHealthDashboard(tenantId);
      setData(res);
      if (res.components.length > 0 && !simComponentId) {
        setSimComponentId(res.components[0].component_id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al consultar salud del sistema');
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshTrigger]);

  useEffect(() => {
    if (data?.components.length && !data.components.some((c) => c.component_id === simComponentId)) {
      setSimComponentId(data.components[0].component_id);
    }
  }, [data, simComponentId]);

  const handleAckAlert = async (alert: OperationalAlert) => {
    setBusyAlertId(alert.id);
    try {
      const res = await apiClient.ackAlert(alert.id, alert.tenant_id);
      setData((prev) =>
        prev
          ? {
              ...prev,
              alerts: prev.alerts.map((a) => (a.id === alert.id ? res.alert : a)),
              summary: {
                ...prev.summary,
                open_alerts: Math.max(0, prev.summary.open_alerts - (alert.status === 'OPEN' ? 1 : 0)),
                acknowledged_alerts: prev.summary.acknowledged_alerts + (alert.status === 'OPEN' ? 1 : 0),
              },
            }
          : prev
      );
      onHealthChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al confirmar alerta');
    } finally {
      setBusyAlertId(null);
    }
  };

  const handleResolveAlert = async (alert: OperationalAlert) => {
    setBusyAlertId(alert.id);
    try {
      const res = await apiClient.resolveAlert(alert.id, alert.tenant_id);
      setData((prev) =>
        prev
          ? {
              ...prev,
              alerts: prev.alerts.map((a) => (a.id === alert.id ? res.alert : a)),
            }
          : prev
      );
      await loadData();
      onHealthChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al resolver alerta');
    } finally {
      setBusyAlertId(null);
    }
  };

  const handleSimulateOutage = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetComp = data?.components.find((c) => c.component_id === simComponentId);
    const resolvedTenant = targetComp?.tenant_id ?? tenantId;
    if (!resolvedTenant || !simComponentId) return;

    setSimulating(true);
    setSimFeedback(null);
    try {
      await apiClient.simulateOutage({
        tenant_id: resolvedTenant,
        component_id: simComponentId,
        target_status: simTargetStatus,
        backdate_minutes: simBackdateMinutes,
        error_message: simErrorMessage.trim() || undefined,
      });
      setSimFeedback({
        type: 'ok',
        text: `Simulación aplicada sobre ${simComponentId} → ${simTargetStatus} (${simBackdateMinutes}m atrás).`,
      });
      await loadData();
      onHealthChanged?.();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : 'Error ejecutando simulación';
      setSimFeedback({ type: 'err', text: msg });
    } finally {
      setSimulating(false);
    }
  };

  const layerMatrix = useMemo(() => {
    const components = data?.components ?? [];
    const byLayer = new Map<ComponentLayer, ComponentHeartbeat[]>();
    for (const layer of ALL_LAYERS_ORDER) {
      byLayer.set(layer, []);
    }
    for (const comp of components) {
      const arr = byLayer.get(comp.component_layer) ?? [];
      arr.push(comp);
      byLayer.set(comp.component_layer, arr);
    }
    return ALL_LAYERS_ORDER.map((layer) => {
      const items = byLayer.get(layer) ?? [];
      const worst: ComponentStatus | 'MISSING' = items.some((x) => x.computed_status === 'OFFLINE')
        ? 'OFFLINE'
        : items.some((x) => x.computed_status === 'DEGRADED')
          ? 'DEGRADED'
          : items.some((x) => x.computed_status === 'STALE')
            ? 'STALE'
            : items.length > 0
              ? 'ONLINE'
              : 'MISSING';
      return { layer, items, worst };
    });
  }, [data]);

  const filteredAlerts = useMemo(() => {
    const alerts = data?.alerts ?? [];
    if (alertFilter === 'ALL') return alerts;
    return alerts.filter((a) => a.status === alertFilter);
  }, [data, alertFilter]);

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center rounded-xl border border-slate-800 bg-slate-900/50 py-16 text-sm text-slate-400">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin text-sky-400" />
        Cargando telemetría NOC / SOC...
      </div>
    );
  }

  const summary = data?.summary;

  return (
    <div className="space-y-6">
      {error && (
        <div
          role="alert"
          className="rounded-xl border border-red-500/40 bg-red-950/40 px-4 py-3 text-xs text-red-200"
        >
          {error}
        </div>
      )}

      {/* SUMMARY BAR */}
      <section aria-label="Resumen de Salud Operativa" className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Card>
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
              Total Componentes
            </div>
            <div className="mt-1 text-2xl font-extrabold text-white">
              {summary?.total_components ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card className="border-emerald-500/30">
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-emerald-400">
              Online
            </div>
            <div className="mt-1 text-2xl font-extrabold text-emerald-300">
              {summary?.online ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card className="border-amber-500/30">
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-amber-400">
              Degraded
            </div>
            <div className="mt-1 text-2xl font-extrabold text-amber-300">
              {summary?.degraded ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card className="border-purple-500/30">
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-purple-400">
              Stale
            </div>
            <div className="mt-1 text-2xl font-extrabold text-purple-300">
              {summary?.stale ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card className={cn((summary?.offline ?? 0) > 0 && 'border-red-500/60 bg-red-950/25')}>
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-red-400">
              Offline
            </div>
            <div className="mt-1 text-2xl font-extrabold text-red-400">
              {summary?.offline ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card className={cn((summary?.open_alerts ?? 0) > 0 && 'border-rose-500/50')}>
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-rose-300">
              Open Alerts
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-2xl font-extrabold text-rose-300">
                {summary?.open_alerts ?? 0}
              </span>
              {(summary?.critical_alerts ?? 0) > 0 && (
                <span className="text-[10px] font-semibold text-red-400">
                  ({summary?.critical_alerts} CRIT)
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="text-[11px] font-medium uppercase tracking-wider text-sky-400">
              Avg Latency
            </div>
            <div className="mt-1 text-2xl font-extrabold text-sky-300">
              {summary?.avg_latency_ms ?? 0}
              <span className="ml-1 text-xs font-normal text-slate-400">ms</span>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* COMPONENT MATRIX BY LAYER */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-sky-400" />
                Matriz de Componentes por Capa (11 Capas Híbridas)
              </CardTitle>
              <CardDescription>
                Infraestructura: &gt;5m DEGRADED, &gt;15m OFFLINE · Endpoints: &gt;24h STALE, &gt;72h OFFLINE
              </CardDescription>
            </div>
            <button
              type="button"
              onClick={() => void loadData()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} />
              Refrescar Matriz
            </button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {layerMatrix.map(({ layer, items, worst }) => (
              <div
                key={layer}
                className={cn(
                  'rounded-xl border p-3.5 transition',
                  worst === 'OFFLINE'
                    ? 'border-red-500/60 bg-red-950/20'
                    : worst === 'DEGRADED'
                      ? 'border-amber-500/40 bg-amber-950/15'
                      : worst === 'STALE'
                        ? 'border-purple-500/40 bg-purple-950/15'
                        : 'border-slate-800 bg-slate-950/60'
                )}
              >
                <div className="mb-2.5 flex items-center justify-between gap-2">
                  <div>
                    <div className="text-xs font-bold text-white">{LAYER_LABELS[layer]}</div>
                    <div className="font-mono text-[10px] text-slate-500">{layer}</div>
                  </div>
                  <Badge variant={worst === 'MISSING' ? 'outline' : statusBadgeVariant(worst)}>
                    {worst === 'MISSING' ? 'SIN REPORTE' : worst}
                  </Badge>
                </div>

                {items.length === 0 ? (
                  <p className="text-xs text-slate-500">
                    Sin heartbeat registrado para esta capa en el tenant seleccionado.
                  </p>
                ) : (
                  <div className="space-y-2.5">
                    {items.map((comp) => (
                      <div
                        key={comp.id}
                        data-testid={`component-card-${comp.component_id}`}
                        className="rounded-lg border border-slate-800/90 bg-slate-900/90 p-2.5 text-xs"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0">
                            <div className="truncate font-semibold text-slate-100">
                              {comp.display_name}
                            </div>
                            <div className="truncate font-mono text-[10px] text-slate-400">
                              {comp.component_id}
                              {comp.version ? ` · v${comp.version}` : ''}
                            </div>
                          </div>
                          <Badge variant={statusBadgeVariant(comp.computed_status)}>
                            {comp.computed_status}
                          </Badge>
                        </div>

                        <div className="mt-2 grid grid-cols-3 gap-1.5 text-[11px] text-slate-300">
                          <div className="rounded bg-slate-950/70 px-2 py-1">
                            <span className="text-slate-500">Latencia: </span>
                            <span className="font-mono">
                              {comp.latency_ms !== null ? `${comp.latency_ms}ms` : '—'}
                            </span>
                          </div>
                          <div className="rounded bg-slate-950/70 px-2 py-1">
                            <span className="text-slate-500">24h: </span>
                            <span className="font-mono">
                              {comp.uptime_pct_24h !== null ? `${comp.uptime_pct_24h}%` : '—'}
                            </span>
                          </div>
                          <div className="rounded bg-slate-950/70 px-2 py-1">
                            <span className="text-slate-500">HB: </span>
                            <span>{formatRelativeTime(comp.last_heartbeat_at)}</span>
                          </div>
                        </div>

                        {(comp.cpu_pct !== null || comp.ram_mb !== null) && (
                          <div className="mt-1.5 flex items-center gap-3 text-[11px] text-slate-400">
                            {comp.cpu_pct !== null && (
                              <span className="inline-flex items-center gap-1">
                                <Cpu className="h-3 w-3 text-sky-400" />
                                CPU {comp.cpu_pct}%
                              </span>
                            )}
                            {comp.ram_mb !== null && (
                              <span className="inline-flex items-center gap-1">
                                <HardDrive className="h-3 w-3 text-indigo-400" />
                                RAM {comp.ram_mb} MB
                              </span>
                            )}
                          </div>
                        )}

                        {comp.last_error && (
                          <div className="mt-2 rounded border border-red-500/30 bg-red-950/40 px-2 py-1.5 text-[11px] text-red-200">
                            <strong>Error:</strong> {comp.last_error}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* OPERATIONAL ALERTS FEED + DEMO OUTAGE SIMULATOR */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Operational Alerts & Disconnections Feed */}
        <Card className="lg:col-span-8">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-4 w-4 text-rose-400" />
                  Feed de Alertas Operativas y Desconexiones
                </CardTitle>
                <CardDescription>
                  Incidentes generados automáticamente por pérdida de heartbeat o degradación
                </CardDescription>
              </div>
              <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-950 p-1">
                {(['ALL', 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'] as const).map((status) => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setAlertFilter(status)}
                    className={cn(
                      'rounded-md px-2 py-1 text-[11px] font-medium transition',
                      alertFilter === status
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-white'
                    )}
                  >
                    {status === 'ALL' ? 'Todas' : status}
                  </button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {filteredAlerts.length === 0 ? (
              <div className="flex items-center justify-center rounded-lg border border-slate-800 bg-slate-950/60 py-10 text-xs text-slate-400">
                <CheckCircle2 className="mr-2 h-4 w-4 text-emerald-400" />
                Sin alertas operativas en este filtro.
              </div>
            ) : (
              <div className="space-y-3">
                {filteredAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    data-testid={`alert-row-${alert.id}`}
                    className={cn(
                      'rounded-xl border p-3.5 text-xs',
                      alert.status === 'OPEN'
                        ? 'border-red-500/40 bg-red-950/20'
                        : alert.status === 'ACKNOWLEDGED'
                          ? 'border-amber-500/35 bg-amber-950/15'
                          : 'border-slate-800 bg-slate-950/60'
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={severityBadgeVariant(alert.severity)}>
                            {alert.severity}
                          </Badge>
                          <Badge variant={alertStatusBadgeVariant(alert.status)}>
                            {alert.status}
                          </Badge>
                          <span className="font-mono text-[11px] text-slate-400">
                            {alert.component_layer} · {alert.component_id}
                          </span>
                        </div>
                        <div className="font-semibold text-white">{alert.title}</div>
                        <p className="text-slate-300">{alert.details}</p>
                        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                          <span className="inline-flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            Disparada: {formatDateTime(alert.triggered_at)}
                          </span>
                          {alert.acknowledged_at && (
                            <span>Ack: {formatDateTime(alert.acknowledged_at)}</span>
                          )}
                          {alert.resolved_at && (
                            <span className="text-emerald-400">
                              Resuelta: {formatDateTime(alert.resolved_at)}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        {alert.status === 'OPEN' && (
                          <button
                            type="button"
                            disabled={busyAlertId === alert.id}
                            onClick={() => void handleAckAlert(alert)}
                            className="inline-flex items-center gap-1 rounded-lg border border-amber-500/40 bg-amber-500/15 px-2.5 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-500/25 disabled:opacity-50"
                          >
                            <Check className="h-3.5 w-3.5" />
                            Ack
                          </button>
                        )}
                        {alert.status !== 'RESOLVED' && (
                          <button
                            type="button"
                            disabled={busyAlertId === alert.id}
                            onClick={() => void handleResolveAlert(alert)}
                            className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1.5 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            Resolve
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Demo Outage Simulator */}
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-amber-400" />
              Simulador NOC de Desconexión (Drill)
            </CardTitle>
            <CardDescription>
              Prueba alertas en vivo y recuperación llamando a{' '}
              <code className="text-slate-300">POST /api/v2/health/simulate-outage</code>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSimulateOutage} className="space-y-3 text-xs">
              <div>
                <label className="mb-1 block font-medium text-slate-300">Componente</label>
                <select
                  value={simComponentId}
                  onChange={(e) => setSimComponentId(e.target.value)}
                  required
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  {(data?.components ?? []).map((comp) => (
                    <option key={comp.component_id} value={comp.component_id}>
                      {comp.display_name} ({comp.component_layer})
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Estado Objetivo</label>
                  <select
                    value={simTargetStatus}
                    onChange={(e) => setSimTargetStatus(e.target.value as ComponentStatus)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                  >
                    <option value="OFFLINE">OFFLINE</option>
                    <option value="DEGRADED">DEGRADED</option>
                    <option value="STALE">STALE</option>
                    <option value="ONLINE">ONLINE (Recuperar)</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Backdate (min)</label>
                  <input
                    type="number"
                    min={0}
                    max={10080}
                    value={simBackdateMinutes}
                    onChange={(e) => setSimBackdateMinutes(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="mb-1 block font-medium text-slate-300">
                  Mensaje de Error (opcional)
                </label>
                <input
                  type="text"
                  value={simErrorMessage}
                  onChange={(e) => setSimErrorMessage(e.target.value)}
                  placeholder="Ej. DNS querylog timeout en AdGuard"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={simulating || !simComponentId}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-amber-600 px-4 py-2 text-xs font-bold text-white transition hover:bg-amber-500 disabled:opacity-50"
              >
                {simTargetStatus === 'ONLINE' ? (
                  <ShieldCheck className="h-4 w-4" />
                ) : (
                  <WifiOff className="h-4 w-4" />
                )}
                {simulating ? 'Aplicando Drill...' : 'Ejecutar Simulación NOC'}
              </button>

              {simFeedback && (
                <div
                  className={cn(
                    'rounded-lg border p-2.5 text-xs',
                    simFeedback.type === 'ok'
                      ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-200'
                      : 'border-red-500/40 bg-red-950/40 text-red-200'
                  )}
                >
                  {simFeedback.text}
                </div>
              )}
            </form>
          </CardContent>
        </Card>
      </section>

      {/* CASB AUTO-REMEDIATION & LOGPUSH PIPELINE HEALTH */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* CASB Auto-Remediation Widget */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <CloudCog className="h-4 w-4 text-sky-400" />
                  Cloudflare CASB · Auto-Remediación SaaS
                </CardTitle>
                <CardDescription>
                  Eventos recientes de Microsoft 365, Google Workspace, Box y AWS S3
                </CardDescription>
              </div>
              <Badge variant="success">
                {data?.casb_summary.auto_remediation_pct ?? 0}% Auto-Remediado
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-white">
                  {data?.casb_summary.total_events ?? 0}
                </div>
                <div className="text-[11px] text-slate-400">Eventos Totales</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-emerald-400">
                  {data?.casb_summary.auto_remediated_count ?? 0}
                </div>
                <div className="text-[11px] text-slate-400">Auto-Remediados</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-amber-400">
                  {(data?.casb_summary.total_events ?? 0) -
                    (data?.casb_summary.auto_remediated_count ?? 0)}
                </div>
                <div className="text-[11px] text-slate-400">Pendientes</div>
              </div>
            </div>

            <div className="space-y-2">
              {(data?.casb_summary.recent_events ?? []).slice(0, 5).map((ev) => (
                <div
                  key={ev.id}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-slate-200">
                      {ev.saas_app} · {ev.resource_name}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={severityBadgeVariant(ev.severity)}>{ev.severity}</Badge>
                      <Badge variant={ev.remediated_automatically ? 'success' : 'destructive'}>
                        {ev.remediated_automatically ? 'Auto-Remediado' : ev.exposure_level}
                      </Badge>
                    </div>
                  </div>
                  {ev.remediation_action && (
                    <p className="mt-1 text-[11px] text-emerald-300">{ev.remediation_action}</p>
                  )}
                </div>
              ))}
              {(data?.casb_summary.recent_events ?? []).length === 0 && (
                <p className="text-xs text-slate-500">Sin eventos CASB recientes.</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Logpush Pipeline Health Widget */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-indigo-400" />
                  Salud del Pipeline Logpush → R2 (CMK)
                </CardTitle>
                <CardDescription>
                  Ingesta forense cifrada con llave gestionada por el cliente (Customer Managed Key)
                </CardDescription>
              </div>
              <Badge variant="default">
                {data?.logpush_summary.cmk_encrypted_pct ?? 0}% CMK
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-white">
                  {data?.logpush_summary.total_batches ?? 0}
                </div>
                <div className="text-[11px] text-slate-400">Lotes Ingeridos</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-sky-300">
                  {(data?.logpush_summary.total_records ?? 0).toLocaleString('es-PA')}
                </div>
                <div className="text-[11px] text-slate-400">Registros</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                <div className="text-lg font-bold text-amber-300">
                  {data?.logpush_summary.avg_lag_seconds ?? 0}s
                </div>
                <div className="text-[11px] text-slate-400">Lag Promedio</div>
              </div>
            </div>

            <div className="space-y-2">
              {(data?.logpush_summary.recent_batches ?? []).slice(0, 5).map((batch) => (
                <div
                  key={batch.id}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-indigo-300">{batch.dataset}</span>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={batch.encrypted_with_customer_key ? 'success' : 'warning'}>
                        {batch.encrypted_with_customer_key ? 'CMK Cifrado' : 'Sin CMK'}
                      </Badge>
                      <span className="text-[11px] text-slate-400">
                        {batch.records_count} reg · {batch.lag_seconds}s lag
                      </span>
                    </div>
                  </div>
                  {batch.r2_object_key && (
                    <div className="mt-1 truncate font-mono text-[10px] text-slate-500">
                      R2: {batch.r2_object_key}
                    </div>
                  )}
                </div>
              ))}
              {(data?.logpush_summary.recent_batches ?? []).length === 0 && (
                <p className="text-xs text-slate-500">Sin lotes Logpush registrados.</p>
              )}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
