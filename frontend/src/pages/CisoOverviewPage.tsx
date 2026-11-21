import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Clock,
  FolderLock,
  Gauge,
  RefreshCw,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiClient } from '../api/client';
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
  CisoDashboardResponse,
  EntityType,
  ExposureHeatmapCell,
  SourceType,
} from '../types';
import {
  ENTITY_LABELS,
  PROFILE_META,
  SOURCE_LABELS,
  severityBadgeVariant,
} from '../utils/format';

export interface CisoOverviewPageProps {
  tenantId: string | null;
  refreshTrigger?: number;
  initialData?: CisoDashboardResponse | null;
}

const DEFAULT_ENTITIES: EntityType[] = [
  'PA_IDENTIDAD_NATURAL',
  'PA_PASAPORTE',
  'PA_DATO_SENSIBLE_SALUD',
  'PA_TARJETA_PAGO',
  'PA_SWIFT_PA',
  'EMAIL_PERSONAL',
];

const DEFAULT_SOURCES: SourceType[] = ['SMB', 'SQL_DB', 'OCR_IMAGE', 'CASB', 'DLP_EDGE'];

function heatCellClasses(cell: ExposureHeatmapCell | undefined): string {
  if (!cell || cell.total_matches === 0) {
    return 'border-slate-800/80 bg-slate-950/60 text-slate-500';
  }
  if (cell.max_severity === 'CRITICAL' || cell.total_matches >= 100) {
    return 'border-red-500/60 bg-red-950/75 text-red-100';
  }
  if (cell.max_severity === 'HIGH' || cell.total_matches >= 25) {
    return 'border-orange-500/50 bg-orange-950/60 text-orange-100';
  }
  if (cell.max_severity === 'MEDIUM' || cell.total_matches >= 10) {
    return 'border-amber-500/40 bg-amber-950/45 text-amber-100';
  }
  return 'border-sky-500/40 bg-sky-950/45 text-sky-100';
}

export function CisoOverviewPage({
  tenantId,
  refreshTrigger = 0,
  initialData = null,
}: CisoOverviewPageProps) {
  const [data, setData] = useState<CisoDashboardResponse | null>(initialData);
  const [loading, setLoading] = useState<boolean>(!initialData);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!tenantId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getCisoDashboard(tenantId);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al cargar Centro CISO');
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshTrigger]);

  const shadowDomainsData = useMemo(
    () =>
      (data?.top_shadow_ai_domains ?? []).map((item) => ({
        domain: item.domain,
        category: item.category,
        blocked: item.blocked_hits,
        unblocked: Math.max(0, item.hits - item.blocked_hits),
        total: item.hits,
      })),
    [data]
  );

  const cellLookup = useMemo(() => {
    const map = new Map<string, ExposureHeatmapCell>();
    for (const cell of data?.risk.heatmap.cells ?? []) {
      map.set(`${cell.entity_type}::${cell.source_type}`, cell);
    }
    return map;
  }, [data]);

  if (!tenantId && !data) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-slate-400">
          Selecciona un tenant o carga los datos demo para visualizar el Centro CISO.
        </CardContent>
      </Card>
    );
  }

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center rounded-xl border border-slate-800 bg-slate-900/50 py-16 text-sm text-slate-400">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin text-sky-400" />
        Evaluando postura CISO y matriz de exposición...
      </div>
    );
  }

  const risk = data?.risk;
  const regCtx = risk?.regulatory_context;
  const kpis = risk?.kpis;
  const semaphore = risk?.semaphore ?? 'AMARILLO';
  const semaphoreVariant =
    semaphore === 'ROJO' ? 'destructive' : semaphore === 'AMARILLO' ? 'warning' : 'success';

  const entityTypes = risk?.heatmap.entity_types?.length ? risk.heatmap.entity_types : DEFAULT_ENTITIES;
  const sourceTypes = risk?.heatmap.source_types?.length ? risk.heatmap.source_types : DEFAULT_SOURCES;

  const vectorItems = risk
    ? [
        { key: 'shadow_ai', label: 'Shadow AI (DNS / Gateway)', weight: '25%', value: risk.vectors.shadow_ai },
        { key: 'storage', label: 'Exposición Repositorios (SMB/SQL/OCR)', weight: '25%', value: risk.vectors.storage },
        { key: 'endpoints', label: 'Endpoints & <all_urls> / Sync', weight: '20%', value: risk.vectors.endpoints },
        { key: 'casb', label: 'CASB SaaS Posture', weight: '15%', value: risk.vectors.casb },
        { key: 'compliance', label: 'Gobernanza & Compliance Ley 81', weight: '15%', value: risk.vectors.compliance },
      ]
    : [];

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

      {/* TOP ROW: EXECUTIVE SCORE CARD + REGULATORY & FINANCIAL EXPOSURE */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Executive Score Card */}
        <Card
          className={cn(
            'lg:col-span-5',
            semaphore === 'ROJO'
              ? 'border-red-500/40 bg-gradient-to-br from-slate-900 via-slate-900 to-red-950/30'
              : semaphore === 'AMARILLO'
                ? 'border-amber-500/35 bg-gradient-to-br from-slate-900 via-slate-900 to-amber-950/20'
                : 'border-emerald-500/35 bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/20'
          )}
        >
          <CardHeader>
            <div className="flex items-start justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Gauge className="h-4 w-4 text-sky-400" />
                  Score Ejecutivo de Riesgo CISO
                </CardTitle>
                <CardDescription>
                  {data?.tenant.name} · Motor Determinista 5 Vectores
                </CardDescription>
              </div>
              <Badge variant={semaphoreVariant} className="text-xs font-bold">
                SEMÁFORO {semaphore}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-baseline justify-between">
              <div className="text-5xl font-black tracking-tight text-white">
                {risk?.global_score ?? 0}
                <span className="ml-1 text-lg font-medium text-slate-400">/100</span>
              </div>
              <div className="text-right text-xs text-slate-400">
                <div>{kpis?.total_findings ?? 0} hallazgos PII</div>
                <div className="text-rose-300">
                  {kpis?.sensitive_findings ?? 0} datos sensibles
                </div>
              </div>
            </div>

            <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className={cn(
                  'h-full rounded-full transition-all',
                  semaphore === 'ROJO'
                    ? 'bg-red-500'
                    : semaphore === 'AMARILLO'
                      ? 'bg-amber-400'
                      : 'bg-emerald-400'
                )}
                style={{ width: `${Math.min(100, risk?.global_score ?? 0)}%` }}
              />
            </div>

            <div className="space-y-2.5 pt-1">
              {vectorItems.map((v) => (
                <div key={v.key} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">
                      {v.label}{' '}
                      <span className="text-[10px] text-slate-500">({v.weight})</span>
                    </span>
                    <span className="font-mono font-bold text-white">{v.value}/100</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/90">
                    <div
                      className={cn(
                        'h-full rounded-full',
                        v.value >= 70
                          ? 'bg-red-500'
                          : v.value >= 40
                            ? 'bg-amber-400'
                            : 'bg-sky-400'
                      )}
                      style={{ width: `${Math.min(100, v.value)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Regulatory & Financial Exposure Card */}
        <Card className="lg:col-span-7">
          <CardHeader>
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Scale className="h-4 w-4 text-amber-400" />
                  Exposición Regulatoria &amp; Financiera (Panamá)
                </CardTitle>
                <CardDescription>
                  {regCtx?.framework_title ?? 'Ley 81 de 2019 y DE 285 de 2021'}
                </CardDescription>
              </div>
              {data?.tenant.regulatory_profile && (
                <span
                  className={cn(
                    'rounded-md border px-2 py-0.5 text-[11px] font-semibold',
                    PROFILE_META[data.tenant.regulatory_profile].badgeClass
                  )}
                >
                  {data.tenant.regulatory_profile}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-red-500/35 bg-red-950/25 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-red-300">
                  Rango de Multa Administrativa
                </div>
                <div className="mt-1 text-lg font-extrabold text-white">
                  {regCtx?.fine_range_pab ?? 'B/. 1,000 a B/. 10,000'}
                </div>
                <div className="mt-0.5 text-[11px] text-slate-300">
                  Regulador: {regCtx?.primary_regulator ?? 'ANTAI'}
                </div>
              </div>

              <div className="rounded-xl border border-amber-500/35 bg-amber-950/20 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-amber-300">
                  Plazo de Notificación &amp; Clausura
                </div>
                <div className="mt-1 font-semibold text-white">
                  {regCtx?.breach_notification_rule ?? '72 horas ante ANTAI y titulares'}
                </div>
                <div className="mt-1 text-[11px] text-amber-200/90">
                  Riesgo de clausura de base de datos, publicación oficial ANTAI e imprescriptibilidad de faltas muy graves.
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <div className="mb-1.5 font-semibold text-rose-300">
                  Riesgos Sancionatorios Activos
                </div>
                <ul className="space-y-1 text-[11px] text-slate-300">
                  {(regCtx?.sanction_risks ?? []).map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-rose-400" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <div className="mb-1.5 font-semibold text-sky-300">
                  Mandatos Sectoriales ({data?.tenant.regulatory_profile})
                </div>
                <ul className="space-y-1 text-[11px] text-slate-300">
                  {(regCtx?.profile_specific_mandates ?? []).map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-sky-400" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 4 SOC/CISO KPI CARDS */}
      <section aria-label="KPIs SOC y CISO" className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                MTTD (Detección)
              </span>
              <Clock className="h-4 w-4 text-sky-400" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">
              <span data-testid="kpi-mttd">{kpis?.mttd_minutes ?? 0}</span>
              <span className="ml-1 text-sm font-normal text-slate-400">min</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Intervalo medio de detección vía heartbeats &amp; Logpush
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                MTTR (Respuesta)
              </span>
              <Activity className="h-4 w-4 text-amber-400" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-amber-300">
              <span data-testid="kpi-mttr">{kpis?.mttr_minutes ?? 0}</span>
              <span className="ml-1 text-sm font-normal text-slate-400">min</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Tiempo medio de remediación CASB &amp; alertas SOC
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Cobertura de Activos
              </span>
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-emerald-300">
              <span data-testid="kpi-coverage">{kpis?.asset_coverage_pct ?? 0}</span>
              <span className="ml-0.5 text-sm font-normal text-slate-400">%</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Sensores y endpoints ONLINE sobre inventario monitoreado
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Remediación Automática CASB
              </span>
              <Sparkles className="h-4 w-4 text-indigo-400" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-indigo-300">
              <span data-testid="kpi-casb-rem">{kpis?.casb_auto_remediation_pct ?? 0}</span>
              <span className="ml-0.5 text-sm font-normal text-slate-400">%</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Incidentes SaaS mitigados automáticamente sin intervención manual
            </p>
          </CardContent>
        </Card>
      </section>

      {/* RECHARTS: RISK SCORE TREND + TOP SHADOW AI DOMAINS */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-6">
          <CardHeader>
            <CardTitle>Tendencia de Riesgo (14–30 Días)</CardTitle>
            <CardDescription>
              Evolución histórica del Score Global frente a vectores Shadow AI y Almacenamiento
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72 w-full">
              {(data?.risk_history ?? []).length > 0 ? (
                <ResponsiveContainer width="100%" height="100%" minWidth={240} minHeight={220}>
                  <AreaChart
                    data={data?.risk_history ?? []}
                    margin={{ top: 10, right: 16, left: -12, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="globalRiskGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.45} />
                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="recorded_date" stroke="#94a3b8" fontSize={11} />
                    <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={11} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Area
                      type="monotone"
                      dataKey="global_score"
                      name="Score Global"
                      stroke="#f43f5e"
                      fillOpacity={1}
                      fill="url(#globalRiskGrad)"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="shadow_ai_score"
                      name="Shadow AI"
                      stroke="#38bdf8"
                      fill="transparent"
                      strokeWidth={1.5}
                    />
                    <Area
                      type="monotone"
                      dataKey="storage_score"
                      name="Storage"
                      stroke="#f59e0b"
                      fill="transparent"
                      strokeWidth={1.5}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-xs text-slate-500">
                  Sin serie histórica de riesgo registrada aún.
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-6">
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <div>
                <CardTitle>Top Dominios Shadow AI (Bloqueados vs Sin Bloqueo)</CardTitle>
                <CardDescription>
                  Telemetría consolidada AdGuard DNS + Endpoints + Cloudflare AI Gateway
                </CardDescription>
              </div>
              <Badge variant="destructive">
                {kpis?.unblocked_shadow_ai_hits ?? 0} sin bloqueo
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-72 w-full">
              {shadowDomainsData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%" minWidth={240} minHeight={220}>
                  <BarChart
                    data={shadowDomainsData}
                    layout="vertical"
                    margin={{ top: 8, right: 16, left: 16, bottom: 8 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" stroke="#94a3b8" fontSize={11} />
                    <YAxis
                      type="category"
                      dataKey="domain"
                      stroke="#e2e8f0"
                      fontSize={11}
                      width={115}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px' }} />
                    <Bar
                      dataKey="unblocked"
                      stackId="hits"
                      name="Sin Bloqueo"
                      fill="#f43f5e"
                      radius={[0, 0, 0, 0]}
                    />
                    <Bar
                      dataKey="blocked"
                      stackId="hits"
                      name="Bloqueados"
                      fill="#10b981"
                      radius={[0, 4, 4, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-xs text-slate-500">
                  Sin eventos Shadow AI registrados.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      {/* DATA EXPOSURE HEATMAP MATRIX */}
      <Card>
        <CardHeader>
          <CardTitle>Matriz de Exposición de Datos (Heatmap Entidad × Origen)</CardTitle>
          <CardDescription>
            Cruce determinista entre categorías PII de Panamá y vectores de almacenamiento / tránsito
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table
              data-testid="exposure-heatmap-table"
              className="w-full border-separate border-spacing-1.5 text-left text-xs"
            >
              <thead>
                <tr>
                  <th className="p-2 font-semibold text-slate-400">Tipo de Entidad PII</th>
                  {sourceTypes.map((src) => (
                    <th key={src} className="p-2 text-center font-mono font-semibold text-slate-300">
                      {SOURCE_LABELS[src] ?? src}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entityTypes.map((entity) => (
                  <tr key={entity}>
                    <td className="rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2">
                      <div className="font-semibold text-slate-200">
                        {ENTITY_LABELS[entity] ?? entity}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500">{entity}</div>
                    </td>
                    {sourceTypes.map((src) => {
                      const cell = cellLookup.get(`${entity}::${src}`);
                      const matrixCount = risk?.heatmap.matrix?.[entity]?.[src] ?? 0;
                      const matches = cell?.total_matches ?? matrixCount;
                      const sensitive = (cell?.sensitive_count ?? 0) > 0;

                      return (
                        <td
                          key={`${entity}-${src}`}
                          data-testid={`heatmap-cell-${entity}-${src}`}
                          className={cn(
                            'rounded-lg border p-2 text-center transition',
                            heatCellClasses(cell)
                          )}
                        >
                          <div className="text-sm font-extrabold">
                            {matches > 0 ? matches.toLocaleString('es-PA') : '0'}
                          </div>
                          {matches > 0 ? (
                            <div className="mt-0.5 flex flex-wrap items-center justify-center gap-1 text-[10px]">
                              <span>{cell?.findings_count ?? 1} hall.</span>
                              {sensitive && (
                                <span className="rounded bg-red-500/30 px-1 py-0.5 font-bold text-red-100">
                                  SENSIBLE
                                </span>
                              )}
                            </div>
                          ) : (
                            <div className="text-[10px] text-slate-600">—</div>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* LEGAL FINDINGS + TOP RISKY REPOSITORIES */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-7">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-rose-400" />
              Hallazgos Legales y Regulatorios Deterministas
            </CardTitle>
            <CardDescription>
              Articulado de Ley 81, DE 285 y marco sectorial aplicable sin inferencia de LLMs
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(risk?.legal_findings ?? []).length === 0 ? (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-4 text-xs text-emerald-200">
                Sin incumplimientos legales activos detectados para los umbrales actuales.
              </div>
            ) : (
              (risk?.legal_findings ?? []).map((lf, idx) => (
                <div
                  key={`${lf.vector}-${idx}`}
                  className="rounded-xl border border-slate-800 bg-slate-950/75 p-3.5 text-xs space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-bold text-sky-300">{lf.citation}</span>
                    <Badge variant={severityBadgeVariant(lf.severity)}>{lf.severity}</Badge>
                  </div>
                  <p className="text-slate-200">{lf.summary}</p>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FolderLock className="h-4 w-4 text-amber-400" />
              Repositorios con Mayor Exposición
            </CardTitle>
            <CardDescription>
              Clasificados por volumen total de coincidencias PII detectadas
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2.5">
              {(data?.top_risky_repositories ?? []).map((repo, idx) => (
                <div
                  key={`${repo.source_type}-${repo.repository_name}-${idx}`}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2.5 text-xs"
                >
                  <div className="min-w-0 pr-3">
                    <div className="truncate font-semibold text-white">{repo.repository_name}</div>
                    <div className="flex items-center gap-2 text-[11px] text-slate-400">
                      <Badge variant="outline" className="text-[10px]">
                        {repo.source_type}
                      </Badge>
                      <span>{repo.findings_count} hallazgos</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-base font-extrabold text-amber-300">
                      {repo.total_matches.toLocaleString('es-PA')}
                    </div>
                    <div className="text-[10px] text-slate-500">coincidencias</div>
                  </div>
                </div>
              ))}
              {(data?.top_risky_repositories ?? []).length === 0 && (
                <p className="text-xs text-slate-500">Sin repositorios con hallazgos registrados.</p>
              )}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
