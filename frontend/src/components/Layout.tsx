import React from 'react';
import {
  Activity,
  AlertTriangle,
  DatabaseZap,
  KeyRound,
  RefreshCw,
  Scale,
  Server,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
} from 'lucide-react';
import type { DashboardTab, HealthOverviewResponse, Tenant } from '../types';
import { LAYER_LABELS, PROFILE_META } from '../utils/format';
import { Badge, cn } from './ui/card';

export interface LayoutProps {
  activeTab: DashboardTab;
  onSelectTab: (tab: DashboardTab) => void;
  healthOverview: HealthOverviewResponse | null;
  tenants: Tenant[];
  selectedTenantId: string | null;
  onSelectTenant: (tenantId: string) => void;
  onSeedDemo?: () => void;
  seedingDemo?: boolean;
  onRefresh?: () => void;
  refreshing?: boolean;
  onOpenAuth?: () => void;
  hasToken?: boolean;
  children: React.ReactNode;
}

const TABS: Array<{ id: DashboardTab; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'health', label: 'Salud & Monitoreo (NOC/SOC)', icon: Activity },
  { id: 'ciso', label: 'Centro CISO', icon: ShieldAlert },
  { id: 'dpo', label: 'Cumplimiento DPO & Legal', icon: Scale },
  { id: 'assets', label: 'Activos, Escaneos & Tenants', icon: Server },
];

export function Layout({
  activeTab,
  onSelectTab,
  healthOverview,
  tenants,
  selectedTenantId,
  onSelectTenant,
  onSeedDemo,
  seedingDemo = false,
  onRefresh,
  refreshing = false,
  onOpenAuth,
  hasToken = true,
  children,
}: LayoutProps) {
  const selectedTenant = tenants.find((t) => t.id === selectedTenantId) ?? tenants[0] ?? null;
  const profileInfo = selectedTenant ? PROFILE_META[selectedTenant.regulatory_profile] : null;

  const components = healthOverview?.components ?? [];
  const offlineComponents = components.filter((c) => c.computed_status === 'OFFLINE');
  const degradedOrStaleComponents = components.filter(
    (c) => c.computed_status === 'DEGRADED' || c.computed_status === 'STALE'
  );

  const summary = healthOverview?.summary;
  const totalComponents = summary?.total_components ?? components.length;
  const offlineCount = summary?.offline ?? offlineComponents.length;
  const degradedCount = (summary?.degraded ?? 0) + (summary?.stale ?? 0);
  const onlineCount = summary?.online ?? components.filter((c) => c.computed_status === 'ONLINE').length;
  const openAlertsCount = summary?.open_alerts ?? 0;

  let healthPillClass = 'border-slate-700 bg-slate-900 text-slate-300';
  let healthPillText = 'SIN TELEMETRÍA';
  let healthDotClass = 'bg-slate-400';

  if (offlineCount > 0) {
    healthPillClass = 'border-red-500/60 bg-red-500/15 text-red-200 animate-pulse';
    healthPillText = `${offlineCount} OFFLINE`;
    healthDotClass = 'bg-red-500';
  } else if (degradedCount > 0 || degradedOrStaleComponents.length > 0) {
    healthPillClass = 'border-amber-500/50 bg-amber-500/15 text-amber-200';
    healthPillText = `${Math.max(degradedCount, degradedOrStaleComponents.length)} DEGRADADO/STALE`;
    healthDotClass = 'bg-amber-400';
  } else if (totalComponents > 0) {
    healthPillClass = 'border-emerald-500/50 bg-emerald-500/15 text-emerald-200';
    healthPillText = `ONLINE (${onlineCount}/${totalComponents})`;
    healthDotClass = 'bg-emerald-400';
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* TOP BAR */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-slate-950/95 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          {/* Brand + Live Health Pill */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-sky-500/40 bg-sky-500/15 text-sky-400">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-white">VEKTOR81</span>
                  <Badge variant="outline" className="text-[10px]">
                    v2 HYBRID SOC
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-400">
                  CISO · SOC · DPO Command Center (Panamá)
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onSelectTab('health')}
              data-testid="global-health-pill"
              title="Ver estado de infraestructura y alertas"
              className={cn(
                'inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold transition hover:brightness-110',
                healthPillClass
              )}
            >
              <span className={cn('h-2 w-2 rounded-full', healthDotClass)} />
              <span>Salud Global: {healthPillText}</span>
            </button>
          </div>

          {/* Tenant Selector + Regulatory Profile + Actions */}
          <div className="flex flex-wrap items-center gap-2">
            {tenants.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="tenant-selector" className="sr-only">
                  Seleccionar Tenant
                </label>
                <select
                  id="tenant-selector"
                  aria-label="Seleccionar Tenant"
                  value={selectedTenant?.id ?? ''}
                  onChange={(e) => onSelectTenant(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-white focus:border-sky-500 focus:outline-none"
                >
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.id})
                    </option>
                  ))}
                </select>

                {profileInfo && (
                  <span
                    data-testid="regulatory-profile-badge"
                    className={cn(
                      'inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-semibold',
                      profileInfo.badgeClass
                    )}
                    title={profileInfo.label}
                  >
                    {selectedTenant?.regulatory_profile}
                  </span>
                )}
              </div>
            ) : (
              <span className="rounded-md border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs text-slate-400">
                Sin tenants activos
              </span>
            )}

            {onSeedDemo && (
              <button
                type="button"
                onClick={onSeedDemo}
                disabled={seedingDemo}
                className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-3 py-1.5 text-xs font-medium text-indigo-200 transition hover:bg-indigo-500/25 disabled:opacity-50"
              >
                <DatabaseZap className="h-3.5 w-3.5" />
                {seedingDemo ? 'Cargando Demo...' : 'Cargar Datos Demo'}
              </button>
            )}

            {onRefresh && (
              <button
                type="button"
                onClick={onRefresh}
                disabled={refreshing}
                aria-label="Refrescar datos"
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-200 transition hover:bg-slate-800 disabled:opacity-50"
              >
                <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} />
                <span className="hidden sm:inline">Actualizar</span>
              </button>
            )}

            {onOpenAuth && (
              <button
                type="button"
                onClick={onOpenAuth}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition',
                  hasToken
                    ? 'border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800'
                    : 'border-amber-500/50 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25'
                )}
              >
                <KeyRound className="h-3.5 w-3.5" />
                <span>{hasToken ? 'Token' : 'Autenticar'}</span>
              </button>
            )}
          </div>
        </div>

        {/* 4-TAB NAVIGATION */}
        <nav
          aria-label="Navegación principal"
          className="mx-auto flex max-w-7xl items-center gap-1 overflow-x-auto border-t border-slate-800/80 px-4 sm:px-6"
        >
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            const showHealthBadge = tab.id === 'health' && (offlineCount > 0 || openAlertsCount > 0);
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => onSelectTab(tab.id)}
                className={cn(
                  'inline-flex shrink-0 items-center gap-2 border-b-2 px-3.5 py-2.5 text-xs font-semibold transition',
                  isActive
                    ? 'border-sky-400 text-sky-300 bg-sky-500/5'
                    : 'border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200'
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{tab.label}</span>
                {showHealthBadge && (
                  <span
                    className={cn(
                      'rounded-full px-1.5 py-0.5 text-[10px] font-bold',
                      offlineCount > 0 ? 'bg-red-500/25 text-red-200' : 'bg-amber-500/25 text-amber-200'
                    )}
                  >
                    {offlineCount > 0 ? `${offlineCount} OFF` : openAlertsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </header>

      {/* GLOBAL TOP OUTAGE ALERT BANNER */}
      {offlineComponents.length > 0 && (
        <div
          role="alert"
          data-testid="global-outage-banner"
          className="border-b border-red-500/60 bg-gradient-to-r from-red-950/90 via-red-900/70 to-red-950/90 animate-pulse"
        >
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-2.5 sm:px-6">
            <div className="flex items-center gap-3 text-xs text-red-100">
              <span className="relative flex h-3 w-3 shrink-0">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex h-3 w-3 rounded-full bg-red-500" />
              </span>
              <WifiOff className="h-4 w-4 shrink-0 text-red-300" />
              <div>
                <span className="font-bold uppercase tracking-wide text-red-200">
                  Alerta de Desconexión Crítica ({offlineComponents.length} OFFLINE):
                </span>{' '}
                <span className="text-red-100">
                  {offlineComponents
                    .map(
                      (c) =>
                        `${c.display_name} (${LAYER_LABELS[c.component_layer] ?? c.component_layer})`
                    )
                    .join(' · ')}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab('health')}
              className="shrink-0 rounded-lg border border-red-400/50 bg-red-500/25 px-3 py-1 text-xs font-bold text-white transition hover:bg-red-500/40"
            >
              Ir a Salud &amp; Monitoreo
            </button>
          </div>
        </div>
      )}

      {offlineComponents.length === 0 && degradedOrStaleComponents.length > 0 && (
        <div
          role="status"
          data-testid="global-degraded-banner"
          className="border-b border-amber-500/40 bg-amber-950/50"
        >
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-2 sm:px-6">
            <div className="flex items-center gap-2.5 text-xs text-amber-100">
              <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
              <span>
                <strong>Degradación / Retraso ({degradedOrStaleComponents.length}):</strong>{' '}
                {degradedOrStaleComponents
                  .map((c) => `${c.display_name} [${c.computed_status}]`)
                  .join(' · ')}
              </span>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab('health')}
              className="shrink-0 rounded-md border border-amber-500/40 bg-amber-500/20 px-2.5 py-1 text-xs font-semibold text-amber-100 hover:bg-amber-500/30"
            >
              Revisar en Salud &amp; Monitoreo
            </button>
          </div>
        </div>
      )}

      {/* MAIN CONTENT */}
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">{children}</main>
    </div>
  );
}
