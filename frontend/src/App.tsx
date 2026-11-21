import React, { useCallback, useEffect, useState } from 'react';
import { DatabaseZap, KeyRound, ShieldAlert } from 'lucide-react';
import {
  apiClient,
  ApiError,
  clearStoredApiToken,
  getStoredApiToken,
  setStoredApiToken,
  setUnauthorizedHandler,
} from './api/client';
import { AuthGateModal } from './components/AuthGateModal';
import { Layout } from './components/Layout';
import { Card, CardContent } from './components/ui/card';
import { AssetsAdminPage } from './pages/AssetsAdminPage';
import { CisoOverviewPage } from './pages/CisoOverviewPage';
import { ComplianceDpoPage } from './pages/ComplianceDpoPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import type { DashboardTab, HealthOverviewResponse, Tenant } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<DashboardTab>('health');
  const [apiToken, setApiToken] = useState<string>(() => getStoredApiToken());
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(() => !getStoredApiToken());
  const [authError, setAuthError] = useState<string | null>(null);

  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState<string | null>(null);
  const [healthOverview, setHealthOverview] = useState<HealthOverviewResponse | null>(null);

  const [loadingShell, setLoadingShell] = useState<boolean>(false);
  const [seedingDemo, setSeedingDemo] = useState<boolean>(false);
  const [shellError, setShellError] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setAuthError('El servidor rechazó la credencial (401 Unauthorized). Ingresa un API Token válido.');
      setAuthModalOpen(true);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const loadShell = useCallback(
    async (preferredTenantId?: string | null) => {
      const token = getStoredApiToken();
      if (!token) {
        setAuthModalOpen(true);
        return;
      }

      setLoadingShell(true);
      setShellError(null);
      try {
        const tenantRes = await apiClient.getTenants();
        const nextTenants = tenantRes.tenants ?? [];
        setTenants(nextTenants);

        let nextTenantId: string | null = null;
        if (preferredTenantId && nextTenants.some((t) => t.id === preferredTenantId)) {
          nextTenantId = preferredTenantId;
        } else if (selectedTenantId && nextTenants.some((t) => t.id === selectedTenantId)) {
          nextTenantId = selectedTenantId;
        } else {
          nextTenantId = nextTenants[0]?.id ?? null;
        }

        setSelectedTenantId(nextTenantId);

        const healthRes = await apiClient.getHealthOverview(nextTenantId);
        setHealthOverview(healthRes);
        setAuthError(null);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          return;
        }
        setShellError(err instanceof Error ? err.message : 'Error conectando con Vektor81 Control Plane');
      } finally {
        setLoadingShell(false);
      }
    },
    [selectedTenantId]
  );

  useEffect(() => {
    if (apiToken) {
      void loadShell();
    }
  }, [apiToken]);

  const handleSubmitToken = (newToken: string) => {
    setStoredApiToken(newToken);
    setApiToken(newToken);
    setAuthError(null);
    setAuthModalOpen(false);
    setRefreshTrigger((prev) => prev + 1);
  };

  const handleSelectTenant = async (nextTenantId: string) => {
    setSelectedTenantId(nextTenantId);
    setRefreshTrigger((prev) => prev + 1);
    try {
      const healthRes = await apiClient.getHealthOverview(nextTenantId);
      setHealthOverview(healthRes);
    } catch {
      // Handled by page / unauthorized interceptor
    }
  };

  const handleSeedDemo = async () => {
    setSeedingDemo(true);
    setShellError(null);
    try {
      const res = await apiClient.seedDemo();
      await loadShell(res.tenants_seeded?.[0] ?? 'banco-istmo');
      setRefreshTrigger((prev) => prev + 1);
    } catch (err) {
      setShellError(err instanceof Error ? err.message : 'Error al cargar datos demo');
    } finally {
      setSeedingDemo(false);
    }
  };

  const handleRefreshAll = async () => {
    await loadShell(selectedTenantId);
    setRefreshTrigger((prev) => prev + 1);
  };

  const handleHealthChanged = useCallback(() => {
    void (async () => {
      try {
        const healthRes = await apiClient.getHealthOverview(selectedTenantId);
        setHealthOverview(healthRes);
      } catch {
        // Ignore transient background refresh failures
      }
    })();
  }, [selectedTenantId]);

  const handleTenantsChanged = useCallback(
    (selectId?: string) => {
      void loadShell(selectId ?? selectedTenantId).then(() => {
        setRefreshTrigger((prev) => prev + 1);
      });
    },
    [loadShell, selectedTenantId]
  );

  return (
    <>
      <Layout
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        healthOverview={healthOverview}
        tenants={tenants}
        selectedTenantId={selectedTenantId}
        onSelectTenant={(id) => void handleSelectTenant(id)}
        onSeedDemo={() => void handleSeedDemo()}
        seedingDemo={seedingDemo}
        onRefresh={() => void handleRefreshAll()}
        refreshing={loadingShell}
        onOpenAuth={() => {
          setAuthError(null);
          setAuthModalOpen(true);
        }}
        hasToken={Boolean(apiToken)}
      >
        {shellError && (
          <div
            role="alert"
            className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-500/40 bg-red-950/40 px-4 py-3 text-xs text-red-200"
          >
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 shrink-0 text-red-400" />
              <span>{shellError}</span>
            </div>
            <button
              type="button"
              onClick={() => {
                clearStoredApiToken();
                setApiToken('');
                setAuthModalOpen(true);
              }}
              className="inline-flex items-center gap-1 rounded-md border border-red-500/40 bg-red-500/20 px-2.5 py-1 font-semibold text-red-100 hover:bg-red-500/30"
            >
              <KeyRound className="h-3 w-3" />
              Cambiar Token
            </button>
          </div>
        )}

        {apiToken && !loadingShell && tenants.length === 0 ? (
          <Card className="border-indigo-500/30 bg-slate-900/90">
            <CardContent className="flex flex-col items-center justify-center py-14 text-center space-y-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-indigo-500/40 bg-indigo-500/15 text-indigo-300">
                <DatabaseZap className="h-6 w-6" />
              </div>
              <div className="max-w-lg space-y-1">
                <h2 className="text-base font-bold text-white">
                  Control Plane conectado sin tenants activos
                </h2>
                <p className="text-xs text-slate-400">
                  Puedes poblar inmediatamente los 3 tenants panameños de demostración (
                  <code className="text-slate-300">banco-istmo</code>,{' '}
                  <code className="text-slate-300">clinica-pacifica</code>,{' '}
                  <code className="text-slate-300">bufete-balboa</code>) o crear un tenant en la
                  pestaña Activos &amp; Tenants.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => void handleSeedDemo()}
                  disabled={seedingDemo}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  <DatabaseZap className="h-4 w-4" />
                  {seedingDemo ? 'Sembrando D1...' : 'Cargar Datos Demo'}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('assets')}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800"
                >
                  Crear Tenant Manualmente
                </button>
              </div>
            </CardContent>
          </Card>
        ) : (
          <>
            {activeTab === 'health' && (
              <SystemHealthPage
                tenantId={selectedTenantId}
                refreshTrigger={refreshTrigger}
                onHealthChanged={handleHealthChanged}
              />
            )}
            {activeTab === 'ciso' && (
              <CisoOverviewPage tenantId={selectedTenantId} refreshTrigger={refreshTrigger} />
            )}
            {activeTab === 'dpo' && (
              <ComplianceDpoPage tenantId={selectedTenantId} refreshTrigger={refreshTrigger} />
            )}
            {activeTab === 'assets' && (
              <AssetsAdminPage
                tenantId={selectedTenantId}
                tenants={tenants}
                refreshTrigger={refreshTrigger}
                onTenantsChanged={handleTenantsChanged}
              />
            )}
          </>
        )}
      </Layout>

      <AuthGateModal
        isOpen={authModalOpen}
        initialToken={apiToken}
        errorMessage={authError}
        canClose={Boolean(apiToken)}
        onSubmitToken={handleSubmitToken}
        onClose={() => setAuthModalOpen(false)}
      />
    </>
  );
}
