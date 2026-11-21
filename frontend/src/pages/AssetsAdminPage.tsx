import React, { useCallback, useEffect, useState } from 'react';
import {
  Building2,
  Database,
  HardDrive,
  KeyRound,
  MonitorCheck,
  Plus,
  Puzzle,
  Radio,
  RefreshCw,
  Save,
  Search,
  Server,
  Terminal,
} from 'lucide-react';
import {
  apiClient,
  getStoredCollectorToken,
  setStoredCollectorToken,
} from '../api/client';
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
  AlertSeverity,
  AssetsDashboardResponse,
  DbScanRequest,
  DnsStatsResponse,
  EntityType,
  RegulatoryProfile,
  SourceType,
  Tenant,
} from '../types';
import {
  ENTITY_LABELS,
  severityBadgeVariant,
  statusBadgeVariant,
} from '../utils/format';

export interface AssetsAdminPageProps {
  tenantId: string | null;
  tenants: Tenant[];
  refreshTrigger?: number;
  onTenantsChanged?: (selectTenantId?: string) => void;
  initialData?: AssetsDashboardResponse | null;
}

const DB_DEFAULT_PORTS: Record<DbScanRequest['db_type'], number> = {
  postgresql: 5432,
  mssql: 1433,
  mysql: 3306,
  oracle: 1521,
  sqlite: 0,
};

export function AssetsAdminPage({
  tenantId,
  tenants,
  refreshTrigger = 0,
  onTenantsChanged,
  initialData = null,
}: AssetsAdminPageProps) {
  const [data, setData] = useState<AssetsDashboardResponse | null>(initialData);
  const [loading, setLoading] = useState<boolean>(!initialData);
  const [error, setError] = useState<string | null>(null);

  // Findings filters
  const [sourceFilter, setSourceFilter] = useState<'' | SourceType>('');
  const [entityFilter, setEntityFilter] = useState<'' | EntityType>('');
  const [severityFilter, setSeverityFilter] = useState<'' | AlertSeverity>('');

  // Active tenant edit form
  const activeTenant = tenants.find((t) => t.id === tenantId) ?? null;
  const [editProfile, setEditProfile] = useState<RegulatoryProfile>('ANTAI_LEY81');
  const [editDpoName, setEditDpoName] = useState('');
  const [editDpoEmail, setEditDpoEmail] = useState('');
  const [editDpoRegistered, setEditDpoRegistered] = useState(false);
  const [editDpoRef, setEditDpoRef] = useState('');
  const [savingTenant, setSavingTenant] = useState(false);
  const [tenantFeedback, setTenantFeedback] = useState<string | null>(null);

  // Create tenant form
  const [showCreateTenant, setShowCreateTenant] = useState(false);
  const [newTenantId, setNewTenantId] = useState('');
  const [newTenantName, setNewTenantName] = useState('');
  const [newTenantIndustry, setNewTenantIndustry] = useState('Servicios Financieros');
  const [newTenantProfile, setNewTenantProfile] = useState<RegulatoryProfile>('ANTAI_LEY81');
  const [newTenantDpoName, setNewTenantDpoName] = useState('');
  const [newTenantDpoEmail, setNewTenantDpoEmail] = useState('');
  const [newTenantDpoReg, setNewTenantDpoReg] = useState(false);
  const [newTenantDpoRef, setNewTenantDpoRef] = useState('');
  const [creatingTenant, setCreatingTenant] = useState(false);

  // Collector Token Settings
  const [collectorToken, setCollectorToken] = useState<string>(() => getStoredCollectorToken());
  const [collectorTokenSavedMsg, setCollectorTokenSavedMsg] = useState<string | null>(null);

  // SMB Scan Form (simulate_if_unreachable UNCHECKED BY DEFAULT)
  const [smbIp, setSmbIp] = useState('192.168.10.5');
  const [smbDomain, setSmbDomain] = useState('WORKGROUP');
  const [smbUser, setSmbUser] = useState('');
  const [smbPassword, setSmbPassword] = useState('');
  const [smbPort, setSmbPort] = useState(445);
  const [smbSimulate, setSmbSimulate] = useState(false);
  const [scanningSmb, setScanningSmb] = useState(false);
  const [smbResultMsg, setSmbResultMsg] = useState<string | null>(null);

  // DB Scan Form (simulate_if_unreachable UNCHECKED BY DEFAULT)
  const [dbType, setDbType] = useState<DbScanRequest['db_type']>('postgresql');
  const [dbHost, setDbHost] = useState('192.168.10.20');
  const [dbPort, setDbPort] = useState(5432);
  const [dbName, setDbName] = useState('core_clientes');
  const [dbSqlitePath, setDbSqlitePath] = useState('/app/data/sample.db');
  const [dbUser, setDbUser] = useState('vektor_ro');
  const [dbPassword, setDbPassword] = useState('');
  const [dbSampleLimit, setDbSampleLimit] = useState(200);
  const [dbSimulate, setDbSimulate] = useState(false);
  const [scanningDb, setScanningDb] = useState(false);
  const [dbResultMsg, setDbResultMsg] = useState<string | null>(null);

  // DNS Stats probe
  const [dnsStats, setDnsStats] = useState<DnsStatsResponse | null>(null);
  const [loadingDns, setLoadingDns] = useState(false);
  const [collectorActionError, setCollectorActionError] = useState<string | null>(null);

  useEffect(() => {
    if (activeTenant) {
      setEditProfile(activeTenant.regulatory_profile);
      setEditDpoName(activeTenant.dpo_name ?? '');
      setEditDpoEmail(activeTenant.dpo_email ?? '');
      setEditDpoRegistered(Boolean(activeTenant.dpo_antai_registered));
      setEditDpoRef(activeTenant.dpo_antai_reg_ref ?? '');
    }
  }, [activeTenant]);

  const loadData = useCallback(async () => {
    if (!tenantId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getAssetsDashboard(tenantId, {
        source_type: sourceFilter,
        entity_type: entityFilter,
        severity: severityFilter,
      });
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al cargar activos y hallazgos');
    } finally {
      setLoading(false);
    }
  }, [tenantId, sourceFilter, entityFilter, severityFilter]);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshTrigger]);

  const handleSaveTenantSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId) return;
    setSavingTenant(true);
    setTenantFeedback(null);
    try {
      await apiClient.updateTenant(tenantId, {
        regulatory_profile: editProfile,
        dpo_name: editDpoName.trim() || null,
        dpo_email: editDpoEmail.trim() || null,
        dpo_antai_registered: editDpoRegistered,
        dpo_antai_reg_ref: editDpoRef.trim() || null,
      });
      setTenantFeedback('Perfil regulatorio y datos DPO actualizados.');
      onTenantsChanged?.(tenantId);
    } catch (err) {
      setTenantFeedback(err instanceof Error ? err.message : 'Error al actualizar tenant');
    } finally {
      setSavingTenant(false);
    }
  };

  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingTenant(true);
    setError(null);
    try {
      const res = await apiClient.createTenant({
        id: newTenantId.trim().toLowerCase(),
        name: newTenantName.trim(),
        industry: newTenantIndustry.trim(),
        regulatory_profile: newTenantProfile,
        dpo_name: newTenantDpoName.trim() || null,
        dpo_email: newTenantDpoEmail.trim() || null,
        dpo_antai_registered: newTenantDpoReg,
        dpo_antai_reg_ref: newTenantDpoRef.trim() || null,
      });
      setShowCreateTenant(false);
      setNewTenantId('');
      setNewTenantName('');
      onTenantsChanged?.(res.tenant.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al crear tenant');
    } finally {
      setCreatingTenant(false);
    }
  };

  const handleSaveCollectorToken = (e: React.FormEvent) => {
    e.preventDefault();
    setStoredCollectorToken(collectorToken);
    setCollectorTokenSavedMsg(
      collectorToken.trim()
        ? 'Collector Token guardado en sessionStorage.'
        : 'Collector Token limpiado.'
    );
  };

  const handleTriggerSmbScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanningSmb(true);
    setSmbResultMsg(null);
    try {
      const res = await apiClient.scanSmb({
        server_ip: smbIp.trim(),
        domain: smbDomain.trim() || 'WORKGROUP',
        username: smbUser.trim(),
        password: smbPassword,
        port: smbPort,
        max_depth: 3,
        max_file_mb: 10,
        simulate_if_unreachable: smbSimulate,
        tenant_id: tenantId ?? undefined,
        regulatory_profile: activeTenant?.regulatory_profile,
      });
      setSmbResultMsg(
        `Escaneo SMB completado (${String(res.files_with_pii_count ?? res.inserted ?? 0)} hallazgos PII, ${String(res.scan_duration_ms ?? 0)}ms).`
      );
      await loadData();
    } catch (err) {
      setSmbResultMsg(err instanceof Error ? `Error SMB: ${err.message}` : 'Error en escaneo SMB');
    } finally {
      setScanningSmb(false);
    }
  };

  const handleTriggerDbScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanningDb(true);
    setDbResultMsg(null);
    try {
      const payload: DbScanRequest =
        dbType === 'sqlite'
          ? {
              db_type: 'sqlite',
              sqlite_path: dbSqlitePath.trim(),
              sample_limit: dbSampleLimit,
              simulate_if_unreachable: dbSimulate,
              tenant_id: tenantId ?? undefined,
              regulatory_profile: activeTenant?.regulatory_profile,
            }
          : {
              db_type: dbType,
              host: dbHost.trim(),
              port: dbPort >= 1 ? dbPort : DB_DEFAULT_PORTS[dbType],
              database: dbName.trim(),
              username: dbUser.trim(),
              password: dbPassword,
              sample_limit: dbSampleLimit,
              simulate_if_unreachable: dbSimulate,
              tenant_id: tenantId ?? undefined,
              regulatory_profile: activeTenant?.regulatory_profile,
            };
      const res = await apiClient.scanDb(payload);
      setDbResultMsg(
        `Escaneo SQL DB (${dbType}) completado: ${String(res.findings_count ?? 0)} hallazgos en ${String(res.tables_scanned ?? 0)} tablas.`
      );
      await loadData();
    } catch (err) {
      setDbResultMsg(
        err instanceof Error ? `Error DB Scan: ${err.message}` : 'Error en escaneo SQL DB'
      );
    } finally {
      setScanningDb(false);
    }
  };

  const handleFetchDnsStats = async () => {
    setLoadingDns(true);
    setCollectorActionError(null);
    try {
      const res = await apiClient.getDnsStats(500, tenantId);
      setDnsStats(res);
    } catch (err) {
      setCollectorActionError(
        err instanceof Error ? `AdGuard DNS (/api/v1/dns-stats): ${err.message}` : 'Error DNS'
      );
    } finally {
      setLoadingDns(false);
    }
  };

  const handleDownloadPowershell = async () => {
    setCollectorActionError(null);
    try {
      await apiClient.downloadPowershellAgent(tenantId);
    } catch (err) {
      setCollectorActionError(
        err instanceof Error
          ? `Error descargando agente PowerShell: ${err.message}`
          : 'Error descargando agente'
      );
    }
  };

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

      {/* TENANT PROFILE & DPO REGISTRATION + COLLECTOR SETTINGS */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-7">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Building2 className="h-4 w-4 text-sky-400" />
                  Configuración Regulatoria del Tenant &amp; Registro DPO
                </CardTitle>
                <CardDescription>
                  Cambia marco normativo (ANTAI / SBP / Salud Ley 68) o crea un nuevo tenant MSSP
                </CardDescription>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateTenant((prev) => !prev)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-500/25"
              >
                <Plus className="h-3.5 w-3.5" />
                Nuevo Tenant
              </button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            {showCreateTenant && (
              <form
                onSubmit={handleCreateTenant}
                className="rounded-xl border border-slate-700 bg-slate-950/90 p-4 space-y-3"
              >
                <div className="font-bold text-white">Crear Nuevo Tenant Multi-Empresa</div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-slate-300">ID Slug (a-z, 0-9, -)</label>
                    <input
                      type="text"
                      required
                      pattern="[a-z0-9-]{2,64}"
                      value={newTenantId}
                      onChange={(e) => setNewTenantId(e.target.value)}
                      placeholder="empresa-panama"
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-slate-300">Razón Social</label>
                    <input
                      type="text"
                      required
                      value={newTenantName}
                      onChange={(e) => setNewTenantName(e.target.value)}
                      placeholder="Corporación Istmeña S.A."
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-slate-300">Perfil Regulatorio</label>
                    <select
                      value={newTenantProfile}
                      onChange={(e) => setNewTenantProfile(e.target.value as RegulatoryProfile)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    >
                      <option value="ANTAI_LEY81">ANTAI_LEY81</option>
                      <option value="SBP_001_2022">SBP_001_2022</option>
                      <option value="SALUD_LEY68">SALUD_LEY68</option>
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-slate-300">Industria</label>
                    <input
                      type="text"
                      value={newTenantIndustry}
                      onChange={(e) => setNewTenantIndustry(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-slate-300">Nombre DPO</label>
                    <input
                      type="text"
                      value={newTenantDpoName}
                      onChange={(e) => setNewTenantDpoName(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-slate-300">Email DPO</label>
                    <input
                      type="email"
                      value={newTenantDpoEmail}
                      onChange={(e) => setNewTenantDpoEmail(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                    />
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-4">
                    <label className="inline-flex items-center gap-2 text-slate-300">
                      <input
                        type="checkbox"
                        checked={newTenantDpoReg}
                        onChange={(e) => setNewTenantDpoReg(e.target.checked)}
                      />
                      Registrado ante ANTAI
                    </label>
                    <input
                      type="text"
                      value={newTenantDpoRef}
                      onChange={(e) => setNewTenantDpoRef(e.target.value)}
                      placeholder="Ref. ANTAI-DPO-2026-..."
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-white"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setShowCreateTenant(false)}
                      className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300"
                    >
                      Cancelar
                    </button>
                    <button
                      type="submit"
                      disabled={creatingTenant}
                      className="rounded-lg bg-sky-600 px-4 py-1.5 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
                    >
                      {creatingTenant ? 'Creando...' : 'Crear Tenant'}
                    </button>
                  </div>
                </div>
              </form>
            )}

            {activeTenant ? (
              <form onSubmit={handleSaveTenantSettings} className="space-y-3">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">
                      Perfil Regulatorio ({activeTenant.name})
                    </label>
                    <select
                      value={editProfile}
                      onChange={(e) => setEditProfile(e.target.value as RegulatoryProfile)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                    >
                      <option value="ANTAI_LEY81">ANTAI_LEY81 (Ley 81 / DE 285)</option>
                      <option value="SBP_001_2022">SBP_001_2022 (Bancos Panamá)</option>
                      <option value="SALUD_LEY68">SALUD_LEY68 (Expediente Clínico 20a)</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">
                      Referencia Registro ANTAI
                    </label>
                    <input
                      type="text"
                      value={editDpoRef}
                      onChange={(e) => setEditDpoRef(e.target.value)}
                      placeholder="ANTAI-DPO-2026-0142"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-white"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">Nombre del DPO</label>
                    <input
                      type="text"
                      value={editDpoName}
                      onChange={(e) => setEditDpoName(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">Email del DPO</label>
                    <input
                      type="email"
                      value={editDpoEmail}
                      onChange={(e) => setEditDpoEmail(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3">
                  <label className="inline-flex items-center gap-2 text-slate-300">
                    <input
                      type="checkbox"
                      checked={editDpoRegistered}
                      onChange={(e) => setEditDpoRegistered(e.target.checked)}
                    />
                    DPO formalmente registrado ante ANTAI (Art. 45 Ley 81)
                  </label>

                  <button
                    type="submit"
                    disabled={savingTenant}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-1.5 font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
                  >
                    <Save className="h-3.5 w-3.5" />
                    {savingTenant ? 'Guardando...' : 'Guardar Perfil y DPO'}
                  </button>
                </div>

                {tenantFeedback && (
                  <div className="rounded-lg border border-sky-500/30 bg-sky-950/30 p-2 text-sky-200">
                    {tenantFeedback}
                  </div>
                )}
              </form>
            ) : (
              <p className="text-slate-400">Selecciona o crea un tenant para editar su perfil.</p>
            )}
          </CardContent>
        </Card>

        {/* Collector Token + Agent PowerShell + AdGuard DNS */}
        <Card className="lg:col-span-5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-amber-400" />
              Colector On-Premise, Agente &amp; Token
            </CardTitle>
            <CardDescription>
              Descarga el recolector GPO (.ps1), consulta AdGuard DNS o configura el Token del Colector
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <form onSubmit={handleSaveCollectorToken} className="space-y-2">
              <label className="block font-medium text-slate-300">
                Collector Token (<code className="text-slate-400">/api/v1/*</code>)
              </label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <KeyRound className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                  <input
                    type="password"
                    value={collectorToken}
                    onChange={(e) => setCollectorToken(e.target.value)}
                    placeholder="Token opcional del colector local"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-8 pr-3 font-mono text-xs text-white"
                  />
                </div>
                <button
                  type="submit"
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-semibold text-slate-200 hover:bg-slate-800"
                >
                  Guardar
                </button>
              </div>
              {collectorTokenSavedMsg && (
                <div className="text-[11px] text-emerald-300">{collectorTokenSavedMsg}</div>
              )}
            </form>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <button
                type="button"
                onClick={() => void handleDownloadPowershell()}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-2 font-semibold text-sky-200 hover:bg-sky-500/25"
              >
                <Terminal className="h-4 w-4" />
                Agente PowerShell (.ps1)
              </button>
              <button
                type="button"
                onClick={() => void handleFetchDnsStats()}
                disabled={loadingDns}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-3 py-2 font-semibold text-indigo-200 hover:bg-indigo-500/25 disabled:opacity-50"
              >
                <Radio className="h-4 w-4" />
                {loadingDns ? 'Consultando...' : 'Consultar AdGuard DNS'}
              </button>
            </div>

            {collectorActionError && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-950/35 p-2.5 text-[11px] text-amber-200">
                {collectorActionError}
              </div>
            )}

            {dnsStats && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/75 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">AdGuard DNS Telemetry</span>
                  <Badge variant={dnsStats.adguard_live_connected ? 'success' : 'warning'}>
                    {dnsStats.adguard_status ??
                      (dnsStats.adguard_live_connected ? 'LIVE ADGUARD' : 'OFFLINE / FALLBACK')}
                  </Badge>
                </div>
                <div className="text-[11px] text-slate-300">
                  {dnsStats.total_queries_inspected} consultas ·{' '}
                  <strong className="text-rose-300">{dnsStats.shadow_ai_hits_total}</strong> hits
                  Shadow AI ({dnsStats.dictionary_domains_loaded} dominios cargados)
                </div>
                {dnsStats.last_error && (
                  <div className="text-[11px] text-amber-300">{dnsStats.last_error}</div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* ON-PREMISE SCANS: SMB WINDOWS SERVER + RELATIONAL SQL DB */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* SMB Scan Form */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-4 w-4 text-amber-400" />
              Disparar Escaneo SMB Windows Server (<code className="text-xs text-slate-400">/api/v1/scan-smb</code>)
            </CardTitle>
            <CardDescription>
              Audita recursos compartidos LAN buscando cédulas, RUC, pasaportes y emails
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleTriggerSmbScan} className="space-y-3 text-xs">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label className="mb-1 block text-slate-300">IP / Host SMB</label>
                  <input
                    type="text"
                    required
                    value={smbIp}
                    onChange={(e) => setSmbIp(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-300">Dominio / Workgroup</label>
                  <input
                    type="text"
                    value={smbDomain}
                    onChange={(e) => setSmbDomain(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-300">Puerto</label>
                  <input
                    type="number"
                    value={smbPort}
                    onChange={(e) => setSmbPort(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-slate-300">Usuario SMB (Vacío = Guest)</label>
                  <input
                    type="text"
                    value={smbUser}
                    onChange={(e) => setSmbUser(e.target.value)}
                    placeholder="Guest / Anónimo"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-slate-300">Contraseña SMB</label>
                  <input
                    type="password"
                    value={smbPassword}
                    onChange={(e) => setSmbPassword(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <label className="inline-flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={smbSimulate}
                  onChange={(e) => setSmbSimulate(e.target.checked)}
                />
                Simular si no hay red (Demo)
              </label>

              <button
                type="submit"
                disabled={scanningSmb}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
              >
                <Search className="h-4 w-4" />
                {scanningSmb ? 'Escaneando SMB...' : 'Ejecutar Escaneo SMB'}
              </button>

              {smbResultMsg && (
                <div className="rounded-lg border border-sky-500/35 bg-sky-950/35 p-2.5 text-sky-200">
                  {smbResultMsg}
                </div>
              )}
            </form>
          </CardContent>
        </Card>

        {/* Relational SQL DB Scan Form */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-4 w-4 text-emerald-400" />
              Disparar Escaneo SQL DB Relacional (<code className="text-xs text-slate-400">/api/v1/scan-db</code>)
            </CardTitle>
            <CardDescription>
              Inspecciona esquemas PostgreSQL, SQL Server, MySQL o SQLite con enmascaramiento local
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleTriggerDbScan} className="space-y-3 text-xs">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label className="mb-1 block text-slate-300">Motor SQL</label>
                  <select
                    value={dbType}
                    onChange={(e) => {
                      const next = e.target.value as DbScanRequest['db_type'];
                      setDbType(next);
                      setDbPort(DB_DEFAULT_PORTS[next]);
                    }}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  >
                    <option value="postgresql">PostgreSQL</option>
                    <option value="mssql">SQL Server (MSSQL)</option>
                    <option value="mysql">MySQL / MariaDB</option>
                    <option value="oracle">Oracle</option>
                    <option value="sqlite">SQLite</option>
                  </select>
                </div>
                {dbType === 'sqlite' ? (
                  <div className="sm:col-span-2">
                    <label className="mb-1 block text-slate-300">Ruta SQLite (en colector)</label>
                    <input
                      type="text"
                      required
                      value={dbSqlitePath}
                      onChange={(e) => setDbSqlitePath(e.target.value)}
                      placeholder="/app/data/sample.db"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white font-mono"
                    />
                  </div>
                ) : (
                  <>
                    <div>
                      <label className="mb-1 block text-slate-300">Host / IP</label>
                      <input
                        type="text"
                        required
                        value={dbHost}
                        onChange={(e) => setDbHost(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-slate-300">Puerto</label>
                      <input
                        type="number"
                        min={1}
                        max={65535}
                        value={dbPort}
                        onChange={(e) => setDbPort(Number(e.target.value))}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                      />
                    </div>
                  </>
                )}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
                {dbType !== 'sqlite' && (
                  <>
                    <div>
                      <label className="mb-1 block text-slate-300">Base de Datos</label>
                      <input
                        type="text"
                        required
                        value={dbName}
                        onChange={(e) => setDbName(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-slate-300">Usuario</label>
                      <input
                        type="text"
                        value={dbUser}
                        onChange={(e) => setDbUser(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-slate-300">Contraseña</label>
                      <input
                        type="password"
                        value={dbPassword}
                        onChange={(e) => setDbPassword(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                      />
                    </div>
                  </>
                )}
                <div>
                  <label className="mb-1 block text-slate-300">Muestra (filas)</label>
                  <input
                    type="number"
                    min={1}
                    max={2000}
                    value={dbSampleLimit}
                    onChange={(e) => setDbSampleLimit(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <label className="inline-flex items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={dbSimulate}
                  onChange={(e) => setDbSimulate(e.target.checked)}
                />
                Simular si no hay red (Demo)
              </label>

              <button
                type="submit"
                disabled={scanningDb}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
              >
                <Database className="h-4 w-4" />
                {scanningDb ? 'Escaneando SQL DB...' : 'Ejecutar Escaneo SQL DB'}
              </button>

              {dbResultMsg && (
                <div className="rounded-lg border border-emerald-500/35 bg-emerald-950/35 p-2.5 text-emerald-200">
                  {dbResultMsg}
                </div>
              )}
            </form>
          </CardContent>
        </Card>
      </section>

      {/* ENDPOINTS INVENTORY TABLE */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                <MonitorCheck className="h-4 w-4 text-sky-400" />
                Inventario de Endpoints ({data?.summary.endpoints_total ?? 0})
              </CardTitle>
              <CardDescription>
                Extensiones con permiso &lt;all_urls&gt;, exposición local en Box/OneDrive y score de riesgo
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="warning">
                {data?.summary.endpoints_with_all_urls ?? 0} con &lt;all_urls&gt;
              </Badge>
              <Badge variant="destructive">
                {data?.summary.endpoints_box_unprotected ?? 0} Box sin DLP
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5 pr-3">Hostname / Estado</th>
                  <th className="pb-2.5 px-3">Usuario</th>
                  <th className="pb-2.5 px-3">Extensiones &lt;all_urls&gt;</th>
                  <th className="pb-2.5 px-3">Box / OneDrive Sync &amp; DLP</th>
                  <th className="pb-2.5 pl-3 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.endpoints ?? []).map((ep) => {
                  const riskyExts = ep.details?.risky_extensions ?? [];
                  return (
                    <tr key={ep.id} className="hover:bg-slate-900/50">
                      <td className="py-3 pr-3 align-top">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white">{ep.hostname}</span>
                          <Badge variant={statusBadgeVariant(ep.status)}>{ep.status}</Badge>
                        </div>
                        <div className="text-[11px] text-slate-400">
                          {ep.ip_address ?? 'LAN'} · {ep.os_version}
                        </div>
                      </td>
                      <td className="py-3 px-3 align-top font-mono text-slate-300">
                        {ep.username}
                      </td>
                      <td className="py-3 px-3 align-top">
                        {riskyExts.length > 0 ? (
                          <div className="space-y-1">
                            {riskyExts.map((ext, i) => (
                              <div key={i} className="flex items-center gap-1.5 text-rose-300">
                                <Puzzle className="h-3.5 w-3.5 shrink-0 text-rose-400" />
                                <span>{ext.name}</span>
                                <span className="text-[10px] text-slate-400">({ext.browser})</span>
                              </div>
                            ))}
                          </div>
                        ) : ep.risky_extensions_count > 0 ? (
                          <Badge variant="destructive">
                            {ep.risky_extensions_count} ext &lt;all_urls&gt;
                          </Badge>
                        ) : (
                          <span className="text-slate-500">Sin extensiones riesgosas</span>
                        )}
                      </td>
                      <td className="py-3 px-3 align-top">
                        <div className="flex items-start gap-2">
                          <HardDrive className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                          <div className="space-y-1">
                            <div className="text-slate-200">
                              Box: <strong>{ep.box_exposed_files}</strong> exp. · OneDrive:{' '}
                              <strong>{ep.onedrive_exposed_files}</strong> exp.
                            </div>
                            <Badge variant={ep.box_dlp_active ? 'success' : 'destructive'}>
                              {ep.box_dlp_active ? 'DLP Activo' : 'SIN CONTROL DLP'}
                            </Badge>
                          </div>
                        </div>
                      </td>
                      <td className="py-3 pl-3 text-right align-top">
                        <span
                          className={cn(
                            'font-mono text-sm font-extrabold',
                            ep.endpoint_risk_score >= 60
                              ? 'text-red-400'
                              : ep.endpoint_risk_score >= 30
                                ? 'text-amber-300'
                                : 'text-emerald-300'
                          )}
                        >
                          {ep.endpoint_risk_score}/100
                        </span>
                      </td>
                    </tr>
                  );
                })}
                {(data?.endpoints ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500">
                      {loading ? 'Cargando endpoints...' : 'Sin endpoints reportados para este tenant.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* MASKED SCAN FINDINGS TABLE WITH FILTERS */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>
                Hallazgos PII Enmascarados ({data?.findings.length ?? 0})
              </CardTitle>
              <CardDescription>
                Minimización estricta de datos: sólo muestras enmascaradas y huella SHA-256
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <select
                aria-label="Filtrar por origen"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value as '' | SourceType)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-white"
              >
                <option value="">Todos los Orígenes</option>
                <option value="SMB">SMB</option>
                <option value="SQL_DB">SQL_DB</option>
                <option value="OCR_IMAGE">OCR_IMAGE</option>
                <option value="CASB">CASB</option>
                <option value="DLP_EDGE">DLP_EDGE</option>
              </select>

              <select
                aria-label="Filtrar por entidad"
                value={entityFilter}
                onChange={(e) => setEntityFilter(e.target.value as '' | EntityType)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-white"
              >
                <option value="">Todas las Entidades</option>
                <option value="PA_IDENTIDAD_NATURAL">PA_IDENTIDAD_NATURAL</option>
                <option value="PA_PASAPORTE">PA_PASAPORTE</option>
                <option value="PA_DATO_SENSIBLE_SALUD">PA_DATO_SENSIBLE_SALUD</option>
                <option value="PA_TARJETA_PAGO">PA_TARJETA_PAGO</option>
                <option value="PA_SWIFT_PA">PA_SWIFT_PA</option>
                <option value="EMAIL_PERSONAL">EMAIL_PERSONAL</option>
              </select>

              <select
                aria-label="Filtrar por severidad"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as '' | AlertSeverity)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-white"
              >
                <option value="">Todas las Severidades</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <button
                type="button"
                onClick={() => void loadData()}
                className="rounded-lg border border-slate-700 bg-slate-900 p-1.5 text-slate-300 hover:bg-slate-800"
                aria-label="Recargar hallazgos"
              >
                <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
              </button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5 pr-3">Origen / Repositorio</th>
                  <th className="pb-2.5 px-3">Entidad PII</th>
                  <th className="pb-2.5 px-3">Muestra Enmascarada</th>
                  <th className="pb-2.5 px-3">Matches / Edad</th>
                  <th className="pb-2.5 pl-3 text-right">Severidad</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.findings ?? []).map((f) => (
                  <tr key={f.id} className="hover:bg-slate-900/50">
                    <td className="py-2.5 pr-3">
                      <div className="flex items-center gap-1.5">
                        <Badge variant="outline">{f.source_type}</Badge>
                        <span className="font-semibold text-white">{f.repository_name}</span>
                        {f.is_simulated === 1 && (
                          <Badge variant="purple" className="text-[10px]">
                            SIMULADO
                          </Badge>
                        )}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">{f.location_path}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="font-medium text-slate-200">
                        {ENTITY_LABELS[f.entity_type] ?? f.entity_type}
                      </div>
                      {f.is_sensitive === 1 && (
                        <Badge variant="destructive" className="mt-0.5 text-[10px]">
                          DATO SENSIBLE
                        </Badge>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-amber-300">
                      {f.masked_sample}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="font-bold text-white">{f.match_count}</div>
                      {f.retention_age_days !== null && (
                        <div
                          className={cn(
                            'text-[10px]',
                            f.retention_violation === 1 ? 'text-red-400 font-semibold' : 'text-slate-400'
                          )}
                        >
                          {f.retention_age_days}d {f.retention_violation === 1 ? '(Violación)' : ''}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 pl-3 text-right">
                      <Badge variant={severityBadgeVariant(f.severity)}>{f.severity}</Badge>
                    </td>
                  </tr>
                ))}
                {(data?.findings ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500">
                      Sin hallazgos para los filtros seleccionados.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
