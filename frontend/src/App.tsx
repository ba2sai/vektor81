import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  MonitorCheck,
  FileWarning,
  Activity,
  FileDown,
  Server,
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Puzzle,
  HardDrive,
  Scale,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Badge,
} from './components/ui/card';

interface RiskBreakdown {
  shadow_ai_subscore: number;
  shadow_ai_weighted: number;
  storage_exposure_subscore: number;
  storage_exposure_weighted: number;
  extensions_subscore: number;
  extensions_weighted: number;
}

interface LegalConclusion {
  articulo: string;
  severidad: string;
  hallazgo: string;
  dictamen: string;
}

interface EndpointItem {
  id: number;
  hostname: string;
  username: string;
  ip_address: string | null;
  os_version: string;
  last_seen: string | null;
  dns_hits_count: number;
  risky_extensions_count: number;
  box_exposed_files: number;
  box_dlp_active: boolean;
  endpoint_risk_score: number;
  risky_extensions: Array<{
    extension_id: string;
    name: string;
    browser: string;
    permissions: string[];
  }>;
  box_audit: {
    installed?: boolean;
    sync_path?: string;
    total_synced_files?: number;
    sensitive_files_count?: number;
    dlp_enabled?: boolean;
    sample_files?: string[];
  };
}

interface SmbFinding {
  unc_path: string;
  share: string;
  filename: string;
  size_kb: number;
  cedulas_found: string[];
  rucs_found: string[];
  emails_found: string[];
  cedula_count: number;
  ruc_count: number;
  email_count: number;
  severity: string;
}

interface DashboardData {
  generated_at: string;
  kpis: {
    audited_endpoints: number;
    shadow_ai_events: number;
    exposed_files_smb_box: number;
    global_risk_score: number;
  };
  risk: {
    total_score: number;
    semaphore: 'ROJO' | 'AMARILLO' | 'VERDE';
    semaphore_color: string;
    compliance_level: string;
    legal_exposure_range: string;
    breakdown: RiskBreakdown;
    legal_conclusions: LegalConclusion[];
  };
  endpoints: EndpointItem[];
  top_ai_domains: Array<{
    domain: string;
    count: number;
    category: string;
  }>;
  latest_smb: {
    target_ip: string;
    server_name: string;
    auth_mode: string;
    guest_access_allowed: boolean;
    total_shares: number;
    critical_shares_found: string[];
    total_office_pdf_files: number;
    files_with_pii_count: number;
    cedula_matches_count: number;
    ruc_matches_count: number;
    email_matches_count: number;
    findings_detail: SmbFinding[];
    created_at: string;
  } | null;
}

const BAR_COLORS = [
  '#38bdf8',
  '#f43f5e',
  '#f59e0b',
  '#a855f7',
  '#10b981',
  '#fb7185',
  '#60a5fa',
  '#eab308',
];

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanningSmb, setScanningSmb] = useState<boolean>(false);
  const [smbStatusMsg, setSmbStatusMsg] = useState<string | null>(null);

  // Estado del formulario de escaneo SMB Windows Server
  const [serverIp, setServerIp] = useState<string>('192.168.10.5');
  const [smbUser, setSmbUser] = useState<string>('');
  const [smbPassword, setSmbPassword] = useState<string>('');
  const [smbDomain, setSmbDomain] = useState<string>('WORKGROUP');

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/dashboard');
      if (!res.ok) throw new Error('Error al consultar /api/v1/dashboard');
      const json: DashboardData = await res.json();
      setData(json);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const handleTriggerSmbScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanningSmb(true);
    setSmbStatusMsg(null);
    try {
      const res = await fetch('/api/v1/scan-smb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          server_ip: serverIp,
          username: smbUser,
          password: smbPassword,
          domain: smbDomain,
          port: 445,
          max_depth: 3,
          sample_kb_limit: 16,
          simulate_if_unreachable: true,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText);
      }
      const result = await res.json();
      setSmbStatusMsg(
        `Auditoría SMB completada en ${result.scan_duration_ms}ms: ${result.files_with_pii_count} archivos con PII detectados (${result.cedula_matches_count} cédulas panameñas).`
      );
      await fetchDashboard();
    } catch (err: any) {
      setSmbStatusMsg(`Error en escaneo SMB: ${err.message}`);
    } finally {
      setScanningSmb(false);
    }
  };

  const handleDownloadPdfReport = () => {
    window.open('/api/v1/report/pdf', '_blank');
  };

  const handlePreviewHtmlReport = () => {
    window.open('/api/v1/report/pdf?format=html', '_blank');
  };

  const semaphoreBadgeVariant =
    data?.risk.semaphore === 'ROJO'
      ? 'destructive'
      : data?.risk.semaphore === 'AMARILLO'
      ? 'warning'
      : 'success';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* BARRA SUPERIOR EJECUTIVA */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-500/15 border border-sky-500/40 text-sky-400">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white">
                  VEKTOR81 AUDIT APPLIANCE
                </h1>
                <Badge variant="default">100% ON-PREMISE LAN</Badge>
                <Badge variant="outline">0% LLM / DETERMINISTA</Badge>
              </div>
              <p className="text-xs text-slate-400">
                Auditoría de Gobernanza de IA (&ldquo;Shadow AI&rdquo;) &amp; Protección de Datos Personales — Ley 81 de Panamá
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={fetchDashboard}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 transition"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
              Actualizar Telemetría
            </button>

            <a
              href="/api/v1/agent/powershell"
              download="Vektor81-EndpointCollector.ps1"
              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-medium text-sky-300 hover:bg-sky-500/20 transition"
            >
              <Terminal className="h-3.5 w-3.5" />
              Descargar Agente PowerShell (.ps1)
            </a>

            <button
              onClick={handlePreviewHtmlReport}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 transition"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              Vista Previa Informe
            </button>

            <button
              onClick={handleDownloadPdfReport}
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-red-600 to-amber-600 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-red-900/30 hover:from-red-500 hover:to-amber-500 transition"
            >
              <FileDown className="h-4 w-4" />
              Generar Informe Ejecutivo PDF (Ley 81)
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {/* 4 TARJETAS KPI PRINCIPALES */}
        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Equipos Auditados
              </CardTitle>
              <MonitorCheck className="h-5 w-5 text-sky-400" />
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-extrabold text-white">
                {data?.kpis.audited_endpoints ?? 0}
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Estaciones Windows reportando vía agente PowerShell
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Eventos Shadow AI Detectados
              </CardTitle>
              <Activity className="h-5 w-5 text-rose-400" />
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-extrabold text-rose-400">
                {data?.kpis.shadow_ai_events ?? 0}
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Consultas DNS a LLMs y convertidores PDF públicos
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Archivos en Riesgo (SMB / Box)
              </CardTitle>
              <FileWarning className="h-5 w-5 text-amber-400" />
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-extrabold text-amber-400">
                {data?.kpis.exposed_files_smb_box ?? 0}
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Con Cédula Panameña, RUC o sincronizados sin DLP
              </p>
            </CardContent>
          </Card>

          <Card className="border-red-500/40 bg-gradient-to-br from-slate-900 via-slate-900 to-red-950/30">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wider text-slate-300">
                Score de Riesgo Global (Ley 81)
              </CardTitle>
              <Scale className="h-5 w-5 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black text-white">
                  {data?.kpis.global_risk_score ?? 0}
                  <span className="text-sm font-normal text-slate-400">/100</span>
                </div>
                {data && (
                  <Badge variant={semaphoreBadgeVariant}>
                    SEMÁFORO {data.risk.semaphore}
                  </Badge>
                )}
              </div>
              <p className="mt-1 text-[11px] text-slate-300 truncate">
                40% Shadow AI · 30% SMB/Box · 30% Ext &lt;all_urls&gt;
              </p>
            </CardContent>
          </Card>
        </section>

        {/* GRÁFICA DE BARRAS SHADOW AI + FORMULARIO DE ESCANEO SMB */}
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Gráfica Recharts: Herramientas de IA no autorizadas más utilizadas */}
          <Card className="lg:col-span-7">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Herramientas de IA Pública No Autorizadas Más Utilizadas</CardTitle>
                  <CardDescription>
                    Tráfico interceptado en DNS local (AdGuard Home + Caché DNS de Endpoints Windows)
                  </CardDescription>
                </div>
                <Badge variant="destructive">Peso Score: 40%</Badge>
              </div>
            </CardHeader>
            <CardContent>
              <div className="h-72 w-full">
                {data && data.top_ai_domains.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={data.top_ai_domains}
                      layout="vertical"
                      margin={{ top: 8, right: 24, left: 20, bottom: 8 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis type="number" stroke="#94a3b8" fontSize={12} />
                      <YAxis
                        dataKey="domain"
                        type="category"
                        stroke="#e2e8f0"
                        fontSize={12}
                        width={125}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                        formatter={(value: any, _name: any, props: any) => [
                          `${value} conexiones (${props.payload.category})`,
                          'Eventos DNS',
                        ]}
                      />
                      <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                        {data.top_ai_domains.map((_entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={BAR_COLORS[index % BAR_COLORS.length]}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-slate-500">
                    Sin eventos de Shadow AI registrados.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Formulario para disparar escaneo SMB al Windows Server */}
          <Card className="lg:col-span-5">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="h-5 w-5 text-amber-400" />
                  <div>
                    <CardTitle>Auditoría SMB Windows Server</CardTitle>
                    <CardDescription>
                      Escanea carpetas críticas buscando Cédula Panameña, RUC y Emails
                    </CardDescription>
                  </div>
                </div>
                <Badge variant="warning">Peso Score: 30%</Badge>
              </div>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleTriggerSmbScan} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      IP Windows Server (LAN)
                    </label>
                    <input
                      type="text"
                      value={serverIp}
                      onChange={(e) => setServerIp(e.target.value)}
                      placeholder="192.168.10.5"
                      required
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Dominio / Workgroup
                    </label>
                    <input
                      type="text"
                      value={smbDomain}
                      onChange={(e) => setSmbDomain(e.target.value)}
                      placeholder="WORKGROUP"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Usuario SMB (Vacío = Guest)
                    </label>
                    <input
                      type="text"
                      value={smbUser}
                      onChange={(e) => setSmbUser(e.target.value)}
                      placeholder="Guest / Anónimo"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Contraseña SMB
                    </label>
                    <input
                      type="password"
                      value={smbPassword}
                      onChange={(e) => setSmbPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={scanningSmb}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 transition"
                >
                  <Search className="h-4 w-4" />
                  {scanningSmb
                    ? 'Inspeccionando Shares y Expresiones Regulares...'
                    : 'Disparar Escaneo SMB al Windows Server'}
                </button>
              </form>

              {smbStatusMsg && (
                <div className="mt-3 rounded-lg border border-sky-500/30 bg-sky-500/10 p-2.5 text-xs text-sky-200">
                  {smbStatusMsg}
                </div>
              )}

              {/* Resumen del último escaneo SMB */}
              {data?.latest_smb && (
                <div className="mt-4 space-y-2 rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">
                      {data.latest_smb.server_name} ({data.latest_smb.target_ip})
                    </span>
                    <Badge variant={data.latest_smb.guest_access_allowed ? 'destructive' : 'warning'}>
                      {data.latest_smb.auth_mode}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-3 gap-2 pt-1 text-center">
                    <div className="rounded bg-slate-900 p-1.5">
                      <div className="text-base font-bold text-rose-400">
                        {data.latest_smb.cedula_matches_count}
                      </div>
                      <div className="text-[10px] text-slate-400">Cédulas Panameñas</div>
                    </div>
                    <div className="rounded bg-slate-900 p-1.5">
                      <div className="text-base font-bold text-amber-400">
                        {data.latest_smb.ruc_matches_count}
                      </div>
                      <div className="text-[10px] text-slate-400">RUC Detectados</div>
                    </div>
                    <div className="rounded bg-slate-900 p-1.5">
                      <div className="text-base font-bold text-sky-400">
                        {data.latest_smb.total_office_pdf_files}
                      </div>
                      <div className="text-[10px] text-slate-400">Docs (.pdf/.xlsx/.docx)</div>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </section>

        {/* TABLA DE EQUIPOS CON MÁS EXTENSIONES RIESGOSAS Y ARCHIVOS EN BOX */}
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle>
                  Inventario de Equipos: Extensiones con Permiso &lt;all_urls&gt; y Sincronización Box Drive
                </CardTitle>
                <CardDescription>
                  Estaciones Windows ordenadas por nivel de exposición a exfiltración en navegador y carpetas Box locales
                </CardDescription>
              </div>
              <Badge variant="warning">Peso Extensiones: 30%</Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="pb-3 pr-4 font-semibold">Equipo / IP</th>
                    <th className="pb-3 px-4 font-semibold">Usuario</th>
                    <th className="pb-3 px-4 font-semibold">Hits DNS Shadow AI</th>
                    <th className="pb-3 px-4 font-semibold">
                      Extensiones Riesgosas (&lt;all_urls&gt;)
                    </th>
                    <th className="pb-3 px-4 font-semibold">Auditoría Box Drive Local</th>
                    <th className="pb-3 pl-4 text-right font-semibold">Riesgo Endpoint</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {data?.endpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-slate-900/50">
                      <td className="py-3.5 pr-4 align-top">
                        <div className="font-bold text-white">{ep.hostname}</div>
                        <div className="text-[11px] text-slate-400">
                          {ep.ip_address || 'LAN'} · {ep.os_version}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 align-top font-mono text-slate-300">
                        {ep.username}
                      </td>
                      <td className="py-3.5 px-4 align-top">
                        <Badge variant={ep.dns_hits_count > 20 ? 'destructive' : 'warning'}>
                          {ep.dns_hits_count} conexiones IA
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 align-top">
                        <div className="space-y-1">
                          {ep.risky_extensions.map((ext, i) => (
                            <div
                              key={i}
                              className="flex items-center gap-1.5 text-xs text-rose-300"
                            >
                              <Puzzle className="h-3.5 w-3.5 shrink-0 text-rose-400" />
                              <span className="font-medium">{ext.name}</span>
                              <span className="text-[10px] text-slate-400">({ext.browser})</span>
                            </div>
                          ))}
                          {ep.risky_extensions.length === 0 && (
                            <span className="text-slate-500">Ninguna detectada</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 align-top">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4 text-amber-400 shrink-0" />
                          <div>
                            <div className="text-slate-200">
                              <strong>{ep.box_exposed_files}</strong> archivos sensibles de{' '}
                              {ep.box_audit?.total_synced_files ?? 0} sincronizados
                            </div>
                            <div className="mt-0.5 flex items-center gap-2">
                              {ep.box_dlp_active ? (
                                <Badge variant="success">DLP Activo</Badge>
                              ) : (
                                <Badge variant="destructive">SIN CONTROL DLP</Badge>
                              )}
                              <span className="text-[11px] text-slate-400 truncate max-w-xs">
                                {ep.box_audit?.sync_path}
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="py-3.5 pl-4 text-right align-top">
                        <span className="inline-flex items-center gap-1 font-bold text-rose-400 text-sm">
                          {ep.endpoint_risk_score}/100
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* HALLAZGOS DETALLADOS EN WINDOWS SERVER SMB Y DICTAMEN LEGAL LEY 81 */}
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <Card className="lg:col-span-7">
            <CardHeader>
              <CardTitle>
                Archivos Críticos con PII Panameña Expuestos en Windows Server (SMB)
              </CardTitle>
              <CardDescription>
                Muestras enmascaradas según principio de minimización de datos (Cédula, RUC, Email)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="pb-2.5 pr-3">Archivo / Ruta UNC</th>
                      <th className="pb-2.5 px-3">Share</th>
                      <th className="pb-2.5 px-3">Cédulas (Muestra)</th>
                      <th className="pb-2.5 pl-3 text-right">Severidad</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {data?.latest_smb?.findings_detail.map((item, idx) => (
                      <tr key={idx}>
                        <td className="py-2.5 pr-3">
                          <div className="font-semibold text-slate-200">{item.filename}</div>
                          <div className="font-mono text-[10px] text-slate-400">
                            {item.unc_path}
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <Badge variant="outline">{item.share}</Badge>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-amber-300">
                          {item.cedulas_found.join(', ')} ({item.cedula_count})
                        </td>
                        <td className="py-2.5 pl-3 text-right">
                          <Badge variant="destructive">{item.severity}</Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          <Card className="lg:col-span-5">
            <CardHeader>
              <CardTitle>Dictamen Determinista — Ley 81 de Panamá (ANTAI)</CardTitle>
              <CardDescription>
                Conclusiones generadas por el motor de reglas sin uso de LLMs
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {data?.risk.legal_conclusions.map((item, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-sky-300">{item.articulo}</span>
                    <Badge
                      variant={item.severidad === 'CRÍTICA' ? 'destructive' : 'warning'}
                    >
                      {item.severidad}
                    </Badge>
                  </div>
                  <p className="text-slate-300">
                    <strong>Hallazgo:</strong> {item.hallazgo}
                  </p>
                  <p className="text-slate-400">
                    <strong>Dictamen:</strong> {item.dictamen}
                  </p>
                </div>
              ))}
            </CardContent>
          </Card>
        </section>
      </main>
    </div>
  );
}
