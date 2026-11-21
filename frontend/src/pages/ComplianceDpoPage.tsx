import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Clock,
  Download,
  ExternalLink,
  FileCheck2,
  FileDown,
  FileJson,
  Globe,
  Plus,
  RefreshCw,
  Scale,
  ShieldCheck,
  UserCheck,
  X,
  XCircle,
} from 'lucide-react';
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
  AlertSeverity,
  AntaiBreachDraftResponse,
  ArcoRightType,
  BreachIncident,
  DpoDashboardResponse,
  FichaTecnicaSnapshot,
} from '../types';
import {
  downloadJsonFile,
  formatBreachCountdown,
  formatDateTime,
  severityBadgeVariant,
} from '../utils/format';

export interface ComplianceDpoPageProps {
  tenantId: string | null;
  refreshTrigger?: number;
  initialData?: DpoDashboardResponse | null;
}

const ART37_ELEMENTS: Array<{
  key: keyof AntaiBreachDraftResponse['five_required_elements'];
  label: string;
}> = [
  { key: 'what_happened', label: '1. Qué ocurrió (naturaleza del incidente)' },
  { key: 'compromised_data_types', label: '2. Tipos de datos personales comprometidos' },
  { key: 'measures_adopted', label: '3. Medidas técnicas y organizativas adoptadas' },
  { key: 'titular_actions', label: '4. Acciones recomendadas a los titulares' },
  { key: 'contact_point', label: '5. Punto de contacto (DPO / Responsable)' },
];

export function ComplianceDpoPage({
  tenantId,
  refreshTrigger = 0,
  initialData = null,
}: ComplianceDpoPageProps) {
  const [data, setData] = useState<DpoDashboardResponse | null>(initialData);
  const [loading, setLoading] = useState<boolean>(!initialData);
  const [error, setError] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());

  // Ficha Técnica verification state
  const [generatingFicha, setGeneratingFicha] = useState(false);
  const [latestFichaMeta, setLatestFichaMeta] = useState<{
    snapshot: FichaTecnicaSnapshot;
    integrityVerified: boolean | null;
  } | null>(null);

  // ANTAI Draft modal state
  const [antaiDraft, setAntaiDraft] = useState<AntaiBreachDraftResponse | null>(null);
  const [loadingDraftId, setLoadingDraftId] = useState<string | null>(null);

  // DSAR export preview
  const [exportingDsarId, setExportingDsarId] = useState<string | null>(null);
  const [pdfFeedback, setPdfFeedback] = useState<string | null>(null);

  // Forms visibility
  const [showBreachForm, setShowBreachForm] = useState(false);
  const [showDsarForm, setShowDsarForm] = useState(false);
  const [showTransferForm, setShowTransferForm] = useState(false);

  // New Breach Form state
  const [breachTitle, setBreachTitle] = useState('');
  const [breachSeverity, setBreachSeverity] = useState<AlertSeverity>('CRITICAL');
  const [breachWhatHappened, setBreachWhatHappened] = useState('');
  const [breachDataTypes, setBreachDataTypes] = useState('PA_IDENTIDAD_NATURAL, EMAIL_PERSONAL');
  const [breachAffectedCount, setBreachAffectedCount] = useState(50);
  const [breachMeasures, setBreachMeasures] = useState('');
  const [breachTitularActions, setBreachTitularActions] = useState('');
  const [breachContactPoint, setBreachContactPoint] = useState('');
  const [submittingBreach, setSubmittingBreach] = useState(false);

  // New DSAR Form state
  const [dsarName, setDsarName] = useState('');
  const [dsarIdMasked, setDsarIdMasked] = useState('');
  const [dsarRight, setDsarRight] = useState<ArcoRightType>('ACCESO');
  const [dsarSystems, setDsarSystems] = useState('CORE-SQL, SMB-FileServer');
  const [dsarNotes, setDsarNotes] = useState('');
  const [submittingDsar, setSubmittingDsar] = useState(false);

  // New Transfer Form state
  const [trRecipient, setTrRecipient] = useState('');
  const [trCountry, setTrCountry] = useState('US');
  const [trCrossBorder, setTrCrossBorder] = useState(true);
  const [trPurpose, setTrPurpose] = useState('');
  const [trCategories, setTrCategories] = useState('PA_IDENTIDAD_NATURAL, Correo corporativo');
  const [trLegalBasis, setTrLegalBasis] = useState('');
  const [trDpaActive, setTrDpaActive] = useState(false);
  const [trRetentionDays, setTrRetentionDays] = useState(365);
  const [trDestructorVerified, setTrDestructorVerified] = useState(false);
  const [submittingTransfer, setSubmittingTransfer] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  const loadData = useCallback(async () => {
    if (!tenantId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getDpoDashboard(tenantId);
      setData(res);
      if (res.dpo_governance.dpo_name || res.dpo_governance.dpo_email) {
        setBreachContactPoint(
          (prev) =>
            prev ||
            `${res.dpo_governance.dpo_name ?? 'DPO'} <${res.dpo_governance.dpo_email ?? ''}>`
        );
      }
      if (res.ficha_tecnica_snapshots.length > 0) {
        try {
          const fichaVerify = await apiClient.getFichaTecnicas(tenantId, { includeLatest: true });
          if (fichaVerify.selected_snapshot) {
            setLatestFichaMeta({
              snapshot: fichaVerify.selected_snapshot,
              integrityVerified: fichaVerify.integrity_verified,
            });
          }
        } catch {
          // Keep dashboard data even if R2 verify check is unavailable
        }
      } else {
        setLatestFichaMeta(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al cargar módulo DPO & Legal');
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshTrigger]);

  const handleGenerateFicha = async () => {
    if (!tenantId) return;
    setGeneratingFicha(true);
    setError(null);
    try {
      const generated = await apiClient.generateFichaTecnica(tenantId);
      const verified = await apiClient.getFichaTecnicas(tenantId, {
        snapshotId: generated.snapshot.id,
      });
      setLatestFichaMeta({
        snapshot: generated.snapshot,
        integrityVerified: verified.integrity_verified ?? true,
      });
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al generar Ficha Técnica');
    } finally {
      setGeneratingFicha(false);
    }
  };

  const handleViewAntaiDraft = async (breach: BreachIncident) => {
    setLoadingDraftId(breach.id);
    setError(null);
    try {
      const draft = await apiClient.getBreachAntaiDraft(breach.id, breach.tenant_id);
      setAntaiDraft(draft);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al obtener borrador ANTAI');
    } finally {
      setLoadingDraftId(null);
    }
  };

  const handleMarkAntaiNotified = async (breach: BreachIncident) => {
    try {
      await apiClient.updateBreach(
        breach.id,
        { status: 'NOTIFIED_ANTAI', antai_notified_at: new Date().toISOString() },
        breach.tenant_id
      );
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al actualizar brecha');
    }
  };

  const handleCreateBreach = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId) return;
    setSubmittingBreach(true);
    setError(null);
    try {
      await apiClient.createBreach({
        tenant_id: tenantId,
        title: breachTitle.trim(),
        severity: breachSeverity,
        what_happened: breachWhatHappened.trim(),
        compromised_data_types: breachDataTypes
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        affected_records_estimate: breachAffectedCount,
        measures_adopted: breachMeasures.trim(),
        titular_actions: breachTitularActions.trim(),
        contact_point: breachContactPoint.trim(),
      });
      setShowBreachForm(false);
      setBreachTitle('');
      setBreachWhatHappened('');
      setBreachMeasures('');
      setBreachTitularActions('');
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al registrar incidente 72h');
    } finally {
      setSubmittingBreach(false);
    }
  };

  const handleCreateDsar = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId) return;
    setSubmittingDsar(true);
    setError(null);
    try {
      await apiClient.createDsar({
        tenant_id: tenantId,
        requester_name: dsarName.trim(),
        requester_id_masked: dsarIdMasked.trim(),
        right_type: dsarRight,
        target_systems: dsarSystems
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        notes: dsarNotes.trim() || undefined,
      });
      setShowDsarForm(false);
      setDsarName('');
      setDsarIdMasked('');
      setDsarNotes('');
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al crear solicitud ARCO-P');
    } finally {
      setSubmittingDsar(false);
    }
  };

  const handleExportDsar = async (dsarId: string) => {
    setExportingDsarId(dsarId);
    setError(null);
    try {
      const pkg = await apiClient.exportDsar(dsarId, tenantId);
      downloadJsonFile(`ARCO_DSAR_${dsarId}.json`, pkg);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al exportar paquete ARCO-P');
    } finally {
      setExportingDsarId(null);
    }
  };

  const handleCreateTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantId) return;
    setSubmittingTransfer(true);
    setError(null);
    try {
      await apiClient.createTransfer({
        tenant_id: tenantId,
        recipient_name: trRecipient.trim(),
        destination_country: trCountry.trim().toUpperCase(),
        is_cross_border: trCrossBorder,
        purpose: trPurpose.trim(),
        data_categories: trCategories
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        legal_basis: trLegalBasis.trim(),
        dpa_contract_active: trDpaActive,
        max_retention_days: trRetentionDays,
        destructor_verified: trDestructorVerified,
      });
      setShowTransferForm(false);
      setTrRecipient('');
      setTrPurpose('');
      setTrLegalBasis('');
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al registrar transferencia');
    } finally {
      setSubmittingTransfer(false);
    }
  };

  const handlePdfDownload = async (format: 'pdf' | 'html') => {
    setPdfFeedback(null);
    try {
      await apiClient.downloadPdfReport(format, tenantId);
    } catch (err) {
      setPdfFeedback(
        err instanceof Error
          ? `Colector On-Premise no respondió para informe ${format.toUpperCase()}: ${err.message}`
          : 'Error descargando informe'
      );
    }
  };

  if (!tenantId && !data) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-slate-400">
          Selecciona un tenant o carga los datos demo para gestionar cumplimiento DPO &amp; Legal.
        </CardContent>
      </Card>
    );
  }

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center rounded-xl border border-slate-800 bg-slate-900/50 py-16 text-sm text-slate-400">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin text-sky-400" />
        Cargando expediente DPO, reloj 72h y matriz ARCO-P...
      </div>
    );
  }

  const dpoGov = data?.dpo_governance;
  const retention = data?.retention_summary;

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

      {/* TOP ROW: DPO GOVERNANCE, RETENTION SUMMARY, FICHA TECNICA & PDF */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* DPO Governance Status (Art. 45 Ley 81) */}
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-sky-400" />
              Gobernanza DPO (Art. 45 Ley 81)
            </CardTitle>
            <CardDescription>
              Designación y registro formal ante la ANTAI
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Estado de Registro</span>
              <Badge variant={dpoGov?.compliant ? 'success' : 'destructive'}>
                {dpoGov?.dpo_antai_registered ? 'REGISTRADO ANTE ANTAI' : 'PENDIENTE ANTAI'}
              </Badge>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-1">
              <div className="font-semibold text-white">
                {dpoGov?.dpo_name ?? 'Sin DPO asignado'}
              </div>
              <div className="text-slate-400">{dpoGov?.dpo_email ?? 'Sin correo registrado'}</div>
              <div className="font-mono text-[11px] text-sky-300">
                Ref ANTAI: {dpoGov?.dpo_antai_reg_ref ?? 'No registrada'}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Sectoral Retention Violations Summary */}
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Archive className="h-4 w-4 text-amber-400" />
              Retención Sectorial ({data?.tenant.regulatory_profile})
            </CardTitle>
            <CardDescription>
              7 años máximo general vs. 20 años post-mortem expediente clínico (Ley 68)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <div
                  className={cn(
                    'text-xl font-extrabold',
                    (retention?.violations_count ?? 0) > 0 ? 'text-red-400' : 'text-emerald-400'
                  )}
                >
                  {retention?.violations_count ?? 0}
                </div>
                <div className="text-[10px] text-slate-400">Violaciones</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <div className="text-xl font-extrabold text-white">
                  {retention?.total_findings_with_age ?? 0}
                </div>
                <div className="text-[10px] text-slate-400">Con Antigüedad</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-2">
                <div className="text-xl font-extrabold text-amber-300">
                  {retention?.max_age_days ?? 0}d
                </div>
                <div className="text-[10px] text-slate-400">Máxima Edad</div>
              </div>
            </div>
            <p className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5 text-[11px] text-slate-300">
              {retention?.rule_description}
            </p>
          </CardContent>
        </Card>

        {/* 1-Click Immutable Ficha Técnica & Executive PDF */}
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileCheck2 className="h-4 w-4 text-emerald-400" />
              Ficha Técnica Inmutable (R2) &amp; PDF
            </CardTitle>
            <CardDescription>
              Evidencia criptográfica SHA-256 para inspecciones ANTAI / SBP
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void handleGenerateFicha()}
                disabled={generatingFicha}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-bold text-white transition hover:bg-emerald-500 disabled:opacity-50"
              >
                <ShieldCheck className="h-4 w-4" />
                {generatingFicha ? 'Sellando en R2...' : 'Generar Ficha Técnica Inmutable'}
              </button>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void handlePdfDownload('pdf')}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/15 px-3 py-1.5 text-xs font-semibold text-red-200 hover:bg-red-500/25"
              >
                <FileDown className="h-3.5 w-3.5" />
                Informe Ejecutivo PDF
              </button>
              <button
                type="button"
                onClick={() => void handlePdfDownload('html')}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Vista HTML
              </button>
            </div>

            {pdfFeedback && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-950/40 p-2 text-[11px] text-amber-200">
                {pdfFeedback}
              </div>
            )}

            {latestFichaMeta && (
              <div
                data-testid="ficha-tecnica-badge"
                className="rounded-lg border border-emerald-500/40 bg-emerald-950/25 p-2.5 space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">
                    Versión v{latestFichaMeta.snapshot.version_num}
                  </span>
                  <Badge variant={latestFichaMeta.integrityVerified ? 'success' : 'warning'}>
                    {latestFichaMeta.integrityVerified
                      ? 'SHA-256 VERIFICADO R2'
                      : 'PENDIENTE VERIFICACIÓN'}
                  </Badge>
                </div>
                <div className="truncate font-mono text-[10px] text-emerald-300">
                  SHA-256: {latestFichaMeta.snapshot.sha256_hash}
                </div>
                <div className="truncate font-mono text-[10px] text-slate-400">
                  R2: {latestFichaMeta.snapshot.r2_object_key}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* 72-HOUR BREACH NOTIFICATION CLOCK (DE 285 ART. 37 Y ART. 48.3) */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-rose-400" />
                Reloj de Notificación de Brechas 72 Horas (DE 285 Art. 37 y Art. 48.3)
              </CardTitle>
              <CardDescription>
                Control de plazo fatal de 72h ante ANTAI y titulares con verificación de los 5 elementos obligatorios
              </CardDescription>
            </div>
            <button
              type="button"
              onClick={() => setShowBreachForm((prev) => !prev)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-500/25"
            >
              <Plus className="h-3.5 w-3.5" />
              Registrar Incidente 72h
            </button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showBreachForm && (
            <form
              onSubmit={handleCreateBreach}
              className="rounded-xl border border-slate-700 bg-slate-950/90 p-4 space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <label className="mb-1 block font-medium text-slate-300">Título del Incidente</label>
                  <input
                    type="text"
                    required
                    value={breachTitle}
                    onChange={(e) => setBreachTitle(e.target.value)}
                    placeholder="Ej. Exposición temporal de expediente sin cifrado"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white focus:border-sky-500 focus:outline-none"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">Severidad</label>
                    <select
                      value={breachSeverity}
                      onChange={(e) => setBreachSeverity(e.target.value as AlertSeverity)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-white"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block font-medium text-slate-300">Reg. Afectados</label>
                    <input
                      type="number"
                      min={0}
                      value={breachAffectedCount}
                      onChange={(e) => setBreachAffectedCount(Number(e.target.value))}
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-white"
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    1. Qué ocurrió (what_happened)
                  </label>
                  <textarea
                    required
                    rows={2}
                    value={breachWhatHappened}
                    onChange={(e) => setBreachWhatHappened(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    2. Tipos de datos comprometidos (coma)
                  </label>
                  <input
                    type="text"
                    required
                    value={breachDataTypes}
                    onChange={(e) => setBreachDataTypes(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                  <label className="mt-2 mb-1 block font-medium text-slate-300">
                    5. Punto de contacto (DPO)
                  </label>
                  <input
                    type="text"
                    required
                    value={breachContactPoint}
                    onChange={(e) => setBreachContactPoint(e.target.value)}
                    placeholder="DPO <dpo@empresa.pa>"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    3. Medidas adoptadas (measures_adopted)
                  </label>
                  <textarea
                    required
                    rows={2}
                    value={breachMeasures}
                    onChange={(e) => setBreachMeasures(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    4. Acciones para titulares (titular_actions)
                  </label>
                  <textarea
                    required
                    rows={2}
                    value={breachTitularActions}
                    onChange={(e) => setBreachTitularActions(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowBreachForm(false)}
                  className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300 hover:bg-slate-800"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={submittingBreach}
                  className="rounded-lg bg-rose-600 px-4 py-1.5 font-semibold text-white hover:bg-rose-500 disabled:opacity-50"
                >
                  {submittingBreach ? 'Registrando...' : 'Iniciar Reloj 72h'}
                </button>
              </div>
            </form>
          )}

          {(data?.breaches ?? []).length === 0 ? (
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-6 text-center text-xs text-slate-400">
              Sin incidentes de seguridad registrados en el reloj de 72 horas.
            </div>
          ) : (
            <div className="space-y-4">
              {(data?.breaches ?? []).map((breach) => {
                const countdown = formatBreachCountdown(
                  breach.deadline_72h_at,
                  breach.status,
                  breach.hours_remaining_72h,
                  nowMs
                );
                const missingSet = new Set(breach.missing_art37_elements);

                return (
                  <div
                    key={breach.id}
                    data-testid={`breach-card-${breach.id}`}
                    className={cn(
                      'rounded-xl border p-4 text-xs space-y-3',
                      countdown.isOverdue
                        ? 'border-red-500/60 bg-red-950/25'
                        : countdown.isNotified
                          ? 'border-emerald-500/40 bg-emerald-950/15'
                          : 'border-amber-500/45 bg-amber-950/15'
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={severityBadgeVariant(breach.severity)}>
                            {breach.severity}
                          </Badge>
                          <Badge variant="outline">{breach.status}</Badge>
                          <span
                            data-testid={`breach-countdown-${breach.id}`}
                            className={cn(
                              'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono font-bold',
                              countdown.isOverdue
                                ? 'border-red-500/60 bg-red-500/20 text-red-200'
                                : countdown.isNotified
                                  ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200'
                                  : 'border-amber-500/50 bg-amber-500/20 text-amber-200'
                            )}
                          >
                            <Clock className="h-3 w-3" />
                            {countdown.text}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-white">{breach.title}</h4>
                        <div className="text-[11px] text-slate-400">
                          Detectado: {formatDateTime(breach.detected_at)} · Límite 72h:{' '}
                          {formatDateTime(breach.deadline_72h_at)} · Afectados estimados:{' '}
                          <strong className="text-slate-200">
                            {breach.affected_records_estimate}
                          </strong>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => void handleViewAntaiDraft(breach)}
                          disabled={loadingDraftId === breach.id}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-1.5 font-semibold text-sky-200 hover:bg-sky-500/25 disabled:opacity-50"
                        >
                          <FileJson className="h-3.5 w-3.5" />
                          {loadingDraftId === breach.id ? 'Cargando...' : 'Ver / Descargar Borrador ANTAI'}
                        </button>
                        {breach.status !== 'NOTIFIED_ANTAI' && breach.status !== 'CLOSED' && (
                          <button
                            type="button"
                            onClick={() => void handleMarkAntaiNotified(breach)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 font-semibold text-emerald-200 hover:bg-emerald-500/25"
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            Marcar Notificado ANTAI
                          </button>
                        )}
                      </div>
                    </div>

                    {/* 5 Mandatory Elements Checklist (DE 285 Art. 37) */}
                    <div className="rounded-lg border border-slate-800/90 bg-slate-950/75 p-3">
                      <div className="mb-2 flex items-center justify-between">
                        <span className="font-semibold text-slate-200">
                          Checklist 5 Elementos Obligatorios (DE 285 Art. 37)
                        </span>
                        <Badge variant={breach.art37_complete ? 'success' : 'destructive'}>
                          {breach.art37_complete ? '5/5 COMPLETO PARA ANTAI' : 'ELEMENTOS FALTANTES'}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
                        {ART37_ELEMENTS.map((el) => {
                          const isMissing = missingSet.has(el.key);
                          return (
                            <div
                              key={el.key}
                              className={cn(
                                'flex items-start gap-1.5 rounded-md border px-2 py-1.5 text-[11px]',
                                isMissing
                                  ? 'border-red-500/40 bg-red-950/30 text-red-200'
                                  : 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200'
                              )}
                            >
                              {isMissing ? (
                                <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                              ) : (
                                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                              )}
                              <span>{el.label}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ARCO-P (DSAR) ORCHESTRATOR */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Scale className="h-4 w-4 text-sky-400" />
                Orquestador ARCO-P (DSAR — Calendario Hábil de Panamá)
              </CardTitle>
              <CardDescription>
                SLA legal: 10 días hábiles (Acceso / Portabilidad) · 5 días hábiles (Rectificación / Cancelación / Oposición)
              </CardDescription>
            </div>
            <button
              type="button"
              onClick={() => setShowDsarForm((prev) => !prev)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-500/25"
            >
              <Plus className="h-3.5 w-3.5" />
              Nueva Solicitud ARCO-P
            </button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showDsarForm && (
            <form
              onSubmit={handleCreateDsar}
              className="rounded-xl border border-slate-700 bg-slate-950/90 p-4 space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Nombre del Titular</label>
                  <input
                    type="text"
                    required
                    value={dsarName}
                    onChange={(e) => setDsarName(e.target.value)}
                    placeholder="María Pérez"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    Cédula / ID Enmascarado
                  </label>
                  <input
                    type="text"
                    required
                    value={dsarIdMasked}
                    onChange={(e) => setDsarIdMasked(e.target.value)}
                    placeholder="8-***-5521"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Derecho ARCO-P</label>
                  <select
                    value={dsarRight}
                    onChange={(e) => setDsarRight(e.target.value as ArcoRightType)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  >
                    <option value="ACCESO">ACCESO (10 días hábiles)</option>
                    <option value="PORTABILIDAD">PORTABILIDAD (10 días hábiles)</option>
                    <option value="RECTIFICACION">RECTIFICACION (5 días hábiles)</option>
                    <option value="CANCELACION">CANCELACION (5 días hábiles)</option>
                    <option value="OPOSICION">OPOSICION (5 días hábiles)</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">
                    Sistemas Objetivo (coma)
                  </label>
                  <input
                    type="text"
                    value={dsarSystems}
                    onChange={(e) => setDsarSystems(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
              </div>
              <div>
                <label className="mb-1 block font-medium text-slate-300">Notas</label>
                <input
                  type="text"
                  value={dsarNotes}
                  onChange={(e) => setDsarNotes(e.target.value)}
                  placeholder="Detalle de solicitud recibida por canal formal..."
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowDsarForm(false)}
                  className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={submittingDsar}
                  className="rounded-lg bg-sky-600 px-4 py-1.5 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
                >
                  {submittingDsar ? 'Creando...' : 'Registrar ARCO-P'}
                </button>
              </div>
            </form>
          )}

          <div className="overflow-x-auto">
            <table data-testid="arco-dsar-table" className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5 pr-3">Titular</th>
                  <th className="pb-2.5 px-3">Derecho ARCO-P</th>
                  <th className="pb-2.5 px-3">SLA Legal</th>
                  <th className="pb-2.5 px-3">Días Hábiles PA</th>
                  <th className="pb-2.5 px-3">Sistemas</th>
                  <th className="pb-2.5 px-3">Estado</th>
                  <th className="pb-2.5 pl-3 text-right">Evidencia</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.dsars ?? []).map((dsar) => (
                  <tr key={dsar.id} className="hover:bg-slate-900/50">
                    <td className="py-3 pr-3">
                      <div className="font-semibold text-white">{dsar.requester_name}</div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {dsar.requester_id_masked}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <Badge variant="default">{dsar.right_type}</Badge>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {dsar.sla_business_days} días hábiles
                    </td>
                    <td className="py-3 px-3">
                      <Badge
                        variant={
                          dsar.is_overdue
                            ? 'destructive'
                            : dsar.business_days_remaining <= 2
                              ? 'warning'
                              : 'success'
                        }
                      >
                        {dsar.is_overdue
                          ? `VENCIDO (${dsar.business_days_remaining}d)`
                          : `${dsar.business_days_remaining} días hábiles`}
                      </Badge>
                    </td>
                    <td className="py-3 px-3 text-[11px] text-slate-300">
                      {dsar.target_systems.join(', ') || '—'}
                    </td>
                    <td className="py-3 px-3">
                      <Badge variant={dsar.status === 'COMPLETED' ? 'success' : 'outline'}>
                        {dsar.status}
                      </Badge>
                    </td>
                    <td className="py-3 pl-3 text-right">
                      <button
                        type="button"
                        onClick={() => void handleExportDsar(dsar.id)}
                        disabled={exportingDsarId === dsar.id}
                        className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-sky-300 hover:bg-slate-800 disabled:opacity-50"
                      >
                        <Download className="h-3 w-3" />
                        {exportingDsarId === dsar.id ? 'Exportando...' : 'Exportar JSON'}
                      </button>
                    </td>
                  </tr>
                ))}
                {(data?.dsars ?? []).length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-6 text-center text-slate-500">
                      Sin solicitudes ARCO-P registradas.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* THIRD-PARTY & CROSS-BORDER TRANSFER REGISTRY */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-indigo-400" />
                Registro de Transferencias Internacionales &amp; Terceros (Arts. 25, 32-33, 41.4 Ley 81)
              </CardTitle>
              <CardDescription>
                Flujos transfronterizos sin contrato DPA activo resaltados como riesgo crítico
              </CardDescription>
            </div>
            <button
              type="button"
              onClick={() => setShowTransferForm((prev) => !prev)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-3 py-1.5 text-xs font-semibold text-indigo-200 hover:bg-indigo-500/25"
            >
              <Plus className="h-3.5 w-3.5" />
              Registrar Transferencia
            </button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showTransferForm && (
            <form
              onSubmit={handleCreateTransfer}
              className="rounded-xl border border-slate-700 bg-slate-950/90 p-4 space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
                <div className="sm:col-span-2">
                  <label className="mb-1 block font-medium text-slate-300">Destinatario / SaaS</label>
                  <input
                    type="text"
                    required
                    value={trRecipient}
                    onChange={(e) => setTrRecipient(e.target.value)}
                    placeholder="Ej. OpenAI API / AWS East"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">País Destino (ISO)</label>
                  <input
                    type="text"
                    required
                    value={trCountry}
                    onChange={(e) => setTrCountry(e.target.value)}
                    placeholder="US"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white uppercase"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Retención Máx (días)</label>
                  <input
                    type="number"
                    min={1}
                    required
                    value={trRetentionDays}
                    onChange={(e) => setTrRetentionDays(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Finalidad</label>
                  <input
                    type="text"
                    required
                    value={trPurpose}
                    onChange={(e) => setTrPurpose(e.target.value)}
                    placeholder="Procesamiento documental"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Base Legal</label>
                  <input
                    type="text"
                    required
                    value={trLegalBasis}
                    onChange={(e) => setTrLegalBasis(e.target.value)}
                    placeholder="Cláusulas Contractuales Tipo + DPA"
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1 block font-medium text-slate-300">Categorías (coma)</label>
                  <input
                    type="text"
                    value={trCategories}
                    onChange={(e) => setTrCategories(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-white"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-6">
                <label className="inline-flex items-center gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={trCrossBorder}
                    onChange={(e) => setTrCrossBorder(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-900"
                  />
                  Transferencia Internacional
                </label>
                <label className="inline-flex items-center gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={trDpaActive}
                    onChange={(e) => setTrDpaActive(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-900"
                  />
                  Contrato DPA Activo
                </label>
                <label className="inline-flex items-center gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={trDestructorVerified}
                    onChange={(e) => setTrDestructorVerified(e.target.checked)}
                    className="rounded border-slate-600 bg-slate-900"
                  />
                  Destrucción / Retorno Verificado
                </label>
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowTransferForm(false)}
                  className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={submittingTransfer}
                  className="rounded-lg bg-indigo-600 px-4 py-1.5 font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  {submittingTransfer ? 'Guardando...' : 'Guardar Transferencia'}
                </button>
              </div>
            </form>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5 pr-3">Destinatario</th>
                  <th className="pb-2.5 px-3">País / Alcance</th>
                  <th className="pb-2.5 px-3">Finalidad y Base Legal</th>
                  <th className="pb-2.5 px-3">Retención Máx.</th>
                  <th className="pb-2.5 pl-3 text-right">Estado DPA (Art. 33)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.transfers ?? []).map((tr) => {
                  const isUncontractedRisk = tr.is_cross_border && !tr.dpa_contract_active;
                  return (
                    <tr
                      key={tr.id}
                      className={cn(
                        isUncontractedRisk
                          ? 'bg-red-950/40 text-red-100'
                          : 'hover:bg-slate-900/50'
                      )}
                    >
                      <td className="py-3 pr-3">
                        <div className="font-semibold text-white">{tr.recipient_name}</div>
                        <div className="text-[11px] text-slate-400">
                          {tr.data_categories.join(', ')}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-1.5">
                          <Badge variant="outline">{tr.destination_country}</Badge>
                          {tr.is_cross_border && <Badge variant="warning">Transfronteriza</Badge>}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-200">{tr.purpose}</div>
                        <div className="text-[11px] text-slate-400">{tr.legal_basis}</div>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-300">
                        {tr.max_retention_days} días
                      </td>
                      <td className="py-3 pl-3 text-right">
                        {isUncontractedRisk ? (
                          <Badge variant="destructive" className="gap-1">
                            <AlertTriangle className="h-3 w-3" />
                            SIN DPA ACTIVO
                          </Badge>
                        ) : (
                          <Badge variant="success">DPA Activo</Badge>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {(data?.transfers ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500">
                      Sin transferencias registradas.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* ANTAI DRAFT MODAL */}
      {antaiDraft && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Borrador de Notificación ANTAI 72h"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 p-4 backdrop-blur-sm"
        >
          <div className="flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <h3 className="text-sm font-bold text-white">
                  Borrador Oficial ANTAI — Notificación de Brecha 72h
                </h3>
                <p className="text-[11px] text-slate-400">{antaiDraft.legal_basis}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    downloadJsonFile(`ANTAI_Draft_${antaiDraft.incident_id}.json`, antaiDraft)
                  }
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500"
                >
                  <Download className="h-3.5 w-3.5" />
                  Descargar JSON
                </button>
                <button
                  type="button"
                  onClick={() => setAntaiDraft(null)}
                  aria-label="Cerrar borrador ANTAI"
                  className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            <div className="overflow-auto p-5">
              <pre className="rounded-xl border border-slate-800 bg-slate-950 p-4 text-[11px] text-sky-200 overflow-x-auto">
                {JSON.stringify(antaiDraft, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
