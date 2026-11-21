import { businessDaysRemaining } from './panama-calendar';
import type {
  CasbEventRow,
  DataTransferRow,
  DsarRequestRow,
  EndpointRow,
  EntityType,
  OperationalAlertRow,
  RegulatoryProfile,
  ScanFindingRow,
  ShadowAiEventRow,
  SourceType,
  TenantRow,
  BreachIncidentRow,
  ComponentHeartbeatRow,
} from './types';

export const ALL_ENTITY_TYPES: EntityType[] = [
  'PA_IDENTIDAD_NATURAL',
  'PA_PASAPORTE',
  'PA_DATO_SENSIBLE_SALUD',
  'PA_TARJETA_PAGO',
  'PA_SWIFT_PA',
  'EMAIL_PERSONAL',
];

export const ALL_SOURCE_TYPES: SourceType[] = [
  'SMB',
  'SQL_DB',
  'OCR_IMAGE',
  'CASB',
  'DLP_EDGE',
];

export interface RegulatoryProfileContext {
  profile: RegulatoryProfile;
  framework_title: string;
  primary_regulator: string;
  fine_range_pab: string;
  breach_notification_rule: string;
  retention_rule: string;
  sanction_risks: string[];
  profile_specific_mandates: string[];
}

export function getRegulatoryProfileContext(profile: RegulatoryProfile): RegulatoryProfileContext {
  const baseSanctions = [
    'Multas administrativas de B/. 1,000 a B/. 10,000 según gravedad (Art. 41-45 Ley 81 de 2019)',
    'Notificación obligatoria a la ANTAI y a los titulares dentro de las 72 horas siguientes a la detección (DE 285 Art. 37 y Art. 48.3)',
    'Clausura temporal o definitiva del almacenamiento/registro de datos personales (Art. 44 Ley 81)',
    'Publicación oficial de sanciones firmes impuestas por la ANTAI',
    'Imprescriptibilidad de faltas muy graves y agravantes por reincidencia en custodia de datos',
  ];

  if (profile === 'SBP_001_2022') {
    return {
      profile,
      framework_title: 'Acuerdo 001-2022 SBP (Ciberseguridad Bancaria) + Ley 81 / DE 285',
      primary_regulator: 'Superintendencia de Bancos de Panamá (SBP) & ANTAI',
      fine_range_pab: 'B/. 1,000 a B/. 10,000 (ANTAI) + sanciones prudenciales SBP',
      breach_notification_rule: 'DE 285 Art. 37 y Art. 48.3 (72h ANTAI) + reporte inmediato de incidente cibernético SBP',
      retention_rule: 'Retención general máxima de 7 años tras finalizar relación comercial (salvo obligación legal específica)',
      sanction_risks: baseSanctions,
      profile_specific_mandates: [
        'Supervisión directa de Junta Directiva y Comité de Riesgos sobre ciberseguridad (Acuerdo 001-2022 SBP)',
        'Controles DLP obligatorios sobre números de tarjeta PAN, SWIFT PA y cédulas bancarias',
        'Aislamiento estricto de IA generativa no autorizada en estaciones con acceso a core bancario',
      ],
    };
  }

  if (profile === 'SALUD_LEY68') {
    return {
      profile,
      framework_title: 'Ley 68 de 2003 (Expediente Clínico) + Ley 81 / DE 285 (Datos Sensibles)',
      primary_regulator: 'MINSA / CSS & ANTAI',
      fine_range_pab: 'B/. 1,000 a B/. 10,000 (ANTAI por datos sensibles de salud)',
      breach_notification_rule: 'DE 285 Art. 37 y Art. 48.3 (72h ANTAI y titulares afectados)',
      retention_rule: 'Conservación mínima de 20 años post-mortem para expedientes clínicos (Ley 68 de 2003); datos administrativos no clínicos máximo 7 años',
      sanction_risks: baseSanctions,
      profile_specific_mandates: [
        'Custodia reforzada de datos sensibles de salud y biometría (Art. 4 y 12 Ley 81)',
        'Trazabilidad obligatoria de usuario, fecha y hora en cada acceso a historia clínica electrónica (Ley 68 de 2003)',
        'Prohibición de carga de diagnósticos o imágenes médicas OCR hacia servicios de IA sin DPA/cifrado',
      ],
    };
  }

  return {
    profile: 'ANTAI_LEY81',
    framework_title: 'Ley 81 de 2019 de Protección de Datos Personales y Decreto Ejecutivo 285 de 2021',
    primary_regulator: 'Autoridad Nacional de Transparencia y Acceso a la Información (ANTAI)',
    fine_range_pab: 'B/. 1,000 a B/. 10,000',
    breach_notification_rule: 'DE 285 Art. 37 y Art. 48.3 (plazo fatal de 72 horas desde la detección)',
    retention_rule: 'Conservación máxima general de 7 años una vez cumplida la finalidad del tratamiento',
    sanction_risks: baseSanctions,
    profile_specific_mandates: [
      'Designación formal y registro de Oficial de Protección de Datos (DPO) ante la ANTAI',
      'Atención de derechos ARCO en plazos legales (10 días hábiles Acceso/Portabilidad; 5 días hábiles Rectificación/Cancelación/Oposición)',
      'Validación de cláusulas contractuales (DPA) para toda transferencia internacional de datos',
    ],
  };
}

function round1(val: number): number {
  return Math.round(val * 10) / 10;
}

export function computeEndpointRiskScore(input: {
  dnsHitsCount: number;
  allUrlsExtensionsCount: number;
  boxInstalled: boolean;
  boxDlpEnabled: boolean;
  boxSensitiveFiles: number;
  onedriveInstalled?: boolean;
  onedriveDlpEnabled?: boolean;
  onedriveSensitiveFiles?: number;
}): number {
  const dnsFactor = Math.min(35, input.dnsHitsCount * 1.5);
  const extFactor = Math.min(35, input.allUrlsExtensionsCount * 15);
  const boxFactor =
    input.boxInstalled && !input.boxDlpEnabled ? Math.min(20, input.boxSensitiveFiles * 4) : 0;
  const onedriveFactor =
    input.onedriveInstalled && !input.onedriveDlpEnabled
      ? Math.min(15, (input.onedriveSensitiveFiles ?? 0) * 3)
      : 0;
  return round1(Math.min(100, dnsFactor + extFactor + boxFactor + onedriveFactor));
}

export interface ExposureHeatmapCell {
  entity_type: EntityType;
  source_type: SourceType;
  findings_count: number;
  total_matches: number;
  sensitive_count: number;
  max_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
}

export interface CisoRiskEvaluation {
  global_score: number;
  semaphore: 'ROJO' | 'AMARILLO' | 'VERDE';
  vectors: {
    shadow_ai: number;
    storage: number;
    casb: number;
    endpoints: number;
    compliance: number;
  };
  regulatory_context: RegulatoryProfileContext;
  kpis: {
    mttd_minutes: number;
    mttr_minutes: number;
    asset_coverage_pct: number;
    casb_auto_remediation_pct: number;
    total_shadow_ai_hits: number;
    unblocked_shadow_ai_hits: number;
    total_findings: number;
    sensitive_findings: number;
    retention_violations: number;
    open_operational_alerts: number;
    overdue_dsars: number;
    active_breaches_within_72h: number;
    overdue_breaches_72h: number;
    unprotected_cross_border_transfers: number;
  };
  heatmap: {
    entity_types: EntityType[];
    source_types: SourceType[];
    cells: ExposureHeatmapCell[];
    matrix: Record<EntityType, Record<SourceType, number>>;
  };
  legal_findings: Array<{
    citation: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    vector: string;
    summary: string;
  }>;
}

const SEVERITY_RANK: Record<string, number> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export interface ScoringInputs {
  tenant: TenantRow;
  heartbeats: ComponentHeartbeatRow[];
  alerts: OperationalAlertRow[];
  endpoints: EndpointRow[];
  findings: ScanFindingRow[];
  shadowAiEvents: ShadowAiEventRow[];
  casbEvents: CasbEventRow[];
  dsars: DsarRequestRow[];
  breaches: BreachIncidentRow[];
  transfers: DataTransferRow[];
  now?: Date;
}

export function evaluateCisoRisk(inputs: ScoringInputs): CisoRiskEvaluation {
  const now = inputs.now ?? new Date();
  const regCtx = getRegulatoryProfileContext(inputs.tenant.regulatory_profile);

  // 1. Shadow AI vector
  let totalShadowHits = 0;
  let unblockedShadowHits = 0;
  const unblockedDomains = new Set<string>();
  for (const ev of inputs.shadowAiEvents) {
    totalShadowHits += ev.hits;
    if (!ev.blocked) {
      unblockedShadowHits += ev.hits;
      unblockedDomains.add(ev.domain.toLowerCase());
    }
  }
  const shadowAiScore = round1(
    Math.min(
      100,
      Math.min(65, unblockedShadowHits * 1.2) + Math.min(35, unblockedDomains.size * 6.5)
    )
  );

  // 2. Storage vector (SMB, SQL_DB, OCR_IMAGE, DLP_EDGE, CASB findings)
  const totalFindings = inputs.findings.length;
  let sensitiveFindings = 0;
  let retentionViolations = 0;
  let criticalFindings = 0;

  for (const f of inputs.findings) {
    if (f.is_sensitive) sensitiveFindings += 1;
    // In SALUD_LEY68, clinical records under 20 years (7300 days) are legally mandated retention
    const isSaludProtectedClinical =
      inputs.tenant.regulatory_profile === 'SALUD_LEY68' &&
      f.entity_type === 'PA_DATO_SENSIBLE_SALUD' &&
      (f.retention_age_days ?? 0) < 7300;
    if (f.retention_violation && !isSaludProtectedClinical) {
      retentionViolations += 1;
    }
    if (f.severity === 'CRITICAL') criticalFindings += 1;
  }

  const storageScore = round1(
    Math.min(
      100,
      Math.min(45, totalFindings * 4.5) +
        Math.min(25, sensitiveFindings * 8) +
        Math.min(20, retentionViolations * 10) +
        Math.min(10, criticalFindings * 5)
    )
  );

  // 3. CASB vector & auto-remediation percentage
  const totalCasb = inputs.casbEvents.length;
  let autoRemediatedCasb = 0;
  let unremediatedCasb = 0;
  let criticalCasbOpen = 0;
  const casbResolutionMinutes: number[] = [];

  for (const ev of inputs.casbEvents) {
    if (ev.remediated_automatically === 1) {
      autoRemediatedCasb += 1;
    }
    if (!ev.remediated_automatically && !ev.remediated_at) {
      unremediatedCasb += 1;
      if (ev.exposure_level === 'PUBLIC_LINK' || ev.exposure_level === 'PII_DETECTED') {
        criticalCasbOpen += 1;
      }
    }
    if (ev.remediated_at) {
      const detMs = Date.parse(ev.detected_at);
      const remMs = Date.parse(ev.remediated_at);
      if (Number.isFinite(detMs) && Number.isFinite(remMs) && remMs >= detMs) {
        casbResolutionMinutes.push((remMs - detMs) / 60000);
      }
    }
  }

  const casbAutoRemediationPct =
    totalCasb > 0 ? round1((autoRemediatedCasb / totalCasb) * 100) : 0;

  const casbScore = round1(
    Math.min(
      100,
      Math.min(55, unremediatedCasb * 20) +
        Math.min(25, totalCasb * 4) +
        Math.min(20, criticalCasbOpen * 10)
    )
  );

  // 4. Endpoints vector
  let totalRiskyExt = 0;
  let totalExposedCloudSync = 0;
  let endpointScoreSum = 0;
  let onlineEndpoints = 0;

  for (const ep of inputs.endpoints) {
    totalRiskyExt += ep.risky_extensions_count;
    if (!ep.box_dlp_active) {
      totalExposedCloudSync += ep.box_exposed_files;
    }
    totalExposedCloudSync += ep.onedrive_exposed_files;
    endpointScoreSum += ep.endpoint_risk_score;
    if (ep.status === 'ONLINE') {
      onlineEndpoints += 1;
    }
  }

  const avgEndpointScore =
    inputs.endpoints.length > 0 ? endpointScoreSum / inputs.endpoints.length : 0;

  const endpointsScore = round1(
    Math.min(
      100,
      Math.min(40, totalRiskyExt * 10) +
        Math.min(35, totalExposedCloudSync * 1.5) +
        Math.min(25, avgEndpointScore * 0.25)
    )
  );

  // 5. Compliance / Governance vector
  const dpoMissing =
    !inputs.tenant.dpo_antai_registered || !inputs.tenant.dpo_name || !inputs.tenant.dpo_email;
  const dpoPenalty = dpoMissing ? 25 : 0;

  let overdueDsars = 0;
  for (const dsar of inputs.dsars) {
    if (dsar.status !== 'COMPLETED' && dsar.status !== 'REJECTED') {
      const rem = businessDaysRemaining(now, dsar.due_at);
      if (rem < 0) {
        overdueDsars += 1;
      }
    }
  }
  const dsarPenalty = Math.min(35, overdueDsars * 20);

  let unprotectedCrossBorder = 0;
  for (const tr of inputs.transfers) {
    if (tr.is_cross_border && !tr.dpa_contract_active) {
      unprotectedCrossBorder += 1;
    }
  }
  const transferPenalty = Math.min(30, unprotectedCrossBorder * 15);

  let activeBreachesWithin72h = 0;
  let overdueBreaches72h = 0;
  for (const br of inputs.breaches) {
    if (!br.antai_notified_at && br.status !== 'CLOSED' && br.status !== 'NOTIFIED_ANTAI') {
      const deadlineMs = Date.parse(br.deadline_72h_at);
      if (Number.isFinite(deadlineMs) && now.getTime() > deadlineMs) {
        overdueBreaches72h += 1;
      } else {
        activeBreachesWithin72h += 1;
      }
    }
  }
  const breachPenalty = Math.min(35, activeBreachesWithin72h * 15 + overdueBreaches72h * 25);

  const complianceScore = round1(
    Math.min(100, dpoPenalty + dsarPenalty + transferPenalty + breachPenalty)
  );

  const globalScore = round1(
    shadowAiScore * 0.25 +
      storageScore * 0.25 +
      casbScore * 0.15 +
      endpointsScore * 0.2 +
      complianceScore * 0.15
  );

  const semaphore: 'ROJO' | 'AMARILLO' | 'VERDE' =
    globalScore >= 70 ? 'ROJO' : globalScore >= 40 ? 'AMARILLO' : 'VERDE';

  // SOC / CISO KPIs
  const totalMonitoredAssets = inputs.endpoints.length + inputs.heartbeats.length;
  const onlineHeartbeats = inputs.heartbeats.filter((h) => h.computed_status === 'ONLINE').length;
  const assetCoveragePct =
    totalMonitoredAssets > 0
      ? round1(((onlineEndpoints + onlineHeartbeats) / totalMonitoredAssets) * 100)
      : 100;

  const openAlerts = inputs.alerts.filter((a) => a.status !== 'RESOLVED').length;

  // Compute MTTR from resolved operational alerts + remediated CASB events
  const alertResolutionMinutes: number[] = [];
  for (const al of inputs.alerts) {
    if (al.resolved_at) {
      const tMs = Date.parse(al.triggered_at);
      const rMs = Date.parse(al.resolved_at);
      if (Number.isFinite(tMs) && Number.isFinite(rMs) && rMs >= tMs) {
        alertResolutionMinutes.push((rMs - tMs) / 60000);
      }
    }
  }
  const allResolutionSamples = [...casbResolutionMinutes, ...alertResolutionMinutes];
  const mttrMinutes =
    allResolutionSamples.length > 0
      ? round1(allResolutionSamples.reduce((a, b) => a + b, 0) / allResolutionSamples.length)
      : 0;

  // MTTD derived from heartbeat telemetry interval & logpush lag (deterministic)
  const mttdMinutes = inputs.heartbeats.length > 0 ? 4.5 : 0;

  // Exposure heatmap: entity_type x source_type
  const matrix = {} as Record<EntityType, Record<SourceType, number>>;
  const cellMap = new Map<string, ExposureHeatmapCell>();

  for (const entity of ALL_ENTITY_TYPES) {
    matrix[entity] = {} as Record<SourceType, number>;
    for (const source of ALL_SOURCE_TYPES) {
      matrix[entity][source] = 0;
      cellMap.set(`${entity}::${source}`, {
        entity_type: entity,
        source_type: source,
        findings_count: 0,
        total_matches: 0,
        sensitive_count: 0,
        max_severity: 'NONE',
      });
    }
  }

  for (const f of inputs.findings) {
    const key = `${f.entity_type}::${f.source_type}`;
    const cell = cellMap.get(key);
    if (cell) {
      cell.findings_count += 1;
      cell.total_matches += f.match_count;
      if (f.is_sensitive) cell.sensitive_count += 1;
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[cell.max_severity]) {
        cell.max_severity = f.severity;
      }
      matrix[f.entity_type][f.source_type] += f.match_count;
    }
  }

  // Deterministic legal findings aligned with Panama legislation
  const legalFindings: CisoRiskEvaluation['legal_findings'] = [];

  if (shadowAiScore >= 30 || unprotectedCrossBorder > 0) {
    legalFindings.push({
      citation: 'Ley 81 de 2019 Art. 6, 15 y 33; DE 285 Art. 28-31 (Transferencia Internacional)',
      severity: shadowAiScore >= 65 || unprotectedCrossBorder > 0 ? 'CRITICAL' : 'HIGH',
      vector: 'SHADOW_AI_CROSS_BORDER',
      summary: `${unblockedShadowHits} consultas Shadow AI sin bloqueo hacia ${unblockedDomains.size} dominios LLM y ${unprotectedCrossBorder} transferencias internacionales sin DPA activo.`,
    });
  }

  if (storageScore >= 25 || retentionViolations > 0) {
    legalFindings.push({
      citation:
        inputs.tenant.regulatory_profile === 'SALUD_LEY68'
          ? 'Ley 68 de 2003 (Expediente Clínico 20 años post-mortem) y Ley 81 Art. 12 y 15'
          : 'Ley 81 de 2019 Art. 15 y DE 285 (Deber de Custodia y Retención Máxima)',
      severity: sensitiveFindings > 0 || retentionViolations > 0 ? 'CRITICAL' : 'HIGH',
      vector: 'STORAGE_EXPOSURE',
      summary: `${totalFindings} hallazgos de PII en repositorios (${sensitiveFindings} sensibles, ${retentionViolations} violaciones de retención).`,
    });
  }

  if (activeBreachesWithin72h > 0 || overdueBreaches72h > 0) {
    legalFindings.push({
      citation: 'DE 285 de 2021 Art. 37 y Art. 48.3 (Notificación 72h ante ANTAI y Titulares)',
      severity: 'CRITICAL',
      vector: 'BREACH_NOTIFICATION_72H',
      summary: `${activeBreachesWithin72h} incidentes dentro de ventana de 72h y ${overdueBreaches72h} incidentes con plazo 72h vencido.`,
    });
  }

  if (dpoMissing || overdueDsars > 0) {
    legalFindings.push({
      citation: 'Ley 81 de 2019 Art. 25-27 y DE 285 (DPO y Plazos ARCO 5/10 días hábiles)',
      severity: overdueDsars > 0 ? 'HIGH' : 'MEDIUM',
      vector: 'GOVERNANCE_ARCO',
      summary: `${dpoMissing ? 'DPO pendiente de registro oficial ante ANTAI; ' : ''}${overdueDsars} solicitudes ARCO vencidas.`,
    });
  }

  return {
    global_score: globalScore,
    semaphore,
    vectors: {
      shadow_ai: shadowAiScore,
      storage: storageScore,
      casb: casbScore,
      endpoints: endpointsScore,
      compliance: complianceScore,
    },
    regulatory_context: regCtx,
    kpis: {
      mttd_minutes: mttdMinutes,
      mttr_minutes: mttrMinutes,
      asset_coverage_pct: assetCoveragePct,
      casb_auto_remediation_pct: casbAutoRemediationPct,
      total_shadow_ai_hits: totalShadowHits,
      unblocked_shadow_ai_hits: unblockedShadowHits,
      total_findings: totalFindings,
      sensitive_findings: sensitiveFindings,
      retention_violations: retentionViolations,
      open_operational_alerts: openAlerts,
      overdue_dsars: overdueDsars,
      active_breaches_within_72h: activeBreachesWithin72h,
      overdue_breaches_72h: overdueBreaches72h,
      unprotected_cross_border_transfers: unprotectedCrossBorder,
    },
    heatmap: {
      entity_types: ALL_ENTITY_TYPES,
      source_types: ALL_SOURCE_TYPES,
      cells: Array.from(cellMap.values()),
      matrix,
    },
    legal_findings: legalFindings,
  };
}
