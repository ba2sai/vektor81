export type ComponentLayer =
  | 'CONTROL_PLANE'
  | 'TUNNEL'
  | 'ONPREM_COLLECTOR'
  | 'ADGUARD_DNS'
  | 'ENDPOINT_AGENT'
  | 'DB_CONNECTOR'
  | 'SMB_CONNECTOR'
  | 'WAZUH_FIM'
  | 'CLOUDFLARE_DLP'
  | 'CLOUDFLARE_CASB'
  | 'LOGPUSH';

export type ComponentStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'STALE';

export type RegulatoryProfile = 'ANTAI_LEY81' | 'SBP_001_2022' | 'SALUD_LEY68';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export type ArcoRightType =
  | 'ACCESO'
  | 'RECTIFICACION'
  | 'CANCELACION'
  | 'OPOSICION'
  | 'PORTABILIDAD';

export type DsarStatus = 'PENDING' | 'OPEN' | 'IN_PROGRESS' | 'COMPLETED' | 'REJECTED';

export type BreachStatus = 'DETECTED' | 'CONTAINING' | 'NOTIFIED_ANTAI' | 'CLOSED';

export type EntityType =
  | 'PA_IDENTIDAD_NATURAL'
  | 'PA_PASAPORTE'
  | 'PA_DATO_SENSIBLE_SALUD'
  | 'PA_TARJETA_PAGO'
  | 'PA_SWIFT_PA'
  | 'EMAIL_PERSONAL';

export type SourceType = 'SMB' | 'SQL_DB' | 'OCR_IMAGE' | 'CASB' | 'DLP_EDGE';

export type DashboardTab = 'health' | 'ciso' | 'dpo' | 'assets';

export interface Tenant {
  id: string;
  name: string;
  industry: string;
  regulatory_profile: RegulatoryProfile;
  dpo_name: string | null;
  dpo_email: string | null;
  dpo_antai_registered: number | boolean;
  dpo_antai_reg_ref: string | null;
  active: number | boolean;
  created_at: string;
}

export interface TenantCreatePayload {
  id: string;
  name: string;
  industry?: string;
  regulatory_profile: RegulatoryProfile;
  dpo_name?: string | null;
  dpo_email?: string | null;
  dpo_antai_registered?: boolean;
  dpo_antai_reg_ref?: string | null;
}

export interface TenantUpdatePayload {
  name?: string;
  industry?: string;
  regulatory_profile?: RegulatoryProfile;
  dpo_name?: string | null;
  dpo_email?: string | null;
  dpo_antai_registered?: boolean;
  dpo_antai_reg_ref?: string | null;
  active?: boolean;
}

export interface ComponentHeartbeat {
  id: string;
  tenant_id: string;
  component_layer: ComponentLayer;
  component_id: string;
  display_name: string;
  reported_status: ComponentStatus;
  computed_status: ComponentStatus;
  latency_ms: number | null;
  version: string | null;
  cpu_pct: number | null;
  ram_mb: number | null;
  uptime_pct_24h: number | null;
  last_error: string | null;
  metadata_json: string;
  last_heartbeat_at: string;
  updated_at: string;
}

export interface OperationalAlert {
  id: string;
  tenant_id: string;
  component_id: string;
  component_layer: ComponentLayer;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  details: string;
  triggered_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface HealthSyncResult {
  evaluated: number;
  statusUpdates: number;
  alertsCreated: number;
  alertsResolved: number;
}

export interface HealthSummary {
  total_components: number;
  online: number;
  degraded: number;
  offline: number;
  stale: number;
  open_alerts: number;
  acknowledged_alerts: number;
  resolved_alerts: number;
  critical_alerts: number;
  avg_latency_ms?: number;
}

export interface HealthOverviewResponse {
  tenant_id: string | null;
  summary: HealthSummary;
  components: ComponentHeartbeat[];
  alerts: OperationalAlert[];
  sync: HealthSyncResult;
}

export interface LayerGroup {
  layer: ComponentLayer;
  count: number;
  online: number;
  worst_status: ComponentStatus;
  components: ComponentHeartbeat[];
}

export interface CasbEvent {
  id: string;
  tenant_id: string;
  event_id: string;
  saas_app: string;
  resource_name: string;
  finding_type: string;
  exposure_level: string;
  remediated_automatically: number;
  remediation_action: string | null;
  severity: AlertSeverity;
  detected_at: string;
  remediated_at: string | null;
}

export interface LogpushBatch {
  id: string;
  tenant_id: string;
  dataset: string;
  records_count: number;
  lag_seconds: number;
  encrypted_with_customer_key: number;
  r2_object_key: string | null;
  summary_json: string;
  ingested_at: string;
}

export interface SocHealthDashboardResponse {
  tenant_id: string | null;
  summary: HealthSummary & { avg_latency_ms: number };
  layers: LayerGroup[];
  components: ComponentHeartbeat[];
  alerts: OperationalAlert[];
  casb_summary: {
    total_events: number;
    auto_remediated_count: number;
    auto_remediation_pct: number;
    recent_events: CasbEvent[];
  };
  logpush_summary: {
    total_batches: number;
    total_records: number;
    avg_lag_seconds: number;
    cmk_encrypted_pct: number;
    recent_batches: LogpushBatch[];
  };
  sync: HealthSyncResult;
}

export interface SimulateOutagePayload {
  tenant_id: string;
  component_id: string;
  target_status?: ComponentStatus;
  backdate_minutes?: number;
  error_message?: string;
}

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
    severity: AlertSeverity;
    vector: string;
    summary: string;
  }>;
}

export interface RiskHistoryPoint {
  id: string;
  tenant_id: string;
  recorded_date: string;
  global_score: number;
  shadow_ai_score: number;
  storage_score: number;
  endpoints_score: number;
  casb_score: number;
  compliance_score: number;
}

export interface CisoDashboardResponse {
  tenant: {
    id: string;
    name: string;
    industry: string;
    regulatory_profile: RegulatoryProfile;
    dpo_antai_registered: boolean;
  };
  risk: CisoRiskEvaluation;
  risk_history: RiskHistoryPoint[];
  top_shadow_ai_domains: Array<{
    domain: string;
    category: string;
    hits: number;
    blocked_hits: number;
  }>;
  top_risky_repositories: Array<{
    repository_name: string;
    source_type: string;
    findings_count: number;
    total_matches: number;
  }>;
}

export interface DsarRequest {
  id: string;
  tenant_id: string;
  requester_name: string;
  requester_id_masked: string;
  right_type: ArcoRightType;
  sla_business_days: number;
  received_at: string;
  due_at: string;
  status: DsarStatus | string;
  target_systems_json: string;
  target_systems: string[];
  notes: string | null;
  completed_at: string | null;
  evidence_json: string;
  evidence: Record<string, unknown>;
  business_days_remaining: number;
  is_overdue: boolean;
}

export interface DsarCreatePayload {
  tenant_id: string;
  requester_name: string;
  requester_id_masked: string;
  right_type: ArcoRightType;
  target_systems: string[];
  notes?: string;
  received_at?: string;
}

export interface DsarUpdatePayload {
  status?: DsarStatus;
  notes?: string;
  target_systems?: string[];
  evidence?: Record<string, unknown>;
  completed_at?: string | null;
}

export interface BreachIncident {
  id: string;
  tenant_id: string;
  title: string;
  severity: AlertSeverity;
  status: BreachStatus | string;
  what_happened: string;
  compromised_data_types_json: string;
  compromised_data_types: string[];
  affected_records_estimate: number;
  measures_adopted: string;
  titular_actions: string;
  contact_point: string;
  detected_at: string;
  deadline_72h_at: string;
  antai_notified_at: string | null;
  hours_remaining_72h: number;
  is_overdue_72h: boolean;
  art37_complete: boolean;
  missing_art37_elements: string[];
}

export interface BreachCreatePayload {
  tenant_id: string;
  title: string;
  severity: AlertSeverity;
  what_happened: string;
  compromised_data_types: string[];
  affected_records_estimate: number;
  measures_adopted: string;
  titular_actions: string;
  contact_point: string;
  detected_at?: string;
}

export interface BreachUpdatePayload {
  status?: BreachStatus;
  severity?: AlertSeverity;
  antai_notified_at?: string | null;
}

export interface AntaiBreachDraftResponse {
  document_type: string;
  legal_basis: string;
  generated_at: string;
  incident_id: string;
  title: string;
  severity: AlertSeverity;
  status: string;
  detected_at: string;
  deadline_72h_at: string;
  countdown: {
    hours_remaining: number;
    minutes_remaining: number;
    is_overdue: boolean;
  };
  tenant: {
    id: string;
    name: string;
    regulatory_profile: RegulatoryProfile;
    dpo_name: string | null;
    dpo_email: string | null;
    dpo_antai_registered: boolean;
    dpo_antai_reg_ref: string | null;
  } | null;
  affected_records_estimate: number;
  five_required_elements: {
    what_happened: string;
    compromised_data_types: string[];
    measures_adopted: string;
    titular_actions: string;
    contact_point: string;
  };
  ready_for_submission: boolean;
  missing_elements: string[];
}

export interface DataTransfer {
  id: string;
  tenant_id: string;
  recipient_name: string;
  destination_country: string;
  is_cross_border: boolean;
  purpose: string;
  data_categories_json: string;
  data_categories: string[];
  legal_basis: string;
  dpa_contract_active: boolean;
  max_retention_days: number;
  destructor_verified: boolean;
  dpa_gap: boolean;
  created_at: string;
}

export interface TransferCreatePayload {
  tenant_id: string;
  recipient_name: string;
  destination_country: string;
  is_cross_border: boolean;
  purpose: string;
  data_categories: string[];
  legal_basis: string;
  dpa_contract_active: boolean;
  max_retention_days: number;
  destructor_verified?: boolean;
}

export interface FichaTecnicaSnapshot {
  id: string;
  tenant_id: string;
  version_num: number;
  regulatory_profile: RegulatoryProfile;
  r2_object_key: string;
  sha256_hash: string;
  generated_by: string;
  generated_at: string;
}

export interface DpoDashboardResponse {
  tenant: {
    id: string;
    name: string;
    industry: string;
    regulatory_profile: RegulatoryProfile;
  };
  regulatory_context: RegulatoryProfileContext;
  dpo_governance: {
    dpo_name: string | null;
    dpo_email: string | null;
    dpo_antai_registered: boolean;
    dpo_antai_reg_ref: string | null;
    compliant: boolean;
  };
  dsars: DsarRequest[];
  breaches: BreachIncident[];
  transfers: DataTransfer[];
  retention_summary: {
    total_findings_with_age: number;
    violations_count: number;
    max_age_days: number;
    rule_description: string;
  };
  ficha_tecnica_snapshots: FichaTecnicaSnapshot[];
}

export interface RiskyExtensionDetail {
  extension_id: string;
  name: string;
  browser: string;
  version?: string;
  permissions?: string[];
  has_all_urls: boolean;
}

export interface EndpointAssetRecord {
  id: string;
  tenant_id: string;
  hostname: string;
  username: string;
  ip_address: string | null;
  os_version: string;
  agent_version: string;
  dns_hits_count: number;
  risky_extensions_count: number;
  box_exposed_files: number;
  box_dlp_active: boolean;
  onedrive_exposed_files: number;
  endpoint_risk_score: number;
  status: ComponentStatus;
  last_seen_at: string;
  details_json: string;
  details: {
    risky_extensions?: RiskyExtensionDetail[];
    box_sample_files?: string[];
    box_audit?: {
      installed?: boolean;
      sync_path?: string | null;
      total_synced_files?: number;
      sensitive_files_count?: number;
      dlp_enabled?: boolean;
      sample_files_masked?: string[];
    };
    onedrive_audit?: {
      installed?: boolean;
      sync_path?: string | null;
      total_synced_files?: number;
      sensitive_files_count?: number;
      dlp_enabled?: boolean;
      sample_files_masked?: string[];
    } | null;
  };
}

export interface ScanFindingRecord {
  id: string;
  tenant_id: string;
  scan_id: string;
  source_type: SourceType;
  repository_name: string;
  location_path: string;
  entity_type: EntityType;
  masked_sample: string;
  value_sha256: string;
  match_count: number;
  is_sensitive: number;
  severity: AlertSeverity;
  retention_age_days: number | null;
  retention_violation: number;
  is_simulated: number;
  detected_at: string;
}

export interface ShadowAiEventRecord {
  id: string;
  tenant_id: string;
  source: string;
  client_ip: string;
  hostname: string | null;
  domain: string;
  category: string;
  hits: number;
  blocked: number;
  recorded_at: string;
}

export interface AssetsDashboardResponse {
  tenant_id: string;
  summary: {
    endpoints_total: number;
    endpoints_with_all_urls: number;
    endpoints_box_unprotected: number;
    findings_total: number;
    sensitive_findings_total: number;
    shadow_ai_events_total: number;
  };
  endpoints: EndpointAssetRecord[];
  findings: ScanFindingRecord[];
  shadow_ai_events: ShadowAiEventRecord[];
}

export interface SeedDemoResponse {
  ok: boolean;
  tenants_seeded: string[];
  components_seeded: number;
  alerts_active: number;
  findings_seeded: number;
  endpoints_seeded: number;
  dsars_seeded: number;
  breaches_seeded: number;
  transfers_seeded: number;
}

export interface SmbScanRequest {
  server_ip: string;
  username?: string;
  password?: string;
  domain?: string;
  port?: number;
  max_depth?: number;
  max_file_mb?: number;
  simulate_if_unreachable: boolean;
  tenant_id?: string;
  regulatory_profile?: RegulatoryProfile;
}

export interface DbScanRequest {
  db_type: 'postgresql' | 'mssql' | 'mysql' | 'sqlite' | 'oracle';
  sqlite_path?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  sample_limit?: number;
  simulate_if_unreachable?: boolean;
  tenant_id?: string;
  regulatory_profile?: RegulatoryProfile;
}

export interface DnsStatsResponse {
  adguard_status?: string;
  adguard_live_connected: boolean;
  latency_ms?: number | null;
  last_error?: string | null;
  adguard_endpoint: string;
  dictionary_domains_loaded: number;
  total_queries_inspected: number;
  shadow_ai_hits_total: number;
  by_client_ip: Array<{
    client: string;
    total_hits: number;
    domains: Array<{ domain: string; count: number }>;
  }>;
  by_category: Array<{ category: string; count: number }>;
  top_domains: Array<{ domain: string; count: number; category: string }>;
}
