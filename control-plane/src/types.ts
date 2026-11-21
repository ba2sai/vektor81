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

export type UserRole = 'MSSP_ADMIN' | 'CISO' | 'DPO' | 'COLLECTOR' | 'AUDITOR';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export type ArcoRightType =
  | 'ACCESO'
  | 'RECTIFICACION'
  | 'CANCELACION'
  | 'OPOSICION'
  | 'PORTABILIDAD';

export type EntityType =
  | 'PA_IDENTIDAD_NATURAL'
  | 'PA_PASAPORTE'
  | 'PA_DATO_SENSIBLE_SALUD'
  | 'PA_TARJETA_PAGO'
  | 'PA_SWIFT_PA'
  | 'EMAIL_PERSONAL';

export type SourceType = 'SMB' | 'SQL_DB' | 'OCR_IMAGE' | 'CASB' | 'DLP_EDGE';

export interface Env {
  DB: D1Database;
  EVIDENCE_BUCKET: R2Bucket;
  ALLOWED_ORIGINS?: string;
  ENABLE_DEMO_TOOLS?: string;
  ENVIRONMENT?: string;
  CONTROL_PLANE_ENV?: string;
  VEKTOR81_DEV_API_KEY?: string;
  VEKTOR81_API_KEY?: string;
}

export interface AuthContext {
  tokenId: string;
  tenantId: string | null;
  role: UserRole;
  label: string;
  isDevKey: boolean;
}

export interface AppVariables {
  auth: AuthContext;
  resolvedTenantId: string | null;
}

export interface TenantRow {
  id: string;
  name: string;
  industry: string;
  regulatory_profile: RegulatoryProfile;
  dpo_name: string | null;
  dpo_email: string | null;
  dpo_antai_registered: number;
  dpo_antai_reg_ref: string | null;
  active: number;
  created_at: string;
}

export interface ApiTokenRow {
  id: string;
  tenant_id: string | null;
  token_sha256: string;
  role: UserRole;
  label: string;
  active: number;
  created_at: string;
}

export interface ComponentHeartbeatRow {
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

export interface OperationalAlertRow {
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

export interface EndpointRow {
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
  box_dlp_active: number;
  onedrive_exposed_files: number;
  endpoint_risk_score: number;
  status: ComponentStatus;
  last_seen_at: string;
  details_json: string;
}

export interface ScanFindingRow {
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

export interface ShadowAiEventRow {
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

export interface CasbEventRow {
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

export interface LogpushBatchRow {
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

export interface DsarRequestRow {
  id: string;
  tenant_id: string;
  requester_name: string;
  requester_id_masked: string;
  right_type: ArcoRightType;
  sla_business_days: number;
  received_at: string;
  due_at: string;
  status: string;
  target_systems_json: string;
  notes: string | null;
  completed_at: string | null;
  evidence_json: string;
}

export interface BreachIncidentRow {
  id: string;
  tenant_id: string;
  title: string;
  severity: AlertSeverity;
  status: string;
  what_happened: string;
  compromised_data_types_json: string;
  affected_records_estimate: number;
  measures_adopted: string;
  titular_actions: string;
  contact_point: string;
  detected_at: string;
  deadline_72h_at: string;
  antai_notified_at: string | null;
}

export interface DataTransferRow {
  id: string;
  tenant_id: string;
  recipient_name: string;
  destination_country: string;
  is_cross_border: number;
  purpose: string;
  data_categories_json: string;
  legal_basis: string;
  dpa_contract_active: number;
  max_retention_days: number;
  destructor_verified: number;
  created_at: string;
}

export interface FichaTecnicaSnapshotRow {
  id: string;
  tenant_id: string;
  version_num: number;
  regulatory_profile: RegulatoryProfile;
  r2_object_key: string;
  sha256_hash: string;
  generated_by: string;
  generated_at: string;
}

export interface RiskHistoryRow {
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
