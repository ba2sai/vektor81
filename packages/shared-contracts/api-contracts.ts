/**
 * Shared API contracts between Vektor81 Control Plane (Cloudflare Workers),
 * Edge DLP Validation Worker, On-Premise Collector, Windows Endpoint Agent,
 * and the CISO/SOC/DPO Dashboard.
 */

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

export interface HeartbeatPayload {
  tenant_id: string;
  component_layer: ComponentLayer;
  component_id: string;
  display_name: string;
  status: ComponentStatus;
  latency_ms?: number;
  version?: string;
  cpu_pct?: number;
  ram_mb?: number;
  uptime_pct_24h?: number;
  last_error?: string | null;
  metadata?: Record<string, unknown>;
  timestamp?: string;
}

export interface ShadowAiDnsHit {
  domain: string;
  count: number;
  category: string;
  last_timestamp?: string;
}

export interface RiskyExtensionItem {
  extension_id: string;
  name: string;
  browser: 'Chrome' | 'Edge' | string;
  version?: string;
  permissions: string[];
  has_all_urls: boolean;
}

export interface LocalSyncAuditPayload {
  provider: 'BoxDrive' | 'OneDrive' | string;
  installed: boolean;
  sync_path?: string | null;
  total_synced_files: number;
  sensitive_files_count: number;
  dlp_enabled: boolean;
  sample_files_masked: string[];
}

export interface EndpointIngestPayload {
  tenant_id: string;
  hostname: string;
  username: string;
  ip_address?: string | null;
  os_version?: string;
  agent_version?: string;
  shadow_ai_dns_hits: ShadowAiDnsHit[];
  risky_extensions: RiskyExtensionItem[];
  box_audit: LocalSyncAuditPayload;
  onedrive_audit?: LocalSyncAuditPayload | null;
  timestamp?: string;
}

export interface MaskedFindingItem {
  source_type: 'SMB' | 'SQL_DB' | 'OCR_IMAGE' | 'CASB' | 'DLP_EDGE';
  repository_name: string;
  location_path: string;
  entity_type:
    | 'PA_IDENTIDAD_NATURAL'
    | 'PA_PASAPORTE'
    | 'PA_DATO_SENSIBLE_SALUD'
    | 'PA_TARJETA_PAGO'
    | 'PA_SWIFT_PA'
    | 'EMAIL_PERSONAL';
  masked_sample: string;
  value_sha256: string;
  match_count: number;
  is_sensitive: boolean;
  severity: AlertSeverity;
  retention_age_days?: number | null;
  retention_violation?: boolean;
  detected_at?: string;
}

export interface FindingBatchPayload {
  tenant_id: string;
  scan_id: string;
  scanner_layer: 'SMB_CONNECTOR' | 'DB_CONNECTOR' | 'ONPREM_COLLECTOR';
  is_simulated: boolean;
  findings: MaskedFindingItem[];
  total_assets_scanned: number;
  scan_duration_ms: number;
}

export interface ShadowAiEventBatch {
  tenant_id: string;
  source: 'ADGUARD_DNS' | 'ENDPOINT_AGENT' | 'AI_GATEWAY';
  total_queries_inspected: number;
  events: Array<{
    client_ip: string;
    hostname?: string;
    domain: string;
    category: string;
    hits: number;
    blocked?: boolean;
    timestamp?: string;
  }>;
}

export interface CasbWebhookPayload {
  tenant_id: string;
  event_id: string;
  saas_app: 'Microsoft 365' | 'Google Workspace' | 'AWS S3' | 'Box' | string;
  resource_name: string;
  finding_type: string;
  exposure_level: 'PUBLIC_LINK' | 'EXTERNAL_SHARE' | 'OAUTH_RISKY' | 'PII_DETECTED';
  remediated_automatically: boolean;
  remediation_action?: string;
  severity: AlertSeverity;
  detected_at: string;
  remediated_at?: string | null;
}

export interface LogpushBatchPayload {
  tenant_id: string;
  dataset: 'gateway_http' | 'dlp_forensic' | 'casb_findings' | 'audit_logs';
  records_count: number;
  lag_seconds: number;
  encrypted_with_customer_key: boolean;
  r2_object_key?: string;
  summary_counts: Record<string, number>;
}

export type ArcoRightType = 'ACCESO' | 'RECTIFICACION' | 'CANCELACION' | 'OPOSICION' | 'PORTABILIDAD';

export interface DsarCreatePayload {
  tenant_id: string;
  requester_name: string;
  requester_id_masked: string;
  right_type: ArcoRightType;
  target_systems: string[];
  notes?: string;
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
