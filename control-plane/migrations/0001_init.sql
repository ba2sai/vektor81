-- Vektor81 v2 Multi-Tenant Control Plane Initial Schema (D1 / SQLite)

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  industry TEXT NOT NULL DEFAULT 'General',
  regulatory_profile TEXT NOT NULL CHECK (regulatory_profile IN ('ANTAI_LEY81', 'SBP_001_2022', 'SALUD_LEY68')),
  dpo_name TEXT,
  dpo_email TEXT,
  dpo_antai_registered INTEGER NOT NULL DEFAULT 0,
  dpo_antai_reg_ref TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT,
  token_sha256 TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('MSSP_ADMIN', 'CISO', 'DPO', 'COLLECTOR', 'AUDITOR')),
  label TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant_id ON api_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_sha256 ON api_tokens(token_sha256);

CREATE TABLE IF NOT EXISTS component_heartbeats (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  component_layer TEXT NOT NULL,
  component_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  reported_status TEXT NOT NULL CHECK (reported_status IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'STALE')),
  computed_status TEXT NOT NULL CHECK (computed_status IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'STALE')),
  latency_ms REAL,
  version TEXT,
  cpu_pct REAL,
  ram_mb REAL,
  uptime_pct_24h REAL DEFAULT 100.0,
  last_error TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  last_heartbeat_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, component_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_heartbeats_tenant_status ON component_heartbeats(tenant_id, computed_status);
CREATE INDEX IF NOT EXISTS idx_heartbeats_tenant_layer ON component_heartbeats(tenant_id, component_layer);

CREATE TABLE IF NOT EXISTS operational_alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  component_id TEXT NOT NULL,
  component_layer TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')) DEFAULT 'OPEN',
  title TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  triggered_at TEXT NOT NULL,
  acknowledged_at TEXT,
  resolved_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON operational_alerts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_component ON operational_alerts(tenant_id, component_id, status);

CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  username TEXT NOT NULL,
  ip_address TEXT,
  os_version TEXT NOT NULL DEFAULT 'Windows 11 Pro',
  agent_version TEXT NOT NULL DEFAULT '2.0.0',
  dns_hits_count INTEGER NOT NULL DEFAULT 0,
  risky_extensions_count INTEGER NOT NULL DEFAULT 0,
  box_exposed_files INTEGER NOT NULL DEFAULT 0,
  box_dlp_active INTEGER NOT NULL DEFAULT 0,
  onedrive_exposed_files INTEGER NOT NULL DEFAULT 0,
  endpoint_risk_score REAL NOT NULL DEFAULT 0.0,
  status TEXT NOT NULL CHECK (status IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'STALE')) DEFAULT 'ONLINE',
  last_seen_at TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(tenant_id, hostname),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant ON endpoints(tenant_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_tenant_last_seen ON endpoints(tenant_id, last_seen_at);

CREATE TABLE IF NOT EXISTS scan_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  repository_name TEXT NOT NULL,
  location_path TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  masked_sample TEXT NOT NULL,
  value_sha256 TEXT NOT NULL,
  match_count INTEGER NOT NULL DEFAULT 1,
  is_sensitive INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  retention_age_days INTEGER,
  retention_violation INTEGER NOT NULL DEFAULT 0,
  is_simulated INTEGER NOT NULL DEFAULT 0,
  detected_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_detected ON scan_findings(tenant_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_entity ON scan_findings(tenant_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_source ON scan_findings(tenant_id, source_type);

CREATE TABLE IF NOT EXISTS shadow_ai_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  hostname TEXT,
  domain TEXT NOT NULL,
  category TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  blocked INTEGER NOT NULL DEFAULT 0,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_tenant_recorded ON shadow_ai_events(tenant_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_shadow_ai_tenant_domain ON shadow_ai_events(tenant_id, domain);

CREATE TABLE IF NOT EXISTS casb_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  saas_app TEXT NOT NULL,
  resource_name TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  exposure_level TEXT NOT NULL,
  remediated_automatically INTEGER NOT NULL DEFAULT 0,
  remediation_action TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  detected_at TEXT NOT NULL,
  remediated_at TEXT,
  UNIQUE(tenant_id, event_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_casb_tenant_detected ON casb_events(tenant_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_casb_tenant_app ON casb_events(tenant_id, saas_app);

CREATE TABLE IF NOT EXISTS logpush_batches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  dataset TEXT NOT NULL,
  records_count INTEGER NOT NULL DEFAULT 0,
  lag_seconds REAL NOT NULL DEFAULT 0,
  encrypted_with_customer_key INTEGER NOT NULL DEFAULT 0,
  r2_object_key TEXT,
  summary_json TEXT NOT NULL DEFAULT '{}',
  ingested_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_logpush_tenant_ingested ON logpush_batches(tenant_id, ingested_at);

CREATE TABLE IF NOT EXISTS dsar_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  requester_id_masked TEXT NOT NULL,
  right_type TEXT NOT NULL CHECK (right_type IN ('ACCESO', 'RECTIFICACION', 'CANCELACION', 'OPOSICION', 'PORTABILIDAD')),
  sla_business_days INTEGER NOT NULL,
  received_at TEXT NOT NULL,
  due_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  target_systems_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT,
  completed_at TEXT,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dsar_tenant_status ON dsar_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dsar_tenant_due ON dsar_requests(tenant_id, due_at);

CREATE TABLE IF NOT EXISTS breach_incidents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  status TEXT NOT NULL DEFAULT 'DETECTED',
  what_happened TEXT NOT NULL,
  compromised_data_types_json TEXT NOT NULL DEFAULT '[]',
  affected_records_estimate INTEGER NOT NULL DEFAULT 0,
  measures_adopted TEXT NOT NULL,
  titular_actions TEXT NOT NULL,
  contact_point TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  deadline_72h_at TEXT NOT NULL,
  antai_notified_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_breaches_tenant_status ON breach_incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_breaches_tenant_deadline ON breach_incidents(tenant_id, deadline_72h_at);

CREATE TABLE IF NOT EXISTS data_transfers (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  recipient_name TEXT NOT NULL,
  destination_country TEXT NOT NULL,
  is_cross_border INTEGER NOT NULL DEFAULT 1,
  purpose TEXT NOT NULL,
  data_categories_json TEXT NOT NULL DEFAULT '[]',
  legal_basis TEXT NOT NULL,
  dpa_contract_active INTEGER NOT NULL DEFAULT 0,
  max_retention_days INTEGER NOT NULL DEFAULT 365,
  destructor_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_transfers_tenant ON data_transfers(tenant_id, is_cross_border);

CREATE TABLE IF NOT EXISTS ficha_tecnica_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  version_num INTEGER NOT NULL,
  regulatory_profile TEXT NOT NULL,
  r2_object_key TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  generated_by TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ficha_tenant_version ON ficha_tecnica_snapshots(tenant_id, version_num);

CREATE TABLE IF NOT EXISTS risk_history (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  recorded_date TEXT NOT NULL,
  global_score REAL NOT NULL,
  shadow_ai_score REAL NOT NULL,
  storage_score REAL NOT NULL,
  endpoints_score REAL NOT NULL,
  casb_score REAL NOT NULL,
  compliance_score REAL NOT NULL,
  UNIQUE(tenant_id, recorded_date),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_risk_history_tenant_date ON risk_history(tenant_id, recorded_date);
