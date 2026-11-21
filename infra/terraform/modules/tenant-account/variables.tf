# Variables for Vektor81 Siloed Tenant Account Module (Cloudflare Partner/MSSP)
# Gateway Tiered Policies only inherit DNS across parent/child accounts, so HTTP DLP,
# CASB, and Custom Validation Workers are deployed per siloed client account.

variable "account_id" {
  description = "Target Cloudflare tenant account ID (32-char hex) provisioned via Tenant API."
  type        = string

  validation {
    condition     = length(trimspace(var.account_id)) > 0
    error_message = "account_id must be a non-empty Cloudflare account identifier."
  }
}

variable "tenant_id" {
  description = "Short slug identifier for the Panamanian enterprise tenant (e.g. banco-istmo)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$", var.tenant_id))
    error_message = "tenant_id must be lowercase alphanumeric with hyphens (3-50 chars)."
  }
}

variable "tenant_name" {
  description = "Display name of the tenant organization."
  type        = string
}

variable "regulatory_profile" {
  description = "Applicable Panamanian regulatory framework profile."
  type        = string

  validation {
    condition     = contains(["ANTAI_LEY81", "SBP_001_2022", "SALUD_LEY68"], var.regulatory_profile)
    error_message = "regulatory_profile must be one of: ANTAI_LEY81, SBP_001_2022, SALUD_LEY68."
  }
}

variable "validation_worker_name" {
  description = "Name of the Cloudflare Worker (DlpValidationEntrypoint) deployed in the tenant account for RUCTB/Ley 81 validation."
  type        = string
}

variable "control_plane_webhook_url" {
  description = "HTTPS endpoint on the Vektor81 control plane receiving CASB remediation and DLP alerts."
  type        = string

  validation {
    condition     = can(regex("^https?://", var.control_plane_webhook_url))
    error_message = "control_plane_webhook_url must start with http:// or https://."
  }
}

variable "webhook_secret" {
  description = "Shared secret sent in the cf-webhook-auth header to authenticate CASB/DLP webhook events."
  type        = string
  sensitive   = true
}

variable "customer_dlp_public_key" {
  description = "Base64-encoded customer public key for Cloudflare DLP Payload Encryption (zero-knowledge custody)."
  type        = string
  sensitive   = true
}

variable "r2_logpush_destination_conf" {
  description = "Cloudflare R2 destination_conf URI for Logpush forensic and audit log storage."
  type        = string
  sensitive   = true
}

variable "tunnel_name" {
  description = "Name of the outbound cloudflared tunnel connecting the on-premise Presidio/SMB/SQL collector."
  type        = string
}

variable "data_localization_region" {
  description = "Cloudflare Data Localization Suite (DLS) boundary annotation: us, fedramp, eu, or global."
  type        = string
  default     = "us"

  validation {
    condition     = contains(["us", "fedramp", "eu", "global"], var.data_localization_region)
    error_message = "data_localization_region must be one of: us, fedramp, eu, global."
  }
}

variable "ai_gateway_id" {
  description = "Identifier for the tenant AI Gateway inspecting LLM egress traffic."
  type        = string
  default     = "vektor81-ai-gateway"
}

variable "dlp_payload_masking_level" {
  description = "DLP payload masking mode applied alongside customer_dlp_public_key (partial = 25% visible, full = redacted)."
  type        = string
  default     = "partial"

  validation {
    condition     = contains(["partial", "full", "clear", "default"], var.dlp_payload_masking_level)
    error_message = "dlp_payload_masking_level must be one of: partial, full, clear, default."
  }
}

variable "onprem_collector_hostname" {
  description = "Internal Zero Trust hostname routed via cloudflared to the on-premise collector."
  type        = string
  default     = "collector.internal.vektor81.local"
}

variable "onprem_collector_service_url" {
  description = "Local origin URL for the on-premise collector container reached over outbound tunnel."
  type        = string
  default     = "http://vektor81-collector:8080"
}

variable "casb_google_workspace_enabled" {
  description = "Enable Terraform-managed Google Workspace CASB integration (domain-wide delegation)."
  type        = bool
  default     = false
}

variable "casb_google_service_account_json" {
  description = "Google Workspace service account JSON credentials for non-OAuth CASB scanning."
  type        = string
  default     = ""
  sensitive   = true
}

variable "casb_google_admin_email" {
  description = "Google Workspace super-admin email for domain-wide delegation CASB scanning."
  type        = string
  default     = ""
}

variable "casb_box_enabled" {
  description = "Enable Terraform-managed Box CASB integration (server authentication)."
  type        = bool
  default     = false
}

variable "casb_box_enterprise_id" {
  description = "Box enterprise ID for server-authenticated CASB integration."
  type        = string
  default     = ""
}

variable "casb_m365_oauth_integration_id" {
  description = "Optional pre-authorized Microsoft 365 OAuth CASB integration ID (onboarded via dashboard/Tenant API)."
  type        = string
  default     = ""
}

variable "casb_aws_s3_integration_id" {
  description = "Optional AWS S3 CASB integration ID (onboarded via IAM role/Tenant API)."
  type        = string
  default     = ""
}

variable "enable_logpush" {
  description = "Whether to provision Logpush jobs to R2 (requires Enterprise/Logpush entitlement)."
  type        = bool
  default     = true
}
