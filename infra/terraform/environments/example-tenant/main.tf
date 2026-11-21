terraform {
  required_version = ">= 1.6"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  # Provide CLOUDFLARE_API_TOKEN via environment variable or tfvars (never commit tokens)
  api_token = var.cloudflare_api_token
}

variable "cloudflare_api_token" {
  description = "Cloudflare Partner/MSSP API token with Zero Trust, DLP, CASB, Logpush, and Tunnel Write permissions."
  type        = string
  default     = null
  sensitive   = true
}

variable "account_id" {
  description = "Isolated Cloudflare tenant account ID provisioned via Tenant API."
  type        = string
}

variable "tenant_id" {
  description = "Tenant slug identifier."
  type        = string
}

variable "tenant_name" {
  description = "Tenant legal / display name."
  type        = string
}

variable "regulatory_profile" {
  description = "Panamanian regulatory framework (ANTAI_LEY81, SBP_001_2022, SALUD_LEY68)."
  type        = string
}

variable "validation_worker_name" {
  description = "Name of the DlpValidationEntrypoint Worker deployed in the tenant account."
  type        = string
}

variable "control_plane_webhook_url" {
  description = "HTTPS webhook URL on Vektor81 control plane."
  type        = string
}

variable "webhook_secret" {
  description = "Shared secret for cf-webhook-auth header."
  type        = string
  sensitive   = true
}

variable "customer_dlp_public_key" {
  description = "Base64-encoded customer public key for DLP Payload Encryption."
  type        = string
  sensitive   = true
}

variable "r2_logpush_destination_conf" {
  description = "R2 Logpush destination URI."
  type        = string
  sensitive   = true
}

variable "tunnel_name" {
  description = "Outbound cloudflared tunnel name."
  type        = string
}

variable "data_localization_region" {
  description = "Cloudflare Data Localization Suite region (us, fedramp, eu, global)."
  type        = string
  default     = "us"
}

variable "dlp_payload_masking_level" {
  description = "DLP payload masking mode (partial or full)."
  type        = string
  default     = "partial"
}

variable "ai_gateway_id" {
  description = "Tenant AI Gateway ID."
  type        = string
  default     = "vektor81-ai-gateway"
}

variable "casb_google_workspace_enabled" {
  description = "Enable Terraform-managed Google Workspace CASB integration."
  type        = bool
  default     = false
}

variable "casb_google_service_account_json" {
  description = "Google Workspace service account JSON."
  type        = string
  default     = ""
  sensitive   = true
}

variable "casb_google_admin_email" {
  description = "Google Workspace super-admin email."
  type        = string
  default     = ""
}

variable "casb_box_enabled" {
  description = "Enable Terraform-managed Box CASB integration."
  type        = bool
  default     = false
}

variable "casb_box_enterprise_id" {
  description = "Box Enterprise ID."
  type        = string
  default     = ""
}

variable "casb_m365_oauth_integration_id" {
  description = "Pre-authorized Microsoft 365 OAuth CASB integration ID."
  type        = string
  default     = ""
}

variable "casb_aws_s3_integration_id" {
  description = "Pre-authorized AWS S3 CASB integration ID."
  type        = string
  default     = ""
}

variable "enable_logpush" {
  description = "Provision R2 Logpush jobs."
  type        = bool
  default     = true
}

module "tenant" {
  source = "../../modules/tenant-account"

  account_id                      = var.account_id
  tenant_id                       = var.tenant_id
  tenant_name                     = var.tenant_name
  regulatory_profile              = var.regulatory_profile
  validation_worker_name          = var.validation_worker_name
  control_plane_webhook_url       = var.control_plane_webhook_url
  webhook_secret                  = var.webhook_secret
  customer_dlp_public_key         = var.customer_dlp_public_key
  r2_logpush_destination_conf     = var.r2_logpush_destination_conf
  tunnel_name                     = var.tunnel_name
  data_localization_region        = var.data_localization_region
  dlp_payload_masking_level       = var.dlp_payload_masking_level
  ai_gateway_id                   = var.ai_gateway_id
  casb_google_workspace_enabled   = var.casb_google_workspace_enabled
  casb_google_service_account_json = var.casb_google_service_account_json
  casb_google_admin_email         = var.casb_google_admin_email
  casb_box_enabled                = var.casb_box_enabled
  casb_box_enterprise_id          = var.casb_box_enterprise_id
  casb_m365_oauth_integration_id  = var.casb_m365_oauth_integration_id
  casb_aws_s3_integration_id      = var.casb_aws_s3_integration_id
  enable_logpush                  = var.enable_logpush
}

output "tunnel_id" {
  description = "Tenant cloudflared tunnel UUID."
  value       = module.tenant.tunnel_id
}

output "dlp_profile_ids" {
  description = "Tenant Panama Ley 81 custom DLP profile IDs."
  value       = module.tenant.dlp_profile_ids
}

output "logpush_job_ids" {
  description = "Tenant R2 Logpush job IDs."
  value       = module.tenant.logpush_job_ids
}
