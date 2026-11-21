# CASB SaaS Integrations, Auto-Remediation Webhook Policies, and Logpush to R2
# with Cloudflare Data Localization Suite (DLS) boundary annotations.

locals {
  data_localization_annotation = {
    region                     = var.data_localization_region
    customer_metadata_boundary = var.data_localization_region == "global" ? "unrestricted" : var.data_localization_region
    ley81_art41_4_custody      = "R2 zero-egress vault + customer public-key DLP payload encryption"
    regulatory_profile         = var.regulatory_profile
  }

  # Four-SaaS CASB posture & auto-remediation matrix aligned with CasbWebhookPayload contract
  casb_remediation_matrix = {
    microsoft_365 = {
      saas_app            = "Microsoft 365"
      onboarding_mode     = "oauth_or_api"
      integration_id      = var.casb_m365_oauth_integration_id
      monitored_surfaces  = ["OneDrive", "SharePoint", "Outlook", "EntraAdmin", "Copilot"]
      remediation_actions = ["REVOKE_PUBLIC_LINK", "REMOVE_EXTERNAL_SHARE", "FLAG_RISKY_OAUTH"]
      webhook_url         = var.control_plane_webhook_url
    }
    google_workspace = {
      saas_app            = "Google Workspace"
      onboarding_mode     = "domain_wide_delegation"
      enabled             = var.casb_google_workspace_enabled
      monitored_surfaces  = ["Google Drive", "Gmail", "Calendar", "Gemini"]
      remediation_actions = ["REVOKE_PUBLIC_LINK", "REMOVE_EXTERNAL_SHARE", "REVOKE_THIRD_PARTY_OAUTH"]
      webhook_url         = var.control_plane_webhook_url
    }
    aws_s3 = {
      saas_app            = "AWS S3"
      onboarding_mode     = "iam_cross_account_role"
      integration_id      = var.casb_aws_s3_integration_id
      monitored_surfaces  = ["S3 Buckets", "Public ACLs", "Bucket Policies"]
      remediation_actions = ["BLOCK_PUBLIC_ACCESS_ALERT", "QUARANTINE_EXPOSED_OBJECT_WEBHOOK"]
      webhook_url         = var.control_plane_webhook_url
    }
    box = {
      saas_app            = "Box"
      onboarding_mode     = "server_authentication"
      enabled             = var.casb_box_enabled
      monitored_surfaces  = ["Box Enterprise Folders", "Shared Links", "Box Drive"]
      remediation_actions = ["EXPIRE_PUBLIC_LINK", "DOWNGRADE_COLLABORATOR_SCOPE"]
      webhook_url         = var.control_plane_webhook_url
    }
  }

  # Logical dataset keys match packages/shared-contracts/api-contracts.ts LogpushBatchPayload
  logpush_datasets = {
    gateway_http = {
      dataset     = "gateway_http"
      field_names = ["AccountID", "Action", "Datetime", "DestinationIP", "Email", "HTTPHost", "HTTPMethod", "PolicyID", "RequestID", "URL"]
    }
    dlp_forensic = {
      dataset     = "dlp_forensic_copies"
      field_names = ["AccountID", "Datetime", "ForensicCopyID", "GatewayRequestID", "Headers", "Payload", "Phase", "TriggeredRuleID"]
    }
    casb_findings = {
      dataset     = "casb_findings"
      field_names = ["AccountID", "Datetime", "FindingTypeID", "IntegrationID", "Severity", "Status"]
    }
    audit_logs = {
      dataset     = "audit_logs"
      field_names = ["ActionResult", "ActionType", "ActorEmail", "ActorIP", "ID", "ResourceType", "When"]
    }
  }
}

# Non-OAuth Google Workspace CASB Integration (Domain-Wide Delegation Service Account)
resource "cloudflare_zero_trust_casb_integration" "google_workspace" {
  count = var.casb_google_workspace_enabled ? 1 : 0

  account_id = var.account_id
  name       = "Vektor81-${var.tenant_id}-CASB-GoogleWorkspace"
  paused     = false

  google_workspace = {
    google_domain_wide_delegation_service_account = {
      service_account_key_json = var.casb_google_service_account_json
      administrator_email      = var.casb_google_admin_email
    }
  }
}

# Non-OAuth Box CASB Integration (Server Authentication)
resource "cloudflare_zero_trust_casb_integration" "box" {
  count = var.casb_box_enabled ? 1 : 0

  account_id = var.account_id
  name       = "Vektor81-${var.tenant_id}-CASB-Box"
  paused     = false

  box = {
    box_server_authentication = {
      enterprise_id = var.casb_box_enterprise_id
    }
  }
}

# Webhook Destination on Vektor81 Control Plane for Real-Time CASB & DLP Remediation
resource "cloudflare_notification_policy_webhooks" "control_plane_casb" {
  account_id = var.account_id
  name       = "vektor81-${var.tenant_id}-casb-remediation"
  url        = var.control_plane_webhook_url
  secret     = var.webhook_secret
}

# Notification Policy routing CASB posture findings to the Control Plane Webhook
resource "cloudflare_notification_policy" "casb_findings_webhook" {
  account_id  = var.account_id
  name        = "Vektor81 [${var.tenant_id}] CASB Remediation & Posture Webhook (${var.regulatory_profile})"
  description = "Dispatches CASB findings across M365, Google Workspace, AWS S3, and Box to Vektor81 Control Plane."
  enabled     = true
  alert_type  = "casb_weekly_digest"

  mechanisms = {
    webhooks = [
      {
        id = cloudflare_notification_policy_webhooks.control_plane_casb.id
      }
    ]
  }
}

# Tracks declarative CASB integration & auto-remediation webhook rules across all 4 SaaS platforms
# (Microsoft 365 OAuth and AWS S3 IAM integrations require non-Terraform OAuth/IAM handshake completion)
resource "terraform_data" "casb_remediation_rules" {
  triggers_replace = {
    tenant_id   = var.tenant_id
    webhook_id  = cloudflare_notification_policy_webhooks.control_plane_casb.id
    webhook_url = var.control_plane_webhook_url
    m365_id     = var.casb_m365_oauth_integration_id
    s3_id       = var.casb_aws_s3_integration_id
  }

  input = {
    account_id                 = var.account_id
    tenant_id                  = var.tenant_id
    regulatory_profile         = var.regulatory_profile
    notification_webhook_id    = cloudflare_notification_policy_webhooks.control_plane_casb.id
    control_plane_webhook_url  = var.control_plane_webhook_url
    integrations               = local.casb_remediation_matrix
    data_localization_metadata = local.data_localization_annotation
  }
}

# Logpush Jobs pushing gateway_http, dlp_forensic, casb_findings, and audit_logs to R2
resource "cloudflare_logpush_job" "tenant_r2" {
  for_each = var.enable_logpush ? local.logpush_datasets : {}

  account_id       = var.account_id
  name             = "vektor81-${var.tenant_id}-${each.key}-dls-${var.data_localization_region}"
  dataset          = each.value.dataset
  destination_conf = var.r2_logpush_destination_conf
  enabled          = true

  # Data Localization Suite (DLS) boundary annotation: var.data_localization_region
  output_options = {
    field_names      = each.value.field_names
    output_type      = "ndjson"
    timestamp_format = "rfc3339"
  }
}

# Explicit Data Localization Suite (DLS) metadata record for audit traceability
resource "terraform_data" "data_localization_suite_annotation" {
  triggers_replace = {
    region    = var.data_localization_region
    tenant_id = var.tenant_id
  }

  input = merge(local.data_localization_annotation, {
    account_id    = var.account_id
    logpush_names = [for k, job in cloudflare_logpush_job.tenant_r2 : job.name]
  })
}
