output "tunnel_id" {
  description = "UUID of the outbound cloudflared tunnel for the tenant on-premise collector."
  value       = cloudflare_zero_trust_tunnel_cloudflared.onprem_collector.id
}

output "dlp_profile_ids" {
  description = "Map of Vektor81 Panama Ley 81 custom DLP profile IDs (audit, block_mass, block_sensitive)."
  value = {
    audit           = cloudflare_zero_trust_dlp_custom_profile.panama_ley81_audit.id
    block_mass      = cloudflare_zero_trust_dlp_custom_profile.panama_ley81_block.id
    block_sensitive = cloudflare_zero_trust_dlp_custom_profile.panama_ley81_sensitive_block.id
  }
}

output "logpush_job_ids" {
  description = "Map of Logpush job IDs keyed by Vektor81 logical dataset (gateway_http, dlp_forensic, casb_findings, audit_logs)."
  value = {
    for k, job in cloudflare_logpush_job.tenant_r2 : k => job.id
  }
}

output "dlp_custom_entry_ids" {
  description = "IDs of the 5 custom Panama regex detection entries bound to the Custom Validation Worker."
  value = {
    for k, entry in cloudflare_zero_trust_dlp_custom_entry.panama_patterns : k => entry.id
  }
}

output "dlp_wordlist_entry_ids" {
  description = "IDs of the 4 sensitive-context Custom Wordlists (CWL)."
  value = {
    medical_diagnoses        = cloudflare_zero_trust_dlp_custom_entry.cwl_medical_diagnoses.id
    css_payroll              = cloudflare_zero_trust_dlp_custom_entry.cwl_css_payroll.id
    biometric_religion_union = cloudflare_zero_trust_dlp_custom_entry.cwl_biometric_religion_union.id
    confidentiality_labels   = cloudflare_zero_trust_dlp_custom_entry.cwl_confidentiality_labels.id
  }
}

output "casb_webhook_id" {
  description = "ID of the Cloudflare Notification Webhook pointing to the Vektor81 control plane."
  value       = cloudflare_notification_policy_webhooks.control_plane_casb.id
}

output "ai_gateway_id" {
  description = "ID of the tenant Cloudflare AI Gateway."
  value       = cloudflare_ai_gateway.tenant_ai_gateway.id
}

output "data_localization_region" {
  description = "Configured Data Localization Suite (DLS) region annotation."
  value       = var.data_localization_region
}
