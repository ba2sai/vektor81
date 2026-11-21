# Panama Ley 81 / DE 285 Custom DLP Profiles & Rust Regex Detection Entries
#
# Cloudflare DLP Rust Regex Constraints (2026):
# - Maximum 25 custom regex entries per account (we use exactly 5 high-density entries).
# - Strictly NO '*' or '+' quantifiers; only bounded '{min,max}' repetition is permitted.
# - Maximum 1,024 bytes UTF-8 match length.
# - False-positive filtering (date collisions, Juridica vs Natural RUC, RUCTB Mod-11 DV,
#   APAP inventory context) is delegated to var.validation_worker_name (DlpValidationEntrypoint).

locals {
  # Consolidated 5 Panama detection patterns (all strictly bounded, zero '*' or '+' quantifiers)
  panama_regex_entries = {
    pa_cedula_standard = {
      name        = "Vektor81-${var.tenant_id}-PA-Cedula-Standard-AV-PI"
      description = "Panama Standard (1-13), AV (pre-2006), and PI (Comarca) Cedula/RUC. Validator: ${var.validation_worker_name}"
      regex       = "\\b(?:1[0-3]|[1-9])(?:AV|PI){0,1}-[0-9]{1,4}-[0-9]{1,6}\\b"
    }
    pa_cedula_special = {
      name        = "Vektor81-${var.tenant_id}-PA-Cedula-Special-PE-E-N"
      description = "Panama Special Cedula prefixes PE, E, and N. Validator: ${var.validation_worker_name}"
      regex       = "\\b(?:PE|E|N)-[0-9]{1,4}-[0-9]{1,6}\\b"
    }
    pa_nt_foreigner = {
      name        = "Vektor81-${var.tenant_id}-PA-NT-Foreigner-ID"
      description = "Panama DGI Numero Tributario (NT) for resident foreigners. Validator: ${var.validation_worker_name}"
      regex       = "\\b(?:1[0-3]|[1-9])-NT-[0-9]{1,4}-[0-9]{1,6}\\b"
    }
    pa_passport_apap = {
      name        = "Vektor81-${var.tenant_id}-PA-Passport-APAP"
      description = "Panama Passport APAP 9-char format (XX9999999); context-checked by ${var.validation_worker_name}"
      regex       = "\\b[A-Z]{2}[0-9]{7}\\b"
    }
    pa_swift_bic = {
      name        = "Vektor81-${var.tenant_id}-PA-SWIFT-BIC"
      description = "Panama SWIFT/BIC banking code (8 or 11 chars with ISO country code PA). Validator: ${var.validation_worker_name}"
      regex       = "\\b[A-Z]{4}PA[A-Z0-9]{2}(?:[A-Z0-9]{3}){0,1}\\b"
    }
  }

  # All CWL entry IDs defined in dlp_wordlists.tf for shared sensitive context
  sensitive_wordlist_entry_ids = [
    cloudflare_zero_trust_dlp_custom_entry.cwl_medical_diagnoses.id,
    cloudflare_zero_trust_dlp_custom_entry.cwl_css_payroll.id,
    cloudflare_zero_trust_dlp_custom_entry.cwl_biometric_religion_union.id,
    cloudflare_zero_trust_dlp_custom_entry.cwl_confidentiality_labels.id,
  ]
}

# 1. Primary Low/Medium Audit Profile (owns the 5 custom regex entries; OCR & AI context enabled)
resource "cloudflare_zero_trust_dlp_custom_profile" "panama_ley81_audit" {
  account_id           = var.account_id
  name                 = "Vektor81-${var.tenant_id}-${var.regulatory_profile}-Audit"
  description          = "Low/Medium threshold visibility & Shadow AI audit profile (${var.regulatory_profile}). Validation Worker: ${var.validation_worker_name}"
  allowed_match_count  = 1
  confidence_threshold = "low"
  ai_context_enabled   = true
  ocr_enabled          = true

  shared_entries = [
    for id in local.sensitive_wordlist_entry_ids : {
      enabled  = true
      entry_id = id
    }
  ]
}

# 2. The 5 Custom Regex Entries (count = 5 <= 25 account limit)
resource "cloudflare_zero_trust_dlp_custom_entry" "panama_patterns" {
  for_each = local.panama_regex_entries

  account_id  = var.account_id
  profile_id  = cloudflare_zero_trust_dlp_custom_profile.panama_ley81_audit.id
  name        = each.value.name
  description = each.value.description
  enabled     = true

  pattern = {
    regex = each.value.regex
  }
}

# 3. High-Threshold Mass Exfiltration Block Profile (>= 5 matches)
resource "cloudflare_zero_trust_dlp_custom_profile" "panama_ley81_block" {
  account_id           = var.account_id
  name                 = "Vektor81-${var.tenant_id}-${var.regulatory_profile}-Block-Mass"
  description          = "High threshold (>= 5 matches) mass-exfiltration block profile (${var.regulatory_profile}). Validation Worker: ${var.validation_worker_name}"
  allowed_match_count  = 5
  confidence_threshold = "high"
  ai_context_enabled   = true
  ocr_enabled          = true

  shared_entries = concat(
    [
      for entry in cloudflare_zero_trust_dlp_custom_entry.panama_patterns : {
        enabled  = true
        entry_id = entry.id
      }
    ],
    [
      for id in local.sensitive_wordlist_entry_ids : {
        enabled  = true
        entry_id = id
      }
    ]
  )
}

# 4. High-Confidence Sensitive Context Block Profile (>= 1 match elevated to 0.95 by Worker/CWL)
resource "cloudflare_zero_trust_dlp_custom_profile" "panama_ley81_sensitive_block" {
  account_id           = var.account_id
  name                 = "Vektor81-${var.tenant_id}-${var.regulatory_profile}-Block-Sensitive"
  description          = "High confidence sensitive-context (Ley 81 Art. 4 / Ley 68) block profile. Validation Worker: ${var.validation_worker_name}"
  allowed_match_count  = 1
  confidence_threshold = "high"
  ai_context_enabled   = true
  ocr_enabled          = true

  shared_entries = concat(
    [
      for entry in cloudflare_zero_trust_dlp_custom_entry.panama_patterns : {
        enabled  = true
        entry_id = entry.id
      }
    ],
    [
      for id in local.sensitive_wordlist_entry_ids : {
        enabled  = true
        entry_id = id
      }
    ]
  )
}

# Associates the 5 regex entries with the tenant's deployed DlpValidationEntrypoint Worker.
# Provider v5.x configures the Custom Validation Worker binding via Cloudflare API
# (/accounts/{account_id}/dlp/entries/custom/{entry_id}) post-apply during tenant onboarding.
resource "terraform_data" "dlp_validation_worker_bindings" {
  triggers_replace = {
    worker_name = var.validation_worker_name
    entry_ids   = join(",", [for k in sort(keys(cloudflare_zero_trust_dlp_custom_entry.panama_patterns)) : cloudflare_zero_trust_dlp_custom_entry.panama_patterns[k].id])
  }

  input = {
    account_id         = var.account_id
    worker_name        = var.validation_worker_name
    entrypoint         = "DlpValidationEntrypoint"
    fallback_behavior  = "score:0"
    regulatory_profile = var.regulatory_profile
    bound_entries = {
      for k, entry in cloudflare_zero_trust_dlp_custom_entry.panama_patterns : k => {
        entry_id   = entry.id
        entry_name = entry.name
        api_path   = "/accounts/${var.account_id}/dlp/entries/custom/${entry.id}"
      }
    }
  }
}
