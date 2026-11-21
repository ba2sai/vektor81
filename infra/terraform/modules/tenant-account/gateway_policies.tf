# Cloudflare Gateway HTTP DLP Policies, AI Gateway Egress Inspection,
# and DLP Payload Encryption Settings (Customer Public Key Custody).
#
# Precedence Evaluation Order (lower integer executes first):
#   100 - BLOCK mass exfiltration (>= 5 PII matches) or sensitive Ley 81 Art. 4 / Ley 68 context.
#   150 - BLOCK AI Gateway / Shadow LLM egress carrying Panamanian PII to external LLMs.
#   200 - ALLOW / AUDIT Low & Medium threshold matches + Shadow AI visibility logging.

locals {
  # Core external LLM & Shadow AI endpoints aligned with backend/ai_domains.json
  shadow_ai_hosts = [
    "chatgpt.com",
    "chat.openai.com",
    "api.openai.com",
    "claude.ai",
    "api.anthropic.com",
    "gemini.google.com",
    "aistudio.google.com",
    "deepseek.com",
    "api.deepseek.com",
    "perplexity.ai",
    "copilot.microsoft.com",
    "grok.com",
    "poe.com",
    "openrouter.ai",
    "huggingface.co",
    "ilovepdf.com",
    "smallpdf.com",
    "gateway.ai.cloudflare.com",
  ]

  shadow_ai_hosts_wirefilter = join(" ", [for h in local.shadow_ai_hosts : "\"${h}\""])
}

# Account-level DLP Settings: OCR + AI Context + Customer-Key Payload Encryption
resource "cloudflare_zero_trust_dlp_settings" "tenant_dlp_settings" {
  account_id          = var.account_id
  ai_context_analysis = true
  ocr                 = true

  payload_logging = {
    masking_level = var.dlp_payload_masking_level # "partial" (25% visible) or "full"
    public_key    = var.customer_dlp_public_key
  }
}

# Managed AI Gateway for governed LLM egress logging and observability
resource "cloudflare_ai_gateway" "tenant_ai_gateway" {
  account_id                 = var.account_id
  id                         = var.ai_gateway_id
  cache_invalidate_on_update = true
  cache_ttl                  = 0
  collect_logs               = true
}

# Policy 1 (High Threshold Block): Mass exfiltration (>= 5 matches) or sensitive Art. 4 / Ley 68 context
resource "cloudflare_zero_trust_gateway_policy" "dlp_http_block_high" {
  account_id  = var.account_id
  name        = "Vektor81 [${var.tenant_id}] DLP Block Mass Exfiltration & Sensitive Data (${var.regulatory_profile})"
  description = "Blocks HTTP/HTTPS egress with >= 5 Panamanian PII matches or sensitive Art. 4 / Ley 68 context."
  enabled     = true
  precedence  = 100
  action      = "block"
  filters     = ["http"]

  traffic = <<-EOT
    any(http.request.bodies.dlp.matched_profiles[*] in {
      "${cloudflare_zero_trust_dlp_custom_profile.panama_ley81_block.id}"
      "${cloudflare_zero_trust_dlp_custom_profile.panama_ley81_sensitive_block.id}"
    })
  EOT

  rule_settings = {
    block_page_enabled = true
    block_page_reason  = "Bloqueado por Vektor81 DLP (${var.regulatory_profile}): posible exfiltracion masiva o datos sensibles protegidos bajo la Ley 81 de Panama."

    payload_log = {
      enabled = true
    }

    notification_settings = {
      enabled     = true
      msg         = "ALERTA CRITICA Vektor81 [${var.tenant_id}]: Bloqueo DLP de alta severidad (${var.regulatory_profile})"
      support_url = var.control_plane_webhook_url
    }
  }
}

# Policy 2 (AI Gateway / Shadow LLM Egress Inspection): Prevent Panamanian PII leaks to LLMs
resource "cloudflare_zero_trust_gateway_policy" "ai_gateway_llm_dlp_inspection" {
  account_id  = var.account_id
  name        = "Vektor81 [${var.tenant_id}] AI Gateway & LLM DLP Egress Inspection (${var.regulatory_profile})"
  description = "Inspects and blocks Panamanian PII egress to external generative AI and AI Gateway hosts (Ley 81 Arts. 32-33)."
  enabled     = true
  precedence  = 150
  action      = "block"
  filters     = ["http"]

  traffic = <<-EOT
    http.request.host in {${local.shadow_ai_hosts_wirefilter}} and
    any(http.request.bodies.dlp.matched_profiles[*] in {
      "${cloudflare_zero_trust_dlp_custom_profile.panama_ley81_audit.id}"
      "${cloudflare_zero_trust_dlp_custom_profile.panama_ley81_sensitive_block.id}"
    })
  EOT

  rule_settings = {
    block_page_enabled = true
    block_page_reason  = "Bloqueado por Vektor81 AI Guardrail (${var.regulatory_profile}): prohibido enviar cedulas, RUC o datos sensibles hacia modelos LLM externos."

    payload_log = {
      enabled = true
    }

    notification_settings = {
      enabled     = true
      msg         = "Vektor81 [${var.tenant_id}] Bloqueo Shadow AI con PII Panamena detectada"
      support_url = var.control_plane_webhook_url
    }
  }
}

# Policy 3 (Allow / Audit): Low/Medium threshold visibility & Shadow AI egress logging
resource "cloudflare_zero_trust_gateway_policy" "dlp_http_allow_audit" {
  account_id  = var.account_id
  name        = "Vektor81 [${var.tenant_id}] DLP Allow & Audit Visibility (${var.regulatory_profile})"
  description = "Audits Low/Medium Panamanian DLP matches and Shadow AI domain access without disrupting approved workflows."
  enabled     = true
  precedence  = 200
  action      = "allow"
  filters     = ["http"]

  traffic = <<-EOT
    any(http.request.bodies.dlp.matched_profiles[*] in {
      "${cloudflare_zero_trust_dlp_custom_profile.panama_ley81_audit.id}"
    }) or http.request.host in {${local.shadow_ai_hosts_wirefilter}}
  EOT

  rule_settings = {
    payload_log = {
      enabled = true
    }

    notification_settings = {
      enabled     = true
      msg         = "Vektor81 [${var.tenant_id}] Auditoria DLP/Shadow AI (${var.regulatory_profile})"
      support_url = var.control_plane_webhook_url
    }
  }
}
