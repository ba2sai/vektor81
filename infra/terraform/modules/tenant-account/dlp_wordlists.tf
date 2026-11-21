# Custom Wordlists (CWL) for Sensitive Ley 81 / SBP / Ley 68 Context
#
# CRITICAL CLOUDFLARE DLP GUARDRAILS:
# - Custom Wordlists are stored in cleartext at Cloudflare: NEVER place real PII,
#   cedulas, RUC numbers, passport numbers, or payment card numbers in any CWL!
# - Maximum 200 words per CWL and maximum 1,000 words across the account.
# - Used solely as semantic/context boosters alongside the 5 regex patterns and
#   Custom Validation Worker to classify sensitive Art. 4 / Ley 68 / SBP traffic.

resource "cloudflare_zero_trust_dlp_custom_entry" "cwl_medical_diagnoses" {
  account_id     = var.account_id
  name           = "Vektor81-${var.tenant_id}-CWL-Salud-Ley68"
  description    = "Sensitive health & clinical diagnosis context terms ONLY (Ley 81 Art. 4 / Ley 68). No PII."
  enabled        = true
  type           = "word_list"
  case_sensitive = false
  secret         = false

  word_list = [
    "diagnostico",
    "diagnóstico",
    "historia clinica",
    "historia clínica",
    "expediente clinico",
    "expediente clínico",
    "receta medica",
    "receta médica",
    "laboratorio clinico",
    "laboratorio clínico",
    "vih",
    "sida",
    "oncologia",
    "oncología",
    "psiquiatrico",
    "psiquiátrico",
    "salud mental",
    "epicrisis",
    "anamnesis",
    "incapacidad medica",
    "incapacidad médica",
    "certificado medico",
    "certificado médico",
    "paciente",
    "grupo sanguineo",
    "grupo sanguíneo",
    "serologia",
    "serología",
    "tamizaje",
    "patologia",
    "patología",
  ]
}

resource "cloudflare_zero_trust_dlp_custom_entry" "cwl_css_payroll" {
  account_id     = var.account_id
  name           = "Vektor81-${var.tenant_id}-CWL-Planilla-CSS"
  description    = "Panama Caja de Seguro Social (CSS) and payroll context terms ONLY. No PII."
  enabled        = true
  type           = "word_list"
  case_sensitive = false
  secret         = false

  word_list = [
    "seguro social",
    "css",
    "ficha css",
    "planilla",
    "planilla css",
    "cuota obrero patronal",
    "salario neto",
    "salario bruto",
    "deducciones",
    "decimo tercer mes",
    "décimo tercer mes",
    "impuesto sobre la renta",
    "isr",
    "seguro educativo",
    "riesgos profesionales",
    "siacap",
    "talonario de pago",
    "comprobante de pago",
    "fondo de cesantia",
    "fondo de cesantía",
    "prestaciones laborales",
    "liquidacion laboral",
    "liquidación laboral",
  ]
}

resource "cloudflare_zero_trust_dlp_custom_entry" "cwl_biometric_religion_union" {
  account_id     = var.account_id
  name           = "Vektor81-${var.tenant_id}-CWL-Sensibles-Art4"
  description    = "Ley 81 Art. 4 special category terms (biometric, genetic, religion, union) ONLY. No PII."
  enabled        = true
  type           = "word_list"
  case_sensitive = false
  secret         = false

  word_list = [
    "biometria",
    "biometría",
    "huella dactilar",
    "reconocimiento facial",
    "iris",
    "perfil genetico",
    "perfil genético",
    "adn",
    "religion",
    "religión",
    "credo",
    "culto",
    "afiliacion sindical",
    "afiliación sindical",
    "sindicato",
    "conviccion politica",
    "convicción política",
    "origen etnico",
    "origen étnico",
    "preferencia sexual",
    "orientacion sexual",
    "orientación sexual",
    "antecedentes penales",
    "discapacidad",
    "dato biometrico",
  ]
}

resource "cloudflare_zero_trust_dlp_custom_entry" "cwl_confidentiality_labels" {
  account_id     = var.account_id
  name           = "Vektor81-${var.tenant_id}-CWL-Confidencialidad"
  description    = "Panama confidentiality, ANTAI, SBP, and ARCO-P document classification labels ONLY. No PII."
  enabled        = true
  type           = "word_list"
  case_sensitive = false
  secret         = false

  word_list = [
    "confidencial",
    "estrictamente confidencial",
    "uso interno",
    "restringido",
    "secreto bancario",
    "dato sensible",
    "datos sensibles",
    "ley 81",
    "decreto 285",
    "antai",
    "superintendencia de bancos",
    "sbp",
    "ley 68",
    "arco-p",
    "consentimiento expreso",
    "brecha de seguridad",
    "custodia de datos",
    "proteccion de datos",
    "protección de datos",
    "no divulgar",
  ]
}
