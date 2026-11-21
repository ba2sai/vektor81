<#
.SYNOPSIS
    Agente Recolector Zero-Footprint Vektor81 v2 — Shadow AI, Extensiones, Cloud Sync y Ley 81 (Panamá).
.DESCRIPTION
    Se ejecuta en estaciones Windows 10/11 (vía GPO, Tarea Programada o Intune/RMM) sin requerir permisos de administrador local.
    Audita vectores críticos para el cumplimiento de la Ley 81 / DE 285 de Panamá:
      1. Caché local de resolución DNS (Get-DnsClientCache) frente a 155+ dominios de Shadow AI y convertidores Cloud.
      2. Extensiones de Google Chrome y Microsoft Edge con permisos de alto riesgo (<all_urls>, *://*/*, http://*/*, https://*/*, webRequest, clipboardRead).
      3. Carpetas locales sincronizadas de Box Drive y OneDrive, validando identidad natural panameña (sin falsos positivos de fechas o RUCs jurídicos), verificando políticas DLP en registro y enmascarando dígitos con Mask-PiiToken.
      4. Telemetría autenticada (HTTPS obligatorio por defecto, Bearer token, X-Tenant-Id) y bloque heartbeat para monitoreo continuo.
.PARAMETER CollectorUrl
    URL base del Collector o Control Plane Vektor81 (por defecto: https://collector.vektor81.local).
.PARAMETER CollectorToken
    Token Bearer para autenticación (o variable de entorno VEKTOR81_COLLECTOR_TOKEN).
.PARAMETER TenantId
    Identificador del tenant enviado en cabecera X-Tenant-Id y en el cuerpo JSON (por defecto: default-tenant).
.PARAMETER AllowInsecureHttp
    Permite explícitamente transmitir sobre http:// en entornos LAN de laboratorio/migración.
.PARAMETER HeartbeatOnly
    Envía únicamente el heartbeat ligero del agente al endpoint /api/v1/health/heartbeat (o /api/v2/health/heartbeat) sin escaneo completo.
.PARAMETER DryRun
    Emite el payload JSON por salida estándar localmente sin realizar peticiones HTTP POST.
.PARAMETER AgentVersion
    Versión declarada del agente endpoint (por defecto: 2.0.0).
.PARAMETER ApiVersion
    Versión de ruta API destino ("v1" para collector local, "v2" para control-plane directo). Por defecto: "v1".
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CollectorUrl = "https://collector.vektor81.local",

    [Parameter(Mandatory = $false)]
    [string]$CollectorToken = "",

    [Parameter(Mandatory = $false)]
    [string]$TenantId = "default-tenant",

    [Parameter(Mandatory = $false)]
    [switch]$AllowInsecureHttp,

    [Parameter(Mandatory = $false)]
    [switch]$HeartbeatOnly,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [string]$AgentVersion = "2.0.0",

    [Parameter(Mandatory = $false)]
    [ValidateSet("v1", "v2")]
    [string]$ApiVersion = "v1"
)

# =====================================================================
# FUNCIONES AUXILIARES PURAS (IMPORTABLES VIA DOT-SOURCING)
# =====================================================================

function Remove-Diacritics {
    <#
    .SYNOPSIS
        Normaliza texto a minúsculas ASCII sin tildes ni diacríticos para matching de contexto en español.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return ""
    }

    $normalized = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $normalized.ToCharArray()) {
        $category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch)
        if ($category -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($ch)
        }
    }

    return $sb.ToString().ToLowerInvariant()
}

function Test-PanamaNaturalId {
    <#
    .SYNOPSIS
        Valida identificadores de persona natural panameña (cédula, AV, PI, PE, E, N, NT)
        rechazando colisiones de fecha y RUCs jurídicos / folios mercantiles.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Token = ""
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return $false
    }

    $clean = $Token.Trim().ToUpperInvariant()

    $naturalRegex = '^(?:(?:1[0-3]|[1-9])(?:AV|PI)?-(?:\d{1,4})-(?:\d{1,6})|(?:PE|E|N)-(?:\d{1,4})-(?:\d{1,6})|(?:1[0-3]|[1-9])-NT-(?:\d{1,4})-(?:\d{1,6}))$'
    if ($clean -notmatch $naturalRegex) {
        return $false
    }

    $parts = $clean -split '-'
    if ($parts.Count -eq 4) {
        # Formato {1-13}-NT-{libro}-{tomo}
        $libro = [int]$parts[2]
        $tomo = [int]$parts[3]
        if ($libro -lt 1 -or $tomo -lt 1) {
            return $false
        }
        return $true
    }

    if ($parts.Count -ne 3) {
        return $false
    }

    $seg1Str = $parts[0]
    $seg2Str = $parts[1]
    $seg3Str = $parts[2]

    if ([int]$seg2Str -lt 1 -or [int]$seg3Str -lt 1) {
        return $false
    }

    if ($seg1Str -match '^\d+$') {
        $seg1 = [int]$seg1Str
        $seg2 = [int]$seg2Str
        $seg3 = [int]$seg3Str

        # Rechazar RUCs jurídicos (prefijo > 13 o folio mercantil de 5+ dígitos en segundo segmento)
        if ($seg1 -gt 13 -or $seg2Str.Length -ge 5) {
            return $false
        }

        # Rechazar colisiones con fechas calendario DD-MM-YYYY
        if (
            $seg1Str.Length -le 2 -and
            $seg2Str.Length -le 2 -and
            $seg3Str.Length -eq 4 -and
            $seg1 -ge 1 -and $seg1 -le 31 -and
            $seg2 -ge 1 -and $seg2 -le 12 -and
            $seg3 -ge 1900 -and $seg3 -le 2099
        ) {
            return $false
        }
    }

    return $true
}

function Get-PanamaContextMatches {
    <#
    .SYNOPSIS
        Devuelve las palabras clave de contexto presentes en texto normalizado con límites de palabra alfanuméricos.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$NormalizedText = "",

        [Parameter(Mandatory = $true)]
        [string[]]$Keywords
    )

    $matched = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($NormalizedText)) {
        return ,$matched.ToArray()
    }

    $seen = @{}
    foreach ($rawKw in $Keywords) {
        $kw = (Remove-Diacritics -Text $rawKw).Trim()
        if ([string]::IsNullOrEmpty($kw) -or $seen.ContainsKey($kw)) {
            continue
        }
        $escaped = [regex]::Escape($kw)
        $pattern = "(?<![a-z0-9])$escaped(?![a-z0-9])"
        if ([regex]::IsMatch($NormalizedText, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $seen[$kw] = $true
            $matched.Add($kw)
        }
    }

    return ,$matched.ToArray()
}

function Find-PanamaNaturalIdsInText {
    <#
    .SYNOPSIS
        Analiza un texto libre buscando cédulas naturales panameñas con veto contextual corporativo
        (salvo término explícito de identidad personal) y detección de contexto sensible Ley 81 / Ley 68.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [pscustomobject]@{
            HasNaturalId             = $false
            MatchedTokens            = @()
            VetoedTokens             = @()
            CorporateContextDetected = $false
            IdentityContextDetected  = $false
            SensitiveContextDetected = $false
            SensitiveSignals         = @()
        }
    }

    $corporateKeywords = @(
        "sociedad anonima", "s.a.", "s. a.", "s.r.l.", "s. de r.l.",
        "persona juridica", "razon social", "registro publico", "folio mercantil",
        "factura fiscal", "contribuyente juridico", "proveedor", "proveedores",
        "b2b", "corp.", "ltda.", "ltda", "inc.", "llc", "compania", "consorcio",
        "aviso de operacion", "orden de compra", "ruc juridico"
    )

    $identityKeywords = @(
        "cedula", "cip", "c.i.p.", "portador", "portadora",
        "cedula de identidad", "documento personal", "documento de identidad",
        "identidad personal", "persona natural", "tribunal electoral"
    )

    $sensitiveKeywords = @(
        "vih", "hiv", "sida", "seropositivo", "diagnostico", "historia clinica",
        "expediente clinico", "historial medico", "css", "minsa", "paciente",
        "enfermedad", "patologia", "tratamiento medico", "clinica", "hospital",
        "receta medica", "oncologia", "psiquiatrico", "psiquiatria", "discapacidad",
        "embarazo", "biometrica", "biometrico", "biometria", "huella",
        "huella dactilar", "huella biometrica", "reconocimiento facial", "adn",
        "genetico", "sindicato", "sindical", "afiliado", "afiliacion sindical",
        "partido politico", "religion", "orientacion sexual", "origen etnico"
    )

    $normText = Remove-Diacritics -Text $Text
    $corporateMatches = Get-PanamaContextMatches -NormalizedText $normText -Keywords $corporateKeywords
    $identityMatches = Get-PanamaContextMatches -NormalizedText $normText -Keywords $identityKeywords
    $sensitiveMatches = Get-PanamaContextMatches -NormalizedText $normText -Keywords $sensitiveKeywords

    $corporateDetected = ($corporateMatches.Count -gt 0)
    $identityDetected = ($identityMatches.Count -gt 0)
    $sensitiveDetected = ($sensitiveMatches.Count -gt 0)

    $candidatePattern = '(?<![A-Za-z0-9-])(?:(?:1[0-3]|[1-9])-NT-\d{1,4}-\d{1,6}|(?:1[0-3]|[1-9])(?:AV|PI)-\d{1,4}-\d{1,6}|(?:PE|E|N)-\d{1,4}-\d{1,6}|\d{1,8}-\d{1,6}-\d{1,7})(?![A-Za-z0-9-])'
    $regexMatches = [regex]::Matches($Text, $candidatePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $matchedTokens = New-Object System.Collections.Generic.List[string]
    $vetoedTokens = New-Object System.Collections.Generic.List[string]

    foreach ($m in $regexMatches) {
        $candidate = $m.Value
        if (-not (Test-PanamaNaturalId -Token $candidate)) {
            $vetoedTokens.Add($candidate)
            continue
        }

        if ($corporateDetected -and -not $identityDetected) {
            $vetoedTokens.Add($candidate)
            continue
        }

        $matchedTokens.Add($candidate)
    }

    return [pscustomobject]@{
        HasNaturalId             = ($matchedTokens.Count -gt 0)
        MatchedTokens            = @($matchedTokens.ToArray())
        VetoedTokens             = @($vetoedTokens.ToArray())
        CorporateContextDetected = $corporateDetected
        IdentityContextDetected  = $identityDetected
        SensitiveContextDetected = $sensitiveDetected
        SensitiveSignals         = @($sensitiveMatches)
    }
}

function Test-PanamaNaturalIdInText {
    <#
    .SYNOPSIS
        Retorna $true si el texto contiene al menos una cédula natural panameña válida no vetada por contexto corporativo.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    $assessment = Find-PanamaNaturalIdsInText -Text $Text
    return [bool]$assessment.HasNaturalId
}

function Test-PanamaSensitiveContext {
    <#
    .SYNOPSIS
        Retorna $true si el texto contiene indicadores de datos sensibles (Art. 4 Ley 81 / Ley 68).
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    $sensitiveKeywords = @(
        "vih", "hiv", "sida", "seropositivo", "diagnostico", "historia clinica",
        "expediente clinico", "historial medico", "css", "minsa", "paciente",
        "enfermedad", "patologia", "tratamiento medico", "clinica", "hospital",
        "receta medica", "oncologia", "psiquiatrico", "psiquiatria", "discapacidad",
        "embarazo", "biometrica", "biometrico", "biometria", "huella",
        "huella dactilar", "huella biometrica", "reconocimiento facial", "adn",
        "genetico", "sindicato", "sindical", "afiliado", "afiliacion sindical",
        "partido politico", "religion", "orientacion sexual", "origen etnico"
    )

    $normText = Remove-Diacritics -Text $Text
    $matches = Get-PanamaContextMatches -NormalizedText $normText -Keywords $sensitiveKeywords
    return ($matches.Count -gt 0)
}

function Mask-PiiToken {
    <#
    .SYNOPSIS
        Enmascara cualquier dígito (y parte local de correos) en tokens o nombres de archivo de muestra
        para evitar transmisión de PII en texto plano (Principio de Minimización Ley 81).
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Token = ""
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return ""
    }

    $masked = [regex]::Replace(
        $Token,
        '([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        '$1***@$2'
    )
    $masked = [regex]::Replace($masked, '\d', '*')
    return $masked
}

function Get-ShadowAiDomainMap {
    <#
    .SYNOPSIS
        Diccionario determinista de 155 dominios de Shadow AI y convertidores Cloud alineado con backend/ai_domains.json.
    #>
    return @{
        "chatgpt.com"             = "LLM Conversacional"
        "chat.openai.com"         = "LLM Conversacional"
        "api.openai.com"          = "API LLM Pública"
        "openai.com"              = "LLM Conversacional"
        "claude.ai"               = "LLM Conversacional"
        "anthropic.com"           = "LLM Conversacional"
        "api.anthropic.com"       = "API LLM Pública"
        "deepseek.com"            = "LLM Conversacional"
        "chat.deepseek.com"       = "LLM Conversacional"
        "api.deepseek.com"        = "API LLM Pública"
        "perplexity.ai"           = "Buscador IA"
        "www.perplexity.ai"       = "Buscador IA"
        "gemini.google.com"       = "LLM Conversacional"
        "bard.google.com"         = "LLM Conversacional"
        "aistudio.google.com"     = "API LLM Pública"
        "notebooklm.google.com"   = "Análisis Documental IA"
        "notebooklm.google"       = "Análisis Documental IA"
        "copilot.microsoft.com"   = "LLM Conversacional"
        "edgeservices.bing.com"   = "LLM Conversacional"
        "sydney.bing.com"         = "LLM Conversacional"
        "grok.com"                = "LLM Conversacional"
        "x.ai"                    = "LLM Conversacional"
        "console.x.ai"            = "API LLM Pública"
        "poe.com"                 = "Agregador LLM"
        "you.com"                 = "Buscador IA"
        "phind.com"               = "Asistente de Código IA"
        "mistral.ai"              = "LLM Conversacional"
        "chat.mistral.ai"         = "LLM Conversacional"
        "console.mistral.ai"      = "API LLM Pública"
        "cohere.com"              = "API LLM Pública"
        "coral.cohere.com"        = "LLM Conversacional"
        "huggingface.co"          = "Repositorio Modelos IA"
        "hf.space"                = "Apps IA Públicas"
        "replicate.com"           = "Apps IA Públicas"
        "together.ai"             = "API LLM Pública"
        "api.together.xyz"        = "API LLM Pública"
        "groq.com"                = "API LLM Pública"
        "console.groq.com"        = "API LLM Pública"
        "openrouter.ai"           = "Agregador LLM"
        "fireworks.ai"            = "API LLM Pública"
        "anyscale.com"            = "API LLM Pública"
        "ai21.com"                = "API LLM Pública"
        "character.ai"            = "LLM Conversacional"
        "beta.character.ai"       = "LLM Conversacional"
        "pi.ai"                   = "LLM Conversacional"
        "inflection.ai"           = "LLM Conversacional"
        "kimi.moonshot.cn"        = "LLM Conversacional"
        "moonshot.cn"             = "LLM Conversacional"
        "qwenlm.ai"               = "LLM Conversacional"
        "chat.qwenlm.ai"          = "LLM Conversacional"
        "tongyi.aliyun.com"       = "LLM Conversacional"
        "yiyan.baidu.com"         = "LLM Conversacional"
        "doubao.com"              = "LLM Conversacional"
        "zhipuai.cn"              = "LLM Conversacional"
        "chatglm.cn"              = "LLM Conversacional"
        "01.ai"                   = "LLM Conversacional"
        "ilovepdf.com"            = "Procesamiento PDF / Docs"
        "www.ilovepdf.com"        = "Procesamiento PDF / Docs"
        "smallpdf.com"            = "Procesamiento PDF / Docs"
        "www.smallpdf.com"        = "Procesamiento PDF / Docs"
        "pdf24.org"               = "Procesamiento PDF / Docs"
        "tools.pdf24.org"         = "Procesamiento PDF / Docs"
        "sejda.com"               = "Procesamiento PDF / Docs"
        "sodapdf.com"             = "Procesamiento PDF / Docs"
        "pdfcandy.com"            = "Procesamiento PDF / Docs"
        "pdfforge.org"            = "Procesamiento PDF / Docs"
        "docfly.com"              = "Procesamiento PDF / Docs"
        "pdf2go.com"              = "Procesamiento PDF / Docs"
        "chatpdf.com"             = "Análisis Documental IA"
        "www.chatpdf.com"         = "Análisis Documental IA"
        "pdf.ai"                  = "Análisis Documental IA"
        "askyourpdf.com"          = "Análisis Documental IA"
        "humata.ai"               = "Análisis Documental IA"
        "docsumo.com"             = "Análisis Documental IA"
        "ross.ai"                 = "IA Legal no autorizada"
        "casetext.com"            = "IA Legal no autorizada"
        "spellbook.legal"         = "IA Legal no autorizada"
        "harvey.ai"               = "IA Legal no autorizada"
        "lawgeex.com"             = "IA Legal no autorizada"
        "luminance.com"           = "IA Legal no autorizada"
        "deepl.com"               = "Traducción Cloud sin DLP"
        "www.deepl.com"           = "Traducción Cloud sin DLP"
        "api.deepl.com"           = "Traducción Cloud sin DLP"
        "translate.google.com"    = "Traducción Cloud sin DLP"
        "reverso.net"             = "Traducción Cloud sin DLP"
        "grammarly.com"           = "Asistente de Escritura IA"
        "app.grammarly.com"       = "Asistente de Escritura IA"
        "coda.io"                 = "Productividad IA"
        "notion.so"               = "Productividad IA"
        "api.notion.com"          = "Productividad IA"
        "quillbot.com"            = "Asistente de Escritura IA"
        "wordtune.com"            = "Asistente de Escritura IA"
        "jasper.ai"               = "Asistente de Escritura IA"
        "copy.ai"                 = "Asistente de Escritura IA"
        "writesonic.com"          = "Asistente de Escritura IA"
        "rytr.me"                 = "Asistente de Escritura IA"
        "anyword.com"             = "Asistente de Escritura IA"
        "sudowrite.com"           = "Asistente de Escritura IA"
        "hyperwriteai.com"        = "Asistente de Escritura IA"
        "jenny.ai"                = "Asistente de Escritura IA"
        "otter.ai"                = "Transcripción de Reuniones IA"
        "fireflies.ai"            = "Transcripción de Reuniones IA"
        "read.ai"                 = "Transcripción de Reuniones IA"
        "tldv.io"                 = "Transcripción de Reuniones IA"
        "fathom.video"            = "Transcripción de Reuniones IA"
        "krisp.ai"                = "Transcripción de Reuniones IA"
        "grain.com"               = "Transcripción de Reuniones IA"
        "avoma.com"               = "Transcripción de Reuniones IA"
        "supernormal.com"         = "Transcripción de Reuniones IA"
        "notta.ai"                = "Transcripción de Reuniones IA"
        "sonix.ai"                = "Transcripción de Reuniones IA"
        "descript.com"            = "Audio / Video IA"
        "elevenlabs.io"           = "Audio / Video IA"
        "api.elevenlabs.io"       = "Audio / Video IA"
        "murf.ai"                 = "Audio / Video IA"
        "speechify.com"           = "Audio / Video IA"
        "suno.com"                = "Audio / Video IA"
        "udio.com"                = "Audio / Video IA"
        "midjourney.com"          = "Generación Multimedia IA"
        "leonardo.ai"             = "Generación Multimedia IA"
        "ideogram.ai"             = "Generación Multimedia IA"
        "runwayml.com"            = "Generación Multimedia IA"
        "pika.art"                = "Generación Multimedia IA"
        "luma.ai"                 = "Generación Multimedia IA"
        "sora.com"                = "Generación Multimedia IA"
        "stability.ai"            = "Generación Multimedia IA"
        "clipdrop.co"             = "Generación Multimedia IA"
        "canva.com"               = "Diseño / Suite IA"
        "gamma.app"               = "Presentaciones IA"
        "tome.app"                = "Presentaciones IA"
        "beautiful.ai"            = "Presentaciones IA"
        "slidesai.io"             = "Presentaciones IA"
        "cursor.sh"               = "Asistente de Código IA"
        "cursor.com"              = "Asistente de Código IA"
        "api2.cursor.sh"          = "Asistente de Código IA"
        "codeium.com"             = "Asistente de Código IA"
        "windsurf.ai"             = "Asistente de Código IA"
        "tabnine.com"             = "Asistente de Código IA"
        "sourcegraph.com"         = "Asistente de Código IA"
        "replit.com"              = "Asistente de Código IA"
        "v0.dev"                  = "Asistente de Código IA"
        "bolt.new"                = "Asistente de Código IA"
        "lovable.dev"             = "Asistente de Código IA"
        "julius.ai"               = "Análisis de Datos / Excel IA"
        "rows.com"                = "Análisis de Datos / Excel IA"
        "formulabot.com"          = "Análisis de Datos / Excel IA"
        "sheetai.app"             = "Análisis de Datos / Excel IA"
        "numerous.ai"             = "Análisis de Datos / Excel IA"
        "monica.im"               = "Extensión Navegador IA"
        "harpa.ai"                = "Extensión Navegador IA"
        "merlin.foyer.work"       = "Extensión Navegador IA"
        "sider.ai"                = "Extensión Navegador IA"
        "maxai.me"                = "Extensión Navegador IA"
        "glasp.co"                = "Extensión Navegador IA"
        "liner.com"               = "Extensión Navegador IA"
    }
}

function Resolve-CanonicalAiDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$DomainMap
    )

    $candidate = $Fqdn.Trim().ToLowerInvariant().TrimEnd('.')
    while (-not [string]::IsNullOrEmpty($candidate)) {
        if ($DomainMap.ContainsKey($candidate)) {
            return $candidate
        }
        $dotIdx = $candidate.IndexOf('.')
        if ($dotIdx -lt 0 -or $dotIdx -ge ($candidate.Length - 1)) {
            break
        }
        $candidate = $candidate.Substring($dotIdx + 1)
    }

    return $null
}

function Get-ShadowAiDnsHits {
    <#
    .SYNOPSIS
        Inspecciona la caché DNS local (Get-DnsClientCache) o entradas provistas contra el diccionario Shadow AI.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$DnsEntries,

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$DomainMap
    )

    if (-not $PSBoundParameters.ContainsKey("DomainMap") -or $null -eq $DomainMap) {
        $DomainMap = Get-ShadowAiDomainMap
    }

    if (-not $PSBoundParameters.ContainsKey("DnsEntries")) {
        try {
            $DnsEntries = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
        } catch {
            $DnsEntries = @()
        }
    }

    $hitsGrouped = @{}
    $utcNow = (Get-Date).ToUniversalTime().ToString("o")

    foreach ($entry in $DnsEntries) {
        if ($null -eq $entry) { continue }
        $rawName = $entry.Entry
        if ([string]::IsNullOrWhiteSpace($rawName)) { continue }

        $canonical = Resolve-CanonicalAiDomain -Fqdn ([string]$rawName) -DomainMap $DomainMap
        if ($null -eq $canonical) { continue }

        if (-not $hitsGrouped.ContainsKey($canonical)) {
            $hitsGrouped[$canonical] = [ordered]@{
                domain         = $canonical
                count          = 0
                category       = $DomainMap[$canonical]
                last_timestamp = $utcNow
            }
        }
        $hitsGrouped[$canonical].count += 1
    }

    $resultList = New-Object System.Collections.Generic.List[object]
    foreach ($item in $hitsGrouped.Values) {
        $resultList.Add($item)
    }

    return ,$resultList.ToArray()
}

function Get-RiskyBrowserExtensions {
    <#
    .SYNOPSIS
        Audita extensiones de Chrome y Edge en busca de permisos de interceptación o portapapeles de alto riesgo.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary[]]$BrowserRoots
    )

    if (-not $PSBoundParameters.ContainsKey("BrowserRoots") -or $null -eq $BrowserRoots) {
        $BrowserRoots = @(
            @{ Browser = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
            @{ Browser = "Edge";   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
        )
    }

    $wildcardHostPerms = @("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
    $riskyApiPerms = @("webRequest", "clipboardRead")

    $riskyExtensions = New-Object System.Collections.Generic.List[object]
    $seenExtensions = @{}

    foreach ($root in $BrowserRoots) {
        if ($null -eq $root -or [string]::IsNullOrWhiteSpace($root.Path) -or -not (Test-Path $root.Path)) {
            continue
        }

        $manifestFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
        $profileDirs = @(Get-ChildItem -Path $root.Path -Directory -ErrorAction SilentlyContinue)
        foreach ($profileDir in $profileDirs) {
            $extRoot = Join-Path $profileDir.FullName "Extensions"
            if (-not (Test-Path $extRoot)) {
                continue
            }
            $found = @(Get-ChildItem -Path $extRoot -Filter "manifest.json" -Recurse -File -ErrorAction SilentlyContinue)
            foreach ($f in $found) {
                $manifestFiles.Add($f)
            }
        }

        foreach ($manifestFile in $manifestFiles) {
            if ($manifestFile.FullName -notmatch "\\Extensions\\([^\\]+)\\([^\\]+)\\manifest\.json$") {
                continue
            }

            $extId = $Matches[1]
            $dedupKey = "$($root.Browser):$extId"
            if ($seenExtensions.ContainsKey($dedupKey)) {
                continue
            }

            try {
                $manifestJson = Get-Content -Path $manifestFile.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                $allPerms = New-Object System.Collections.Generic.List[string]

                foreach ($permSource in @($manifestJson.permissions, $manifestJson.host_permissions, $manifestJson.optional_permissions)) {
                    if ($null -eq $permSource) { continue }
                    foreach ($p in @($permSource)) {
                        if ($p -is [string] -and -not [string]::IsNullOrWhiteSpace($p)) {
                            $allPerms.Add($p)
                        }
                    }
                }

                $stringPerms = $allPerms.ToArray()
                $hasAllUrls = $false
                $hasRiskyApi = $false

                foreach ($p in $stringPerms) {
                    if ($p -in $wildcardHostPerms) {
                        $hasAllUrls = $true
                    }
                    if ($p -in $riskyApiPerms) {
                        $hasRiskyApi = $true
                    }
                }

                if ($hasAllUrls -or $hasRiskyApi) {
                    $extName = [string]$manifestJson.name
                    if ([string]::IsNullOrWhiteSpace($extName) -or $extName -like "__MSG_*") {
                        $extName = "Extensión Browser ($extId)"
                    }
                    $extVersion = if ([string]::IsNullOrWhiteSpace([string]$manifestJson.version)) { "0.0.0" } else { [string]$manifestJson.version }

                    $seenExtensions[$dedupKey] = $true
                    $riskyExtensions.Add([ordered]@{
                        extension_id = $extId
                        name         = $extName
                        browser      = [string]$root.Browser
                        version      = $extVersion
                        permissions  = @($stringPerms)
                        has_all_urls = $hasAllUrls
                    })
                }
            } catch {
                # Continuar si un manifest está corrupto o bloqueado por el navegador
            }
        }
    }

    return ,$riskyExtensions.ToArray()
}

function Get-BoxDriveSyncPaths {
    $candidates = @("$env:USERPROFILE\Box", "$env:USERPROFILE\Box Sync", "$env:LOCALAPPDATA\Box\Box")
    $resolved = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            $norm = $candidate.TrimEnd('\').ToLowerInvariant()
            if (-not $seen.ContainsKey($norm)) {
                $seen[$norm] = $true
                $resolved.Add($candidate)
            }
        }
    }
    return ,$resolved.ToArray()
}

function Get-OneDriveSyncPaths {
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($envCandidate in @($env:OneDriveCommercial, $env:OneDrive, $env:OneDriveConsumer)) {
        if (-not [string]::IsNullOrWhiteSpace($envCandidate)) {
            $candidates.Add($envCandidate)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE) -and (Test-Path $env:USERPROFILE)) {
        $profileDirs = @(Get-ChildItem -Path $env:USERPROFILE -Directory -Filter "OneDrive*" -ErrorAction SilentlyContinue)
        foreach ($dir in $profileDirs) {
            $candidates.Add($dir.FullName)
        }
    }

    $resolved = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            $norm = $candidate.TrimEnd('\').ToLowerInvariant()
            if (-not $seen.ContainsKey($norm)) {
                $seen[$norm] = $true
                $resolved.Add($candidate)
            }
        }
    }
    return ,$resolved.ToArray()
}

function Get-BoxDriveDlpState {
    foreach ($regPath in @("HKLM:\SOFTWARE\Box\Box", "HKLM:\SOFTWARE\Policies\Box\Box")) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            if ($props.EnterpriseDlpEnabled -eq 1 -or $props.BoxShieldEnabled -eq 1) {
                return $true
            }
        }
    }
    return $false
}

function Get-OneDriveDlpState {
    $aipPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
        "HKLM:\SOFTWARE\Microsoft\OneDrive",
        "HKCU:\Software\Microsoft\OneDrive"
    )
    foreach ($regPath in $aipPaths) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            if ($props.EnableAIPIntegration -eq 1 -or $props.DlpEnabled -eq 1 -or $props.BlockTenantSync -eq 1) {
                return $true
            }
        }
    }

    $mipProps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InformationProtection" -ErrorAction SilentlyContinue
    if ($null -ne $mipProps -and ($mipProps.EnableDlp -eq 1 -or $mipProps.DlpEnabled -eq 1)) {
        return $true
    }

    $wipProps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataProtection" -ErrorAction SilentlyContinue
    if ($null -ne $wipProps -and $wipProps.EnforcementLevel -ge 2) {
        return $true
    }

    return $false
}

function Invoke-CloudSyncFolderAudit {
    <#
    .SYNOPSIS
        Audita una carpeta local sincronizada (Box Drive o OneDrive) buscando PII natural panameña
        y palabras clave críticas, enmascarando siempre los nombres de archivo de muestra.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Provider,

        [Parameter(Mandatory = $false)]
        [string[]]$SyncPaths = @(),

        [Parameter(Mandatory = $false)]
        [bool]$DlpEnabled = $false,

        [Parameter(Mandatory = $false)]
        [int]$MaxFiles = 500,

        [Parameter(Mandatory = $false)]
        [int]$MaxSamples = 8,

        [Parameter(Mandatory = $false)]
        [int]$MaxScanMs = 5000
    )

    $existingPaths = New-Object System.Collections.Generic.List[string]
    foreach ($p in $SyncPaths) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path $p)) {
            $existingPaths.Add($p)
        }
    }

    $sensitiveKeywordsRegex = '(?i)(cedula|cédula|planilla|contrato|nomina|nómina|finanzas|kyc|fideicomiso|confidencial|expediente|paciente|historia.?clinica|vih|sindicato|biometrica|biométrica|pasaporte|salario|rrhh)'
    $targetExtensions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ext in @(".pdf", ".xlsx", ".docx", ".csv", ".xls", ".doc", ".txt")) {
        [void]$targetExtensions.Add($ext)
    }
    $skipDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($skip in @(".git", "node_modules", ".venv", "__pycache__", '$RECYCLE.BIN', "System Volume Information")) {
        [void]$skipDirs.Add($skip)
    }

    $totalFiles = 0
    $sensitiveCount = 0
    $samplesMasked = New-Object System.Collections.Generic.List[string]

    if ($existingPaths.Count -gt 0) {
        $docFilePaths = New-Object System.Collections.Generic.List[string]
        $queue = New-Object System.Collections.Generic.Queue[string]
        foreach ($syncDir in $existingPaths) {
            $queue.Enqueue($syncDir)
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($queue.Count -gt 0 -and $docFilePaths.Count -lt $MaxFiles -and $stopwatch.ElapsedMilliseconds -lt $MaxScanMs) {
            $currentDir = $queue.Dequeue()
            try {
                foreach ($filePath in [System.IO.Directory]::EnumerateFiles($currentDir)) {
                    $fileExt = [System.IO.Path]::GetExtension($filePath)
                    if ($targetExtensions.Contains($fileExt)) {
                        $docFilePaths.Add($filePath)
                        if ($docFilePaths.Count -ge $MaxFiles) { break }
                    }
                }
                if ($docFilePaths.Count -lt $MaxFiles -and $stopwatch.ElapsedMilliseconds -lt $MaxScanMs) {
                    foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($currentDir)) {
                        $dirName = [System.IO.Path]::GetFileName($subDir)
                        if (-not $skipDirs.Contains($dirName)) {
                            $queue.Enqueue($subDir)
                        }
                    }
                }
            } catch {
                # Omitir carpetas sin permisos de lectura o en sincronización bloqueada
            }
        }

        $totalFiles = $docFilePaths.Count
        foreach ($docPath in $docFilePaths) {
            $docName = [System.IO.Path]::GetFileName($docPath)
            $docDir = [System.IO.Path]::GetDirectoryName($docPath)
            $combinedText = "$docDir $docName"
            $hasNaturalId = Test-PanamaNaturalIdInText -Text $combinedText
            $hasSensitiveKeyword = ($docName -match $sensitiveKeywordsRegex) -or ($docDir -match $sensitiveKeywordsRegex)
            $hasSensitiveContext = Test-PanamaSensitiveContext -Text $combinedText

            if ($hasNaturalId -or $hasSensitiveKeyword -or $hasSensitiveContext) {
                $sensitiveCount += 1
                if ($samplesMasked.Count -lt $MaxSamples) {
                    $samplesMasked.Add((Mask-PiiToken -Token $docName))
                }
            }
        }
    }

    return [ordered]@{
        provider              = $Provider
        installed             = [bool]($existingPaths.Count -gt 0)
        sync_path             = if ($existingPaths.Count -gt 0) { $existingPaths[0] } else { $null }
        total_synced_files    = $totalFiles
        sensitive_files_count = $sensitiveCount
        dlp_enabled           = $DlpEnabled
        sample_files_masked   = @($samplesMasked.ToArray())
    }
}

function Test-CollectorUrlSecurity {
    <#
    .SYNOPSIS
        Verifica política HTTPS obligatoria: rechaza http:// sin -AllowInsecureHttp (salvo en -DryRun).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        [switch]$AllowInsecureHttp,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $trimmed = $Url.Trim()
    if ($trimmed -match '^\s*http://') {
        if ($DryRun) {
            return [pscustomobject]@{
                Allowed        = $true
                IsInsecureHttp = $true
                Reason         = "DryRun local omite la transmisión de red."
            }
        }
        if ($AllowInsecureHttp) {
            return [pscustomobject]@{
                Allowed        = $true
                IsInsecureHttp = $true
                Reason         = "HTTP permitido explícitamente mediante -AllowInsecureHttp."
            }
        }
        return [pscustomobject]@{
            Allowed        = $false
            IsInsecureHttp = $true
            Reason         = "Transmisión rechazada sobre HTTP en texto claro ('$trimmed'). Use HTTPS o pase -AllowInsecureHttp."
        }
    }

    if ($trimmed -match '^\s*https://') {
        return [pscustomobject]@{
            Allowed        = $true
            IsInsecureHttp = $false
            Reason         = "HTTPS verificado."
        }
    }

    return [pscustomobject]@{
        Allowed        = $false
        IsInsecureHttp = $false
        Reason         = "Esquema de URL no soportado en CollectorUrl: '$trimmed'. Use https://."
    }
}

function Resolve-CollectorEndpoint {
    <#
    .SYNOPSIS
        Resuelve la URL final de ingesta o heartbeat según ApiVersion y HeartbeatOnly.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectorUrl,

        [Parameter(Mandatory = $false)]
        [switch]$HeartbeatOnly,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1", "v2")]
        [string]$ApiVersion = "v1"
    )

    $base = $CollectorUrl.Trim().TrimEnd('/')
    if ($base -match '^(.*?)/api/v([12])/(ingest(?:/endpoint)?|health/heartbeat)$') {
        $rootUrl = $Matches[1]
        $detectedVer = "v$($Matches[2])"
        $ApiVersion = $detectedVer
        $base = $rootUrl
    }

    if ($ApiVersion -eq "v2") {
        if ($HeartbeatOnly) {
            return "$base/api/v2/health/heartbeat"
        }
        return "$base/api/v2/ingest/endpoint"
    }

    if ($HeartbeatOnly) {
        return "$base/api/v1/health/heartbeat"
    }
    return "$base/api/v1/ingest"
}

function New-CollectorHeaders {
    <#
    .SYNOPSIS
        Construye cabeceras HTTP para Vektor81 incluyendo X-Tenant-Id y Authorization Bearer cuando está configurado.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$CollectorToken = ""
    )

    $effectiveToken = if (-not [string]::IsNullOrWhiteSpace($CollectorToken)) {
        $CollectorToken.Trim()
    } else {
        $env:VEKTOR81_COLLECTOR_TOKEN
    }

    $headers = @{
        "X-Tenant-Id" = $TenantId
    }

    if (-not [string]::IsNullOrWhiteSpace($effectiveToken)) {
        $headers["Authorization"] = "Bearer $($effectiveToken.Trim())"
    } else {
        Write-Warning "[VEKTOR81] CollectorToken no proporcionado (-CollectorToken o VEKTOR81_COLLECTOR_TOKEN). Se omitirá la cabecera Authorization."
    }

    return $headers
}

function Get-EndpointHostContext {
    $hostname = if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
    $username = if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { "$env:USERDOMAIN\$env:USERNAME" } else { "$env:USERNAME" }

    $ipAddress = $null
    try {
        $ipAddress = (
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notmatch "Loopback|vEthernet|WSL" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -First 1
        ).IPAddress
    } catch {
        $ipAddress = $null
    }
    if ([string]::IsNullOrWhiteSpace($ipAddress)) { $ipAddress = "127.0.0.1" }

    $osInfo = $null
    try {
        $osInfo = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    } catch {
        $osInfo = $null
    }
    if ([string]::IsNullOrWhiteSpace($osInfo)) { $osInfo = "Windows 10/11 Enterprise" }

    return [pscustomobject]@{
        Hostname  = $hostname
        Username  = $username
        IpAddress = $ipAddress
        OsVersion = $osInfo
    }
}

function New-EndpointHeartbeat {
    <#
    .SYNOPSIS
        Genera el bloque HeartbeatPayload conforme a packages/shared-contracts/api-contracts.ts.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $false)]
        [string]$AgentVersion = "2.0.0",

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$Metadata,

        [Parameter(Mandatory = $false)]
        [string]$Timestamp
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        $Timestamp = (Get-Date).ToUniversalTime().ToString("o")
    }

    $hb = [ordered]@{
        tenant_id       = $TenantId
        component_layer = "ENDPOINT_AGENT"
        component_id    = $Hostname
        display_name    = "Windows Endpoint Agent ($Hostname)"
        status          = "ONLINE"
        version         = $AgentVersion
        timestamp       = $Timestamp
    }

    if ($PSBoundParameters.ContainsKey("Metadata") -and $null -ne $Metadata) {
        $hb["metadata"] = $Metadata
    }

    return $hb
}

function New-EndpointIngestPayload {
    <#
    .SYNOPSIS
        Construye el payload completo EndpointIngestPayload v2 con Box Drive, OneDrive y heartbeat embebido.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$HostContext,

        [Parameter(Mandatory = $false)]
        [string]$AgentVersion = "2.0.0",

        [Parameter(Mandatory = $false)]
        [object[]]$ShadowAiDnsHits = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$RiskyExtensions = @(),

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$BoxAudit,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$OneDriveAudit
    )

    $utcNow = (Get-Date).ToUniversalTime().ToString("o")
    $heartbeatBlock = New-EndpointHeartbeat -TenantId $TenantId -Hostname $HostContext.Hostname -AgentVersion $AgentVersion -Timestamp $utcNow

    [object[]]$dnsHitsArr = @()
    if ($null -ne $ShadowAiDnsHits) {
        $dnsHitsArr = @($ShadowAiDnsHits)
    }

    [object[]]$riskyExtArr = @()
    if ($null -ne $RiskyExtensions) {
        $riskyExtArr = @($RiskyExtensions)
    }

    return [ordered]@{
        tenant_id          = $TenantId
        hostname           = $HostContext.Hostname
        username           = $HostContext.Username
        ip_address         = $HostContext.IpAddress
        os_version         = $HostContext.OsVersion
        agent_version      = $AgentVersion
        shadow_ai_dns_hits = $dnsHitsArr
        risky_extensions   = $riskyExtArr
        box_audit          = $BoxAudit
        onedrive_audit     = $OneDriveAudit
        heartbeat          = $heartbeatBlock
        timestamp          = $utcNow
    }
}

# =====================================================================
# EJECUCIÓN PRINCIPAL (PROTEGIDA CONTRA DOT-SOURCING)
# =====================================================================

if ($MyInvocation.InvocationName -ne '.') {
    $securityCheck = Test-CollectorUrlSecurity -Url $CollectorUrl -AllowInsecureHttp:$AllowInsecureHttp -DryRun:$DryRun
    if (-not $securityCheck.Allowed) {
        Write-Error -Message "[VEKTOR81] $($securityCheck.Reason)" -ErrorAction Continue
        exit 1
    }

    if ($securityCheck.IsInsecureHttp -and $AllowInsecureHttp -and -not $DryRun) {
        Write-Warning "[VEKTOR81] Transmitiendo sobre HTTP en texto claro por -AllowInsecureHttp ($CollectorUrl)."
    }

    $hostContext = Get-EndpointHostContext
    $targetEndpoint = Resolve-CollectorEndpoint -CollectorUrl $CollectorUrl -HeartbeatOnly:$HeartbeatOnly -ApiVersion $ApiVersion

    if ($HeartbeatOnly) {
        $payload = New-EndpointHeartbeat -TenantId $TenantId -Hostname $hostContext.Hostname -AgentVersion $AgentVersion -Metadata @{
            hostname       = $hostContext.Hostname
            username       = $hostContext.Username
            ip_address     = $hostContext.IpAddress
            os_version     = $hostContext.OsVersion
            heartbeat_only = $true
        }
    } else {
        $shadowAiDnsHits = Get-ShadowAiDnsHits
        $riskyExtensions = Get-RiskyBrowserExtensions

        $boxPaths = Get-BoxDriveSyncPaths
        $boxDlp = Get-BoxDriveDlpState
        $boxAudit = Invoke-CloudSyncFolderAudit -Provider "BoxDrive" -SyncPaths $boxPaths -DlpEnabled $boxDlp

        $oneDrivePaths = Get-OneDriveSyncPaths
        $oneDriveDlp = Get-OneDriveDlpState
        $oneDriveAudit = Invoke-CloudSyncFolderAudit -Provider "OneDrive" -SyncPaths $oneDrivePaths -DlpEnabled $oneDriveDlp

        $payload = New-EndpointIngestPayload `
            -TenantId $TenantId `
            -HostContext $hostContext `
            -AgentVersion $AgentVersion `
            -ShadowAiDnsHits $shadowAiDnsHits `
            -RiskyExtensions $riskyExtensions `
            -BoxAudit $boxAudit `
            -OneDriveAudit $oneDriveAudit
    }

    if ($DryRun) {
        $prettyJson = $payload | ConvertTo-Json -Depth 6
        Write-Output $prettyJson
        exit 0
    }

    $headers = New-CollectorHeaders -TenantId $TenantId -CollectorToken $CollectorToken
    $jsonBody = $payload | ConvertTo-Json -Depth 6 -Compress
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri $targetEndpoint -Method Post -Headers $headers -Body $utf8Bytes -ContentType "application/json; charset=utf-8" -TimeoutSec 10 -ErrorAction Stop
        if ($HeartbeatOnly) {
            Write-Output "[VEKTOR81] Heartbeat enviado con éxito a $targetEndpoint desde $($hostContext.Hostname) ($($hostContext.IpAddress))."
        } else {
            Write-Output "[VEKTOR81] Auditoría enviada con éxito a $targetEndpoint desde $($hostContext.Hostname) ($($hostContext.IpAddress)) -> Score Endpoint: $($response.endpoint_risk_score)/100"
        }
    } catch {
        Write-Warning "[VEKTOR81] No se pudo contactar al Collector en $targetEndpoint : $($_.Exception.Message)"
        exit 1
    }
}
