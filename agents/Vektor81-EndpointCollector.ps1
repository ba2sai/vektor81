<#
.SYNOPSIS
    Agente Recolector Sin Huella (Zero-Footprint) — Vektor81 Shadow AI & Ley 81 Audit Appliance.
.DESCRIPTION
    Se ejecuta en estaciones Windows 10/11 (vía GPO, Tarea Programada o Intune/RMM) sin requerir permisos de administrador local.
    Audita 3 vectores críticos para el cumplimiento de la Ley 81 de Panamá:
      1. Caché local de resolución DNS (Get-DnsClientCache) buscando dominios de Shadow AI y convertidores PDF.
      2. Extensiones de Google Chrome y Microsoft Edge con privilegios peligrosos (<all_urls>, *://*/*, webRequest).
      3. Carpetas locales sincronizadas de Box Drive, contabilizando documentos (.pdf, .xlsx, .docx) y patrones de Cédula Panameña / RUC.
    Envía el resultado JSON al endpoint local: POST http://<APPLIANCE_IP>/api/v1/ingest
.PARAMETER ApplianceUrl
    URL base del Appliance Vektor81 en la red LAN (por defecto: http://192.168.10.200).
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ApplianceUrl = "http://192.168.10.200"
)

$ErrorActionPreference = "SilentlyContinue"

$IngestEndpoint = "$($ApplianceUrl.TrimEnd('/'))/api/v1/ingest"
$Hostname = $env:COMPUTERNAME
$Username = "$env:USERDOMAIN\$env:USERNAME"

# Obtener IPv4 activa de la interfaz LAN
$IpAddress = (
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch "Loopback|vEthernet|WSL" -and $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1
).IPAddress
if (-not $IpAddress) { $IpAddress = "127.0.0.1" }

$OsInfo = (Get-CimInstance Win32_OperatingSystem).Caption
if (-not $OsInfo) { $OsInfo = "Windows 10/11 Enterprise" }

# =====================================================================
# 1. AUDITORÍA DE CACHÉ DNS LOCAL (SHADOW AI DOMAINS)
# =====================================================================
$TargetAiDomains = @{
    "chatgpt.com"           = "LLM Conversacional"
    "chat.openai.com"       = "LLM Conversacional"
    "api.openai.com"        = "API LLM Pública"
    "claude.ai"             = "LLM Conversacional"
    "deepseek.com"          = "LLM Conversacional"
    "chat.deepseek.com"     = "LLM Conversacional"
    "perplexity.ai"         = "Buscador IA"
    "gemini.google.com"     = "LLM Conversacional"
    "copilot.microsoft.com" = "LLM Conversacional"
    "grok.com"              = "LLM Conversacional"
    "poe.com"               = "Agregador LLM"
    "mistral.ai"            = "LLM Conversacional"
    "huggingface.co"        = "Repositorio Modelos IA"
    "ilovepdf.com"          = "Procesamiento PDF / Docs"
    "smallpdf.com"          = "Procesamiento PDF / Docs"
    "pdf24.org"             = "Procesamiento PDF / Docs"
    "sejda.com"             = "Procesamiento PDF / Docs"
    "chatpdf.com"           = "Análisis Documental IA"
    "pdf.ai"                = "Análisis Documental IA"
    "humata.ai"             = "Análisis Documental IA"
    "deepl.com"             = "Traducción Cloud sin DLP"
    "quillbot.com"          = "Asistente de Escritura IA"
    "grammarly.com"         = "Asistente de Escritura IA"
    "otter.ai"              = "Transcripción de Reuniones IA"
    "fireflies.ai"          = "Transcripción de Reuniones IA"
    "read.ai"               = "Transcripción de Reuniones IA"
    "julius.ai"             = "Análisis de Datos / Excel IA"
    "monica.im"             = "Extensión Navegador IA"
    "harpa.ai"              = "Extensión Navegador IA"
    "sider.ai"              = "Extensión Navegador IA"
    "maxai.me"              = "Extensión Navegador IA"
    "cursor.sh"             = "Asistente de Código IA"
}

$DnsHitsGrouped = @{}
$DnsCacheEntries = Get-DnsClientCache

foreach ($Entry in $DnsCacheEntries) {
    $EntryName = ($Entry.Entry).ToLower().TrimEnd('.')
    foreach ($AiDom in $TargetAiDomains.Keys) {
        if ($EntryName -eq $AiDom -or $EntryName.EndsWith(".$AiDom")) {
            if (-not $DnsHitsGrouped.ContainsKey($AiDom)) {
                $DnsHitsGrouped[$AiDom] = @{
                    domain         = $AiDom
                    count          = 0
                    category       = $TargetAiDomains[$AiDom]
                    last_timestamp = (Get-Date).ToUniversalTime().ToString("o")
                }
            }
            $DnsHitsGrouped[$AiDom].count += 1
        }
    }
}

$ShadowAiDnsHitsList = @($DnsHitsGrouped.Values)

# =====================================================================
# 2. AUDITORÍA DE EXTENSIONES CHROME & EDGE CON PERMISO <all_urls>
# =====================================================================
$BrowserExtensionRoots = @(
    @{ Browser = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ Browser = "Edge";   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
)

$RiskyExtensionsList = @()
$SeenExtensions = @{}

foreach ($Root in $BrowserExtensionRoots) {
    if (-not (Test-Path $Root.Path)) { continue }

    $ManifestFiles = Get-ChildItem -Path $Root.Path -Filter "manifest.json" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\Extensions\\([^\\]+)\\([^\\]+)\\manifest\.json$" }

    foreach ($ManifestFile in $ManifestFiles) {
        if ($ManifestFile.FullName -match "\\Extensions\\([^\\]+)\\([^\\]+)\\manifest\.json$") {
            $ExtId = $Matches[1]
            $Key = "$($Root.Browser):$ExtId"
            if ($SeenExtensions.ContainsKey($Key)) { continue }

            try {
                $ManifestJson = Get-Content -Path $ManifestFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $AllPerms = @()
                if ($ManifestJson.permissions) { $AllPerms += $ManifestJson.permissions }
                if ($ManifestJson.host_permissions) { $AllPerms += $ManifestJson.host_permissions }
                if ($ManifestJson.optional_permissions) { $AllPerms += $ManifestJson.optional_permissions }

                $StringPerms = @($AllPerms | Where-Object { $_ -is [string] })
                $HasAllUrls = $false
                foreach ($p in $StringPerms) {
                    if ($p -in @("<all_urls>", "*://*/*", "http://*/*", "https://*/*")) {
                        $HasAllUrls = $true
                        break
                    }
                }

                if ($HasAllUrls) {
                    $ExtName = [string]$ManifestJson.name
                    if ($ExtName -like "__MSG_*") {
                        $ExtName = "Extensión Browser ($ExtId)"
                    }
                    $SeenExtensions[$Key] = $true
                    $RiskyExtensionsList += @{
                        extension_id = $ExtId
                        name         = $ExtName
                        browser      = $Root.Browser
                        version      = [string]$ManifestJson.version
                        permissions  = $StringPerms
                        has_all_urls = $true
                    }
                }
            } catch {
                # Continuar si un manifest está corrupto
            }
        }
    }
}

# =====================================================================
# 3. AUDITORÍA DE CARPETAS DE BOX DRIVE Y PATRONES LEY 81 (CÉDULA / RUC)
# =====================================================================
$BoxCandidatePaths = @(
    "$env:USERPROFILE\Box",
    "$env:USERPROFILE\Box Sync",
    "$env:LOCALAPPDATA\Box\Box"
)

$BoxSyncPath = $null
foreach ($Candidate in $BoxCandidatePaths) {
    if (Test-Path $Candidate) {
        $BoxSyncPath = $Candidate
        break
    }
}

$CedulaRegex = '\b(?:[1-9]|1[0-3]|PE|E|N)-\d{1,4}-\d{1,6}\b'
$SensitiveKeywordsRegex = '(?i)(cedula|cédula|planilla|contrato|nomina|nómina|finanzas|kyc|ruc|fideicomiso|confidencial)'

$BoxAuditObject = @{
    installed             = [bool]($null -ne $BoxSyncPath)
    sync_path             = $BoxSyncPath
    total_synced_files    = 0
    sensitive_files_count = 0
    dlp_enabled           = $false
    sample_files          = @()
}

# Verificar llave de registro corporativa de Box Shield / Enterprise DLP
$BoxEnterpriseReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Box\Box" -ErrorAction SilentlyContinue
if ($BoxEnterpriseReg -and $BoxEnterpriseReg.EnterpriseDlpEnabled -eq 1) {
    $BoxAuditObject.dlp_enabled = $true
}

if ($BoxSyncPath) {
    $DocFiles = Get-ChildItem -Path $BoxSyncPath -Include *.pdf, *.xlsx, *.docx, *.csv -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 500
    $BoxAuditObject.total_synced_files = ($DocFiles | Measure-Object).Count

    foreach ($Doc in $DocFiles) {
        $IsSensitive = $false
        if ($Doc.Name -match $CedulaRegex -or $Doc.Name -match $SensitiveKeywordsRegex -or $Doc.DirectoryName -match $SensitiveKeywordsRegex) {
            $IsSensitive = $true
        }

        if ($IsSensitive) {
            $BoxAuditObject.sensitive_files_count += 1
            if ($BoxAuditObject.sample_files.Count -lt 8) {
                $BoxAuditObject.sample_files += $Doc.Name
            }
        }
    }
}

# =====================================================================
# 4. ENVÍO DEL PAYLOAD JSON AL APPLIANCE VEKTOR81 (POST /api/v1/ingest)
# =====================================================================
$Payload = @{
    hostname           = $Hostname
    username           = $Username
    ip_address         = $IpAddress
    os_version         = $OsInfo
    shadow_ai_dns_hits = $ShadowAiDnsHitsList
    risky_extensions   = $RiskyExtensionsList
    box_audit          = $BoxAuditObject
}

$JsonBody = $Payload | ConvertTo-Json -Depth 6 -Compress

try {
    $Response = Invoke-RestMethod -Uri $IngestEndpoint -Method Post -Body $JsonBody -ContentType "application/json; charset=utf-8" -TimeoutSec 10
    Write-Output "[VEKTOR81] Auditoría enviada con éxito desde $Hostname ($IpAddress) -> Score Endpoint: $($Response.endpoint_risk_score)/100"
} catch {
    Write-Warning "[VEKTOR81] No se pudo contactar al Appliance en $IngestEndpoint : $($_.Exception.Message)"
}
