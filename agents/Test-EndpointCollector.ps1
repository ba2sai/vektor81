<#
.SYNOPSIS
    Suite de verificación determinista para Vektor81-EndpointCollector.ps1 (Vektor81 v2).
.DESCRIPTION
    Valida sintaxis AST, paridad con panama_pii_test_vectors.json, enmascaramiento PII,
    auditoría Box Drive / OneDrive / Extensiones / DNS Shadow AI, política HTTPS y ejecución -DryRun / -HeartbeatOnly.
#>

$ErrorActionPreference = "Stop"

$script:TotalChecks = 0
$script:PassedChecks = 0
$script:FailedChecks = 0

function Assert-Check {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $false)]
        [string]$Detail = ""
    )

    $script:TotalChecks += 1
    if ($Condition) {
        $script:PassedChecks += 1
        Write-Output "[PASS] $Name"
    } else {
        $script:FailedChecks += 1
        $suffix = if ([string]::IsNullOrWhiteSpace($Detail)) { "" } else { " :: $Detail" }
        Write-Output "[FAIL] $Name$suffix"
    }
}

$CollectorPath = Join-Path $PSScriptRoot "Vektor81-EndpointCollector.ps1"
$VectorsPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\packages\shared-contracts\panama_pii_test_vectors.json"))

Write-Output "=== Vektor81 v2 Windows Endpoint Collector Test Suite ==="
Write-Output "Collector: $CollectorPath"
Write-Output "Vectors:   $VectorsPath"

# 1. PowerShell AST Parse Check
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($CollectorPath, [ref]$tokens, [ref]$parseErrors)
$parseDetail = if ($parseErrors -and $parseErrors.Count -gt 0) {
    ($parseErrors | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; "
} else {
    ""
}
Assert-Check -Name "AST Parse Vektor81-EndpointCollector.ps1 (0 syntax errors)" -Condition ($parseErrors.Count -eq 0) -Detail $parseDetail

if ($parseErrors.Count -gt 0) {
    Write-Output "Aborting suite due to parse errors."
    exit 1
}

# 2. Dot-source pure helper functions without side effects
. $CollectorPath

$expectedFunctions = @(
    "Test-PanamaNaturalId",
    "Test-PanamaNaturalIdInText",
    "Find-PanamaNaturalIdsInText",
    "Test-PanamaSensitiveContext",
    "Mask-PiiToken",
    "Get-ShadowAiDomainMap",
    "Get-ShadowAiDnsHits",
    "Get-RiskyBrowserExtensions",
    "Invoke-CloudSyncFolderAudit",
    "Test-CollectorUrlSecurity",
    "Resolve-CollectorEndpoint",
    "New-CollectorHeaders",
    "New-EndpointHeartbeat",
    "New-EndpointIngestPayload"
)
$missingFunctions = @($expectedFunctions | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
Assert-Check -Name "Dot-sourcing exposes all helper functions" -Condition ($missingFunctions.Count -eq 0) -Detail ("Missing: " + ($missingFunctions -join ", "))

# 3. Panama PII Test Vectors Parity
$vectors = Get-Content -Path $VectorsPath -Raw -Encoding UTF8 | ConvertFrom-Json

$validIds = @($vectors.valid_natural_ids)
$validFailures = @()
foreach ($entry in $validIds) {
    if (-not (Test-PanamaNaturalId -Token $entry.token)) {
        $validFailures += $entry.token
    }
    if (-not (Test-PanamaNaturalId -Token $entry.token.ToLowerInvariant())) {
        $validFailures += "$($entry.token) (lowercase)"
    }
}
Assert-Check -Name "valid_natural_ids ($($validIds.Count) vectors + lowercase)" -Condition ($validFailures.Count -eq 0) -Detail ("Failed: " + ($validFailures -join ", "))

$dateCollisions = @($vectors.date_collisions_must_reject)
$dateFailures = @()
foreach ($d in $dateCollisions) {
    if (Test-PanamaNaturalId -Token $d) {
        $dateFailures += $d
    }
}
Assert-Check -Name "date_collisions_must_reject ($($dateCollisions.Count) vectors)" -Condition ($dateFailures.Count -eq 0) -Detail ("False positives: " + ($dateFailures -join ", "))

$corpRucs = @($vectors.corporate_juridica_must_exclude)
$corpFailures = @()
foreach ($c in $corpRucs) {
    if (Test-PanamaNaturalId -Token $c.token) {
        $corpFailures += $c.token
    }
}
if (Test-PanamaNaturalId -Token "8-12345-678901") {
    $corpFailures += "8-12345-678901"
}
Assert-Check -Name "corporate_juridica_must_exclude ($($corpRucs.Count) vectors + folio mercantil)" -Condition ($corpFailures.Count -eq 0) -Detail ("False positives: " + ($corpFailures -join ", "))

# Contextual natural ID docs
$docsById = @{}
foreach ($doc in $vectors.contextual_documents) {
    $docsById[$doc.id] = $doc
}

$docCorpVeto = $docsById["corp_without_cedula_veto"]
$resCorpVeto = Find-PanamaNaturalIdsInText -Text $docCorpVeto.text
Assert-Check -Name "Contextual doc: corp_without_cedula_veto rejects 8-123-4567" `
    -Condition ((-not (Test-PanamaNaturalIdInText -Text $docCorpVeto.text)) -and $resCorpVeto.CorporateContextDetected -and ($resCorpVeto.MatchedTokens.Count -eq 0)) `
    -Detail "Matched=$($resCorpVeto.MatchedTokens -join ',')"

$docCorpKeep = $docsById["corp_with_explicit_cedula_keep"]
$resCorpKeep = Find-PanamaNaturalIdsInText -Text $docCorpKeep.text
Assert-Check -Name "Contextual doc: corp_with_explicit_cedula_keep retains 8-714-2219" `
    -Condition ((Test-PanamaNaturalIdInText -Text $docCorpKeep.text) -and ($resCorpKeep.MatchedTokens -contains "8-714-2219")) `
    -Detail "Matched=$($resCorpKeep.MatchedTokens -join ',')"

$docHealth = $docsById["sensitive_health_hiv_elevate"]
$resHealth = Find-PanamaNaturalIdsInText -Text $docHealth.text
Assert-Check -Name "Contextual doc: sensitive_health_hiv_elevate detects 8-888-1234 + sensitive context" `
    -Condition ((Test-PanamaNaturalIdInText -Text $docHealth.text) -and ($resHealth.MatchedTokens -contains "8-888-1234") -and $resHealth.SensitiveContextDetected) `
    -Detail "Sensitive=$($resHealth.SensitiveContextDetected), Matched=$($resHealth.MatchedTokens -join ',')"

$docBio = $docsById["sensitive_biometric_union_elevate"]
$resBio = Find-PanamaNaturalIdsInText -Text $docBio.text
Assert-Check -Name "Contextual doc: sensitive_biometric_union_elevate detects E-8-104921 + sensitive context" `
    -Condition ((Test-PanamaNaturalIdInText -Text $docBio.text) -and ($resBio.MatchedTokens -contains "E-8-104921") -and $resBio.SensitiveContextDetected) `
    -Detail "Sensitive=$($resBio.SensitiveContextDetected), Matched=$($resBio.MatchedTokens -join ',')"

# 4. Mask-PiiToken & Sync Folder Audit (Box + OneDrive)
$maskedCedula = Mask-PiiToken -Token "8-888-1234"
$maskedFilename = Mask-PiiToken -Token "Planilla_8-888-1234_2026.xlsx"
Assert-Check -Name "Mask-PiiToken strips all digits from raw cedula and filename" `
    -Condition (($maskedCedula -notmatch '\d') -and ($maskedCedula -match '\*') -and ($maskedFilename -notmatch '\d') -and ($maskedFilename -like "Planilla_*.xlsx")) `
    -Detail "cedula='$maskedCedula', file='$maskedFilename'"

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vektor81-test-" + [Guid]::NewGuid().ToString("N"))
try {
    $syncDir = Join-Path $tempRoot "OneDriveTest"
    New-Item -ItemType Directory -Path $syncDir -Force | Out-Null
    Set-Content -Path (Join-Path $syncDir "Planilla_8-888-1234_Mayo.xlsx") -Value "test" -Encoding UTF8
    Set-Content -Path (Join-Path $syncDir "Expediente_E-8-104921.pdf") -Value "test" -Encoding UTF8
    Set-Content -Path (Join-Path $syncDir "Reporte_12-05-2026.pdf") -Value "test" -Encoding UTF8
    Set-Content -Path (Join-Path $syncDir "Factura_fiscal_S.A._8-123-4567.pdf") -Value "test" -Encoding UTF8

    $oneDriveAudit = Invoke-CloudSyncFolderAudit -Provider "OneDrive" -SyncPaths @($syncDir) -DlpEnabled $false
    $anyDigitsInSamples = @($oneDriveAudit.sample_files_masked | Where-Object { $_ -match '\d' })
    Assert-Check -Name "Invoke-CloudSyncFolderAudit counts sensitive docs without date/corp false positives and masks samples" `
        -Condition ($oneDriveAudit.installed -and $oneDriveAudit.total_synced_files -eq 4 -and $oneDriveAudit.sensitive_files_count -eq 2 -and $oneDriveAudit.sample_files_masked.Count -eq 2 -and $anyDigitsInSamples.Count -eq 0) `
        -Detail "total=$($oneDriveAudit.total_synced_files), sensitive=$($oneDriveAudit.sensitive_files_count), samples=$($oneDriveAudit.sample_files_masked -join ',')"

    $emptyBoxAudit = Invoke-CloudSyncFolderAudit -Provider "BoxDrive" -SyncPaths @() -DlpEnabled $false
    Assert-Check -Name "Invoke-CloudSyncFolderAudit reports empty BoxDrive cleanly" `
        -Condition ((-not $emptyBoxAudit.installed) -and $emptyBoxAudit.total_synced_files -eq 0 -and $emptyBoxAudit.sample_files_masked.Count -eq 0)

    # 5. Shadow AI DNS Map + DNS Hits + Risky Browser Extensions
    $domainMap = Get-ShadowAiDomainMap
    Assert-Check -Name "Get-ShadowAiDomainMap includes expanded ai_domains.json corpus (>= 150 domains)" `
        -Condition ($domainMap.Count -ge 150 -and $domainMap.ContainsKey("chatgpt.com") -and $domainMap.ContainsKey("ilovepdf.com") -and $domainMap.ContainsKey("notebooklm.google.com") -and $domainMap.ContainsKey("ross.ai")) `
        -Detail "Count=$($domainMap.Count)"

    $mockDns = @(
        [pscustomobject]@{ Entry = "sub.chatgpt.com" },
        [pscustomobject]@{ Entry = "chatgpt.com." },
        [pscustomobject]@{ Entry = "chat.openai.com" },
        [pscustomobject]@{ Entry = "microsoft.com" }
    )
    $dnsHits = Get-ShadowAiDnsHits -DnsEntries $mockDns
    $chatgptHit = $dnsHits | Where-Object { $_.domain -eq "chatgpt.com" }
    $chatOpenAiHit = $dnsHits | Where-Object { $_.domain -eq "chat.openai.com" }
    Assert-Check -Name "Get-ShadowAiDnsHits matches subdomains canonically and ignores benign domains" `
        -Condition ($dnsHits.Count -eq 2 -and $chatgptHit.count -eq 2 -and $chatOpenAiHit.count -eq 1) `
        -Detail "Hits=$($dnsHits.Count)"

    $chromeUserData = Join-Path $tempRoot "ChromeUserData"
    $edgeUserData = Join-Path $tempRoot "EdgeUserData"
    $ext1Dir = Join-Path $chromeUserData "Default\Extensions\extallurls123\1.0.0"
    $ext2Dir = Join-Path $edgeUserData "Profile 1\Extensions\extclipweb456\2.1.0"
    $ext3Dir = Join-Path $chromeUserData "Default\Extensions\extsafe789\1.0.0"
    New-Item -ItemType Directory -Path $ext1Dir, $ext2Dir, $ext3Dir -Force | Out-Null

    '{"name":"AI All URLs Helper","version":"1.0.0","permissions":["<all_urls>","tabs"]}' | Set-Content (Join-Path $ext1Dir "manifest.json") -Encoding UTF8
    '{"name":"Clipboard Interceptor","version":"2.1.0","permissions":["clipboardRead","webRequest"]}' | Set-Content (Join-Path $ext2Dir "manifest.json") -Encoding UTF8
    '{"name":"Safe Theme","version":"1.0.0","permissions":["storage"]}' | Set-Content (Join-Path $ext3Dir "manifest.json") -Encoding UTF8

    $mockRoots = @(
        @{ Browser = "Chrome"; Path = $chromeUserData },
        @{ Browser = "Edge"; Path = $edgeUserData }
    )
    $riskyExts = Get-RiskyBrowserExtensions -BrowserRoots $mockRoots
    $ext1 = $riskyExts | Where-Object { $_.extension_id -eq "extallurls123" }
    $ext2 = $riskyExts | Where-Object { $_.extension_id -eq "extclipweb456" }
    Assert-Check -Name "Get-RiskyBrowserExtensions detects <all_urls>, webRequest, clipboardRead and ignores safe extensions" `
        -Condition ($riskyExts.Count -eq 2 -and $ext1.has_all_urls -eq $true -and $ext2.has_all_urls -eq $false -and $ext2.browser -eq "Edge") `
        -Detail "Detected=$($riskyExts.Count)"
} finally {
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 6. HTTPS Enforcement, Routing & Headers
$httpsCheck = Test-CollectorUrlSecurity -Url "https://collector.vektor81.local"
$httpBlockedCheck = Test-CollectorUrlSecurity -Url "http://collector.vektor81.local"
$httpAllowedCheck = Test-CollectorUrlSecurity -Url "http://collector.vektor81.local" -AllowInsecureHttp
$httpDryRunCheck = Test-CollectorUrlSecurity -Url "http://collector.vektor81.local" -DryRun

Assert-Check -Name "Test-CollectorUrlSecurity enforces HTTPS unless -AllowInsecureHttp or -DryRun" `
    -Condition ($httpsCheck.Allowed -and (-not $httpBlockedCheck.Allowed) -and $httpAllowedCheck.Allowed -and $httpDryRunCheck.Allowed)

Assert-Check -Name "Resolve-CollectorEndpoint resolves v1/v2 ingest and heartbeat routes" `
    -Condition (
        (Resolve-CollectorEndpoint -CollectorUrl "https://collector.vektor81.local") -eq "https://collector.vektor81.local/api/v1/ingest" -and
        (Resolve-CollectorEndpoint -CollectorUrl "https://collector.vektor81.local" -HeartbeatOnly) -eq "https://collector.vektor81.local/api/v1/health/heartbeat" -and
        (Resolve-CollectorEndpoint -CollectorUrl "https://control.vektor81.local" -ApiVersion "v2") -eq "https://control.vektor81.local/api/v2/ingest/endpoint" -and
        (Resolve-CollectorEndpoint -CollectorUrl "https://control.vektor81.local" -HeartbeatOnly -ApiVersion "v2") -eq "https://control.vektor81.local/api/v2/health/heartbeat"
    )

$prevEnvToken = $env:VEKTOR81_COLLECTOR_TOKEN
try {
    $env:VEKTOR81_COLLECTOR_TOKEN = ""
    $warnMessages = @()
    $noAuthHeaders = New-CollectorHeaders -TenantId "banco-istmo" -WarningVariable warnMessages 3>$null
    $authHeaders = New-CollectorHeaders -TenantId "banco-istmo" -CollectorToken "secret-tok-1"
    Assert-Check -Name "New-CollectorHeaders sets X-Tenant-Id, Bearer token when provided, and warns cleanly when missing" `
        -Condition (
            $noAuthHeaders["X-Tenant-Id"] -eq "banco-istmo" -and
            (-not $noAuthHeaders.ContainsKey("Authorization")) -and
            $warnMessages.Count -ge 1 -and
            $authHeaders["Authorization"] -eq "Bearer secret-tok-1"
        )
} finally {
    $env:VEKTOR81_COLLECTOR_TOKEN = $prevEnvToken
}

# 7. Subprocess CLI Tests (-DryRun, -HeartbeatOnly, and HTTP refusal exit code)
function Invoke-CollectorSubprocess {
    param([string[]]$Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = ($Arguments -join " ")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

$httpRefusal = Invoke-CollectorSubprocess -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$CollectorPath`"",
    "-CollectorUrl", "`"http://plaintext.vektor81.local`""
)
Assert-Check -Name "CLI rejects plaintext http:// without -AllowInsecureHttp (non-zero exit)" `
    -Condition ($httpRefusal.ExitCode -ne 0 -and ($httpRefusal.StdErr -match "HTTP|rechazada|https")) `
    -Detail "ExitCode=$($httpRefusal.ExitCode)"

$dryRunHttp = Invoke-CollectorSubprocess -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$CollectorPath`"",
    "-CollectorUrl", "`"http://plaintext.vektor81.local`"",
    "-DryRun",
    "-TenantId", "`"banco-istmo`""
)
$dryRunHttpObj = $null
try {
    $dryRunHttpObj = $dryRunHttp.StdOut | ConvertFrom-Json
} catch {
    $dryRunHttpObj = $null
}
Assert-Check -Name "CLI -DryRun succeeds with valid JSON (even on http:// URL)" `
    -Condition (
        $dryRunHttp.ExitCode -eq 0 -and
        $null -ne $dryRunHttpObj -and
        $dryRunHttpObj.tenant_id -eq "banco-istmo" -and
        $dryRunHttpObj.agent_version -eq "2.0.0" -and
        $dryRunHttpObj.box_audit.provider -eq "BoxDrive" -and
        $dryRunHttpObj.onedrive_audit.provider -eq "OneDrive" -and
        $dryRunHttpObj.heartbeat.component_layer -eq "ENDPOINT_AGENT" -and
        $dryRunHttpObj.heartbeat.component_id -eq $env:COMPUTERNAME -and
        $dryRunHttpObj.heartbeat.status -eq "ONLINE" -and
        $dryRunHttpObj.heartbeat.version -eq "2.0.0"
    ) `
    -Detail "ExitCode=$($dryRunHttp.ExitCode)"

$hbOnlyRun = Invoke-CollectorSubprocess -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$CollectorPath`"",
    "-DryRun",
    "-HeartbeatOnly",
    "-TenantId", "`"clinica-pacifica`""
)
$hbObj = $null
try {
    $hbObj = $hbOnlyRun.StdOut | ConvertFrom-Json
} catch {
    $hbObj = $null
}
Assert-Check -Name "CLI -DryRun -HeartbeatOnly emits lightweight HeartbeatPayload without full scan" `
    -Condition (
        $hbOnlyRun.ExitCode -eq 0 -and
        $null -ne $hbObj -and
        $hbObj.tenant_id -eq "clinica-pacifica" -and
        $hbObj.component_layer -eq "ENDPOINT_AGENT" -and
        $hbObj.component_id -eq $env:COMPUTERNAME -and
        $hbObj.status -eq "ONLINE" -and
        $hbObj.version -eq "2.0.0" -and
        $hbObj.metadata.heartbeat_only -eq $true -and
        ($null -eq $hbObj.PSObject.Properties["box_audit"])
    ) `
    -Detail "ExitCode=$($hbOnlyRun.ExitCode)"

$defaultDryRun = Invoke-CollectorSubprocess -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$CollectorPath`"",
    "-DryRun"
)
$defaultDryObj = $null
try {
    $defaultDryObj = $defaultDryRun.StdOut | ConvertFrom-Json
} catch {
    $defaultDryObj = $null
}
$boxSamplesHaveDigits = @($defaultDryObj.box_audit.sample_files_masked | Where-Object { $_ -match '\d' }).Count -gt 0
$odSamplesHaveDigits = @($defaultDryObj.onedrive_audit.sample_files_masked | Where-Object { $_ -match '\d' }).Count -gt 0
Assert-Check -Name "CLI default -DryRun emits valid v2 JSON with default-tenant and zero raw digits in masked samples" `
    -Condition (
        $defaultDryRun.ExitCode -eq 0 -and
        $null -ne $defaultDryObj -and
        $defaultDryObj.tenant_id -eq "default-tenant" -and
        (-not $boxSamplesHaveDigits) -and
        (-not $odSamplesHaveDigits)
    ) `
    -Detail "ExitCode=$($defaultDryRun.ExitCode)"

# 8. Edge cases & 1-element array JSON serialization check
$edgeRejected = @(
    (Test-PanamaNaturalId -Token ""),
    (Test-PanamaNaturalId -Token "08-888-1234"),
    (Test-PanamaNaturalId -Token "8-0-1234"),
    (Test-PanamaNaturalId -Token "8-888-0"),
    (Test-PanamaNaturalId -Token "14-100-200")
)
Assert-Check -Name "Test-PanamaNaturalId rejects malformed/zero/out-of-range province tokens" `
    -Condition (@($edgeRejected | Where-Object { $_ -eq $true }).Count -eq 0)

$singleHostCtx = [pscustomobject]@{ Hostname = "TEST-PC"; Username = "CORP\user"; IpAddress = "10.0.0.5"; OsVersion = "Windows 11 Pro" }
$singleDns = @([ordered]@{ domain = "chatgpt.com"; count = 1; category = "LLM Conversacional"; last_timestamp = "2026-11-21T00:00:00Z" })
$singleExt = @([ordered]@{ extension_id = "ext1"; name = "Ext"; browser = "Chrome"; version = "1.0"; permissions = @("<all_urls>"); has_all_urls = $true })
$singleBox = [ordered]@{ provider = "BoxDrive"; installed = $true; sync_path = "C:\Box"; total_synced_files = 1; sensitive_files_count = 1; dlp_enabled = $false; sample_files_masked = @("Planilla_*-***-****.xlsx") }
$singleOd = [ordered]@{ provider = "OneDrive"; installed = $false; sync_path = $null; total_synced_files = 0; sensitive_files_count = 0; dlp_enabled = $false; sample_files_masked = @() }
$singlePayloadJson = (New-EndpointIngestPayload -TenantId "t1" -HostContext $singleHostCtx -ShadowAiDnsHits $singleDns -RiskyExtensions $singleExt -BoxAudit $singleBox -OneDriveAudit $singleOd) | ConvertTo-Json -Depth 6 -Compress
$singleParsed = $singlePayloadJson | ConvertFrom-Json
Assert-Check -Name "New-EndpointIngestPayload preserves JSON arrays for 0- and 1-element collections" `
    -Condition (
        $singlePayloadJson -match '"shadow_ai_dns_hits":\[\{' -and
        $singlePayloadJson -match '"risky_extensions":\[\{' -and
        $singlePayloadJson -match '"permissions":\["' -and
        $singleParsed.risky_extensions[0].permissions[0] -eq "<all_urls>" -and
        $singlePayloadJson -match '"sample_files_masked":\["Planilla_\*-\*\*\*-\*\*\*\*\.xlsx"\]' -and
        $singlePayloadJson -match '"sample_files_masked":\[\]'
    ) `
    -Detail $singlePayloadJson

Write-Output ""
Write-Output "Summary: $script:PassedChecks/$script:TotalChecks passed, $script:FailedChecks failed."
if ($script:FailedChecks -gt 0) {
    exit 1
}
exit 0
