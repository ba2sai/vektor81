<#
.SYNOPSIS
    Guarda avances locales en Git y realiza push seguro hacia https://github.com/ba2sai/vektor81.git.
.DESCRIPTION
    Valida rama activa, verifica remoto origin, bloquea archivos secretos/binarios no ignorados,
    crea commit si hay cambios y sube la rama activa usando credenciales del sistema (sin prompts colgados).
.PARAMETER Message
    Mensaje del commit. Si se omite y hay cambios, genera "chore: guardar avance (YYYY-MM-DD HH:mm)".
.PARAMETER RepoUrl
    URL HTTPS del repositorio remoto esperado (por defecto: https://github.com/ba2sai/vektor81.git).
.PARAMETER DryRun
    Simula todas las validaciones e imprime las acciones sin modificar Git ni hacer push.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Message = "",

    [Parameter(Mandatory = $false)]
    [string]$RepoUrl = "https://github.com/ba2sai/vektor81.git",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"
$env:GIT_TERMINAL_PROMPT = "0"

function Normalize-RepoUrl {
    param([string]$Url)
    return ($Url.Trim().TrimEnd('/') -replace '\.git$', '').ToLowerInvariant()
}

function Invoke-GitCapture {
    param([string[]]$GitArgs)
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & git @GitArgs 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    return @{
        ExitCode = $code
        Output   = ($output | ForEach-Object { $_.ToString() })
    }
}

# 1. Ubicar raíz del repositorio Git
$rootRes = Invoke-GitCapture -GitArgs @("rev-parse", "--show-toplevel")
if ($rootRes.ExitCode -ne 0 -or -not $rootRes.Output) {
    Write-Error "[guardar-avance] No se encontró un repositorio Git válido desde $((Get-Location).Path)."
    exit 1
}
$RepoRoot = ($rootRes.Output | Select-Object -First 1).Trim()
Push-Location $RepoRoot

try {
    # 2. Validar rama activa (no detached HEAD)
    $branchRes = Invoke-GitCapture -GitArgs @("branch", "--show-current")
    $Branch = ($branchRes.Output -join "").Trim()
    if ($branchRes.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($Branch)) {
        Write-Error "[guardar-avance] Repositorio en estado 'detached HEAD'. Cambia a una rama antes de guardar avance."
        exit 1
    }

    # 3. Validar o configurar remoto origin
    $expectedNorm = Normalize-RepoUrl -Url $RepoUrl
    $originRes = Invoke-GitCapture -GitArgs @("remote", "get-url", "origin")
    $hasOrigin = ($originRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace(($originRes.Output -join "")))

    if ($hasOrigin) {
        $currentOrigin = ($originRes.Output | Select-Object -First 1).Trim()
        if ((Normalize-RepoUrl -Url $currentOrigin) -ne $expectedNorm) {
            Write-Error "[guardar-avance] El remoto 'origin' actual ($currentOrigin) no coincide con '$RepoUrl'. Aborting sin sobrescribir."
            exit 1
        }
        Write-Output "[guardar-avance] Remoto origin verificado: $currentOrigin"
    } else {
        if ($DryRun) {
            Write-Output "[DRY-RUN] Se agregaría remoto: git remote add origin $RepoUrl"
        } else {
            $addRem = Invoke-GitCapture -GitArgs @("remote", "add", "origin", $RepoUrl)
            if ($addRem.ExitCode -ne 0) {
                Write-Error "[guardar-avance] No se pudo agregar remoto origin ($RepoUrl): $($addRem.Output -join "`n")"
                exit 1
            }
            Write-Output "[guardar-avance] Remoto origin agregado: $RepoUrl"
        }
    }

    # 4. Revisar estado y bloquear archivos secretos o artefactos pesados
    $statusRes = Invoke-GitCapture -GitArgs @("status", "--porcelain", "-uall")
    if ($statusRes.ExitCode -ne 0) {
        Write-Error "[guardar-avance] Error consultando git status: $($statusRes.Output -join "`n")"
        exit 1
    }

    $statusLines = @($statusRes.Output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $blockedFiles = @()
    $forbiddenPattern = '(^|[/\\])(\.env(\..+)?|\.dev\.vars|.*\.pem|.*\.key|.*\.tfvars|.*\.sqlite3?|.*\.db|\.venv|node_modules)$'
    $allowedExceptions = '(^|[/\\])(\.env\.example|terraform\.tfvars\.example)$'

    foreach ($line in $statusLines) {
        if ($line.Length -lt 4) { continue }
        $rawPath = $line.Substring(3).Trim().Trim('"')
        if ($rawPath -match ' -> ') {
            $rawPath = ($rawPath -split ' -> ')[-1].Trim().Trim('"')
        }
        $isDeleted = $line.Substring(0, 2) -match 'D'
        if ($isDeleted) { continue }

        if ($rawPath -match $forbiddenPattern -and $rawPath -notmatch $allowedExceptions) {
            $blockedFiles += $rawPath
        } elseif ($rawPath -match '(^|[/\\])(\.venv|node_modules)[/\\]') {
            $blockedFiles += $rawPath
        }
    }

    if ($blockedFiles.Count -gt 0) {
        Write-Error "[guardar-avance] BLOQUEADO por seguridad. Archivos sensibles o de entorno detectados sin ignorar: $($blockedFiles -join ', ')"
        exit 1
    }

    # 5. Commit si existen cambios locales
    $committed = $false
    if ($statusLines.Count -gt 0) {
        $commitMsg = if ([string]::IsNullOrWhiteSpace($Message)) {
            "chore: guardar avance ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
        } else {
            $Message.Trim()
        }

        if ($DryRun) {
            Write-Output "[DRY-RUN] Cambios detectados ($($statusLines.Count) rutas). Se ejecutaría: git add -A && git commit -m `"$commitMsg`""
        } else {
            $addRes = Invoke-GitCapture -GitArgs @("add", "-A")
            if ($addRes.ExitCode -ne 0) {
                Write-Error "[guardar-avance] Error en git add: $($addRes.Output -join "`n")"
                exit 1
            }

            $commitRes = Invoke-GitCapture -GitArgs @("commit", "-m", $commitMsg)
            if ($commitRes.ExitCode -ne 0) {
                Write-Error "[guardar-avance] Error en git commit: $($commitRes.Output -join "`n")"
                exit 1
            }
            $committed = $true
            Write-Output "[guardar-avance] Commit creado: $commitMsg"
        }
    } else {
        Write-Output "[guardar-avance] Árbol de trabajo limpio; sin cambios nuevos que commitear."
    }

    # 6. Verificar si hay commits pendientes por subir o ejecutar push
    $headRes = Invoke-GitCapture -GitArgs @("rev-parse", "--short", "HEAD")
    $headSha = ($headRes.Output | Select-Object -First 1).Trim()

    if ($DryRun) {
        Write-Output "[DRY-RUN] Se ejecutaría: git push -u origin $Branch (HEAD actual: $headSha)"
        Write-Output "[DRY-RUN] Validación completada sin errores."
        exit 0
    }

    $pushRes = Invoke-GitCapture -GitArgs @("push", "-u", "origin", $Branch)
    if ($pushRes.ExitCode -ne 0) {
        $errText = ($pushRes.Output -join "`n")
        Write-Warning "[guardar-avance] Push fallido hacia $RepoUrl (rama: $Branch, HEAD: $headSha)."
        Write-Warning "[guardar-avance] Detalle: $errText"
        Write-Warning "[guardar-avance] Si es un problema de credenciales GitHub, autentica con 'gh auth login' o Git Credential Manager y reintenta: git push -u origin $Branch"
        exit 2
    }

    $postStatus = Invoke-GitCapture -GitArgs @("status", "--short")
    $logRes = Invoke-GitCapture -GitArgs @("log", "-n", "2", "--oneline")

    Write-Output "[guardar-avance] Push completado con éxito."
    Write-Output "  Rama:   $Branch"
    Write-Output "  Remoto: $RepoUrl"
    Write-Output "  HEAD:   $headSha"
    Write-Output "  Commit: $(if ($committed) { 'nuevo commit creado' } else { 'commits previos sincronizados' })"
    Write-Output "  Logs recientes:"
    $logRes.Output | ForEach-Object { Write-Output "    $_" }
    if ($postStatus.Output) {
        Write-Output "  Pendientes: $($postStatus.Output -join '; ')"
    } else {
        Write-Output "  Estado: Árbol limpio"
    }
    exit 0
} finally {
    Pop-Location
}
