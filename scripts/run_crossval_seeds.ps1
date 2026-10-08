<#
.SYNOPSIS
    Runs the k-fold cross-validation (src.pipeline.crossval) once per seed, one
    after the other, logging each seed to logs\runs\. Rules go to rules\crossval\,
    never to rules\accepted\.

.DESCRIPTION
    Combo D (Qwen3-Coder-30B-A3B) keeps about 16.5 GB resident, so the script
    refuses to start with less than -MinFreeGB of free RAM or while another
    synthesis/cross-validation process is running. Close games, browsers and
    chat apps first, run it from your own terminal and leave the machine alone:
    one seed takes about 50 minutes with combo D. A failing seed does not stop
    the next one; the exit code of each is listed at the end.

.EXAMPLE
    .\scripts\run_crossval_seeds.ps1                       # seeds 1 and 2, combo D, CWE-416
    .\scripts\run_crossval_seeds.ps1 -Seeds 3,4,5          # other seeds
    .\scripts\run_crossval_seeds.ps1 -Combo C -MinFreeGB 6 # the small model needs far less RAM
    .\scripts\run_crossval_seeds.ps1 -NoDocs               # prompts without the Semgrep documentation (ablation)
    .\scripts\run_crossval_seeds.ps1 -Combo E -Tag critic -Extra "--critic"   # another option of crossval, tagged in the log name
    .\scripts\run_crossval_seeds.ps1 -NoDocs -ResumeSince 20261007-230000   # continue an interrupted run: finished folds are reused
    .\scripts\run_crossval_seeds.ps1 -DryRun               # only prints what it would run

.NOTES
    If script execution is blocked, run once:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#>
param(
    [string[]]$Seeds = @("1", "2"),
    [string]$Combo = "D",
    [string]$Cwe = "CWE-416",
    [int]$Folds = 5,
    [string]$Format = "template",
    [int]$MaxFixAttempts = 6,
    [string]$Negatives = "../git",
    [double]$MinFreeGB = 20,
    [switch]$NoDocs,
    [string]$ResumeSince = "",
    [string[]]$Extra = @(),
    [string]$Tag = "",
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# "-Seeds 3,4,5" arrives as a single string when the script is started with `powershell -File`: split it.
$seedList = @($Seeds | ForEach-Object { $_ -split "[,\s]+" } | Where-Object { $_ } | ForEach-Object { [int]$_ })
if ($seedList.Count -eq 0) {
    throw "No seeds given."
}

$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "Missing $py. Run .\scripts\setup_windows.ps1 first."
}
if (-not (Test-Path $Negatives)) {
    throw "Real-world code directory not found: $Negatives (clone git/git next to this repository or pass -Negatives)."
}

# --- pre-flight checks ------------------------------------------------------
$freeGB = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
Write-Host "Free RAM: $freeGB GB (needs $MinFreeGB GB for combo $Combo)"
if ($freeGB -lt $MinFreeGB -and -not $Force -and -not $DryRun) {
    throw "Only $freeGB GB of RAM is free. Close other programs, or pass -Force to run anyway."
}

$running = @(Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match "python" -and $_.CommandLine -match "src\.pipeline\.(crossval|synthesize)" })
if ($running.Count -gt 0 -and -not $DryRun) {
    $ids = ($running | ForEach-Object { $_.ProcessId }) -join ", "
    throw "Another synthesis/cross-validation is running (PID $ids). Wait for it or end it first."
}

New-Item -ItemType Directory -Force "logs\runs" | Out-Null
$env:PYTHONUTF8 = "1"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$results = @()

# --- one cross-validation per seed ------------------------------------------
foreach ($seed in $seedList) {
    # not `$tag`: PowerShell variable names are case-insensitive, so that would overwrite the -Tag parameter
    $logTag = $(if ($NoDocs) { "_nodocs" } else { "" }) + $(if ($Tag) { "_$Tag" } else { "" })
    $log = "logs\runs\crossval_${Combo}_${Cwe}${logTag}_seed${seed}_${stamp}.log"
    $cmdArgs = @("-u", "-m", "src.pipeline.crossval",
        "--combo", $Combo, "--cwe", $Cwe, "--folds", $Folds, "--seed", $seed,
        "--format", $Format, "--max-fix-attempts", $MaxFixAttempts, "--negatives", $Negatives)
    if ($NoDocs) { $cmdArgs += "--no-docs" }
    if ($Extra.Count -gt 0) { $cmdArgs += $Extra }
    if ($ResumeSince) { $cmdArgs += @("--resume-since", $ResumeSince) }  # reuse the folds an interrupted run already finished

    Write-Host ""
    Write-Host "=== seed $seed ($(Get-Date -Format 'HH:mm:ss')) -> $log"
    Write-Host "$py $($cmdArgs -join ' ')"
    if ($DryRun) {
        $results += [pscustomobject]@{ Seed = $seed; ExitCode = "dry run"; Log = $log }
        continue
    }

    # stderr goes to the log too (tracebacks); "$_" turns PowerShell's error records into plain text, and the
    # preference is relaxed for the call because Windows PowerShell 5.1 would otherwise stop on the first stderr line.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $py @cmdArgs 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    $results += [pscustomobject]@{ Seed = $seed; ExitCode = $code; Log = $log }
}

# --- summary ----------------------------------------------------------------
Write-Host ""
Write-Host "=== done ($(Get-Date -Format 'HH:mm:ss'))"
$results | Format-Table -AutoSize
if (-not $DryRun) {
    Write-Host "Per-seed summaries (mean and standard deviation over folds): logs\crossval\$Combo\$Cwe\*.json"
    Write-Host "Per-fold run logs: logs\synthesis\$Combo\$Cwe\   Rules: rules\crossval\"
}
