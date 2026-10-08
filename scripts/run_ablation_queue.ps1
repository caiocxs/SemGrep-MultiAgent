<#
.SYNOPSIS
    Runs the planned comparisons of docs/ablation_plan.md one after another (5-fold cross-validation of CWE-416 per
    seed), waiting for free RAM before each one. Each experiment is tagged in its log names (logs\runs\).

.DESCRIPTION
    Combo D (and E) keep about 16.5 GB resident, so the queue waits until -MinFreeGB of RAM is free before starting an
    experiment, and gives up on it after -MaxWaitMinutes. Run it from your own terminal, close games and browsers first
    and leave the machine alone: about 100 minutes per experiment with two seeds for the 30B ones (the two small-model experiments take minutes), about 14 hours for the eight of them.
    A failing experiment does not stop the next one. Compare the results with B0 (the final configuration, seeds 1 and 2
    already exist) using: python -m src.pipeline.compare --a <B0 summaries> --b <experiment summaries>

.EXAMPLE
    .\scripts\run_ablation_queue.ps1 -DryRun                    # only prints what would run
    .\scripts\run_ablation_queue.ps1 -Only nodocs,history       # two of them
    .\scripts\run_ablation_queue.ps1                            # all, seeds 1 and 2

.NOTES
    If script execution is blocked, run once:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#>
param(
    [string[]]$Only = @(),
    [string[]]$Seeds = @("1", "2"),
    [double]$MinFreeGB = 20,
    [int]$MaxWaitMinutes = 120,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# name -> combo and the extra options of src.pipeline.crossval (see docs/ablation_plan.md)
$experiments = [ordered]@{
    nodocs       = @{ Combo = "D"; Extra = @("--no-docs") }
    history      = @{ Combo = "D"; Extra = @("--history") }
    nodiag       = @{ Combo = "E"; Extra = @("--no-diagnosis") }
    critic       = @{ Combo = "E"; Extra = @("--critic") }
    criticnodiag = @{ Combo = "E"; Extra = @("--critic", "--no-diagnosis") }
    merge        = @{ Combo = "E"; Extra = @("--merge") }
    pairs        = @{ Combo = "D"; Extra = @("--example-mode", "pairs") }
    none         = @{ Combo = "D"; Extra = @("--example-mode", "none") }
    qwen4b       = @{ Combo = "C"; Extra = @(); Ram = 6 }   # the 4B model with the final configuration
    phi4         = @{ Combo = "F"; Extra = @(); Ram = 6 }   # a second model family, same size class as the 4B
}

# "-Only a,b" arrives as one string when the script is started with `powershell -File`: split it.
$names = @($Only | ForEach-Object { $_ -split "[,\s]+" } | Where-Object { $_ })
if ($names.Count -eq 0) { $names = @($experiments.Keys) }
foreach ($name in $names) {
    if (-not $experiments.Contains($name)) {
        throw "Unknown experiment '$name'. Known: $($experiments.Keys -join ', ')."
    }
}
$seedList = @($Seeds | ForEach-Object { $_ -split "[,\s]+" } | Where-Object { $_ })

function Wait-ForRam([double]$need, [int]$maxMinutes) {
    $deadline = (Get-Date).AddMinutes($maxMinutes)
    while ($true) {
        $free = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
        if ($free -ge $need) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Write-Host "  free RAM $free GB, waiting for $need GB (close other programs)..."
        Start-Sleep -Seconds 60
    }
}

$results = @()
foreach ($name in $names) {
    $e = $experiments[$name]
    Write-Host ""
    $need = if ($e.ContainsKey("Ram")) { $e.Ram } else { $MinFreeGB }  # the small models need far less RAM
    Write-Host "##### $name (combo $($e.Combo), seeds $($seedList -join ','), options $($e.Extra -join ' ')) at $(Get-Date -Format 'HH:mm:ss')"
    if ($DryRun) {
        & .\scripts\run_crossval_seeds.ps1 -Seeds $seedList -Combo $e.Combo -Tag $name -Extra $e.Extra -DryRun
        $results += [pscustomobject]@{ Experiment = $name; Result = "dry run" }
        continue
    }
    if (-not (Wait-ForRam $need $MaxWaitMinutes)) {
        Write-Host "  not enough free RAM after $MaxWaitMinutes minutes: skipped"
        $results += [pscustomobject]@{ Experiment = $name; Result = "skipped (RAM)" }
        continue
    }
    try {
        & .\scripts\run_crossval_seeds.ps1 -Seeds $seedList -Combo $e.Combo -Tag $name -Extra $e.Extra -MinFreeGB $need
        $results += [pscustomobject]@{ Experiment = $name; Result = "done" }
    } catch {
        Write-Host "  failed: $($_.Exception.Message)"
        $results += [pscustomobject]@{ Experiment = $name; Result = "failed" }
    }
}

Write-Host ""
Write-Host "=== queue finished ($(Get-Date -Format 'HH:mm:ss'))"
$results | Format-Table -AutoSize
Write-Host "Summaries: logs\crossval\<combo>\CWE-416\*.json (the flags of each run are in the summary)."
