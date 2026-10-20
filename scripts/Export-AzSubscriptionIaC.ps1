#Requires -Version 7.3
<#
.SYNOPSIS
    Runs Export-AzResourceGroupIaC.ps1 for every matching resource group in a
    subscription and writes one roll-up of the results.

.DESCRIPTION
    Each resource group is exported exactly as if the exporter had been run on
    it alone - its own folder, state, drift history and reports. This script
    only selects the resource groups, forwards the options and aggregates the
    outcomes into <OutputPath>/subscription-summary.md and .json.

    Resource groups that Azure manages on your behalf are skipped unless
    -IncludeManaged is given: any with a ManagedBy owner (AKS node groups,
    Databricks, managed applications) plus the auto-created ones matched by
    -ExcludeResourceGroupName. Their contents are recreated by their owner, so
    exporting them produces templates nobody should deploy.

    Exit code is the most severe across all resource groups:
    2 if any aborted, 3 if any found drift with -FailOnDrift, 1 if any
    completed with issues, else 0.

.PARAMETER ResourceGroupName
    Names or wildcard patterns to include. Defaults to every resource group.

.PARAMETER ExcludeResourceGroupName
    Names or wildcard patterns to skip. The default skips resource groups that
    Azure creates on its own.

.PARAMETER IncludeManaged
    Also export resource groups that have a ManagedBy owner.

.EXAMPLE
    ./Export-AzSubscriptionIaC.ps1 -OutputPath 'C:\repos\infra-audit'

.EXAMPLE
    # Nightly drift check across every production resource group.
    ./Export-AzSubscriptionIaC.ps1 -ResourceGroupName 'rg-prod-*' -Mode Delta `
        -OutputPath 'C:\repos\infra-audit' -GitCommit -FailOnDrift
#>
[CmdletBinding()]
param(
    [string[]]$ResourceGroupName = @('*'),
    [string[]]$ExcludeResourceGroupName = @('NetworkWatcherRG', 'DefaultResourceGroup-*', 'cloud-shell-storage-*', 'AzureBackupRG*'),
    [switch]$IncludeManaged,
    [string]$SubscriptionId,

    # Forwarded to Export-AzResourceGroupIaC.ps1 unchanged.
    [ValidateSet('Full', 'Delta')][string]$Mode,
    [string]$OutputPath,
    [string]$ConfigPath,
    [string]$TargetLocation,
    [ValidateSet('RedactAndParameterize', 'Placeholder')][string]$SecretPolicy,
    [switch]$AllowResidualSecrets,
    [switch]$SkipRoleAssignments,
    [switch]$SkipLocks,
    [switch]$SkipPolicies,
    [switch]$SkipBicep,
    [switch]$SkipPermissionReport,
    [switch]$GitCommit,
    [switch]$FailOnDrift
)

$ErrorActionPreference = 'Stop'
trap {
    Write-Host "`n  [ABORTED] $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

Import-Module (Join-Path $PSScriptRoot 'AzRgRevEng.psm1') -Force -ErrorAction Stop
$exporter = Join-Path $PSScriptRoot 'Export-AzResourceGroupIaC.ps1'

if ($SubscriptionId) { Set-AzContext -SubscriptionId $SubscriptionId | Out-Null }
$context = Get-AzContext
if (-not $context -or -not $context.Subscription) { throw 'Not signed in to Azure, or no subscription selected. Run: Connect-AzAccount' }

# Same resolution as the exporter, so the roll-up lands next to the RG folders.
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot '../config/export.config.json' }
$root = if ($OutputPath) { $OutputPath } else { [string](Get-RevEngConfigValue -Config (Get-RevEngExportConfig -Path $ConfigPath) -Path 'output.path' -Default './exports') }
if (-not [IO.Path]::IsPathRooted($root)) {
    $anchor = if ($OutputPath) { (Get-Location).Path } else { (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
    $root = Join-Path $anchor $root
}
$root = [IO.Path]::GetFullPath($root)

# --- Select ------------------------------------------------------------------
$all = @(Get-AzResourceGroup | Sort-Object ResourceGroupName)
$selected = [System.Collections.Generic.List[object]]::new()
$skipped = [System.Collections.Generic.List[object]]::new()
foreach ($rg in $all) {
    $name = [string]$rg.ResourceGroupName
    if (-not @($ResourceGroupName | Where-Object { $name -like $_ }).Count) { continue }
    $why = $null
    if (@($ExcludeResourceGroupName | Where-Object { $name -like $_ }).Count) { $why = 'excluded by name' }
    elseif (-not $IncludeManaged -and $rg.ManagedBy) { $why = "managed by $($rg.ManagedBy)" }
    if ($why) { $skipped.Add([pscustomobject]@{ Name = $name; Reason = $why }) } else { $selected.Add($rg) }
}

Write-RevEngLog ("Subscription export: {0} ({1})" -f $context.Subscription.Name, $context.Subscription.Id) -Level Step
Write-RevEngLog ("{0} resource group(s) selected, {1} skipped." -f $selected.Count, $skipped.Count)
foreach ($s in $skipped) { Write-RevEngLog ("skip {0} - {1}" -f $s.Name, $s.Reason) -Indent 1 }
if ($selected.Count -eq 0) {
    Write-RevEngLog 'Nothing to export - check -ResourceGroupName / -ExcludeResourceGroupName.' -Level Warn
    exit 0
}

$forward = @{}
foreach ($p in @('Mode', 'OutputPath', 'ConfigPath', 'TargetLocation', 'SecretPolicy', 'AllowResidualSecrets', 'SkipRoleAssignments',
                 'SkipLocks', 'SkipPolicies', 'SkipBicep', 'SkipPermissionReport', 'GitCommit', 'FailOnDrift')) {
    if ($PSBoundParameters.ContainsKey($p)) { $forward[$p] = $PSBoundParameters[$p] }
}

# --- Export each ---------------------------------------------------------------
$results = [System.Collections.Generic.List[object]]::new()
foreach ($rg in $selected) {
    $name = [string]$rg.ResourceGroupName
    $started = Get-Date
    $global:LASTEXITCODE = 0
    try {
        & $exporter -ResourceGroupName $name @forward
        $code = $LASTEXITCODE
    } catch {
        # The exporter traps its own errors; this only catches a failure to start it.
        Write-RevEngLog ("{0}: {1}" -f $name, $_.Exception.Message) -Level Err
        $code = 2
    }

    $summaryPath = Join-Path $root (Join-Path (ConvertTo-RevEngSafeName -Name $name) 'reports/summary.json')
    $summary = $null
    # A stale summary from an earlier run must not be reported as this run's.
    if ($code -ne 2 -and (Test-Path -LiteralPath $summaryPath) -and (Get-Item -LiteralPath $summaryPath).LastWriteTime -ge $started) {
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json -AsHashtable
    }
    $results.Add([pscustomobject]@{
        ResourceGroup = $name
        ExitCode      = $code
        Drift         = $(if ($summary) { [bool]$summary['driftDetected'] } else { $null })
        Issues        = $(if ($summary) { @($summary['issues']) } else { @() })
        Counts        = $(if ($summary) { $summary['counts'] } else { $null })
        Seconds       = [int]((Get-Date) - $started).TotalSeconds
    })
}

# --- Roll-up -------------------------------------------------------------------
$codes = @($results.ExitCode)
$overall = if ($codes -contains 2) { 2 } elseif ($codes -contains 3) { 3 } elseif ($codes -contains 1) { 1 } else { 0 }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-RevEngJsonFile -Path (Join-Path $root 'subscription-summary.json') -InputObject (New-RevEngOrderedMap @{
    run            = $stamp
    subscriptionId = [string]$context.Subscription.Id
    exitCode       = $overall
    resourceGroups = @($results | ForEach-Object {
        New-RevEngOrderedMap @{ name = $_.ResourceGroup; exitCode = $_.ExitCode; driftDetected = $_.Drift; issues = $_.Issues; counts = $_.Counts; seconds = $_.Seconds }
    })
    skipped        = @($skipped | ForEach-Object { New-RevEngOrderedMap @{ name = $_.Name; reason = $_.Reason } })
}) | Out-Null

$outcome = @{ 0 = 'clean'; 1 = 'issues'; 2 = '**aborted**'; 3 = 'drift' }
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Subscription export - $($context.Subscription.Name)")
$md.Add('')
$md.Add("Run $stamp, subscription ``$($context.Subscription.Id)``. Each resource group's own ``reports/summary.md`` has the detail.")
$md.Add('')
$md.Add('| Resource group | Outcome | New / Modified / Removed | Redacted | Issues |')
$md.Add('|---|---|---|---:|---|')
foreach ($r in $results) {
    $nmr = if ($r.Counts) { '{0} / {1} / {2}' -f $r.Counts['new'], $r.Counts['modified'], $r.Counts['removed'] } else { '-' }
    $red = if ($r.Counts) { $r.Counts['secretsRedacted'] } else { '-' }
    $md.Add("| ``$($r.ResourceGroup)`` | $($outcome[$r.ExitCode]) | $nmr | $red | $((@($r.Issues) -join '; ') -replace '\|', '\|') |")
}
if ($skipped.Count -gt 0) {
    $md.Add('')
    $md.Add('Skipped: ' + (($skipped | ForEach-Object { "``$($_.Name)`` ($($_.Reason))" }) -join ', ') + '.')
}
Write-RevEngTextFile -Content ($md -join [Environment]::NewLine) -Path (Join-Path $root 'subscription-summary.md')

Write-RevEngLog 'Subscription summary' -Level Step
foreach ($r in $results) {
    $level = switch ($r.ExitCode) { 0 { 'Ok' } 1 { 'Warn' } 3 { 'Warn' } default { 'Err' } }
    Write-RevEngLog ("{0} - {1} ({2}s)" -f $r.ResourceGroup, ($outcome[$r.ExitCode] -replace '\*', ''), $r.Seconds) -Level $level
}
Write-RevEngLog ("Roll-up: {0}" -f (Join-Path $root 'subscription-summary.md'))
exit $overall
