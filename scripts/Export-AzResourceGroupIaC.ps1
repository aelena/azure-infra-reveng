#Requires -Version 7.3
<#
.SYNOPSIS
    Reverse-engineers every (or only new/changed) resource in an Azure Resource
    Group into portable, secret-free ARM *and* Bicep templates that can redeploy
    the same resources into another resource group, subscription or tenant.

.DESCRIPTION
    Designed to be run straight from a PowerShell IDE (VS Code / ISE-style
    console). Every behaviour is driven by config/export.config.json; the
    parameters below override individual settings for a single run.

    Pipeline per run:
      1. Verify prerequisites (Az modules, sign-in, Bicep CLI)
      2. Inventory the RG and fingerprint each resource's deployable surface
      3. Diff against the previous run's state (new / modified / removed)
      4. Export ARM for the whole RG plus one file per in-scope resource,
         into a private working folder
      5. REDACT secrets (connection strings, keys, passwords) and turn them into
         secure parameters - then hard-gate on any residual secret-shaped text
      6. Apply portability transforms (strip read-only runtime state, rewrite
         subscription/tenant/RG identifiers to runtime expressions)
      7. Emit sanitised ARM + decompiled Bicep, parameter files and a deploy
         helper, and validate that the Bicep still compiles
      8. Write reports: diff, redactions, portability, region support, RBAC
      9. Persist state and optionally git-commit the run

    NOTHING is written to the output tree until the secret gate has passed.

.PARAMETER ResourceGroupName
    The source Resource Group to reverse-engineer.

.PARAMETER SubscriptionId
    Optional. Switches subscription context before running.

.PARAMETER Mode
    Full  - export every in-scope resource (default; use for a first baseline
            or whenever you want a complete, deployable picture).
    Delta - export only resources that are new or changed since the last run.
            The whole-RG template is always refreshed either way.

.PARAMETER OutputPath
    Root folder for exports. A subfolder per resource group is created under it.

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to ../config/export.config.json.

.PARAMETER TargetLocation
    Optional. Checks each exported resource type for availability in this region
    and writes reports/region-support.md.

.PARAMETER SecretPolicy
    RedactAndParameterize (default) or Placeholder. Overrides secrets.policy.

.PARAMETER AllowResidualSecrets
    Turns the post-export secret gate from a hard failure into a warning. Use
    only when you have manually reviewed the flagged lines and accepted them.

.PARAMETER SkipRoleAssignments
    Skip collecting RBAC role assignments (audit-only data).

.PARAMETER SkipLocks
    Skip collecting resource locks (audit-only data).

.PARAMETER SkipPolicies
    Skip collecting policy assignments (audit-only data).

.PARAMETER SkipBicep
    Emit ARM only. Useful when the Bicep CLI is unavailable.

.PARAMETER GitCommit
    Commit the run inside the repo that contains OutputPath. Never pushes.

.EXAMPLE
    ./Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-example-prod

.EXAMPLE
    # Only what changed since last time, and check it can live in West Europe.
    ./Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-example-prod `
        -Mode Delta -TargetLocation westeurope

.EXAMPLE
    # Cross-tenant prep: full export, committed to the audit repo each run.
    ./Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-example-prod `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -OutputPath 'C:\repos\infra-audit' -GitCommit
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [string]$SubscriptionId,
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
    [switch]$GitCommit
)

$ErrorActionPreference = 'Stop'

# An unhandled error would otherwise leave $LASTEXITCODE at whatever the last
# native command returned - usually 0 - which would make a scheduled run look
# successful. Exit codes: 0 = clean, 1 = completed with issues, 2 = aborted.
trap {
    Write-Host "`n  [ABORTED] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkGray
    exit 2
}

# --- Module ---------------------------------------------------------------
$modulePath = Join-Path $PSScriptRoot 'AzRgRevEng.psm1'
Import-Module $modulePath -Force -ErrorAction Stop

# --- Configuration --------------------------------------------------------
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot '../config/export.config.json' }

$overrides = @{
    'mode'                 = $Mode
    'output.path'          = $OutputPath
    'secrets.policy'       = $SecretPolicy
    'supplemental.roleAssignments'   = $(if ($SkipRoleAssignments) { $false } else { $null })
    'supplemental.locks'             = $(if ($SkipLocks)   { $false } else { $null })
    'supplemental.policyAssignments' = $(if ($SkipPolicies) { $false } else { $null })
    'git.autoCommit'       = $(if ($GitCommit) { $true } else { $null })
}
# A $false override is meaningful, so strip only the nulls.
$config = Get-RevEngExportConfig -Path $ConfigPath -Overrides $overrides

$effectiveMode   = [string](Get-RevEngConfigValue -Config $config -Path 'mode' -Default 'Full')
$outputRoot      = [string](Get-RevEngConfigValue -Config $config -Path 'output.path' -Default './exports')

# A relative path from the CONFIG file is anchored to the repo, so the default
# './exports' means the same folder no matter where you invoke the script from.
# A relative path you pass explicitly stays relative to your current directory,
# which is what you would expect when typing it. Either way the resolved
# absolute path is printed below, so there is no guessing.
if (-not [IO.Path]::IsPathRooted($outputRoot)) {
    $anchor = if ($PSBoundParameters.ContainsKey('OutputPath')) { (Get-Location).Path } else { (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
    $outputRoot = Join-Path $anchor $outputRoot
}
$outputRoot = [IO.Path]::GetFullPath($outputRoot)
$secretPolicy    = [string](Get-RevEngConfigValue -Config $config -Path 'secrets.policy' -Default 'RedactAndParameterize')
$placeholder     = [string](Get-RevEngConfigValue -Config $config -Path 'secrets.placeholder' -Default '__REDACTED__')
$failOnSecret    = [bool](Get-RevEngConfigValue -Config $config -Path 'secrets.failOnResidualSecret' -Default $true)
$keepRawExport   = [bool](Get-RevEngConfigValue -Config $config -Path 'output.keepRawExport' -Default $false)
$keepHistory     = [bool](Get-RevEngConfigValue -Config $config -Path 'output.keepRunHistory' -Default $true)
$historyToKeep   = [int](Get-RevEngConfigValue -Config $config -Path 'output.runHistoryToKeep' -Default 20)
$doBicepBuild    = [bool](Get-RevEngConfigValue -Config $config -Path 'validation.bicepBuild' -Default $true)
$autoCommit      = [bool](Get-RevEngConfigValue -Config $config -Path 'git.autoCommit' -Default $false)
$secretConfig    = Get-RevEngConfigValue -Config $config -Path 'secrets' -Default (New-RevEngOrderedMap)
$portabilityCfg  = Get-RevEngConfigValue -Config $config -Path 'portability' -Default (New-RevEngOrderedMap)
$filters         = Get-RevEngConfigValue -Config $config -Path 'resourceFilters' -Default (New-RevEngOrderedMap)
$emitBicep       = -not $SkipBicep

if ($AllowResidualSecrets) { $failOnSecret = $false }

# --- Prerequisites --------------------------------------------------------
Write-RevEngLog "Azure IaC reverse-engineering: $ResourceGroupName" -Level Step
$context = Assert-RevEngPrerequisite -RequireBicep:$emitBicep

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $context = Get-AzContext
}
$sourceSubscriptionId = [string]$context.Subscription.Id
$sourceTenantId = [string]$context.Tenant.Id

# Fail fast: without a subscription id the supplemental scope and the identifier
# rewriting are both meaningless, and the failure would otherwise surface only
# after every template had already been exported.
if ([string]::IsNullOrWhiteSpace($sourceSubscriptionId)) {
    throw 'The current Azure context has no subscription id. Run Connect-AzAccount, or pass -SubscriptionId explicitly.'
}

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
$primaryLocation = [string]$rg.Location

Write-RevEngLog ("Subscription : {0} ({1})" -f $context.Subscription.Name, $sourceSubscriptionId)
Write-RevEngLog ("Tenant       : {0}" -f $sourceTenantId)
if ([string]::IsNullOrWhiteSpace($sourceTenantId)) {
    Write-RevEngLog 'No tenant id in the current context - tenant id rewriting will be skipped.' -Level Warn
}
Write-RevEngLog ("Region       : {0}" -f $primaryLocation)
Write-RevEngLog ("Mode         : {0}" -f $effectiveMode)
Write-RevEngLog ("Secrets      : {0} (fail on residual: {1})" -f $secretPolicy, $failOnSecret)
Write-RevEngLog ("Output       : {0}" -f $outputRoot)

# Mid-run, .work/ holds the raw export with live secrets in it. Inside a folder
# that a sync client watches, that can reach the cloud before it is deleted.
foreach ($syncRoot in @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer, (Join-Path $HOME 'Dropbox'), (Join-Path $HOME 'Google Drive'))) {
    if ($syncRoot -and $outputRoot.StartsWith($syncRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Write-RevEngLog ("Output path is inside a synced folder ({0}). The transient .work/ folder holds unredacted ARM, so it may sync before deletion - consider -OutputPath on a local-only path." -f $syncRoot) -Level Warn
        break
    }
}

# --- Paths ----------------------------------------------------------------
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$rgRoot   = Join-Path $outputRoot (ConvertTo-RevEngSafeName -Name $ResourceGroupName)
$paths = @{
    Root          = $rgRoot
    Work          = Join-Path $rgRoot '.work'
    Arm           = Join-Path $rgRoot 'arm'
    ArmResources  = Join-Path $rgRoot 'arm/resources'
    Bicep         = Join-Path $rgRoot 'bicep'
    BicepResources= Join-Path $rgRoot 'bicep/resources'
    Reports       = Join-Path $rgRoot 'reports'
    Deploy        = Join-Path $rgRoot 'deploy'
    Runs          = Join-Path $rgRoot 'runs'
    RunFolder     = Join-Path $rgRoot "runs/$runStamp"
    State         = Join-Path $rgRoot 'state.json'
}
foreach ($p in @($paths.Root, $paths.Work, $paths.Arm, $paths.ArmResources, $paths.Reports, $paths.Deploy, $paths.RunFolder)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
}
if ($emitBicep) {
    foreach ($p in @($paths.Bicep, $paths.BicepResources)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

# --- 1. Inventory + fingerprint ------------------------------------------
Write-RevEngLog 'Inventorying resources' -Level Step
$inventory = Get-RevEngResourceInventory -ResourceGroupName $ResourceGroupName -Filters $filters
Write-RevEngLog ("{0} resource(s) in scope after filters." -f $inventory.Count)

if ($inventory.Count -eq 0) {
    Write-RevEngLog 'Nothing in scope - check resourceFilters in the config file.' -Level Warn
    return
}

# --- 2. Diff against previous run ----------------------------------------
$previousState = Get-RevEngPreviousState -Path $paths.State
$previousResources = Get-RevEngConfigValue -Config $previousState -Path 'resources' -Default (New-RevEngOrderedMap)
$isBaseline = ($previousResources.Count -eq 0)
$diff = Compare-RevEngSnapshot -Current $inventory -Previous $previousResources

Write-RevEngLog 'Change summary' -Level Step
if ($isBaseline) { Write-RevEngLog 'No previous state found - this run is the baseline.' -Level Warn }
Write-RevEngLog ("New       : {0}" -f $diff.New.Count)       -Level $(if ($diff.New.Count)      { 'Ok' }   else { 'Info' })
Write-RevEngLog ("Modified  : {0}" -f $diff.Modified.Count)  -Level $(if ($diff.Modified.Count) { 'Warn' } else { 'Info' })
Write-RevEngLog ("Removed   : {0}" -f $diff.Removed.Count)   -Level $(if ($diff.Removed.Count)  { 'Err' }  else { 'Info' })
Write-RevEngLog ("Unchanged : {0}" -f $diff.Unchanged.Count)
if ($diff.Unknown.Count -gt 0) {
    Write-RevEngLog ("Unknown   : {0}  <- could not be fingerprinted; drift cannot be ruled out" -f $diff.Unknown.Count) -Level Err
    foreach ($id in $diff.Unknown) {
        $why = if (Test-RevEngHasKey $inventory[$id] 'fingerprintError') { $inventory[$id]['fingerprintError'] } else { 'no fingerprint in the previous run' }
        Write-RevEngLog ("unknown: {0} [{1}] - {2}" -f $inventory[$id]['name'], $inventory[$id]['type'], $why) -Level Err
    }
}

foreach ($id in $diff.Removed) {
    Write-RevEngLog ("removed: {0} [{1}]" -f $previousResources[$id]['name'], $previousResources[$id]['type']) -Level Err
}
foreach ($id in $diff.Modified) {
    Write-RevEngLog ("changed: {0} [{1}]" -f $inventory[$id]['name'], $inventory[$id]['type']) -Level Warn
}

$targetIds = if ($effectiveMode -eq 'Delta' -and -not $isBaseline) {
    # Unknown resources are exported too - we could not prove they are unchanged.
    @($diff.New) + @($diff.Modified) + @($diff.Unknown)
} else {
    @($inventory.Keys)
}
Write-RevEngLog ("Exporting {0} resource template(s)." -f @($targetIds).Count)

# =========================================================================
# 3. Export ARM into the private working folder
# =========================================================================
Write-RevEngLog 'Exporting ARM from Azure' -Level Step

$exportFailures = [System.Collections.Generic.List[object]]::new()
$workItems = [System.Collections.Generic.List[object]]::new()
$failedIds = [System.Collections.Generic.List[string]]::new()
$mainNote = ''

# Per-resource first, so that if the whole-RG export trips over an unexportable
# resource type we already know which ids to leave out of the retry.
$usedFileNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($id in $targetIds) {
    $meta = $inventory[$id]
    $typeLeaf = ($meta['type'] -split '/')[-1]
    $base = ConvertTo-RevEngSafeName -Name ("{0}_{1}" -f $typeLeaf, $meta['name'])
    $fileName = $base
    $n = 2
    while (-not $usedFileNames.Add($fileName)) { $fileName = "${base}_$n"; $n++ }

    $work = Join-Path $paths.Work "$fileName.json"
    $res = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path $work -ResourceId @($id)
    if ($res.Success) {
        Write-RevEngLog ("{0} [{1}]" -f $meta['name'], $meta['type']) -Level Ok
        $workItems.Add([pscustomobject]@{
            Kind = 'Resource'; Name = $meta['name']; WorkPath = $work
            ArmPath = (Join-Path $paths.ArmResources "$fileName.json")
            BicepPath = (Join-Path $paths.BicepResources "$fileName.bicep")
        })
    } else {
        Write-RevEngLog ("{0} [{1}]: {2}" -f $meta['name'], $meta['type'], ($res.Errors -join '; ')) -Level Err
        $exportFailures.Add([pscustomobject]@{ Resource = $meta['name']; Type = $meta['type']; Errors = $res.Errors })
        $failedIds.Add([string]$id)
    }
}

# Whole-RG template last, with a fallback: Azure fails the entire export when it
# meets a resource type it cannot serialise, so retry without the known-bad ones
# rather than losing main.json altogether.
$fullWorkPath = Join-Path $paths.Work 'main.json'
$fullExport = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path $fullWorkPath

if (-not $fullExport.Success -and $failedIds.Count -gt 0) {
    $retryIds = @($inventory.Keys | Where-Object { $_ -notin $failedIds })
    if ($retryIds.Count -gt 0) {
        Write-RevEngLog ("whole-RG export failed; retrying without {0} unexportable resource(s)..." -f $failedIds.Count) -Level Warn
        $fullExport = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path $fullWorkPath -ResourceId $retryIds
        if ($fullExport.Success) {
            $mainNote = "main.json excludes $($failedIds.Count) resource(s) that Azure cannot export - see the failure list below."
        }
    }
}

if ($fullExport.Success) {
    Write-RevEngLog ('whole resource group -> main.json' + $(if ($mainNote) { ' (partial)' })) -Level Ok
    if ($mainNote) { Write-RevEngLog $mainNote -Level Warn }
    foreach ($e in $fullExport.Errors) { Write-RevEngLog $e -Level Warn }
    $workItems.Add([pscustomobject]@{
        Kind = 'Main'; Name = 'main'; WorkPath = $fullWorkPath
        ArmPath = (Join-Path $paths.Arm 'main.json')
        BicepPath = (Join-Path $paths.Bicep 'main.bicep')
    })
} else {
    Write-RevEngLog ("whole-RG export failed: {0}" -f (@($fullExport.Errors) -join '; ')) -Level Err
    Write-RevEngLog 'Per-resource templates are still usable; only the combined template is missing.' -Level Warn
    $exportFailures.Add([pscustomobject]@{ Resource = '(whole resource group)'; Type = '-'; Errors = $fullExport.Errors })
}

if ($workItems.Count -eq 0) {
    throw 'Every ARM export failed - nothing to process. See the errors above.'
}

# =========================================================================
# 4. Redact secrets + apply portability transforms (in memory)
# =========================================================================
Write-RevEngLog 'Redacting secrets and applying portability transforms' -Level Step

$allRedactions   = [System.Collections.Generic.List[object]]::new()
$allDynamicRefs  = [System.Collections.Generic.List[object]]::new()
$allOutputRisks  = [System.Collections.Generic.List[object]]::new()
$allFindings     = [System.Collections.Generic.List[object]]::new()
$allStripped     = [System.Collections.Generic.List[object]]::new()
$residualLeaks   = [System.Collections.Generic.List[object]]::new()
$externalDeps    = [System.Collections.Generic.List[string]]::new()
$processed       = [System.Collections.Generic.List[object]]::new()

# Every resource is processed twice - once in its own template and once inside
# main.json - so findings are deduplicated on insertion. The resources[N] index
# differs between the two, hence the path normalisation.
$ic = [StringComparer]::OrdinalIgnoreCase
$seenRedaction = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenDynamic   = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenOutput    = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenFinding   = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenStripped  = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenNoise     = [System.Collections.Generic.HashSet[string]]::new($ic)
$seenInline    = [System.Collections.Generic.HashSet[string]]::new($ic)
$normPath = { param($p) [regex]::Replace([string]$p, 'resources\[\d+\]', 'resources[]') }

$noiseRemoved = [System.Collections.Generic.List[object]]::new()
$inlineRemoved = [System.Collections.Generic.List[object]]::new()
$depsRepaired = 0
$excludeChildTypes = @(Get-RevEngConfigValue -Config $filters -Path 'excludeChildTypes' -Default @())
$inlineRules = @(Get-RevEngConfigValue -Config $portabilityCfg -Path 'redundantInlineChildren' -Default @())

foreach ($item in $workItems) {
    $rawJson = Get-Content -LiteralPath $item.WorkPath -Raw
    $template = $rawJson | ConvertFrom-Json -AsHashtable -Depth 64

    # Normalise before anything else: this can drop the large majority of the
    # resources (Azure-managed children), so everything downstream gets cheaper.
    # Deduped like every other finding: each resource is normalised twice, once in
    # its own template and once inside main.json, so a raw tally would double it.
    $noisePass = Remove-RevEngNoiseResource -Template $template -ExcludeType $excludeChildTypes
    $depsRepaired += $noisePass.DependenciesRepaired
    foreach ($n in $noisePass.Removed) {
        # Inner parentheses are required: inside a method call the comma would
        # otherwise be read as an argument separator, not as -f's argument list.
        if ($seenNoise.Add(('{0}|{1}' -f $n.Type, $n.Name))) { $noiseRemoved.Add($n) }
    }

    $inlinePass = Remove-RevEngRedundantInlineChild -Template $noisePass.Template -Rule $inlineRules
    $depsRepaired += $inlinePass.DependenciesRepaired
    foreach ($n in $inlinePass.Removed) {
        if ($seenInline.Add(('{0}|{1}' -f $n.Type, $n.Name))) { $inlineRemoved.Add($n) }
    }
    $template = $inlinePass.Template

    $secretPass = Remove-RevEngSecretMaterial -Template $template -SecretConfig $secretConfig `
        -Policy $secretPolicy -Placeholder $placeholder
    foreach ($r in $secretPass.Redactions) {
        $k = '{0}|{1}|{2}|{3}|{4}' -f $r.ResourceType, $r.ResourceName, $r.Property, (& $normPath $r.Path), $r.ValueFingerprint
        if ($seenRedaction.Add($k)) { $allRedactions.Add($r) }
    }
    foreach ($r in $secretPass.DynamicReferences) {
        $k = '{0}|{1}|{2}|{3}' -f $r.ResourceType, $r.ResourceName, $r.Property, (& $normPath $r.Path)
        if ($seenDynamic.Add($k)) { $allDynamicRefs.Add($r) }
    }
    foreach ($r in $secretPass.OutputRisks) {
        if ($seenOutput.Add([string]$r.Output)) { $allOutputRisks.Add($r) }
    }

    $portPass = Convert-RevEngTemplateForPortability -Template $secretPass.Template `
        -PortabilityConfig $portabilityCfg `
        -SourceSubscriptionId $sourceSubscriptionId `
        -SourceTenantId $sourceTenantId `
        -SourceResourceGroupName $ResourceGroupName `
        -PrimaryLocation $primaryLocation
    foreach ($f in $portPass.Findings) {
        $k = '{0}|{1}|{2}|{3}|{4}' -f $f.Category, $f.ResourceType, $f.ResourceName, (& $normPath $f.Path), $f.Detail
        if ($seenFinding.Add($k)) { $allFindings.Add($f) }
    }
    foreach ($s in $portPass.Stripped) {
        $k = '{0}|{1}|{2}|{3}' -f $s.ResourceName, $s.Property, (& $normPath $s.Path), $s.Reason
        if ($seenStripped.Add($k)) { $allStripped.Add($s) }
    }

    $json = $portPass.Template | ConvertTo-Json -Depth 64

    # Secret gate: scan the *rendered* output, which is what would hit disk.
    $leaks = Test-RevEngSecretLeak -Content $json -SecretConfig $secretConfig -Source (Split-Path -Leaf $item.ArmPath)
    foreach ($l in $leaks) { $residualLeaks.Add($l) }

    # Scanned on the raw export, not the transformed template: by now the literal
    # subscription id has become subscription().subscriptionId, so a resource-id
    # match is no longer possible. Only resource ids are recorded, never values.
    foreach ($d in (Get-RevEngExternalDependency -TemplateJson $rawJson -SourceResourceGroupName $ResourceGroupName)) {
        if (-not $externalDeps.Contains($d)) { $externalDeps.Add($d) }
    }

    $processed.Add([pscustomobject]@{
        Item     = $item
        Template = $portPass.Template
        Json     = $json
    })
}

if ($noiseRemoved.Count -gt 0 -or $inlineRemoved.Count -gt 0) {
    $noiseTypes = @($noiseRemoved | Group-Object Type | Sort-Object Count -Descending)
    Write-RevEngLog ("Normalised templates: dropped {0} Azure-managed child resource(s) and {1} duplicate inline child resource(s); repaired {2} dependsOn entr(ies)." -f $noiseRemoved.Count, $inlineRemoved.Count, $depsRepaired)
    foreach ($g in ($noiseTypes | Select-Object -First 5)) { Write-RevEngLog ("{0} x {1}" -f $g.Count, $g.Name) -Indent 1 }
}

Write-RevEngLog ("{0} secret value(s) redacted, {1} deploy-time reference(s) left intact." -f $allRedactions.Count, $allDynamicRefs.Count) `
    -Level $(if ($allRedactions.Count) { 'Warn' } else { 'Ok' })
Write-RevEngLog ("{0} read-only property value(s) stripped, {1} portability finding(s)." -f $allStripped.Count, $allFindings.Count)

# --- Hard gate ------------------------------------------------------------
if ($residualLeaks.Count -gt 0) {
    Write-RevEngLog ("SECRET GATE: {0} secret-shaped value(s) survived redaction:" -f $residualLeaks.Count) -Level Err
    foreach ($l in ($residualLeaks | Select-Object -First 25)) {
        Write-RevEngLog ("{0}:{1} matched '{2}'" -f $l.File, $l.Line, $l.Pattern) -Level Err
    }
    $gateReport = Join-Path $paths.Reports 'secret-gate-failures.json'
    Write-RevEngJsonFile -InputObject @($residualLeaks) -Path $gateReport | Out-Null
    Write-RevEngLog "Details: $gateReport" -Level Err

    if ($failOnSecret) {
        Remove-Item -LiteralPath $paths.Work -Recurse -Force -ErrorAction SilentlyContinue
        $msg = "Aborted before writing any template: $($residualLeaks.Count) secret-shaped value(s) would have been exported. " +
               'Extend secrets.keyNamePatterns / valuePatterns in the config to cover them, or - if they are confirmed ' +
               "false positives - re-run with -AllowResidualSecrets. Details: $gateReport"
        throw $msg
    }
    Write-RevEngLog 'Continuing anyway because residual secrets were explicitly allowed.' -Level Warn
}

# =========================================================================
# 5. Emit sanitised ARM + Bicep
# =========================================================================
Write-RevEngLog 'Writing sanitised ARM' -Level Step
foreach ($p in $processed) {
    Write-RevEngTextFile -Content $p.Json -Path $p.Item.ArmPath
}
Write-RevEngLog ("{0} ARM template(s) written." -f $processed.Count) -Level Ok

$bicepFailures = [System.Collections.Generic.List[object]]::new()
$bicepWarnings = [System.Collections.Generic.List[object]]::new()
if ($emitBicep) {
    Write-RevEngLog 'Decompiling to Bicep' -Level Step
    foreach ($p in $processed) {
        $r = Convert-RevEngArmToBicep -ArmPath $p.Item.ArmPath -BicepPath $p.Item.BicepPath
        if ($r.Success) {
            Write-RevEngLog (Split-Path -Leaf $p.Item.BicepPath) -Level Ok
            if ($r.Message) { $bicepWarnings.Add([pscustomobject]@{ File = (Split-Path -Leaf $p.Item.BicepPath); Message = $r.Message }) }
        } else {
            Write-RevEngLog ("decompile failed: {0} - {1}" -f (Split-Path -Leaf $p.Item.ArmPath), $r.Message) -Level Err
            $bicepFailures.Add([pscustomobject]@{ File = (Split-Path -Leaf $p.Item.ArmPath); Message = $r.Message })
        }
    }

    # Belt and braces: the decompiler copies literal values across, so re-scan
    # the generated Bicep with the same patterns.
    $leakingBicep = [System.Collections.Generic.List[string]]::new()
    foreach ($f in (Get-ChildItem -Path $paths.Bicep -Filter '*.bicep' -Recurse -File)) {
        $leaks = Test-RevEngSecretLeak -Content (Get-Content -LiteralPath $f.FullName -Raw) `
            -SecretConfig $secretConfig -Source $f.Name
        foreach ($l in $leaks) {
            Write-RevEngLog ("SECRET GATE (bicep): {0}:{1} matched '{2}'" -f $l.File, $l.Line, $l.Pattern) -Level Err
            $residualLeaks.Add($l)
            if (-not $leakingBicep.Contains($f.FullName)) { $leakingBicep.Add($f.FullName) }
        }
    }
    if ($leakingBicep.Count -gt 0 -and $failOnSecret) {
        # The ARM already passed the gate, so this means decompilation rendered
        # something the structural pass could not see. Delete and stop.
        foreach ($f in $leakingBicep) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        Write-RevEngJsonFile -InputObject @($residualLeaks) -Path (Join-Path $paths.Reports 'secret-gate-failures.json') | Out-Null
        Remove-Item -LiteralPath $paths.Work -Recurse -Force -ErrorAction SilentlyContinue
        throw ("Secret-shaped values appeared in the decompiled Bicep of $($leakingBicep.Count) file(s); " +
               'those files have been deleted. See reports/secret-gate-failures.json.')
    }
}

# --- Child-level drift, from the whole-RG template ------------------------
# Get-AzResource does not enumerate most child resources, so the per-resource
# fingerprints above cannot see them. The whole-RG template can, and it is
# refreshed on every run including Delta.
$templateMap = New-RevEngOrderedMap
$childDiff = $null
$mainForMap = $processed | Where-Object { $_.Item.Kind -eq 'Main' } | Select-Object -First 1
if ($mainForMap) {
    $templateMap = Get-RevEngTemplateResourceMap -Template $mainForMap.Template
    $previousTemplateMap = Get-RevEngConfigValue -Config $previousState -Path 'templateResources' -Default (New-RevEngOrderedMap)

    if ($previousTemplateMap.Count -gt 0) {
        $childDiff = Compare-RevEngSnapshot -Current $templateMap -Previous $previousTemplateMap
        $childTotal = $childDiff.New.Count + $childDiff.Modified.Count + $childDiff.Removed.Count

        Write-RevEngLog 'Change summary - template level (includes child resources)' -Level Step
        Write-RevEngLog ("Tracked   : {0} resource(s) in the whole-RG template" -f $templateMap.Count)
        if ($childTotal -eq 0) {
            Write-RevEngLog 'No child-level changes.' -Level Ok
        } else {
            Write-RevEngLog ("New       : {0}" -f $childDiff.New.Count)      -Level $(if ($childDiff.New.Count)      { 'Ok' }   else { 'Info' })
            Write-RevEngLog ("Modified  : {0}" -f $childDiff.Modified.Count) -Level $(if ($childDiff.Modified.Count) { 'Warn' } else { 'Info' })
            Write-RevEngLog ("Removed   : {0}" -f $childDiff.Removed.Count)  -Level $(if ($childDiff.Removed.Count)  { 'Err' }  else { 'Info' })
            foreach ($k in $childDiff.New)      { Write-RevEngLog ("new:     {0} [{1}]" -f $templateMap[$k]['name'], $templateMap[$k]['type']) -Level Ok }
            foreach ($k in $childDiff.Modified) { Write-RevEngLog ("changed: {0} [{1}]" -f $templateMap[$k]['name'], $templateMap[$k]['type']) -Level Warn }
            foreach ($k in $childDiff.Removed)  { Write-RevEngLog ("removed: {0} [{1}]" -f $previousTemplateMap[$k]['name'], $previousTemplateMap[$k]['type']) -Level Err }
        }
    } else {
        Write-RevEngLog ("Template-level baseline recorded: {0} resource(s) including children." -f $templateMap.Count)
    }
}

# --- Prune templates for deleted resources -------------------------------
# Without this the per-resource library keeps claiming a resource that no longer
# exists, which is exactly the drift the exporter is supposed to surface.
if ($diff.Removed.Count -gt 0) {
    Write-RevEngLog 'Pruning templates for removed resources' -Level Step
    foreach ($id in $diff.Removed) {
        $meta = $previousResources[$id]
        $leaf = ([string]$meta['type'] -split '/')[-1]
        $base = ConvertTo-RevEngSafeName -Name ('{0}_{1}' -f $leaf, $meta['name'])
        foreach ($stale in @((Join-Path $paths.ArmResources "$base.json"), (Join-Path $paths.BicepResources "$base.bicep"))) {
            if (Test-Path -LiteralPath $stale) {
                Remove-Item -LiteralPath $stale -Force
                Write-RevEngLog ('pruned {0}' -f (Split-Path -Leaf $stale)) -Level Warn
            }
        }
    }
}

# --- Parameter files + deploy helper -------------------------------------
$mainProcessed = $processed | Where-Object { $_.Item.Kind -eq 'Main' } | Select-Object -First 1
$paramInfo = $null
if ($mainProcessed) {
    Write-RevEngLog 'Emitting parameter files and deploy helper' -Level Step

    # The same parameter file serves both flavours, so write it under arm/ (which
    # always exists) and copy it next to the Bicep only when Bicep was emitted.
    $armParamPath = Join-Path $paths.Arm 'main.parameters.sample.json'
    $paramInfo = New-RevEngParameterFile -Template $mainProcessed.Template `
        -JsonPath $armParamPath `
        -BicepParamPath $(if ($emitBicep) { Join-Path $paths.Bicep 'main.sample.bicepparam' } else { '' }) `
        -BicepTemplateName 'main.bicep'
    Write-RevEngLog ("{0} parameter(s), {1} of them secure." -f $paramInfo.ParameterCount, $paramInfo.SecureParameters.Count) -Level Ok

    if ($emitBicep) {
        Copy-Item -LiteralPath $armParamPath -Destination (Join-Path $paths.Bicep 'main.parameters.sample.json') -Force
    }

    New-RevEngDeployScript -Path (Join-Path $paths.Deploy 'Deploy-Target.ps1')
}

# --- Bicep round-trip validation -----------------------------------------
$buildResult = $null
if ($emitBicep -and $doBicepBuild -and (Test-Path -LiteralPath (Join-Path $paths.Bicep 'main.bicep'))) {
    Write-RevEngLog 'Validating that the generated Bicep compiles' -Level Step
    $buildResult = Test-RevEngBicepBuild -BicepPath (Join-Path $paths.Bicep 'main.bicep')
    if ($buildResult.Success) {
        Write-RevEngLog 'main.bicep compiles cleanly.' -Level Ok
    } else {
        Write-RevEngLog 'main.bicep does NOT compile - review reports/summary.md before deploying.' -Level Err
        foreach ($e in ($buildResult.Errors | Select-Object -First 10)) { Write-RevEngLog $e -Level Err }
    }
}

# =========================================================================
# 6. Supplemental (audit-only) inventory
# =========================================================================
$wantRbac    = [bool](Get-RevEngConfigValue -Config $config -Path 'supplemental.roleAssignments' -Default $true)
$wantLocks   = [bool](Get-RevEngConfigValue -Config $config -Path 'supplemental.locks' -Default $true)
$wantPolicy  = [bool](Get-RevEngConfigValue -Config $config -Path 'supplemental.policyAssignments' -Default $true)

$supplemental = $null
if ($wantRbac -or $wantLocks -or $wantPolicy) {
    Write-RevEngLog 'Collecting RBAC / locks / policy (audit only, not emitted as IaC)' -Level Step
    $supplemental = Get-RevEngSupplementalInventory -ResourceGroupName $ResourceGroupName `
        -SubscriptionId $sourceSubscriptionId `
        -IncludeRoleAssignments:$wantRbac -IncludeLocks:$wantLocks -IncludePolicyAssignments:$wantPolicy
    Write-RevEngJsonFile -InputObject $supplemental -Path (Join-Path $paths.Reports 'rbac-locks-policy.json') | Out-Null
    Write-RevEngLog 'reports/rbac-locks-policy.json' -Level Ok
}

# =========================================================================
# 7. Region suitability
# =========================================================================
$regionSupport = $null
if ($TargetLocation) {
    Write-RevEngLog "Checking resource type availability in '$TargetLocation'" -Level Step
    $types = @($targetIds | ForEach-Object { $inventory[$_]['type'] })
    $regionSupport = Test-RevEngRegionSupport -ResourceType $types -TargetLocation $TargetLocation
    $unsupported = @($regionSupport | Where-Object { $_.Supported -eq 'NO' })
    if ($unsupported.Count -gt 0) {
        Write-RevEngLog ("{0} resource type(s) are NOT available in {1}:" -f $unsupported.Count, $TargetLocation) -Level Err
        foreach ($u in $unsupported) { Write-RevEngLog $u.ResourceType -Level Err }
    } else {
        Write-RevEngLog "All exported resource types are available in $TargetLocation." -Level Ok
    }
}

# =========================================================================
# 8. Reports
# =========================================================================
Write-RevEngLog 'Writing reports' -Level Step

$diffReport = New-RevEngOrderedMap @{
    timestamp         = $runStamp
    resourceGroupName = $ResourceGroupName
    subscriptionId    = $sourceSubscriptionId
    mode              = $effectiveMode
    baseline          = $isBaseline
    # Ordered maps keep the JSON key order stable between runs, so committed
    # reports produce a readable git diff instead of reshuffled noise.
    new               = @($diff.New      | ForEach-Object { New-RevEngOrderedMap @{ id = $_; name = $inventory[$_]['name']; type = $inventory[$_]['type'] } })
    modified          = @($diff.Modified | ForEach-Object { New-RevEngOrderedMap @{ id = $_; name = $inventory[$_]['name']; type = $inventory[$_]['type'] } })
    removed           = @($diff.Removed  | ForEach-Object { New-RevEngOrderedMap @{ id = $_; name = $previousResources[$_]['name']; type = $previousResources[$_]['type'] } })
    unknown           = @($diff.Unknown  | ForEach-Object { New-RevEngOrderedMap @{
        id     = $_
        name   = $inventory[$_]['name']
        type   = $inventory[$_]['type']
        reason = $(if (Test-RevEngHasKey $inventory[$_] 'fingerprintError') { $inventory[$_]['fingerprintError'] } else { 'no fingerprint in the previous run' })
    } })
    unchangedCount    = $diff.Unchanged.Count
    templateLevel     = $(if ($childDiff) { New-RevEngOrderedMap @{
        note     = 'Covers child resources that Get-AzResource does not enumerate (Key Vault secrets, model deployments, DNS records, ...).'
        tracked  = $templateMap.Count
        new      = @($childDiff.New      | ForEach-Object { New-RevEngOrderedMap @{ name = $templateMap[$_]['name']; type = $templateMap[$_]['type'] } })
        modified = @($childDiff.Modified | ForEach-Object { New-RevEngOrderedMap @{ name = $templateMap[$_]['name']; type = $templateMap[$_]['type'] } })
        removed  = @($childDiff.Removed  | ForEach-Object { New-RevEngOrderedMap @{ name = $_.Split('|')[-1];       type = $_.Split('|')[0] } })
    } } else { $null })
}
Write-RevEngJsonFile -InputObject $diffReport -Path (Join-Path $paths.Reports 'diff-report.json') | Out-Null

Write-RevEngJsonFile -Path (Join-Path $paths.Reports 'redaction-report.json') -InputObject (New-RevEngOrderedMap @{
    policy                 = $secretPolicy
    note                   = 'ValueFingerprint is a SHA-256 prefix of the original value. The value itself is never recorded.'
    redactedCount          = $allRedactions.Count
    redactions             = @($allRedactions)
    deployTimeReferences   = @($allDynamicRefs)
    secretBearingOutputs   = @($allOutputRisks)
    residualGateFindings   = @($residualLeaks)
}) | Out-Null

# --- portability-report.md -----------------------------------------------
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Portability report - $ResourceGroupName")
$md.Add('')
$md.Add("Generated $runStamp from subscription ``$sourceSubscriptionId`` (region ``$primaryLocation``), mode **$effectiveMode**.")
$md.Add('')
$md.Add('These templates are a faithful starting point, not a guaranteed one-click clone. Work through the items below before deploying into another resource group or tenant.')
$md.Add('')

$md.Add('## Blocking items (must be resolved)')
$md.Add('')
$actionItems = @($allFindings | Where-Object { $_.Severity -eq 'Action required' })
if ($actionItems.Count -eq 0) {
    $md.Add('_None detected._')
} else {
    $md.Add('| Category | Resource | Type | Detail |')
    $md.Add('|---|---|---|---|')
    foreach ($f in ($actionItems | Sort-Object Category, ResourceName)) {
        $md.Add("| $($f.Category) | ``$($f.ResourceName)`` | ``$($f.ResourceType)`` | $($f.Detail) |")
    }
}
$md.Add('')

$md.Add('## Secrets')
$md.Add('')
if ($allRedactions.Count -eq 0) {
    $md.Add('No literal secret material was found in the export.')
} else {
    $md.Add("$($allRedactions.Count) value(s) were removed and must be supplied at deploy time:")
    $md.Add('')
    $md.Add('| Resource | Property | Parameter | Why |')
    $md.Add('|---|---|---|---|')
    foreach ($r in ($allRedactions | Sort-Object ResourceName, Property)) {
        $pname = if ($r.ParameterName) { "``$($r.ParameterName)``" } else { '_(placeholder)_' }
        $md.Add("| ``$($r.ResourceName)`` | ``$($r.Property)`` | $pname | $($r.Reason) |")
    }
}
$md.Add('')
if ($allDynamicRefs.Count -gt 0) {
    $md.Add("$($allDynamicRefs.Count) value(s) already resolve at deploy time (``listKeys``/``listSecrets``) and were left untouched - they carry no key material.")
    $md.Add('')
}
if ($allOutputRisks.Count -gt 0) {
    $md.Add('**Outputs that expose secret material** (readable by anyone with deployment-history access - consider deleting them):')
    $md.Add('')
    foreach ($o in $allOutputRisks) { $md.Add("- ``$($o.Output)`` - $($o.Note)") }
    $md.Add('')
}

$md.Add('## Review items')
$md.Add('')
$reviewItems = @($allFindings | Where-Object { $_.Severity -eq 'Review' })
if ($reviewItems.Count -eq 0) {
    $md.Add('_None._')
} else {
    $md.Add('| Category | Resource | Detail |')
    $md.Add('|---|---|---|')
    foreach ($f in ($reviewItems | Sort-Object Category, ResourceName)) {
        $md.Add("| $($f.Category) | ``$($f.ResourceName)`` | $($f.Detail) |")
    }
}
$md.Add('')

$md.Add('## External dependencies')
$md.Add('')
if ($externalDeps.Count -eq 0) {
    $md.Add('The templates reference nothing outside this resource group.')
} else {
    $md.Add('These resource ids live outside the source resource group. The exported templates will **not** create them - they must already exist (or be re-pointed) in the target environment:')
    $md.Add('')
    foreach ($d in ($externalDeps | Sort-Object)) { $md.Add("- ``$d``") }
}
$md.Add('')

$md.Add('## Automatic rewrites applied')
$md.Add('')
$rewrites = @($allFindings | Where-Object { $_.Severity -eq 'Rewritten' })
$md.Add("- Environment identifiers rewritten to runtime expressions: **$($rewrites.Count)** occurrence(s) (``subscription().subscriptionId``, ``subscription().tenantId``, ``resourceGroup().name``).")
$md.Add("- Read-only runtime properties stripped: **$($allStripped.Count)**.")
if ($noiseRemoved.Count -gt 0) {
    $md.Add("- Azure-managed child resources dropped: **$($noiseRemoved.Count)** (configurable via ``resourceFilters.excludeChildTypes``):")
    foreach ($g in @($noiseRemoved | Group-Object Type | Sort-Object Count -Descending)) {
        $md.Add("    - $($g.Count) x ``$($g.Name)``")
    }
    $md.Add('  These are provisioned automatically by Azure and are not redeployable. Keeping them would also push the template past Bicep''s 800-resource limit.')
}
if ($inlineRemoved.Count -gt 0) {
    $md.Add("- Duplicate standalone child resources dropped: **$($inlineRemoved.Count)** (already declared inline on their parent, which decompiles to a Bicep dependency cycle):")
    foreach ($g in @($inlineRemoved | Group-Object Type)) {
        $md.Add("    - $($g.Count) x ``$($g.Name)``")
    }
}
if ($depsRepaired -gt 0) {
    $md.Add("- ``dependsOn`` entries re-pointed or removed after those drops: **$depsRepaired**.")
}
$locStrategy = [string](Get-RevEngConfigValue -Config $portabilityCfg -Path 'locationStrategy' -Default 'parameter')
$md.Add("- Region handling: **$locStrategy**$(if ($locStrategy -eq 'parameter') { " (a ``location`` parameter defaulting to ``$primaryLocation``)" })." )
$md.Add('')

if ($regionSupport) {
    $md.Add("## Region support for ``$TargetLocation``")
    $md.Add('')
    $md.Add('| Resource type | Available | Detail |')
    $md.Add('|---|---|---|')
    foreach ($r in $regionSupport) { $md.Add("| ``$($r.ResourceType)`` | $($r.Supported) | $($r.Detail) |") }
    $md.Add('')
    $md.Add('> Provider region lists do not cover SKU-level availability (VM sizes, zone support, some PaaS tiers). Always confirm with `-WhatIfOnly` against the target.')
    $md.Add('')
}

if ($exportFailures.Count -gt 0) {
    $md.Add('## Resources that could not be exported')
    $md.Add('')
    $md.Add('Azure cannot export every resource type to ARM. These need to be authored by hand:')
    $md.Add('')
    $md.Add('| Resource | Type | Error |')
    $md.Add('|---|---|---|')
    foreach ($f in $exportFailures) { $md.Add("| ``$($f.Resource)`` | ``$($f.Type)`` | $((@($f.Errors) -join ' ') -replace '\|', '\|') |") }
    $md.Add('')
}

if ($supplemental) {
    $md.Add('## RBAC, locks and policy')
    $md.Add('')
    $md.Add('Captured to `reports/rbac-locks-policy.json` for audit and drift detection only. They are intentionally **not** generated as IaC: role assignments and access policies reference directory object ids that do not exist in another tenant. Re-create them against the target tenant''s principals.')
    $md.Add('')
}

Write-RevEngTextFile -Content ($md -join [Environment]::NewLine) -Path (Join-Path $paths.Reports 'portability-report.md')

# --- summary.md -----------------------------------------------------------
$sm = [System.Collections.Generic.List[string]]::new()
$sm.Add("# Export summary - $ResourceGroupName")
$sm.Add('')
$sm.Add("| | |")
$sm.Add("|---|---|")
$sm.Add("| Run | $runStamp |")
$sm.Add("| Mode | $effectiveMode$(if ($isBaseline) { ' (baseline)' }) |")
$sm.Add("| Source subscription | ``$sourceSubscriptionId`` |")
$sm.Add("| Source tenant | ``$sourceTenantId`` |")
$sm.Add("| Source region | $primaryLocation |")
$sm.Add("| Resources in scope | $($inventory.Count) |")
$sm.Add("| Templates exported | $($processed.Count) |")
$sm.Add("| New / Modified / Removed | $($diff.New.Count) / $($diff.Modified.Count) / $($diff.Removed.Count) |")
if ($diff.Unknown.Count -gt 0) {
    $sm.Add("| **Could not be fingerprinted** | **$($diff.Unknown.Count)** - drift cannot be ruled out, see diff-report.json |")
}
if ($childDiff) {
    $sm.Add("| Template level, incl. children | $($templateMap.Count) tracked; $($childDiff.New.Count) new / $($childDiff.Modified.Count) modified / $($childDiff.Removed.Count) removed |")
} elseif ($templateMap.Count -gt 0) {
    $sm.Add("| Template level, incl. children | $($templateMap.Count) tracked (baseline) |")
}
$sm.Add("| Secrets redacted | $($allRedactions.Count) |")
$sm.Add("| Secret gate | $(if ($residualLeaks.Count -eq 0) { 'passed' } else { "$($residualLeaks.Count) finding(s) ALLOWED THROUGH" }) |")
$sm.Add("| Export failures | $($exportFailures.Count) |")
if ($emitBicep) {
    $sm.Add("| Bicep decompile failures | $($bicepFailures.Count) |")
    if ($buildResult) { $sm.Add("| main.bicep compiles | $(if ($buildResult.Success) { 'yes' } else { 'NO' }) |") }
}
if ($paramInfo) { $sm.Add("| Parameters (secure) | $($paramInfo.ParameterCount) ($($paramInfo.SecureParameters.Count)) |") }
$sm.Add('')
if ($mainNote) {
    $sm.Add("> **$mainNote**")
    $sm.Add('')
}
$sm.Add('## Next steps')
$sm.Add('')
$sm.Add('1. Read `reports/portability-report.md` - blocking items first.')
$sm.Add('2. Copy `bicep/main.parameters.sample.json` (or `main.sample.bicepparam`), replace every `<SET-ME>`, and override globally unique names.')
$sm.Add('3. Dry run: `./deploy/Deploy-Target.ps1 -ResourceGroupName <target-rg> -Location <region> -WhatIfOnly`.')
$sm.Add('4. Re-run this exporter with `-Mode Delta` on a schedule to catch drift.')
$sm.Add('')
if ($buildResult -and -not $buildResult.Success) {
    $sm.Add('## Bicep compile errors')
    $sm.Add('')
    $sm.Add('```')
    foreach ($e in $buildResult.Errors) { $sm.Add($e) }
    $sm.Add('```')
    $sm.Add('')
}
if ($bicepWarnings.Count -gt 0) {
    $sm.Add('## Bicep decompiler warnings')
    $sm.Add('')
    $sm.Add('Decompilation is best-effort; these files may need hand-finishing.')
    $sm.Add('')
    foreach ($w in $bicepWarnings) { $sm.Add("- ``$($w.File)``: $(($w.Message -split "`r?`n" | Select-Object -First 3) -join ' ')") }
    $sm.Add('')
}
Write-RevEngTextFile -Content ($sm -join [Environment]::NewLine) -Path (Join-Path $paths.Reports 'summary.md')

# =========================================================================
# 8b. Resource types and permissions report
# =========================================================================
$wantPermissions = [bool](Get-RevEngConfigValue -Config $config -Path 'permissions.include' -Default $true)
if ($SkipPermissionReport) { $wantPermissions = $false }

if ($wantPermissions) {
    Write-RevEngLog 'Deriving resource types and required permissions' -Level Step

    # Every type in the export, top-level and child alike.
    $typesInTemplate = @($templateMap.Values | ForEach-Object { $_['type'] })
    $typesTopLevel   = @($inventory.Values   | ForEach-Object { $_['type'] })
    # Sort-Object -Unique, not Select-Object -Unique: the latter is case-SENSITIVE,
    # and Azure returns 'Microsoft.App/containerApps' from Get-AzResource but
    # 'Microsoft.App/containerapps' in the ARM export, which listed both.
    $allTypes        = @(@($typesInTemplate) + @($typesTopLevel) | Where-Object { $_ } | Sort-Object -Unique)

    $perms = @(Get-RevEngRequiredPermission -ResourceType $allTypes)
    Write-RevEngLog ("{0} distinct resource type(s); {1} resolved against the provider catalogue." -f `
        $allTypes.Count, @($perms | Where-Object { $_.Source -eq 'provider-catalogue' }).Count) -Level Ok

    $roleSuggestions = @()
    if ([bool](Get-RevEngConfigValue -Config $config -Path 'permissions.suggestBuiltInRoles' -Default $true)) {
        $writeActions = @($perms | ForEach-Object { $_.Write } | Where-Object { $_ })
        if ($writeActions.Count -gt 0) {
            Write-RevEngLog 'Matching built-in roles (one catalogue-wide call)...'
            $roleSuggestions = @(Get-RevEngBuiltInRoleSuggestion -RequiredAction $writeActions)
        }
    }

    # What the exporting identity actually held, since the run succeeded with it.
    $actualRoles = @()
    try {
        $me = (Get-AzContext).Account.Id
        $actualRoles = @(Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
            Where-Object { $_.SignInName -eq $me -or $_.DisplayName -eq $me } |
            Select-Object -ExpandProperty RoleDefinitionName -Unique)
    } catch { }

    $bt = [string][char]0x60          # backtick, for markdown code spans
    $pm = [System.Collections.Generic.List[string]]::new()
    $pm.Add("# Resource types and permissions - $ResourceGroupName")
    $pm.Add('')
    $pm.Add("Generated $runStamp from subscription $bt$sourceSubscriptionId$bt, region $bt$primaryLocation$bt.")
    $pm.Add('')
    $pm.Add('Two different questions are answered below, and they have different answers:')
    $pm.Add('')
    $pm.Add('1. What this tool needed **to read** the resource group.')
    $pm.Add('2. What a deploying identity needs **to create** these resources somewhere else.')
    $pm.Add('')
    $pm.Add('Per-type actions are read from Azure''s provider operation catalogue at runtime, not hard-coded. Anything that could not be resolved says so rather than guessing.')
    $pm.Add('')

    # ---- resource types -------------------------------------------------
    $pm.Add('## Resource types reverse-engineered')
    $pm.Add('')
    $pm.Add("**$($allTypes.Count)** distinct types across **$($templateMap.Count)** resources in the whole-RG template (**$($inventory.Count)** of them enumerable as top-level resources).")
    $pm.Add('')
    $pm.Add('| Resource type | In template | Top-level | Exported |')
    $pm.Add('|---|---:|---:|---|')
    $failedTypes = @($exportFailures | ForEach-Object { $_.Type })
    foreach ($t in $allTypes) {
        $inTpl = @($typesInTemplate | Where-Object { $_ -ieq $t }).Count
        $top   = @($typesTopLevel   | Where-Object { $_ -ieq $t }).Count
        $status = if ($failedTypes -contains $t) { 'no - Azure cannot export it' } elseif ($inTpl -gt 0) { 'yes' } else { 'not present in the template' }
        $pm.Add("| $bt$t$bt | $inTpl | $top | $status |")
    }
    $pm.Add('')
    if ($noiseRemoved.Count -gt 0) {
        $pm.Add("Excluded as Azure-managed (see ${bt}resourceFilters.excludeChildTypes${bt}):")
        $pm.Add('')
        foreach ($g in @($noiseRemoved | Group-Object Type | Sort-Object Count -Descending)) {
            $pm.Add("- $($g.Count) x $bt$($g.Name)$bt")
        }
        $pm.Add('')
    }

    # ---- permissions to run ---------------------------------------------
    $pm.Add('## Permissions to RUN this exporter')
    $pm.Add('')
    $pm.Add('| Action | Why | Provenance |')
    $pm.Add('|---|---|---|')
    $pm.Add("| ${bt}Microsoft.Resources/subscriptions/resourceGroups/read${bt} | Resolve the resource group | catalogue |")
    $pm.Add("| ${bt}Microsoft.Resources/subscriptions/resourcegroups/resources/read${bt} | Enumerate resources | catalogue |")
    $pm.Add("| ${bt}*/read${bt} on each resource type below | Fetch properties for the fingerprint | catalogue |")
    $pm.Add("| ${bt}Microsoft.Resources/subscriptions/resourceGroups/exportTemplate/action${bt} | The whole-RG and per-resource ARM export | **documented by Microsoft but absent from the provider catalogue** - could not be verified programmatically |")
    if ($wantRbac)   { $pm.Add("| ${bt}Microsoft.Authorization/roleAssignments/read${bt} | RBAC audit collection (optional, ${bt}-SkipRoleAssignments${bt}) | catalogue |") }
    if ($wantLocks)  { $pm.Add("| ${bt}Microsoft.Authorization/locks/read${bt} | Lock audit collection (optional, ${bt}-SkipLocks${bt}) | catalogue |") }
    if ($wantPolicy) { $pm.Add("| ${bt}Microsoft.Authorization/policyAssignments/read${bt} | Policy audit collection (optional, ${bt}-SkipPolicies${bt}) | catalogue |") }
    $pm.Add('')
    $pm.Add("${bt}Reader${bt} covers every ${bt}*/read${bt} above. It does **not** reliably cover the export action, which is why ${bt}Contributor${bt} is the usual answer in practice.")
    $pm.Add('')
    if ($actualRoles.Count -gt 0) {
        $pm.Add("**Empirically:** this run succeeded with the identity holding **$($actualRoles -join ', ')** on this resource group.")
    } else {
        $pm.Add('**Empirically:** the role held by the exporting identity could not be read (that lookup itself needs directory access), but the run succeeded, so whatever it holds is sufficient.')
    }
    $pm.Add('')
    $pm.Add('Reading role assignments additionally needs Microsoft Graph directory read access to resolve principal names; without it that collection fails soft and records the error.')
    $pm.Add('')

    # ---- permissions to deploy ------------------------------------------
    $pm.Add('## Permissions to DEPLOY these resources elsewhere')
    $pm.Add('')
    $pm.Add("Each row is the control-plane action needed to create that type in the target resource group. A deployment also reads what it creates, so ${bt}read${bt} is listed alongside.")
    $pm.Add('')
    $pm.Add('| Resource type | Create | Read | Delete |')
    $pm.Add('|---|---|---|---|')
    foreach ($p in $perms) {
        $w = if ($p.Write)  { "$bt$($p.Write)$bt" }  elseif ($p.Source -eq 'provider-catalogue-unavailable') { '_provider unavailable_' } else { '_not offered_' }
        $r = if ($p.Read)   { "$bt$($p.Read)$bt" }   else { '-' }
        $d = if ($p.Delete) { "$bt$($p.Delete)$bt" } else { '-' }
        $pm.Add("| $bt$($p.ResourceType)$bt | $w | $r | $d |")
    }
    $pm.Add('')
    $unresolved = @($perms | Where-Object { -not $_.Write })
    if ($unresolved.Count -gt 0) {
        $pm.Add("$($unresolved.Count) type(s) have no create action in the catalogue. That usually means a child resource created implicitly with its parent, so it needs no separate permission - but confirm before relying on it.")
        $pm.Add('')
    }
    $pm.Add('Plus, for any deployment at all:')
    $pm.Add('')
    $pm.Add("- ${bt}Microsoft.Resources/deployments/read${bt}, ${bt}/write${bt} and ${bt}/validate/action${bt} at the target scope")
    $pm.Add("- ${bt}Microsoft.Resources/subscriptions/resourceGroups/write${bt} if ${bt}Deploy-Target.ps1${bt} has to create the target resource group")
    $pm.Add('')

    # ---- role suggestions ------------------------------------------------
    if ($roleSuggestions.Count -gt 0) {
        $pm.Add('## Built-in roles that cover those create actions')
        $pm.Add('')
        $pm.Add("Ranked by coverage, then by least privilege. Derived by matching each role's ${bt}Actions${bt} (wildcards expanded) against the create actions above, with ${bt}NotActions${bt} subtracted.")
        $pm.Add('')
        $pm.Add('| Role | Covers | Total actions in role | Grants everything |')
        $pm.Add('|---|---:|---:|---|')
        foreach ($s in $roleSuggestions) {
            $pm.Add("| $($s.Name) | $($s.Covered) / $($s.Total) | $($s.Breadth) | $(if ($s.GrantsEverything) { '**yes**' } else { 'no' }) |")
        }
        $pm.Add('')
        $pm.Add('A role covering everything is not automatically the right choice - prefer the narrowest that covers what you actually deploy, or compose several.')
        $pm.Add('')
    }

    # ---- what cannot be gleaned ------------------------------------------
    $pm.Add('## What this report cannot tell you')
    $pm.Add('')
    $pm.Add('- **Data-plane permissions.** Only control-plane actions are listed. Writing a Key Vault *secret value*, uploading a blob or querying a workspace are governed separately, by data actions or access policies.')
    $pm.Add("- **Role assignments for the resources themselves.** Managed identities in this export will need their own role assignments in the target tenant. Captured for reference in ${bt}rbac-locks-policy.json${bt}, deliberately not generated as IaC.")
    $pm.Add("- **Cross-resource-group and cross-subscription rights** for the external dependencies listed in ${bt}portability-report.md${bt}.")
    $pm.Add('- **Directory permissions.** Creating or assigning identities may need Microsoft Graph roles, which are not Azure RBAC and are not in this catalogue.')
    $pm.Add('- **Deny assignments, Azure Policy and resource locks** in the target can block a deployment that RBAC alone would permit.')
    $pm.Add('')
    $pm.Add("The only way to be certain is a what-if against the target with the actual deploying identity: ${bt}deploy/Deploy-Target.ps1 -WhatIfOnly${bt}.")

    Write-RevEngTextFile -Content ($pm -join [Environment]::NewLine) -Path (Join-Path $paths.Reports 'resources-and-permissions.md')
    Write-RevEngLog 'reports/resources-and-permissions.md' -Level Ok
}

# --- Run history ----------------------------------------------------------
if ($keepHistory) {
    Copy-Item -Path (Join-Path $paths.Reports '*') -Destination $paths.RunFolder -Recurse -Force
    $old = @(Get-ChildItem -Path $paths.Runs -Directory | Sort-Object Name -Descending | Select-Object -Skip $historyToKeep)
    foreach ($d in $old) { Remove-Item -LiteralPath $d.FullName -Recurse -Force }
} else {
    Remove-Item -LiteralPath $paths.RunFolder -Recurse -Force -ErrorAction SilentlyContinue
}

# --- 9. State + cleanup ---------------------------------------------------
Write-RevEngJsonFile -Path $paths.State -InputObject (New-RevEngOrderedMap @{
    schemaVersion     = 2
    resourceGroupName = $ResourceGroupName
    subscriptionId    = $sourceSubscriptionId
    tenantId          = $sourceTenantId
    location          = $primaryLocation
    lastRun           = $runStamp
    mode              = $effectiveMode
    resources         = $inventory
    templateResources = $templateMap
}) | Out-Null

if ($keepRawExport) {
    $rawDest = Join-Path $paths.Root 'raw-unsanitised'
    New-Item -ItemType Directory -Path $rawDest -Force | Out-Null
    Copy-Item -Path (Join-Path $paths.Work '*') -Destination $rawDest -Recurse -Force
    Write-RevEngLog "RAW UNSANITISED ARM kept in $rawDest - it may contain live secrets. Never commit it." -Level Err
}
Remove-Item -LiteralPath $paths.Work -Recurse -Force -ErrorAction SilentlyContinue

# --- Output map -----------------------------------------------------------
Write-RevEngLog 'Done' -Level Step
Write-RevEngLog ("ARM              : {0}" -f $paths.Arm)
if ($emitBicep) { Write-RevEngLog ("Bicep            : {0}" -f $paths.Bicep) }
Write-RevEngLog ("Reports          : {0}" -f $paths.Reports)
Write-RevEngLog ("Deploy helper    : {0}" -f (Join-Path $paths.Deploy 'Deploy-Target.ps1'))
Write-RevEngLog ("State            : {0}" -f $paths.State)

# --- Optional git commit --------------------------------------------------
if ($autoCommit) {
    Write-RevEngLog 'Committing run to git' -Level Step
    $msg = "azure export [{0}] {1} - mode:{2} new:{3} modified:{4} removed:{5} redacted:{6}" -f `
        $ResourceGroupName, $runStamp, $effectiveMode, $diff.New.Count, $diff.Modified.Count, $diff.Removed.Count, $allRedactions.Count
    $commit = Invoke-RevEngGitCommit -Path $outputRoot -Message $msg
    if ($commit.Committed) {
        Write-RevEngLog $commit.Reason -Level Ok
        Write-RevEngLog 'Not pushed - run git push when you are ready.'
    } else {
        Write-RevEngLog $commit.Reason -Level Warn
    }
}

# Deliberate exit code, so a scheduled run can be gated on it. Without this the
# script would inherit whatever the last `az` invocation happened to return.
$issues = ($exportFailures.Count -gt 0) -or ($buildResult -and -not $buildResult.Success) -or ($residualLeaks.Count -gt 0)
if ($issues) {
    Write-RevEngLog 'Completed with issues - see reports/summary.md.' -Level Warn
    exit 1
}
exit 0
