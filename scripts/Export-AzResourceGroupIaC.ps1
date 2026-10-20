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
    Commit the run inside the repo that contains OutputPath. Only this resource
    group's folder is staged and committed. Never pushes.

.PARAMETER FailOnDrift
    Exit with code 3 when anything was added, changed or removed since the
    previous run, at either level. For scheduled drift checks in CI.

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
    [switch]$GitCommit,
    [switch]$FailOnDrift
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

# Before anything touches Azure: a bad regex would otherwise fail after the export.
$configCheck = Test-RevEngConfig -Config $config
foreach ($w in $configCheck.Warnings) { Write-RevEngLog $w -Level Warn }
if ($configCheck.Errors.Count -gt 0) {
    throw ("Invalid configuration in ${ConfigPath}:`n  - " + ($configCheck.Errors -join "`n  - "))
}

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

# The output folder protects itself: whatever repo it is committed to, and
# whatever that repo's own .gitignore says, the unredacted export stays out.
$selfIgnore = Join-Path $paths.Root '.gitignore'
if (-not (Test-Path -LiteralPath $selfIgnore)) {
    Write-RevEngTextFile -Path $selfIgnore -Content (@(
        '# Written by Export-AzResourceGroupIaC.ps1. These can contain live secrets.'
        '.work/'
        'raw-unsanitised/'
        '*.parameters.json'
        '!*.parameters.sample.json'
        '*.bicepparam'
        '!*.sample.bicepparam'
    ) -join [Environment]::NewLine)
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

# Hashes from an older fingerprint format are not comparable with today's, and
# comparing them would report every resource as modified. Re-baseline instead.
$fingerprintVersion = 2
$previousFingerprintVersion = [int](Get-RevEngConfigValue -Config $previousState -Path 'fingerprintVersion' -Default 1)
$rebaselined = ($previousResources.Count -gt 0 -and $previousFingerprintVersion -ne $fingerprintVersion)
if ($rebaselined) {
    Write-RevEngLog ("state.json was written with fingerprint format v{0}; this tool uses v{1}. This run re-baselines - drift is reported again from the next run." -f $previousFingerprintVersion, $fingerprintVersion) -Level Warn
    $previousState['templateResources'] = New-RevEngOrderedMap
    $previousResources = New-RevEngOrderedMap
}
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
    # Unknown resources are refreshed too - we could not prove they are unchanged.
    @($diff.New) + @($diff.Modified) + @($diff.Unknown)
} else {
    @($inventory.Keys)
}

# =========================================================================
# 3. Export ARM into the private working folder
#
# One whole-RG export, every run and in either mode. Per-resource templates are
# cut out of it locally after sanitising, so there is one ARM export operation
# instead of one per resource, and every transform runs exactly once.
# =========================================================================
Write-RevEngLog 'Exporting ARM from Azure' -Level Step

$exportFailures = [System.Collections.Generic.List[object]]::new()
$mainNote = ''
$mainWorkPath = Join-Path $paths.Work 'main.json'
$mainExport = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path $mainWorkPath

if (-not $mainExport.Success) {
    # Azure fails the entire export when it meets a type it cannot serialise.
    # Probe each resource on its own to find out which, then retry without them.
    Write-RevEngLog ("whole-RG export failed: {0}" -f (@($mainExport.Errors) -join '; ')) -Level Warn
    Write-RevEngLog ("probing {0} resource(s) one by one to isolate the unexportable ones..." -f $inventory.Count) -Level Warn

    $probeTemplates = [System.Collections.Generic.List[object]]::new()
    $exportableIds = [System.Collections.Generic.List[string]]::new()
    $n = 0
    foreach ($id in @($inventory.Keys)) {
        $n++
        $meta = $inventory[$id]
        $probe = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path (Join-Path $paths.Work "probe-$n.json") -ResourceId @($id)
        if ($probe.Success) {
            $exportableIds.Add([string]$id)
            $probeTemplates.Add((Get-Content -LiteralPath $probe.Path -Raw | ConvertFrom-Json -AsHashtable -Depth 64))
        } else {
            Write-RevEngLog ("{0} [{1}]: {2}" -f $meta['name'], $meta['type'], ($probe.Errors -join '; ')) -Level Err
            $exportFailures.Add([pscustomobject]@{ Resource = $meta['name']; Type = $meta['type']; Errors = $probe.Errors })
        }
    }

    if ($exportableIds.Count -gt 0) {
        $mainExport = Export-RevEngArmTemplate -ResourceGroupName $ResourceGroupName -Path $mainWorkPath -ResourceId $exportableIds.ToArray()
        if ($mainExport.Success) {
            $mainNote = "main.json excludes $($exportFailures.Count) resource(s) that Azure cannot export - see the failure list in portability-report.md."
        } else {
            # Last resort, e.g. past the export size limit: stitch the probes together.
            Write-RevEngLog ("export of the {0} exportable resource(s) failed too: {1}" -f $exportableIds.Count, (@($mainExport.Errors) -join '; ')) -Level Warn
            Write-RevEngJsonFile -InputObject (Merge-RevEngTemplate -Template $probeTemplates.ToArray()) -Path $mainWorkPath | Out-Null
            $mainExport = [pscustomobject]@{ Success = $true; Path = $mainWorkPath; Errors = @() }
            $mainNote = "main.json was assembled from $($exportableIds.Count) per-resource export(s) because Azure would not export them together. " +
                        'Child resources that Get-AzResource does not enumerate (Key Vault secrets, DNS records, ...) may be missing from it.'
        }
    }
}

if (-not $mainExport.Success) {
    throw 'Every ARM export failed - nothing to process. See the errors above.'
}
Write-RevEngLog ('whole resource group -> main.json' + $(if ($mainNote) { ' (partial)' })) -Level Ok
if ($mainNote) { Write-RevEngLog $mainNote -Level Warn }
foreach ($e in $mainExport.Errors) { Write-RevEngLog $e -Level Warn }

# =========================================================================
# 4. Normalise, redact secrets and apply portability transforms (in memory)
# =========================================================================
Write-RevEngLog 'Redacting secrets and applying portability transforms' -Level Step

$rawJson = Get-Content -LiteralPath $mainWorkPath -Raw
$template = $rawJson | ConvertFrom-Json -AsHashtable -Depth 64

# Normalise before anything else: this can drop the large majority of the
# resources (Azure-managed children), so everything downstream gets cheaper.
$excludeChildTypes = @(Get-RevEngConfigValue -Config $filters -Path 'excludeChildTypes' -Default @())
$inlineRules = @(Get-RevEngConfigValue -Config $portabilityCfg -Path 'redundantInlineChildren' -Default @())

$noisePass = Remove-RevEngNoiseResource -Template $template -ExcludeType $excludeChildTypes
$inlinePass = Remove-RevEngRedundantInlineChild -Template $noisePass.Template -Rule $inlineRules
$noiseRemoved = @($noisePass.Removed)
$inlineRemoved = @($inlinePass.Removed)
$depsRepaired = $noisePass.DependenciesRepaired + $inlinePass.DependenciesRepaired

$secretPass = Remove-RevEngSecretMaterial -Template $inlinePass.Template -SecretConfig $secretConfig `
    -Policy $secretPolicy -Placeholder $placeholder
$allRedactions = @($secretPass.Redactions)
$allDynamicRefs = @($secretPass.DynamicReferences)
$allOutputRisks = @($secretPass.OutputRisks)

$portPass = Convert-RevEngTemplateForPortability -Template $secretPass.Template `
    -PortabilityConfig $portabilityCfg `
    -SourceSubscriptionId $sourceSubscriptionId `
    -SourceTenantId $sourceTenantId `
    -SourceResourceGroupName $ResourceGroupName `
    -PrimaryLocation $primaryLocation
$allFindings = @($portPass.Findings)
$allStripped = @($portPass.Stripped)
$mainTemplate = $portPass.Template
$mainJson = $mainTemplate | ConvertTo-Json -Depth 64

# Secret gate: scan the *rendered* output, which is what would hit disk. Every
# per-resource file is cut out of this template, so it covers those too.
$residualLeaks = [System.Collections.Generic.List[object]]::new()
foreach ($l in (Test-RevEngSecretLeak -Content $mainJson -SecretConfig $secretConfig -Source 'main.json')) { $residualLeaks.Add($l) }

# Scanned on the raw export, not the transformed template: by now the literal
# subscription id has become subscription().subscriptionId, so a resource-id
# match is no longer possible. Only resource ids are recorded, never values.
$externalDeps = @(Get-RevEngExternalDependency -TemplateJson $rawJson -SourceResourceGroupName $ResourceGroupName -SourceSubscriptionId $sourceSubscriptionId)

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

# --- Child-level drift, from the whole-RG template ------------------------
# Get-AzResource does not enumerate most child resources, so the per-resource
# fingerprints above cannot see them. The whole-RG template can, and it is
# refreshed on every run including Delta.
$templateMap = Get-RevEngTemplateResourceMap -Template $mainTemplate
$previousTemplateMap = Get-RevEngConfigValue -Config $previousState -Path 'templateResources' -Default (New-RevEngOrderedMap)
$childDiff = $null
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

# =========================================================================
# 5. Emit sanitised ARM: main.json, then one file per top-level resource
# =========================================================================
Write-RevEngLog 'Writing sanitised ARM' -Level Step
Write-RevEngTextFile -Content $mainJson -Path (Join-Path $paths.Arm 'main.json')
Write-RevEngLog 'main.json' -Level Ok

$parts = @(Split-RevEngTemplate -Template $mainTemplate)

# In Delta mode a file is rewritten when its top-level resource changed, or when
# any of its children changed at template level (which level 1 cannot see).
$targetKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($id in $targetIds) { [void]$targetKeys.Add(('{0}|{1}' -f $inventory[$id]['type'], $inventory[$id]['name'])) }
$changedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if ($childDiff) { foreach ($k in @($childDiff.New) + @($childDiff.Modified)) { [void]$changedMembers.Add([string]$k) } }
$writeAll = ($effectiveMode -ne 'Delta' -or $isBaseline -or -not $childDiff)

$usedFileNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$resourceFiles = [System.Collections.Generic.List[object]]::new()
$splitDepsDropped = 0
foreach ($part in $parts) {
    $base = ConvertTo-RevEngSafeName -Name ('{0}_{1}' -f (($part.Type -split '/')[-1]), $part.Name)
    $fileName = $base
    $n = 2
    while (-not $usedFileNames.Add($fileName)) { $fileName = "${base}_$n"; $n++ }

    # Remembered on the inventory entry, so a later run can prune exactly this file.
    foreach ($id in @($inventory.Keys)) {
        if ($inventory[$id]['type'] -ieq $part.Type -and $inventory[$id]['name'] -ieq $part.Name) { $inventory[$id]['file'] = $fileName }
    }

    $wanted = $writeAll -or $targetKeys.Contains(('{0}|{1}' -f $part.Type, $part.Name)) -or
              @($part.Members | Where-Object { $changedMembers.Contains($_) }).Count -gt 0
    if (-not $wanted) { continue }

    $splitDepsDropped += $part.DependenciesDropped
    $armPath = Join-Path $paths.ArmResources "$fileName.json"
    Write-RevEngTextFile -Content ($part.Template | ConvertTo-Json -Depth 64) -Path $armPath
    $resourceFiles.Add([pscustomobject]@{
        Name      = $part.Name
        Type      = $part.Type
        ArmPath   = $armPath
        BicepPath = (Join-Path $paths.BicepResources "$fileName.bicep")
    })
}
Write-RevEngLog ("{0} per-resource template(s) written, of {1} in the resource group." -f $resourceFiles.Count, $parts.Count) -Level Ok
if ($splitDepsDropped -gt 0) {
    Write-RevEngLog ("{0} dependsOn entr(ies) pointing outside their own file were dropped from the per-resource copies; main.json keeps them." -f $splitDepsDropped)
}

# --- Prune templates for resources that no longer exist -------------------
# Without this the per-resource library keeps claiming a resource that no longer
# exists, which is exactly the drift the exporter is supposed to surface. Full
# mode mirrors the template; Delta removes what the diff says was deleted.
$staleFiles = [System.Collections.Generic.List[string]]::new()
if ($writeAll) {
    foreach ($dir in @($paths.ArmResources, $paths.BicepResources)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File)) {
            if (-not $usedFileNames.Contains($f.BaseName)) { $staleFiles.Add($f.FullName) }
        }
    }
} else {
    foreach ($id in $diff.Removed) {
        $meta = $previousResources[$id]
        $base = if (Test-RevEngHasKey $meta 'file') { [string]$meta['file'] } else {
            ConvertTo-RevEngSafeName -Name ('{0}_{1}' -f (([string]$meta['type'] -split '/')[-1]), $meta['name'])
        }
        if ($usedFileNames.Contains($base)) { continue }
        foreach ($stale in @((Join-Path $paths.ArmResources "$base.json"), (Join-Path $paths.BicepResources "$base.bicep"))) {
            if (Test-Path -LiteralPath $stale) { $staleFiles.Add($stale) }
        }
    }
}
if ($staleFiles.Count -gt 0) {
    Write-RevEngLog 'Pruning templates for removed resources' -Level Step
    foreach ($stale in $staleFiles) {
        Remove-Item -LiteralPath $stale -Force
        Write-RevEngLog ('pruned {0}' -f (Split-Path -Leaf $stale)) -Level Warn
    }
}

# =========================================================================
# 6. Decompile to Bicep
# =========================================================================
$bicepFailures = [System.Collections.Generic.List[object]]::new()
$bicepWarnings = [System.Collections.Generic.List[object]]::new()
if ($emitBicep) {
    Write-RevEngLog 'Decompiling to Bicep' -Level Step
    $toDecompile = @([pscustomobject]@{ ArmPath = (Join-Path $paths.Arm 'main.json'); BicepPath = (Join-Path $paths.Bicep 'main.bicep') }) + @($resourceFiles)
    foreach ($p in $toDecompile) {
        $r = Convert-RevEngArmToBicep -ArmPath $p.ArmPath -BicepPath $p.BicepPath
        if ($r.Success) {
            Write-RevEngLog (Split-Path -Leaf $p.BicepPath) -Level Ok
            if ($r.Message) { $bicepWarnings.Add([pscustomobject]@{ File = (Split-Path -Leaf $p.BicepPath); Message = $r.Message }) }
        } else {
            Write-RevEngLog ("decompile failed: {0} - {1}" -f (Split-Path -Leaf $p.ArmPath), $r.Message) -Level Err
            $bicepFailures.Add([pscustomobject]@{ File = (Split-Path -Leaf $p.ArmPath); Message = $r.Message })
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

# --- Parameter files + deploy helper -------------------------------------
$paramInfo = $null
if ($mainTemplate) {
    Write-RevEngLog 'Emitting parameter files and deploy helper' -Level Step

    # The same parameter file serves both flavours, so write it under arm/ (which
    # always exists) and copy it next to the Bicep only when Bicep was emitted.
    $armParamPath = Join-Path $paths.Arm 'main.parameters.sample.json'
    $paramInfo = New-RevEngParameterFile -Template $mainTemplate `
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
    # Every type, not just this run's changes: a move takes the whole group.
    $types = @($inventory.Values | ForEach-Object { $_['type'] })
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
$sm.Add("| Per-resource templates written | $($resourceFiles.Count) of $($parts.Count) |")
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
$sm.Add('2. Copy `arm/main.parameters.sample.json` to `arm/main.parameters.json` (git-ignored), replace every non-secret `<SET-ME>` and override globally unique names. Leave secure parameters as `<SET-ME>`: the deploy helper prompts for them.')
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

# --- summary.json: the same outcome, for pipelines ------------------------
# Deliberate exit code, so a scheduled run can be gated on it. Without this the
# script would inherit whatever the last `az` invocation happened to return.
$issueList = [System.Collections.Generic.List[string]]::new()
if ($exportFailures.Count -gt 0)                   { $issueList.Add("$($exportFailures.Count) resource(s) Azure could not export") }
if ($bicepFailures.Count -gt 0)                    { $issueList.Add("$($bicepFailures.Count) Bicep decompile failure(s)") }
if ($buildResult -and -not $buildResult.Success)   { $issueList.Add('main.bicep does not compile') }
if ($residualLeaks.Count -gt 0)                    { $issueList.Add("$($residualLeaks.Count) secret-shaped value(s) allowed through") }
if ($diff.Unknown.Count -gt 0)                     { $issueList.Add("$($diff.Unknown.Count) resource(s) could not be fingerprinted") }

$childChanges = if ($childDiff) { $childDiff.New.Count + $childDiff.Modified.Count + $childDiff.Removed.Count } else { 0 }
$driftDetected = (-not $isBaseline) -and (($diff.New.Count + $diff.Modified.Count + $diff.Removed.Count + $childChanges) -gt 0)
# 3 outranks 1 because -FailOnDrift is an explicit request; issues are in the JSON either way.
$exitCode = if ($FailOnDrift -and $driftDetected) { 3 } elseif ($issueList.Count -gt 0) { 1 } else { 0 }

Write-RevEngJsonFile -Path (Join-Path $paths.Reports 'summary.json') -InputObject (New-RevEngOrderedMap @{
    run                = $runStamp
    resourceGroupName  = $ResourceGroupName
    subscriptionId     = $sourceSubscriptionId
    tenantId           = $sourceTenantId
    location           = $primaryLocation
    mode               = $effectiveMode
    baseline           = $isBaseline
    rebaselined        = $rebaselined
    driftDetected      = $driftDetected
    exitCode           = $exitCode
    issues             = @($issueList)
    counts             = New-RevEngOrderedMap @{
        resourcesInScope      = $inventory.Count
        templateResources     = $templateMap.Count
        filesWritten          = $resourceFiles.Count
        new                   = $diff.New.Count
        modified              = $diff.Modified.Count
        removed               = $diff.Removed.Count
        unknown               = $diff.Unknown.Count
        templateLevelChanges  = $childChanges
        secretsRedacted       = $allRedactions.Count
        residualSecrets       = $residualLeaks.Count
        exportFailures        = $exportFailures.Count
        bicepFailures         = $bicepFailures.Count
        blockingItems         = @($allFindings | Where-Object { $_.Severity -eq 'Action required' }).Count
    }
    mainBicepCompiles  = $(if ($buildResult) { [bool]$buildResult.Success } else { $null })
}) | Out-Null

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
    fingerprintVersion = $fingerprintVersion
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
    $commit = Invoke-RevEngGitCommit -Path $paths.Root -Message $msg
    if ($commit.Committed) {
        Write-RevEngLog $commit.Reason -Level Ok
        Write-RevEngLog 'Not pushed - run git push when you are ready.'
    } else {
        Write-RevEngLog $commit.Reason -Level Warn
    }
}

# Deliberate exit code, so a scheduled run can be gated on it. Without this the
# script would inherit whatever the last `az` invocation happened to return.
if ($exitCode -eq 3) {
    Write-RevEngLog 'Drift detected (-FailOnDrift) - see reports/diff-report.json.' -Level Warn
} elseif ($exitCode -eq 1) {
    Write-RevEngLog ('Completed with issues: {0}. See reports/summary.md.' -f ($issueList -join '; ')) -Level Warn
}
exit $exitCode
