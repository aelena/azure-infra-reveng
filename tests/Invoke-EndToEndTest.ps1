#Requires -Version 7.3
<#
.SYNOPSIS
    Runs Export-AzResourceGroupIaC.ps1 end to end against a mocked Azure, then
    asserts the resulting output tree is correct and secret-free.

.DESCRIPTION
    No Azure subscription needed. The Az cmdlets are replaced with functions in
    the GLOBAL scope, which is what makes this work: command lookup from inside a
    module falls back to global, so the module's own Get-AzResource /
    Export-AzResourceGroup calls hit the mocks too.

    The fake resource group deliberately contains the awkward cases:
      - a storage connection string and a SQL admin password (must be redacted)
      - a listKeys() expression and an output that returns one (must survive, and
        the output must be flagged)
      - a resource type Azure refuses to export (the run must continue, and the
        whole-RG template must fall back to the exportable subset)
      - a cross-resource-group reference (must be reported as external)
      - a resource type unavailable in the target region

    Requires the Bicep CLI, since it also checks the generated Bicep compiles.

.EXAMPLE
    ./tests/Invoke-EndToEndTest.ps1

.EXAMPLE
    ./tests/Invoke-EndToEndTest.ps1 -KeepOutput   # leave the tree for inspection
#>
[CmdletBinding()]
param([switch]$KeepOutput)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$exporter = Join-Path $repoRoot 'scripts/Export-AzResourceGroupIaC.ps1'
$outRoot  = Join-Path ([IO.Path]::GetTempPath()) ('azrgreveng-e2e-' + [guid]::NewGuid().ToString('N'))

$global:SUB    = '11111111-2222-3333-4444-555555555555'
$global:TENANT = '99999999-8888-7777-6666-555555555555'
$global:RG     = 'rg-e2e-source'

$script:Pass = 0
$script:Fail = 0
function Assert-That {
    param([bool]$Condition, [string]$Because)
    if ($Condition) { $script:Pass++; Write-Host "  PASS  $Because" -ForegroundColor DarkGreen }
    else            { $script:Fail++; Write-Host "  FAIL  $Because" -ForegroundColor Red }
}

# ---------------------------------------------------------------------------
# Mock Azure
# ---------------------------------------------------------------------------
$global:MockResources = @(
    [pscustomobject]@{ Name = 'ste2e001'; ResourceType = 'Microsoft.Storage/storageAccounts'; Location = 'eastus'; ResourceId = "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Storage/storageAccounts/ste2e001" }
    [pscustomobject]@{ Name = 'app-e2e';   ResourceType = 'Microsoft.Web/sites';               Location = 'eastus'; ResourceId = "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Web/sites/app-e2e" }
    [pscustomobject]@{ Name = 'sql-e2e';   ResourceType = 'Microsoft.Sql/servers';             Location = 'eastus'; ResourceId = "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Sql/servers/sql-e2e" }
    [pscustomobject]@{ Name = 'noexport';  ResourceType = 'Microsoft.Fake/unsupported';        Location = 'eastus'; ResourceId = "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Fake/unsupported/noexport" }
)
$global:MockSalt = 'v1'

# The plaintext secrets the run must never emit.
$global:SecretPassword = 'Sup3rS3cret!e2e'
$global:SecretKey      = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH=='

function global:Get-AzContext {
    [pscustomobject]@{
        Account      = [pscustomobject]@{ Id = 'mock@example.com' }
        Subscription = [pscustomobject]@{ Id = $global:SUB; Name = 'Mock Subscription' }
        Tenant       = [pscustomobject]@{ Id = $global:TENANT }
    }
}
function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$Rest) }

function global:Get-AzResourceGroup {
    param([string]$Name, [Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ ResourceGroupName = $Name; Location = 'eastus' }
}

function global:Get-AzResource {
    param([string]$ResourceGroupName, [string]$ResourceId, [switch]$ExpandProperties, [Parameter(ValueFromRemainingArguments)]$Rest)
    if (-not $ResourceId) { return $global:MockResources }
    $r = $global:MockResources | Where-Object { $_.ResourceId -eq $ResourceId }
    [pscustomobject]@{
        Name = $r.Name; ResourceType = $r.ResourceType; Location = $r.Location; ResourceId = $r.ResourceId
        Sku  = @{ name = 'Standard_LRS' }; Kind = 'StorageV2'; Tags = @{ env = 'test' }
        Properties = @{ salt = $global:MockSalt; name = $r.Name }   # salt drives the change fingerprint
    }
}

function global:Get-AzRoleAssignment {
    param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ DisplayName = 'Platform Team'; SignInName = $null; ObjectId = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
                       ObjectType = 'Group'; RoleDefinitionName = 'Contributor'
                       Scope = "/subscriptions/$global:SUB/resourceGroups/$global:RG"; CanDelegate = $false }
}
function global:Get-AzResourceLock {
    param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ Name = 'no-delete'
                       ResourceId = "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Authorization/locks/no-delete"
                       Properties = [pscustomobject]@{ level = 'CanNotDelete'; notes = 'production' } }
}
function global:Get-AzPolicyAssignment {
    param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ Name = 'require-tags'
                       ResourceId = '/providers/Microsoft.Authorization/policyAssignments/require-tags'
                       Properties = [pscustomobject]@{ DisplayName = 'Require tags'
                                                       PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/xyz'
                                                       Scope = "/subscriptions/$global:SUB/resourceGroups/$global:RG" } }
}
function global:Get-AzResourceProvider {
    param([string]$ProviderNamespace, [Parameter(ValueFromRemainingArguments)]$Rest)
    switch ($ProviderNamespace) {
        'Microsoft.Storage' { [pscustomobject]@{ ResourceTypes = @([pscustomobject]@{ ResourceTypeName = 'storageAccounts'; Locations = @('East US', 'West Europe') }) } }
        'Microsoft.Web'     { [pscustomobject]@{ ResourceTypes = @([pscustomobject]@{ ResourceTypeName = 'sites';           Locations = @('East US', 'West Europe') }) } }
        'Microsoft.Sql'     { [pscustomobject]@{ ResourceTypes = @([pscustomobject]@{ ResourceTypeName = 'servers';         Locations = @('East US') }) } }
        default             { $null }
    }
}

function global:Get-AzProviderOperation {
    param([Parameter(Position = 0)][string]$OperationSearchString, [Parameter(ValueFromRemainingArguments)]$Rest)
    $ns = ($OperationSearchString -split '/')[0]
    switch ($ns) {
        'Microsoft.Storage' { @(
            [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/read';  IsDataAction = $false }
            [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/write'; IsDataAction = $false }
        ) }
        'Microsoft.Web' { @(
            [pscustomobject]@{ Operation = 'Microsoft.Web/sites/read';  IsDataAction = $false }
            [pscustomobject]@{ Operation = 'Microsoft.Web/sites/write'; IsDataAction = $false }
        ) }
        'Microsoft.Sql' { @(
            [pscustomobject]@{ Operation = 'Microsoft.Sql/servers/read';  IsDataAction = $false }
            [pscustomobject]@{ Operation = 'Microsoft.Sql/servers/write'; IsDataAction = $false }
        ) }
        default { throw "provider not found: $ns" }
    }
}

function global:Get-AzRoleDefinition {
    param([Parameter(ValueFromRemainingArguments)]$Rest)
    @(
        [pscustomobject]@{ Name = 'Contributor';                 IsCustom = $false; Actions = @('*');                    NotActions = @('Microsoft.Authorization/*/Delete') }
        [pscustomobject]@{ Name = 'Storage Account Contributor'; IsCustom = $false; Actions = @('Microsoft.Storage/*');  NotActions = @() }
    )
}

function global:New-MockResourceBody {
    param([string]$Name, [string]$Type)
    switch ($Type) {
        'Microsoft.Storage/storageAccounts' { @"
{ "type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
  "name": "[parameters('storageAccounts_${Name}_name')]", "location": "eastus",
  "sku": { "name": "Standard_LRS" }, "kind": "StorageV2",
  "properties": { "provisioningState": "Succeeded",
                  "primaryEndpoints": { "blob": "https://$Name.blob.core.windows.net/" },
                  "minimumTlsVersion": "TLS1_2" } }
"@ }
        'Microsoft.Web/sites' { @"
{ "type": "Microsoft.Web/sites", "apiVersion": "2022-03-01",
  "name": "[parameters('sites_${Name}_name')]", "location": "eastus",
  "identity": { "type": "SystemAssigned", "principalId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "tenantId": "$global:TENANT" },
  "properties": {
    "provisioningState": "Succeeded", "defaultHostName": "$Name.azurewebsites.net",
    "serverFarmId": "/subscriptions/$global:SUB/resourceGroups/$global:RG/providers/Microsoft.Web/serverfarms/plan1",
    "siteConfig": { "appSettings": [
      { "name": "STORAGE", "value": "DefaultEndpointsProtocol=https;AccountName=ste2e001;AccountKey=$global:SecretKey;EndpointSuffix=core.windows.net" },
      { "name": "DYNAMIC", "value": "[concat('AccountKey=', listKeys(resourceId('Microsoft.Storage/storageAccounts', 'ste2e001'), '2023-01-01').keys[0].value)]" },
      { "name": "SHARED_VAULT", "value": "/subscriptions/$global:SUB/resourceGroups/rg-e2e-shared/providers/Microsoft.KeyVault/vaults/kv-e2e-shared" },
      { "name": "HARMLESS", "value": "keep-me" } ] } } }
"@ }
        'Microsoft.Sql/servers' { @"
{ "type": "Microsoft.Sql/servers", "apiVersion": "2022-05-01-preview",
  "name": "$Name", "location": "eastus",
  "properties": { "administratorLogin": "sqladmin", "administratorLoginPassword": "$global:SecretPassword", "version": "12.0" } }
"@ }
        default { $null }
    }
}

function global:Export-AzResourceGroup {
    param(
        [string]$ResourceGroupName, [string]$Path, [string[]]$Resource,
        [switch]$IncludeParameterDefaultValue, [switch]$SkipResourceNameParameterization, [switch]$Force,
        [Parameter(ValueFromRemainingArguments)]$Rest
    )
    $wanted = if ($Resource) { $global:MockResources | Where-Object { $Resource -contains $_.ResourceId } } else { $global:MockResources }
    $bodies = @(); $params = @()
    foreach ($r in $wanted) {
        $body = New-MockResourceBody -Name $r.Name -Type $r.ResourceType
        # Matches real behaviour: Azure fails the whole export on an unsupported type.
        if (-not $body) { throw "The resource type '$($r.ResourceType)' is not supported for export." }
        $bodies += $body
        switch ($r.ResourceType) {
            'Microsoft.Storage/storageAccounts' { $params += """storageAccounts_$($r.Name)_name"": { ""type"": ""String"", ""defaultValue"": ""$($r.Name)"" }" }
            'Microsoft.Web/sites'               { $params += """sites_$($r.Name)_name"": { ""type"": ""String"", ""defaultValue"": ""$($r.Name)"" }" }
        }
    }
    $json = @"
{
  "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": { $($params -join ', ') },
  "resources": [ $($bodies -join ',') ],
  "outputs": { "storageKey": { "type": "string",
    "value": "[listKeys(resourceId('Microsoft.Storage/storageAccounts', 'ste2e001'), '2023-01-01').keys[0].value]" } }
}
"@
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8NoBOM
    [pscustomobject]@{ Path = $Path }
}

# ---------------------------------------------------------------------------
try {
    Write-Host "`n=== RUN 1: full baseline ===" -ForegroundColor Magenta
    & $exporter -ResourceGroupName $global:RG -OutputPath $outRoot -TargetLocation 'westeurope' | Out-Null

    $rgOut    = Join-Path $outRoot $global:RG
    $reports  = Join-Path $rgOut 'reports'
    $armRes   = Join-Path $rgOut 'arm/resources'
    $bicepRes = Join-Path $rgOut 'bicep/resources'

    Write-Host "`nRun 1 assertions" -ForegroundColor Cyan
    Assert-That (Test-Path (Join-Path $rgOut 'arm/main.json'))                       'the whole-RG ARM template exists (fell back past the unexportable resource)'
    Assert-That (Test-Path (Join-Path $rgOut 'bicep/main.bicep'))                    'the whole-RG Bicep template exists'
    Assert-That (Test-Path (Join-Path $rgOut 'bicep/main.sample.bicepparam'))        'a .bicepparam sample was emitted'
    Assert-That (Test-Path (Join-Path $rgOut 'deploy/Deploy-Target.ps1'))            'the deploy helper was emitted'
    Assert-That (Test-Path (Join-Path $rgOut 'state.json'))                          'state was persisted for the next run'
    Assert-That (Test-Path (Join-Path $armRes 'servers_sql-e2e.json'))               'the SQL server got its own ARM template'
    Assert-That (Test-Path (Join-Path $bicepRes 'sites_app-e2e.bicep'))              'the web app got its own Bicep template'
    Assert-That (-not (Test-Path (Join-Path $rgOut '.work')))                        'the private working folder was cleaned up'
    Assert-That (-not (Test-Path (Join-Path $rgOut 'raw-unsanitised')))              'no raw unsanitised export was left behind'

    # The whole point: no plaintext secret anywhere in the output tree.
    $leaked = [System.Collections.Generic.List[string]]::new()
    foreach ($f in (Get-ChildItem $rgOut -Recurse -File)) {
        $content = Get-Content -LiteralPath $f.FullName -Raw
        foreach ($needle in @($global:SecretPassword, $global:SecretKey)) {
            if ($content.Contains($needle)) { $leaked.Add("$($f.Name) contains $needle") }
        }
    }
    Assert-That ($leaked.Count -eq 0) 'NO plaintext secret appears anywhere in the output tree'
    foreach ($l in $leaked) { Write-Host "        $l" -ForegroundColor Red }

    $mainArm = Get-Content -LiteralPath (Join-Path $rgOut 'arm/main.json') -Raw
    Assert-That ($mainArm -match 'securestring')                          'secure parameters were declared'
    Assert-That ($mainArm -match 'listKeys\(')                            'the deploy-time listKeys() reference survived redaction'
    Assert-That ($mainArm -match 'keep-me')                               'non-secret settings were left intact'
    Assert-That (-not ($mainArm -match [regex]::Escape($global:SUB)))     'no literal subscription id remains'
    Assert-That ($mainArm -match 'subscription\(\)\.subscriptionId')      'the subscription id became a runtime expression'
    Assert-That (-not ($mainArm -match 'provisioningState'))              'read-only provisioningState was stripped'
    Assert-That (-not ($mainArm -match 'aaaaaaaa-bbbb-cccc'))             'the identity principalId was stripped'

    $portability = Get-Content -LiteralPath (Join-Path $reports 'portability-report.md') -Raw
    Assert-That ($portability -match 'Globally unique name')              'globally unique names are flagged as blocking'
    Assert-That ($portability -match 'kv-e2e-shared')                     'the cross-RG reference is reported as an external dependency'
    Assert-That ($portability -match 'Microsoft.Fake/unsupported')        'the unexportable resource type is reported'
    Assert-That ($portability -match 'storageKey')                        'the secret-bearing output is flagged'
    Assert-That ($portability -match 'Microsoft.Sql/servers')             'the region check reports the type unavailable in West Europe'

    # Each resource is processed twice (own template + main.json); rows must not double up.
    $uniqueRows = @($portability -split "`r?`n" | Where-Object { $_ -match '^\| Globally unique name' })
    Assert-That ($uniqueRows.Count -eq @($uniqueRows | Select-Object -Unique).Count) 'report rows are deduplicated across templates'

    $redaction = Get-Content -LiteralPath (Join-Path $reports 'redaction-report.json') -Raw
    Assert-That (-not $redaction.Contains($global:SecretPassword))        'the redaction report records no plaintext value'
    Assert-That ($redaction -match 'ValueFingerprint')                    'the redaction report uses value fingerprints instead'

    $paramFile = Get-Content -LiteralPath (Join-Path $rgOut 'arm/main.parameters.sample.json') -Raw
    Assert-That ($paramFile -match '<SET-ME>')                            'secure parameters are left as <SET-ME> sentinels'

    $permReport = Join-Path $reports 'resources-and-permissions.md'
    Assert-That (Test-Path $permReport) 'the resource types and permissions report is produced'
    $pr = Get-Content -LiteralPath $permReport -Raw
    Assert-That ($pr -match 'Microsoft.Storage/storageAccounts/write')  'the create action is derived from the provider catalogue'
    Assert-That ($pr -match 'Microsoft.Web/sites')                      'every exported resource type is listed'
    Assert-That ($pr -match 'Storage Account Contributor|Contributor')  'built-in roles are suggested'
    Assert-That ($pr -match 'Data-plane permissions')                   'the report states what it cannot determine'
    Assert-That (-not ($pr -match $global:SecretPassword))              'the permissions report leaks no secret'

    # -----------------------------------------------------------------------
    Write-Host "`n=== RUN 2: delta, with a change and a deletion ===" -ForegroundColor Magenta
    $global:MockSalt = 'v2-changed'
    $global:MockResources = @($global:MockResources | Where-Object { $_.Name -ne 'sql-e2e' })
    & $exporter -ResourceGroupName $global:RG -OutputPath $outRoot -Mode Delta | Out-Null

    Write-Host "`nRun 2 assertions" -ForegroundColor Cyan
    $diff = Get-Content -LiteralPath (Join-Path $reports 'diff-report.json') -Raw | ConvertFrom-Json
    Assert-That ($diff.mode -eq 'Delta')                                  'the run recorded Delta mode'
    Assert-That (@($diff.removed).Count -eq 1)                            'the deleted SQL server is reported as removed'
    Assert-That (@($diff.removed)[0].name -eq 'sql-e2e')                  'and it is the right resource'
    Assert-That (@($diff.modified).Count -eq 3)                           'the changed resources are reported as modified'
    Assert-That (-not (Test-Path (Join-Path $armRes 'servers_sql-e2e.json')))   'the deleted resource ARM template was pruned'
    Assert-That (-not (Test-Path (Join-Path $bicepRes 'servers_sql-e2e.bicep'))) 'the deleted resource Bicep template was pruned'
    Assert-That (@(Get-ChildItem (Join-Path $rgOut 'runs') -Directory).Count -eq 2) 'both runs are kept in the run history'

    $summary = Get-Content -LiteralPath (Join-Path $reports 'summary.md') -Raw
    Assert-That ($summary -match 'Secret gate \| passed')                 'the secret gate passed'
}
finally {
    if ($KeepOutput) {
        Write-Host "`nOutput left at: $outRoot" -ForegroundColor DarkGray
    } else {
        Remove-Item -LiteralPath $outRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
if ($script:Fail -gt 0) { exit 1 }
exit 0
