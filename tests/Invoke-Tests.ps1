#Requires -Version 7.3
<#
.SYNOPSIS
    Offline tests for the pure transform functions in AzRgRevEng.

.DESCRIPTION
    No Azure connection, no Az modules and no Pester required - just run it.
    These cover the parts where a silent bug would be expensive: secret
    detection, secret redaction, and the ARM string rewriting that makes
    templates portable.

.EXAMPLE
    ./tests/Invoke-Tests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../scripts/AzRgRevEng.psm1') -Force

$script:Pass = 0
$script:Fail = 0
$script:Failures = [System.Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Expected, $Actual, [string]$Because)
    $e = if ($null -eq $Expected) { '<null>' } else { [string]$Expected }
    $a = if ($null -eq $Actual) { '<null>' } else { [string]$Actual }
    if ($e -ceq $a) {
        $script:Pass++
        Write-Host "  PASS  $Because" -ForegroundColor DarkGreen
    } else {
        $script:Fail++
        $script:Failures.Add($Because)
        Write-Host "  FAIL  $Because" -ForegroundColor Red
        Write-Host "        expected: $e" -ForegroundColor DarkGray
        Write-Host "        actual:   $a" -ForegroundColor DarkGray
    }
}

function Assert-True  { param([bool]$Condition, [string]$Because) Assert-Equal -Expected 'True'  -Actual ([string]$Condition) -Because $Because }
function Assert-False { param([bool]$Condition, [string]$Because) Assert-Equal -Expected 'False' -Actual ([string]$Condition) -Because $Because }

function Assert-NotMatch {
    param([string]$Text, [string]$Pattern, [string]$Because)
    Assert-False -Condition ($Text -match $Pattern) -Because $Because
}

function Test-Group { param([string]$Name) Write-Host "`n$Name" -ForegroundColor Cyan }

# The real config drives detection, so tests run against the shipped patterns.
$config = Get-RevEngExportConfig -Path (Join-Path $PSScriptRoot '../config/export.config.json')
$secrets = $config['secrets']
$portability = $config['portability']

$SUB = '11111111-2222-3333-4444-555555555555'
$TENANT = '99999999-8888-7777-6666-555555555555'
$RG = 'rg-source'

# ---------------------------------------------------------------------------
Test-Group 'ARM expression detection'
Assert-True  (Test-RevEngArmExpression -Value "[resourceId('a','b')]") 'expression is detected'
Assert-False (Test-RevEngArmExpression -Value 'plain value')           'plain string is not an expression'
Assert-False (Test-RevEngArmExpression -Value '[[not-an-expression]')   'escaped [[ is a literal, not an expression'
Assert-False (Test-RevEngArmExpression -Value '')                      'empty string is not an expression'

# ---------------------------------------------------------------------------
Test-Group 'ARM expression body splitting'
$segs = Split-RevEngArmExpressionBody -Body "concat('a', parameters('p'), 'b')"
# concat( | 'a' | , parameters( | 'p' | ) ,  | 'b' | )
Assert-Equal 7 $segs.Count 'literal/non-literal segments are separated'
Assert-Equal 'a' $segs[1].Text 'first literal is unquoted'
Assert-True $segs[1].IsLiteral 'first literal is flagged as literal'

$escaped = Split-RevEngArmExpressionBody -Body "concat('it''s')"
Assert-Equal "it's" $escaped[1].Text 'doubled quotes are collapsed'

# ---------------------------------------------------------------------------
Test-Group 'Portable string rewriting'
$repl = @(
    @{ Token = $SUB;    Expression = 'subscription().subscriptionId'; Label = 'subscriptionId' }
    @{ Token = $TENANT; Expression = 'subscription().tenantId';       Label = 'tenantId' }
    @{ Token = "/resourceGroups/$RG/"; Expression = "concat('/resourceGroups/', resourceGroup().name, '/')"; Label = 'resourceGroupName' }
)

$r = Convert-RevEngPortableString -Value 'no tokens in here' -Replacements $repl
Assert-Equal 'no tokens in here' $r.Value 'a string without tokens is returned untouched'

$r = Convert-RevEngPortableString -Value $TENANT -Replacements $repl
Assert-Equal '[subscription().tenantId]' $r.Value 'a bare token becomes a plain expression with no format() wrapper'

$r = Convert-RevEngPortableString -Value "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/st1" -Replacements $repl
Assert-True ($r.Value.StartsWith('[format(')) 'an embedded token produces a format() expression'
Assert-NotMatch $r.Value ([regex]::Escape($SUB)) 'the literal subscription id is gone'
Assert-NotMatch $r.Value ([regex]::Escape("/resourceGroups/$RG/")) 'the literal source RG segment is gone'
Assert-True ($r.Value.EndsWith(']')) 'the rewritten value is a well-formed expression'

$r = Convert-RevEngPortableString -Value "[resourceId('Microsoft.Network/virtualNetworks', '$SUB')]" -Replacements $repl
Assert-Equal "[resourceId('Microsoft.Network/virtualNetworks', subscription().subscriptionId)]" $r.Value 'inside an expression, a whole quoted literal is swapped for the expression'

$r = Convert-RevEngPortableString -Value "[concat('/subscriptions/$SUB/x')]" -Replacements $repl
Assert-Equal "[concat(format('/subscriptions/{0}/x', subscription().subscriptionId))]" $r.Value 'a partial literal inside an expression becomes format()'

$r = Convert-RevEngPortableString -Value "prefix{brace}$SUB" -Replacements $repl
Assert-True ($r.Value -match '\{\{brace\}\}') 'literal braces are escaped for format()'

# ---------------------------------------------------------------------------
Test-Group 'Resource labelling'
Assert-Equal 'sites_app1' (Get-RevEngResourceLabel -Name "[parameters('sites_app1_name')]" -Type 'Microsoft.Web/sites') 'a name parameter reference is reduced to a readable label'
Assert-Equal 'st1'        (Get-RevEngResourceLabel -Name 'st1' -Type 'Microsoft.Storage/storageAccounts')                'a literal name is used as-is'
Assert-Equal 'sites'      (Get-RevEngResourceLabel -Name "[concat('a','b')]" -Type 'Microsoft.Web/sites')                'an opaque expression falls back to the type leaf'
# Child resources must stay distinguishable from their siblings.
Assert-Equal 'vaults_kv1_app-environment' (Get-RevEngResourceLabel -Name "[concat(parameters('vaults_kv1_name'), '/app-environment')]" -Type 'Microsoft.KeyVault/vaults/secrets') 'a child resource keeps its own trailing name segment'
Assert-Equal 'vaults_kv1_backend-key'     (Get-RevEngResourceLabel -Name "[concat(parameters('vaults_kv1_name'), '/backend-key')]" -Type 'Microsoft.KeyVault/vaults/secrets')     'sibling children get distinct labels'
Assert-Equal 'ws1_Heartbeat'              (Get-RevEngResourceLabel -Name "[concat(parameters('ws1_name'), '/Heartbeat')]" -Type 'Microsoft.OperationalInsights/workspaces/tables') 'the pattern holds for other child types'
Assert-Equal 'sites'      (Get-RevEngResourceLabel -Name '' -Type 'Microsoft.Web/sites')                                 'an empty name falls back to the type leaf'

# ---------------------------------------------------------------------------
Test-Group 'Template normalisation (regressions from the first real-RG run)'

# A Log Analytics workspace exports ~1350 built-in table schemas; nothing
# depends on them, and keeping them breaks Bicep's 800-resource limit.
$noisy = @'
{
  "resources": [
    { "type": "Microsoft.OperationalInsights/workspaces", "name": "ws1", "properties": {} },
    { "type": "Microsoft.OperationalInsights/workspaces/tables", "name": "ws1/AzureMetrics", "properties": {} },
    { "type": "Microsoft.OperationalInsights/workspaces/tables", "name": "ws1/Heartbeat", "properties": {} },
    { "type": "Microsoft.OperationalInsights/workspaces/savedSearches", "name": "ws1/search1", "properties": {} },
    { "type": "Microsoft.Storage/storageAccounts", "name": "st1", "properties": {},
      "dependsOn": [ "[resourceId('Microsoft.OperationalInsights/workspaces/tables', 'ws1', 'Heartbeat')]",
                     "[resourceId('Microsoft.OperationalInsights/workspaces', 'ws1')]" ] }
  ]
}
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$noise = Remove-RevEngNoiseResource -Template $noisy -ExcludeType @(
    'Microsoft.OperationalInsights/workspaces/tables',
    'Microsoft.OperationalInsights/workspaces/savedSearches')
Assert-Equal 3 $noise.Removed.Count 'Azure-managed child resources are dropped'
Assert-Equal 2 (@($noise.Template['resources']).Count) 'the real resources are kept'
$stDeps = @(@($noise.Template['resources'] | Where-Object { $_['type'] -eq 'Microsoft.Storage/storageAccounts' })[0]['dependsOn'])
Assert-Equal 1 $stDeps.Count 'a dependsOn pointing at a dropped resource is removed'
Assert-True ($stDeps[0] -match 'workspaces.,') 'the surviving dependency on the workspace itself is untouched'

# Azure exports subnets inline AND standalone; both together decompile to a cycle.
$dup = @'
{
  "resources": [
    { "type": "Microsoft.Network/virtualNetworks", "name": "[parameters('vnetName')]",
      "properties": { "subnets": [ { "name": "snet-a", "properties": {} }, { "name": "snet-b", "properties": {} } ] } },
    { "type": "Microsoft.Network/virtualNetworks/subnets", "name": "[concat(parameters('vnetName'), '/snet-a')]", "properties": {} },
    { "type": "Microsoft.Network/virtualNetworks/subnets", "name": "[concat(parameters('vnetName'), '/snet-b')]", "properties": {} },
    { "type": "Microsoft.Network/privateEndpoints", "name": "pe1", "properties": {},
      "dependsOn": [ "[resourceId('Microsoft.Network/virtualNetworks/subnets', parameters('vnetName'), 'snet-a')]" ] }
  ]
}
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$inline = Remove-RevEngRedundantInlineChild -Template $dup -Rule @(
    @{ parentType = 'Microsoft.Network/virtualNetworks'; childType = 'Microsoft.Network/virtualNetworks/subnets'; inlineProperty = 'subnets' })
Assert-Equal 2 $inline.Removed.Count 'standalone subnets duplicating inline ones are dropped'
Assert-Equal 2 (@($inline.Template['resources']).Count) 'the VNet and the private endpoint remain'
$peDeps = @(@($inline.Template['resources'] | Where-Object { $_['type'] -eq 'Microsoft.Network/privateEndpoints' })[0]['dependsOn'])
Assert-Equal 1 $peDeps.Count 'the dependent keeps exactly one dependency'
Assert-Equal "[resourceId('Microsoft.Network/virtualNetworks', parameters('vnetName'))]" $peDeps[0] 'and it was re-pointed at the parent VNet'
Assert-True ($inline.Template['resources'][0]['properties'].Contains('subnets')) 'the inline subnet definitions are preserved'

# A VNet without inline subnets must keep its standalone subnet resources.
$noInline = @'
{
  "resources": [
    { "type": "Microsoft.Network/virtualNetworks", "name": "vnet2", "properties": {} },
    { "type": "Microsoft.Network/virtualNetworks/subnets", "name": "vnet2/snet-a", "properties": {} }
  ]
}
'@ | ConvertFrom-Json -AsHashtable -Depth 32
$keep = Remove-RevEngRedundantInlineChild -Template $noInline -Rule @(
    @{ parentType = 'Microsoft.Network/virtualNetworks'; childType = 'Microsoft.Network/virtualNetworks/subnets'; inlineProperty = 'subnets' })
Assert-Equal 0 $keep.Removed.Count 'standalone subnets are kept when the parent has none inline'

# Read-only child ids: found on the real RG, where a private endpoint's inline
# connection carried its own id and the Bicep self-referenced (BCP079).
$childIds = @'
{
  "resources": [
    { "type": "Microsoft.Network/privateEndpoints", "name": "[parameters('peName')]",
      "properties": {
        "privateLinkServiceConnections": [
          { "name": "conn1",
            "id": "[concat(resourceId('Microsoft.Network/privateEndpoints', parameters('peName')), '/privateLinkServiceConnections/conn1')]",
            "properties": { "privateLinkServiceId": "[resourceId('Microsoft.DocumentDB/mongoClusters', 'mc1')]" } }
        ],
        "subnet": { "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'vnet1', 'snet-a')]" },
        "settings": [ { "name": "buildId", "id": "build-12345" } ]
      } }
  ]
}
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$cid = Convert-RevEngTemplateForPortability -Template $childIds -PortabilityConfig $portability
$pe = $cid.Template['resources'][0]['properties']
Assert-False ($pe['privateLinkServiceConnections'][0].Contains('id')) 'the self-referencing read-only child id is stripped'
Assert-True  ($pe['privateLinkServiceConnections'][0].Contains('name')) 'the child name is kept'
Assert-True  ($pe['privateLinkServiceConnections'][0]['properties'].Contains('privateLinkServiceId')) 'the cross-resource reference is kept'
Assert-True  ($pe['subnet'].Contains('id')) 'a reference object with no sibling name keeps its id'
Assert-True  ($pe['settings'][0].Contains('id')) 'a non-resource-id value beside a name is left alone'

# ---------------------------------------------------------------------------
Test-Group 'Splitting the whole-RG template into per-resource files'

$t = Get-RevEngExpressionToken -Value "[concat(parameters('vaults_kv1_name'), '/alpha')]"
Assert-Equal 'p:vaults_kv1_name|l:alpha' ($t.Tokens -join '|') 'a child name reduces to its parameter and literal tokens'
$t = Get-RevEngExpressionToken -Value "[resourceId('Microsoft.KeyVault/vaults/secrets', parameters('vaults_kv1_name'), 'alpha')]" -ExtractType
Assert-Equal 'Microsoft.KeyVault/vaults/secrets' $t.Type 'the resource type is taken out of a resourceId() reference'
Assert-Equal 'p:vaults_kv1_name|l:alpha' ($t.Tokens -join '|') 'and the name arguments tokenise exactly like the resource name'
$t = Get-RevEngExpressionToken -Value 'kv1/alpha'
Assert-Equal 'l:kv1|l:alpha' ($t.Tokens -join '|') 'a literal name tokenises on its slashes'

$whole = @'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vaults_kv1_name": { "type": "String", "defaultValue": "kv-one" },
    "serverfarms_plan1_name": { "type": "String", "defaultValue": "plan-one" },
    "sites_app1_name": { "type": "String", "defaultValue": "app-one" },
    "secret_app1_STORAGE": { "type": "securestring" },
    "location": { "type": "string", "defaultValue": "eastus" },
    "unused": { "type": "String", "defaultValue": "x" }
  },
  "resources": [
    { "type": "Microsoft.KeyVault/vaults", "name": "[parameters('vaults_kv1_name')]", "location": "[parameters('location')]", "properties": {} },
    { "type": "Microsoft.KeyVault/vaults/secrets", "name": "[concat(parameters('vaults_kv1_name'), '/alpha')]",
      "dependsOn": [ "[resourceId('Microsoft.KeyVault/vaults', parameters('vaults_kv1_name'))]" ], "properties": {} },
    { "type": "Microsoft.Web/serverfarms", "name": "[parameters('serverfarms_plan1_name')]", "location": "[parameters('location')]", "properties": {} },
    { "type": "Microsoft.Web/sites", "name": "[parameters('sites_app1_name')]", "location": "[parameters('location')]",
      "dependsOn": [ "[resourceId('Microsoft.Web/serverfarms', parameters('serverfarms_plan1_name'))]" ],
      "properties": { "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', parameters('serverfarms_plan1_name'))]",
                      "siteConfig": { "appSettings": [ { "name": "STORAGE", "value": "[parameters('secret_app1_STORAGE')]" } ] } } },
    { "type": "Microsoft.Web/sites/config", "name": "[concat(parameters('sites_app1_name'), '/web')]",
      "dependsOn": [ "[resourceId('Microsoft.Web/sites', parameters('sites_app1_name'))]" ], "properties": {} },
    { "type": "Microsoft.Sql/servers/databases", "name": "orphan-server/db1", "properties": {} }
  ]
}
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$before = $whole | ConvertTo-Json -Depth 32 -Compress
$parts = @(Split-RevEngTemplate -Template $whole)
$byName = @{}; foreach ($p in $parts) { $byName[$p.Name] = $p }

Assert-Equal 4 $parts.Count 'one file per top-level resource, plus one for the orphaned child'
Assert-True ($byName.ContainsKey('kv-one') -and $byName.ContainsKey('app-one') -and $byName.ContainsKey('plan-one')) 'files are named after the real resource name, resolved from the parameter default'
Assert-Equal 2 @($byName['kv-one'].Template['resources']).Count 'a Key Vault file carries its secrets'
Assert-Equal 2 @($byName['app-one'].Template['resources']).Count 'a web app file carries its config child'
Assert-True ($byName.ContainsKey('orphan-server/db1')) 'a child whose parent is not in the template still gets a file'

$app = $byName['app-one'].Template
Assert-False ($app['resources'][0].Contains('dependsOn')) 'a dependsOn pointing at another file is dropped (it would dangle)'
Assert-Equal 1 @($app['resources'][1]['dependsOn']).Count 'a dependsOn on a resource in the same file is kept'
Assert-Equal 1 $byName['app-one'].DependenciesDropped 'dropped dependencies are counted'
$appParams = @($app['parameters'].Keys)
Assert-True ($appParams -contains 'serverfarms_plan1_name') 'a parameter used only in a property reference is carried'
Assert-True ($appParams -contains 'secret_app1_STORAGE') 'the secure parameter created by redaction is carried'
Assert-True ($appParams -contains 'location') 'the location parameter is carried'
Assert-False ($appParams -contains 'vaults_kv1_name') 'parameters of other resources are not'
Assert-False (@($parts | ForEach-Object { @($_.Template['parameters'].Keys) }) -contains 'unused') 'an unreferenced parameter appears in no file'
Assert-True (@($byName['kv-one'].Members) -contains "Microsoft.KeyVault/vaults/secrets|[concat(parameters('vaults_kv1_name'), '/alpha')]") 'members use the template-level map keys'
Assert-Equal $before ($whole | ConvertTo-Json -Depth 32 -Compress) 'the input template is not modified'

# Fallback when Azure refuses to export the resources together.
$m = Merge-RevEngTemplate -Template @(
    (@'
{ "parameters": { "a_name": { "type": "String", "defaultValue": "a" } },
  "resources": [ { "type": "T/x", "name": "[parameters('a_name')]" } ] }
'@ | ConvertFrom-Json -AsHashtable),
    (@'
{ "parameters": { "a_name": { "type": "String", "defaultValue": "a" }, "b_name": { "type": "String", "defaultValue": "b" } },
  "resources": [ { "type": "T/x", "name": "[parameters('a_name')]" }, { "type": "T/x", "name": "[parameters('b_name')]" } ] }
'@ | ConvertFrom-Json -AsHashtable))
Assert-Equal 2 @($m['resources']).Count 'merged templates keep each resource once'
Assert-Equal 'a_name,b_name' (@($m['parameters'].Keys) -join ',') 'and union their parameters'

# ---------------------------------------------------------------------------
Test-Group 'Secret verdicts'
$storageConn = 'DefaultEndpointsProtocol=https;AccountName=st1;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==;EndpointSuffix=core.windows.net'

$v = Get-RevEngSecretVerdict -Name 'connectionString' -Value $storageConn -SecretConfig $secrets
Assert-True $v.IsSecret 'a literal storage connection string is a secret'
Assert-Equal 'Literal' $v.Kind 'it is classified as a literal secret'

$v = Get-RevEngSecretVerdict -Name 'connectionString' -Value "[concat('DefaultEndpointsProtocol=https;AccountName=st1;AccountKey=', listKeys(resourceId('Microsoft.Storage/storageAccounts','st1'),'2023-01-01').keys[0].value)]" -SecretConfig $secrets
Assert-False $v.IsSecret 'a listKeys()-built connection string is not a secret'
Assert-Equal 'Dynamic' $v.Kind 'it is classified as a deploy-time reference'

$v = Get-RevEngSecretVerdict -Name 'administratorLoginPassword' -Value 'P@ssw0rd!VeryReal' -SecretConfig $secrets
Assert-True $v.IsSecret 'a password caught by property name is a secret'

$v = Get-RevEngSecretVerdict -Name 'connectionStringType' -Value 'SQLAzure' -SecretConfig $secrets
Assert-False $v.IsSecret 'connectionStringType is allow-listed (it is a type, not a secret)'

$v = Get-RevEngSecretVerdict -Name 'keyData' -Value 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ some.user@host' -SecretConfig $secrets
Assert-False $v.IsSecret 'an SSH public key is allow-listed'

$v = Get-RevEngSecretVerdict -Name 'adminPassword' -Value "[parameters('adminPassword')]" -SecretConfig $secrets
Assert-False $v.IsSecret 'an existing parameter reference is not re-redacted'

$v = Get-RevEngSecretVerdict -Name 'enabled' -Value 'true' -SecretConfig $secrets
Assert-False $v.IsSecret 'an ordinary boolean-ish value is not a secret'

$v = Get-RevEngSecretVerdict -Name 'administratorLogin' -Value 'sqladmin' -SecretConfig $secrets
Assert-False $v.IsSecret 'an admin *username* is not treated as a secret'

# Found on the first real run: Container Apps use secretRef to NAME a declared
# secret. Redacting it replaced the reference and broke the env var.
$v = Get-RevEngSecretVerdict -Name 'secretRef' -Value 'mongo-connection-string' -SecretConfig $secrets
Assert-False $v.IsSecret 'secretRef names a secret rather than containing one, so it is not redacted'

$v = Get-RevEngSecretVerdict -Name 'secretIdentifier' -Value 'https://kv.vault.azure.net/secrets/x/abc' -SecretConfig $secrets
Assert-False $v.IsSecret 'a Key Vault secret identifier URI is a reference, not a secret'

$v = Get-RevEngSecretVerdict -Name 'administratorLoginPassword' -Value 'Sup3rS3cret!x' -SecretConfig $secrets
Assert-True $v.IsSecret 'but the matching admin password still is'

$v = Get-RevEngSecretVerdict -Name 'someUrl' -Value 'https://x.blob.core.windows.net/c?sv=2022-11-02&sig=aBcDeFgHiJkLmNoPqRsTuV%2FwXyZ0123456789ab%3D' -SecretConfig $secrets
Assert-True $v.IsSecret 'a SAS URL is caught by value shape even under an innocuous property name'

# ---------------------------------------------------------------------------
Test-Group 'Secret redaction end to end'
$templateJson = @"
{
  "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": { "storageAccounts_st1_name": { "type": "string", "defaultValue": "st1" } },
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2022-03-01",
      "name": "app1",
      "location": "East US",
      "identity": { "type": "SystemAssigned", "principalId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "tenantId": "$TENANT" },
      "properties": {
        "provisioningState": "Succeeded",
        "siteConfig": {
          "connectionStrings": [
            { "name": "sql", "connectionString": "Server=tcp:srv.database.windows.net,1433;Database=db;User ID=sa;Password=Sup3rS3cret!x;Encrypt=true", "type": "SQLAzure" },
            { "name": "dyn", "connectionString": "[concat('DefaultEndpointsProtocol=https;AccountName=st1;AccountKey=', listKeys(resourceId('Microsoft.Storage/storageAccounts', 'st1'), '2023-01-01').keys[0].value)]", "type": "Custom" }
          ],
          "appSettings": [
            { "name": "STORAGE", "value": "$storageConn" },
            { "name": "HARMLESS", "value": "just-a-value" }
          ]
        },
        "subnetId": "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default",
        "externalVault": "/subscriptions/$SUB/resourceGroups/rg-shared/providers/Microsoft.KeyVault/vaults/kv-shared"
      }
    }
  ],
  "outputs": {
    "storageKey": { "type": "string", "value": "[listKeys(resourceId('Microsoft.Storage/storageAccounts', 'st1'), '2023-01-01').keys[0].value]" }
  }
}
"@

$template = $templateJson | ConvertFrom-Json -AsHashtable -Depth 64
$redacted = Remove-RevEngSecretMaterial -Template $template -SecretConfig $secrets -Policy 'RedactAndParameterize'

Assert-Equal 2 $redacted.Redactions.Count 'both literal secrets are redacted (SQL password + storage key)'
Assert-Equal 1 (@($redacted.DynamicReferences | Where-Object { $_.Path -match 'connectionStrings' }).Count) 'the listKeys()-built connection string is preserved, not redacted'
Assert-Equal 2 $redacted.DynamicReferences.Count 'both deploy-time references are recorded (connection string + output)'
Assert-Equal 1 $redacted.OutputRisks.Count 'the secret-bearing output is flagged'

$redactedJson = $redacted.Template | ConvertTo-Json -Depth 64
Assert-NotMatch $redactedJson 'Sup3rS3cret' 'the SQL password is gone from the rendered template'
Assert-NotMatch $redactedJson 'abcdefghijklmnopqrstuvwxyz0123456789' 'the storage account key is gone from the rendered template'
Assert-True ($redactedJson -match 'securestring') 'secure parameters were added'
Assert-True ($redactedJson -match 'listKeys\(') 'the deploy-time reference survived'
Assert-True ($redactedJson -match 'just-a-value') 'non-secret settings are untouched'

foreach ($r in $redacted.Redactions) {
    Assert-Equal 'Parameterized' $r.Action "redaction at $($r.Path) became a parameter"
    Assert-True ($redactedJson -match [regex]::Escape("parameters('$($r.ParameterName)')")) "$($r.ParameterName) is referenced by the template"
}

# Name/value pairs should be named after the setting, not the generic 'value' key.
$names = @($redacted.Redactions.ParameterName)
Assert-True ($names -contains 'secret_app1_STORAGE') 'an appSettings secret is named after the setting name'
Assert-True ($names -contains 'secret_app1_sql')     'a connectionStrings secret is named after the connection name'

$gate = Test-RevEngSecretLeak -Content $redactedJson -SecretConfig $secrets -Source 'redacted.json'
Assert-Equal 0 $gate.Count 'the secret gate passes on the redacted template'

$gateRaw = Test-RevEngSecretLeak -Content $templateJson -SecretConfig $secrets -Source 'raw.json'
Assert-True ($gateRaw.Count -ge 2) 'the secret gate does catch the unredacted original'

# ---------------------------------------------------------------------------
Test-Group 'Placeholder policy'
$template2 = $templateJson | ConvertFrom-Json -AsHashtable -Depth 64
$ph = Remove-RevEngSecretMaterial -Template $template2 -SecretConfig $secrets -Policy 'Placeholder' -Placeholder '__REDACTED__'
$phJson = $ph.Template | ConvertTo-Json -Depth 64
Assert-NotMatch $phJson 'Sup3rS3cret' 'placeholder policy also removes the password'
Assert-True ($phJson -match '__REDACTED__') 'the placeholder marker is written'
Assert-Equal 0 (@(Test-RevEngSecretLeak -Content $phJson -SecretConfig $secrets).Count) 'placeholder output passes the gate too'

# ---------------------------------------------------------------------------
Test-Group 'Portability transforms'
$port = Convert-RevEngTemplateForPortability -Template $redacted.Template -PortabilityConfig $portability `
    -SourceSubscriptionId $SUB -SourceTenantId $TENANT -SourceResourceGroupName $RG -PrimaryLocation 'East US'
$portJson = $port.Template | ConvertTo-Json -Depth 64

Assert-NotMatch $portJson 'provisioningState' 'read-only provisioningState is stripped'
Assert-NotMatch $portJson 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' 'the identity principalId is stripped'
Assert-NotMatch $portJson ([regex]::Escape($SUB)) 'no literal subscription id remains'
Assert-True ($portJson -match 'subscription\(\)\.subscriptionId') 'subscription id became a runtime expression'
Assert-True ($portJson -match "parameters\('location'\)") 'the source region became a location parameter'
Assert-True ($port.Template['parameters'].Contains('location')) 'the location parameter was declared'
Assert-True (@($port.Findings | Where-Object { $_.Category -eq 'Environment identifier' }).Count -gt 0) 'rewrites are reported'
Assert-True ($port.Template['resources'][0]['identity'].Contains('type')) 'the deployable identity.type survives stripping'

# ---------------------------------------------------------------------------
Test-Group 'External dependencies'
# @() per the module's collection convention - a lone result arrives unrolled.
$deps = @(Get-RevEngExternalDependency -TemplateJson $templateJson -SourceResourceGroupName $RG)
Assert-Equal 1 $deps.Count 'the cross-RG Key Vault reference is reported'
Assert-True ($deps[0] -match 'kv-shared') 'and it is the right one'
Assert-NotMatch ($deps -join ' ') 'vnet1' 'same-RG references are not reported as external'

$noDeps = @(Get-RevEngExternalDependency -TemplateJson '{"a":"b"}' -SourceResourceGroupName $RG)
Assert-Equal 0 $noDeps.Count 'a template with no external references reports none'

# ---------------------------------------------------------------------------
Test-Group 'Parameter file generation'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("azrgreveng-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $info = New-RevEngParameterFile -Template $port.Template `
        -JsonPath (Join-Path $tmp 'main.parameters.sample.json') `
        -BicepParamPath (Join-Path $tmp 'main.sample.bicepparam')
    Assert-True ($info.SecureParameters.Count -eq 2) 'both secure parameters are listed'

    $pf = Get-Content -LiteralPath (Join-Path $tmp 'main.parameters.sample.json') -Raw
    Assert-True ($pf -match '<SET-ME>') 'secure parameters are left as <SET-ME> sentinels'
    Assert-Equal 0 (@(Test-RevEngSecretLeak -Content $pf -SecretConfig $secrets).Count) 'the parameter file contains no secrets'
    Assert-True ((Get-Content -LiteralPath (Join-Path $tmp 'main.sample.bicepparam') -Raw) -match "using 'main.bicep'") 'the bicepparam targets main.bicep'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
Test-Group 'Snapshot diffing'
$prev = New-RevEngOrderedMap @{
    '/rid/a' = (New-RevEngOrderedMap @{ name = 'a'; type = 't'; location = 'l'; hash = 'h1' })
    '/rid/b' = (New-RevEngOrderedMap @{ name = 'b'; type = 't'; location = 'l'; hash = 'h2' })
}
$curr = New-RevEngOrderedMap @{
    '/rid/a' = (New-RevEngOrderedMap @{ name = 'a'; type = 't'; location = 'l'; hash = 'h1' })
    '/rid/b' = (New-RevEngOrderedMap @{ name = 'b'; type = 't'; location = 'l'; hash = 'CHANGED' })
    '/rid/c' = (New-RevEngOrderedMap @{ name = 'c'; type = 't'; location = 'l'; hash = 'h3' })
}
$d = Compare-RevEngSnapshot -Current $curr -Previous $prev
Assert-Equal '/rid/c' ($d.New -join ',')      'the added resource is detected as new'
Assert-Equal '/rid/b' ($d.Modified -join ',') 'the changed hash is detected as modified'
Assert-Equal '/rid/a' ($d.Unchanged -join ',') 'the identical resource is unchanged'
Assert-Equal 0 $d.Removed.Count               'nothing was removed'

$prevOnly = Compare-RevEngSnapshot -Current (New-RevEngOrderedMap) -Previous $prev
Assert-Equal 2 $prevOnly.Removed.Count 'deletions are detected'

# A resource that could not be fingerprinted must not masquerade as unchanged
# (hides drift) nor as modified (cries wolf on every later run).
$currUnknown = New-RevEngOrderedMap @{
    '/rid/a' = (New-RevEngOrderedMap @{ name = 'a'; type = 't'; location = 'l'; hash = '' })
    '/rid/b' = (New-RevEngOrderedMap @{ name = 'b'; type = 't'; location = 'l'; hash = 'h2' })
}
$du = Compare-RevEngSnapshot -Current $currUnknown -Previous $prev
Assert-Equal '/rid/a' ($du.Unknown -join ',')   'a resource with no current fingerprint is Unknown'
Assert-Equal 0 $du.Modified.Count               'and is NOT counted as modified'
Assert-Equal '/rid/b' ($du.Unchanged -join ',') 'the comparable resource is still judged normally'

$prevUnknown = New-RevEngOrderedMap @{
    '/rid/a' = (New-RevEngOrderedMap @{ name = 'a'; type = 't'; location = 'l'; hash = '' })
    '/rid/b' = (New-RevEngOrderedMap @{ name = 'b'; type = 't'; location = 'l'; hash = 'h2' })
}
$dp = Compare-RevEngSnapshot -Current $prev -Previous $prevUnknown
Assert-Equal '/rid/a' ($dp.Unknown -join ',') 'a missing fingerprint in the PREVIOUS run is Unknown too'

# ---------------------------------------------------------------------------
Test-Group 'Canonical fingerprints (Hashtable key order is randomised per process)'

# Same content, opposite insertion order. A plain Hashtable's enumeration order
# depends on string hash codes, which .NET randomises per process - so only a
# canonical form makes the fingerprint reproducible across runs.
$tagsA = [ordered]@{ env = 'prod'; owner = 'ops'; app = 'x' }
$tagsB = [ordered]@{ app = 'x'; owner = 'ops'; env = 'prod' }
$objA = [pscustomobject]@{ Kind = 'StorageV2'; Tags = $tagsA; Properties = [pscustomobject]@{ b = 1; a = @(3, 1, 2) } }
$objB = [pscustomobject]@{ Properties = [pscustomobject]@{ a = @(3, 1, 2); b = 1 }; Tags = $tagsB; Kind = 'StorageV2' }
Assert-Equal (Get-RevEngObjectHash -InputObject $objA) (Get-RevEngObjectHash -InputObject $objB) 'key and property order do not change the fingerprint'

$objC = [pscustomobject]@{ Kind = 'StorageV2'; Tags = $tagsA; Properties = [pscustomobject]@{ b = 1; a = @(1, 2, 3) } }
Assert-False ((Get-RevEngObjectHash -InputObject $objA) -eq (Get-RevEngObjectHash -InputObject $objC)) 'array order still matters (it is meaningful in ARM)'

$objD = [pscustomobject]@{ Kind = 'StorageV2'; Tags = [ordered]@{ env = 'dev'; owner = 'ops'; app = 'x' }; Properties = [pscustomobject]@{ b = 1; a = @(3, 1, 2) } }
Assert-False ((Get-RevEngObjectHash -InputObject $objA) -eq (Get-RevEngObjectHash -InputObject $objD)) 'a changed tag value changes the fingerprint'

$single = ConvertTo-Json -InputObject (ConvertTo-RevEngCanonicalObject -InputObject @{ list = @('only') }) -Compress
Assert-Equal '{"list":["only"]}' $single 'a one-element array stays an array'

$crossProcess = @(1..2 | ForEach-Object {
    pwsh -NoProfile -Command "Import-Module '$((Join-Path $PSScriptRoot '../scripts/AzRgRevEng.psm1'))'; Get-RevEngObjectHash -InputObject @{ env='prod'; owner='ops'; costcenter='42'; app='x'; tier='web' }"
})
Assert-Equal $crossProcess[0] $crossProcess[1] 'a plain Hashtable hashes identically in two separate processes'

# ---------------------------------------------------------------------------
Test-Group 'Fingerprint resilience (the bug that made every resource look modified)'

$global:AzCallCount = 0
function global:Get-AzResource {
    param([string]$ResourceGroupName, [string]$ResourceId, [switch]$ExpandProperties, [Parameter(ValueFromRemainingArguments)]$Rest)
    if (-not $ResourceId) {
        return @([pscustomobject]@{ Name = 'r1'; ResourceType = 'Microsoft.Storage/storageAccounts'; Location = 'eastus'; ResourceId = '/rid/r1' })
    }
    $global:AzCallCount++
    if ($global:AzCallCount -lt $global:AzFailUntil) { throw 'The request was throttled. (429)' }
    return [pscustomobject]@{
        Name = 'r1'; ResourceType = 'Microsoft.Storage/storageAccounts'; Location = 'eastus'; ResourceId = '/rid/r1'
        Sku = @{ name = 'Standard_LRS' }; Kind = 'StorageV2'; Tags = @{}; Properties = @{ minimumTlsVersion = 'TLS1_2' }
    }
}

# Succeeds on the third attempt: the retry must recover a real fingerprint.
$global:AzCallCount = 0; $global:AzFailUntil = 3
$invRetry = Get-RevEngResourceInventory -ResourceGroupName 'rg' -Filters $null -MaxAttempt 3
Assert-True  ($invRetry['/rid/r1']['hash'].Length -gt 0)               'a transient failure is retried and yields a real fingerprint'
Assert-False (Test-RevEngHasKey $invRetry['/rid/r1'] 'fingerprintError') 'no error is recorded once it succeeds'

# Never succeeds: record NO hash rather than one built from partial data.
$global:AzCallCount = 0; $global:AzFailUntil = 99
$invFail = Get-RevEngResourceInventory -ResourceGroupName 'rg' -Filters $null -MaxAttempt 2
Assert-Equal '' ([string]$invFail['/rid/r1']['hash'])                 'a permanent failure records no fingerprint at all'
Assert-True  (Test-RevEngHasKey $invFail['/rid/r1'] 'fingerprintError') 'and records why'
Assert-True  ($invFail['/rid/r1']['fingerprintError'] -match 'throttled') 'the recorded reason is the real error'

Remove-Item function:global:Get-AzResource
Remove-Variable -Name AzCallCount, AzFailUntil -Scope Global -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Test-Group 'Template-level fingerprints (child resources Get-AzResource cannot see)'

$tpl1 = @'
{ "resources": [
  { "type": "Microsoft.KeyVault/vaults", "name": "kv1", "properties": { "sku": "standard" } },
  { "type": "Microsoft.KeyVault/vaults/secrets", "name": "kv1/alpha", "properties": { "attributes": { "enabled": true } } },
  { "type": "Microsoft.KeyVault/vaults/secrets", "name": "kv1/beta",  "properties": { "attributes": { "enabled": true } } }
] }
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$map1 = Get-RevEngTemplateResourceMap -Template $tpl1
Assert-Equal 3 $map1.Count 'child resources are fingerprinted, not just the parent'
Assert-True ($map1.Contains('Microsoft.KeyVault/vaults/secrets|kv1/alpha')) 'keyed by type and name'
Assert-Equal $map1['Microsoft.KeyVault/vaults/secrets|kv1/alpha'].hash (Get-RevEngTemplateResourceMap -Template $tpl1)['Microsoft.KeyVault/vaults/secrets|kv1/alpha'].hash 'the fingerprint is stable across calls'

# a new secret, one secret changed, one removed
$tpl2 = @'
{ "resources": [
  { "type": "Microsoft.KeyVault/vaults", "name": "kv1", "properties": { "sku": "standard" } },
  { "type": "Microsoft.KeyVault/vaults/secrets", "name": "kv1/alpha", "properties": { "attributes": { "enabled": false } } },
  { "type": "Microsoft.KeyVault/vaults/secrets", "name": "kv1/gamma", "properties": { "attributes": { "enabled": true } } }
] }
'@ | ConvertFrom-Json -AsHashtable -Depth 32

$cd = Compare-RevEngSnapshot -Current (Get-RevEngTemplateResourceMap -Template $tpl2) -Previous $map1
Assert-Equal 'Microsoft.KeyVault/vaults/secrets|kv1/gamma' ($cd.New -join ',')      'an added Key Vault secret is detected'
Assert-Equal 'Microsoft.KeyVault/vaults/secrets|kv1/alpha' ($cd.Modified -join ',') 'a changed secret is detected'
Assert-Equal 'Microsoft.KeyVault/vaults/secrets|kv1/beta'  ($cd.Removed -join ',')  'a deleted secret is detected'
Assert-Equal 'Microsoft.KeyVault/vaults|kv1' ($cd.Unchanged -join ',')              'the untouched parent stays unchanged'

# ---------------------------------------------------------------------------
Test-Group 'Region support'

# Found on the real RG: private DNS zones report Locations = ['global'], and were
# wrongly reported as unavailable in the target region.
function global:Get-AzResourceProvider {
    param([string]$ProviderNamespace, [Parameter(ValueFromRemainingArguments)]$Rest)
    switch ($ProviderNamespace) {
        'Microsoft.Network' { [pscustomobject]@{ ResourceTypes = @(
            [pscustomobject]@{ ResourceTypeName = 'privateDnsZones'; Locations = @('global') }
            [pscustomobject]@{ ResourceTypeName = 'virtualNetworks'; Locations = @('West Europe', 'East US') }
            [pscustomobject]@{ ResourceTypeName = 'weirdThing';      Locations = @() }
        ) } }
        'Microsoft.Sql' { [pscustomobject]@{ ResourceTypes = @(
            [pscustomobject]@{ ResourceTypeName = 'servers'; Locations = @('East US') }
        ) } }
        default { $null }
    }
}

$region = @(Test-RevEngRegionSupport -TargetLocation 'westeurope' -ResourceType @(
    'Microsoft.Network/privateDnsZones', 'Microsoft.Network/virtualNetworks',
    'Microsoft.Network/weirdThing', 'Microsoft.Sql/servers', 'Microsoft.Nope/things'))

$byType = @{}; foreach ($r in $region) { $byType[$r.ResourceType] = $r }
Assert-Equal 'global'  $byType['Microsoft.Network/privateDnsZones'].Supported  'a global resource type is not reported as unavailable'
Assert-Equal 'yes'     $byType['Microsoft.Network/virtualNetworks'].Supported  'an available regional type is reported as available'
Assert-Equal 'global'  $byType['Microsoft.Network/weirdThing'].Supported       'an empty location list also means region-independent'
Assert-Equal 'NO'      $byType['Microsoft.Sql/servers'].Supported             'a genuinely unavailable type is reported as NO'
Assert-Equal 'unknown' $byType['Microsoft.Nope/things'].Supported             'an unqueryable provider is reported as unknown'

Remove-Item function:global:Get-AzResourceProvider

# ---------------------------------------------------------------------------
Test-Group 'Required permissions (derived from the provider catalogue)'

$global:ProviderCalls = 0
function global:Get-AzProviderOperation {
    param([Parameter(Position = 0)][string]$OperationSearchString, [Parameter(ValueFromRemainingArguments)]$Rest)
    $global:ProviderCalls++
    switch -Wildcard ($OperationSearchString) {
        'Microsoft.Storage/*' {
            @(
                [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/read';   IsDataAction = $false }
                [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/write';  IsDataAction = $false }
                [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/delete'; IsDataAction = $false }
                [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'; IsDataAction = $true }
                [pscustomobject]@{ Operation = 'Microsoft.Storage/storageAccounts/blobServices/read'; IsDataAction = $false }
            )
        }
        'Microsoft.KeyVault/*' {
            @(
                [pscustomobject]@{ Operation = 'Microsoft.KeyVault/vaults/read';  IsDataAction = $false }
                [pscustomobject]@{ Operation = 'Microsoft.KeyVault/vaults/write'; IsDataAction = $false }
            )
        }
        default { throw "provider not found: $OperationSearchString" }
    }
}

$perm = @(Get-RevEngRequiredPermission -ResourceType @(
    'Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageAccounts/blobServices',
    'Microsoft.KeyVault/vaults', 'Microsoft.Nope/things'))

$byType = @{}; foreach ($p in $perm) { $byType[$p.ResourceType] = $p }
Assert-Equal 'Microsoft.Storage/storageAccounts/write' $byType['Microsoft.Storage/storageAccounts'].Write 'the create action is resolved from the catalogue'
Assert-Equal 'Microsoft.Storage/storageAccounts/read'  $byType['Microsoft.Storage/storageAccounts'].Read  'the read action is resolved'
Assert-Equal 'Microsoft.KeyVault/vaults/write'         $byType['Microsoft.KeyVault/vaults'].Write         'a second namespace resolves too'
Assert-Equal $null $byType['Microsoft.Storage/storageAccounts/blobServices'].Write 'a type with no create action reports none rather than guessing'
Assert-Equal 'provider-catalogue-unavailable' $byType['Microsoft.Nope/things'].Source 'an unknown provider is flagged, not silently dropped'
Assert-Equal 3 $global:ProviderCalls 'the catalogue is queried once per namespace, not once per type'

# Azure returns 'Microsoft.App/containerApps' from Get-AzResource but
# 'containerapps' in the ARM export; Select-Object -Unique is case-SENSITIVE and
# listed both as separate types.
$global:ProviderCalls = 0
$dupCase = @(Get-RevEngRequiredPermission -ResourceType @(
    'Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageaccounts', 'MICROSOFT.STORAGE/STORAGEACCOUNTS'))
Assert-Equal 1 $dupCase.Count 'resource types differing only in case are treated as one'

# Data actions must not be offered as control-plane permissions.
$dataAction = 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
$leaked = @($perm | Where-Object { $_.Read -eq $dataAction -or $_.Write -eq $dataAction -or $_.Delete -eq $dataAction })
Assert-Equal 0 $leaked.Count 'data actions are excluded from the control-plane list'
Assert-Equal 'Microsoft.Storage/storageAccounts/blobServices/read' $byType['Microsoft.Storage/storageAccounts/blobServices'].Read 'the control-plane read for that child type is still resolved'

# ---------------------------------------------------------------------------
Test-Group 'Built-in role suggestions'

function global:Get-AzRoleDefinition {
    param([Parameter(ValueFromRemainingArguments)]$Rest)
    @(
        [pscustomobject]@{ Name = 'Owner';                     IsCustom = $false; Actions = @('*');                                  NotActions = @() }
        [pscustomobject]@{ Name = 'Contributor';               IsCustom = $false; Actions = @('*');                                  NotActions = @('Microsoft.Authorization/*/Delete') }
        [pscustomobject]@{ Name = 'Storage Account Contributor'; IsCustom = $false; Actions = @('Microsoft.Storage/*');               NotActions = @() }
        [pscustomobject]@{ Name = 'Key Vault Contributor';     IsCustom = $false; Actions = @('Microsoft.KeyVault/*');               NotActions = @() }
        [pscustomobject]@{ Name = 'Reader';                    IsCustom = $false; Actions = @('*/read');                             NotActions = @() }
        [pscustomobject]@{ Name = 'Custom Thing';              IsCustom = $true;  Actions = @('*');                                  NotActions = @() }
    )
}

$sugg = @(Get-RevEngBuiltInRoleSuggestion -RequiredAction @('Microsoft.Storage/storageAccounts/write', 'Microsoft.KeyVault/vaults/write'))
Assert-True ($sugg.Count -gt 0) 'roles are suggested'
Assert-Equal 2 $sugg[0].Covered 'the top suggestion covers every required action'
Assert-True  ($sugg[0].Name -in @('Owner', 'Contributor')) 'only a wildcard role can cover two namespaces here'
$narrow = @($sugg | Where-Object { $_.Name -eq 'Storage Account Contributor' })
Assert-Equal 1 $narrow[0].Covered 'a narrow role is reported with its partial coverage'
Assert-False ($sugg.Name -contains 'Custom Thing') 'custom roles are excluded'
Assert-False ($sugg.Name -contains 'Reader') 'a read-only role does not cover create actions'

# Least privilege first when coverage ties.
$single = @(Get-RevEngBuiltInRoleSuggestion -RequiredAction @('Microsoft.Storage/storageAccounts/write'))
Assert-Equal 'Storage Account Contributor' $single[0].Name 'with equal coverage the narrowest role ranks first'
Assert-False $single[0].GrantsEverything 'and it does not grant everything'

# NotActions must subtract.
$deny = @(Get-RevEngBuiltInRoleSuggestion -RequiredAction @('Microsoft.Authorization/roleAssignments/Delete'))
$contrib = @($deny | Where-Object { $_.Name -eq 'Contributor' })
Assert-Equal 0 $contrib.Count 'a role whose NotActions exclude the action is not suggested'

Remove-Item function:global:Get-AzProviderOperation, function:global:Get-AzRoleDefinition
Remove-Variable -Name ProviderCalls -Scope Global -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Test-Group 'Config overrides'
$c = Get-RevEngExportConfig -Path (Join-Path $PSScriptRoot '../config/export.config.json') -Overrides @{
    'mode'           = 'Delta'
    'secrets.policy' = 'Placeholder'
    'output.path'    = $null
}
Assert-Equal 'Delta'       $c['mode']                'a scalar override is applied'
Assert-Equal 'Placeholder' $c['secrets']['policy']   'a nested override is applied'
Assert-Equal './exports'   $c['output']['path']      'a null override leaves the config value intact'

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
if ($script:Fail -gt 0) {
    Write-Host 'Failed assertions:' -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
exit 0
