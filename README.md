# azure-infra-reveng

Reverse-engineers an existing Azure Resource Group into **ARM and Bicep templates that can redeploy the same resources into another resource group, subscription or tenant** — with secrets stripped out into secure parameters, a report of everything that still needs a human decision, and drift detection between runs.

Built to be run straight from a PowerShell IDE. One script, one config file, no state outside the output folder.

| Goal | How |
|---|---|
| **Document** infrastructure as code | Sanitised ARM + Bicep per resource, plus one deployable whole-RG template |
| **Replicate** it elsewhere | Environment identifiers become runtime expressions; secrets and unique names become parameters; a `Deploy-Target.ps1` helper does a what-if first |
| **Detect drift** | Every resource fingerprinted and diffed against the previous run — new / modified / removed / unknown — at two levels |
| **Plan access** | A report of every resource type found and the permissions needed to read it here and create it elsewhere |

**It never writes to Azure.** Every call is `Get-Az*` plus `Export-AzResourceGroup`, which only serialises a template. Nothing is created, modified or deleted.

---

## Credentials: what you actually need

There are **no API keys, connection strings or secrets to configure**. This tool stores no credentials of its own and has no config file for them. It authenticates as *you*, through the standard Azure PowerShell context, and reads that context from wherever `Az.Accounts` normally keeps it.

Pick whichever of the three below matches where you are running it.

### 1. Interactive — a person at a terminal

```powershell
Connect-AzAccount                              # opens a browser
Connect-AzAccount -Subscription '<sub-id>'     # or pin the subscription
Connect-AzAccount -UseDeviceAuthentication     # no browser available
```

**Run this in PowerShell, not bash** — `Connect-AzAccount` is a cmdlet, not an executable. From a bash prompt use `pwsh -NoProfile -Command "Connect-AzAccount"`.

The sign-in persists to `~/.Azure` (`ContextSaveMode: CurrentUser` by default), so later PowerShell processes pick it up and you do not re-authenticate per terminal. Check with `Get-AzContextAutosaveSetting`.

### 2. Service principal — CI, or an unattended schedule

Create one scoped to the resource group you are exporting:

```powershell
$sp = New-AzADServicePrincipal -DisplayName 'azure-infra-reveng' `
        -Role 'Reader' -Scope '/subscriptions/<sub-id>/resourceGroups/<rg>'
```

Then authenticate with it. **The secret is a credential — pass it from your secret store, never commit it:**

```powershell
$cred = [pscredential]::new($env:AZURE_CLIENT_ID,
                            (ConvertTo-SecureString $env:AZURE_CLIENT_SECRET -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $env:AZURE_TENANT_ID
```

In Azure Pipelines, prefer an **ARM service connection with workload identity federation** and the `AzurePowerShell@5` task — no secret exists to leak:

```yaml
- task: AzurePowerShell@5
  inputs:
    azureSubscription: <your-service-connection>
    ScriptType: filePath
    ScriptPath: scripts/Export-AzResourceGroupIaC.ps1
    ScriptArguments: -ResourceGroupName <rg> -OutputPath $(Build.ArtifactStagingDirectory)/export
    azurePowerShellVersion: LatestVersion
```

### 3. Managed identity — running on an Azure VM, Container App or Automation account

```powershell
Connect-AzAccount -Identity
```

### Azure roles the identity needs

| To do this | Grant |
|---|---|
| Read the resource group and every resource's properties | `Reader` on the resource group |
| Export ARM templates | `Microsoft.Resources/subscriptions/resourceGroups/exportTemplate/action` — see the note below |
| Collect role assignments (optional, `-SkipRoleAssignments`) | `Microsoft.Authorization/roleAssignments/read`, plus Microsoft Graph directory read to resolve principal names |
| Collect locks and policy (optional) | `Microsoft.Authorization/locks/read`, `Microsoft.Authorization/policyAssignments/read` |

**About the export action:** it is documented by Microsoft but **absent from Azure's provider operation catalogue**, so it cannot be verified programmatically and is not covered by a role you can look up. In practice `Reader` alone is often *not* enough to export templates and `Contributor` is what works. Start with `Reader`; if the export step fails while the inventory succeeds, that is the missing piece.

Every run writes `reports/resources-and-permissions.md` with the actual per-type permissions for **your** resource group, derived from Azure's catalogue at runtime — including which role your identity empirically held on a run that worked.

### Prerequisites

```powershell
Install-Module Az -Scope CurrentUser -Repository PSGallery -Force
winget install Microsoft.AzureCLI      # provides `az`, needed only for Bicep
az bicep install
```

PowerShell **7.3+**, `Az.Accounts` and `Az.Resources`. The Azure CLI with Bicep is needed only for Bicep output — `-SkipBicep` drops that dependency and emits ARM alone.

---

## Quick start

```powershell
git clone https://github.com/aelena/azure-infra-reveng.git
cd azure-infra-reveng

./tests/Invoke-Tests.ps1                       # ~2s, no Azure at all - proves the toolchain

Connect-AzAccount
./scripts/Export-AzResourceGroupIaC.ps1 -ResourceGroupName <rg> -OutputPath 'C:\temp\azure-audit'
```

Then read `C:\temp\azure-audit\<rg>\reports\summary.md`.

### Where to send the output

**Keep it out of a synced folder for the first run.** Mid-run the raw, *unredacted* export sits in a `.work/` folder before redaction. It is deleted on success, but OneDrive or Dropbox can upload it in that window. The script warns if it detects one; `.gitignore` excludes it regardless.

`-OutputPath` accepts an absolute path. If relative: omitted (so the config default `./exports` applies) it resolves against the **repo root**; passed explicitly it resolves against your **current directory**. The resolved path is printed as `Output :` in the first few lines.

---

## Running it

```powershell
# Everything
./scripts/Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-prod -OutputPath 'C:\repos\infra-audit'

# Only what changed since last time - the drift check
./scripts/Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-prod -Mode Delta

# Planning a regional move: check the types exist in the target region
./scripts/Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-prod -TargetLocation westeurope

# Cross-subscription, committing each run to an audit repo
./scripts/Export-AzResourceGroupIaC.ps1 -ResourceGroupName rg-prod `
    -SubscriptionId <sub-id> -OutputPath 'C:\repos\infra-audit' -GitCommit
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-ResourceGroupName` | *required* | Source RG to reverse-engineer |
| `-SubscriptionId` | current context | Switch subscription before running |
| `-Mode` | `Full` | `Full` = every in-scope resource; `Delta` = only new/changed since last run |
| `-OutputPath` | `./exports` | Root output folder (a subfolder per RG is created) |
| `-ConfigPath` | `config/export.config.json` | Use a different config file |
| `-TargetLocation` | — | Also check resource-type availability in that region |
| `-SecretPolicy` | `RedactAndParameterize` | Or `Placeholder` |
| `-AllowResidualSecrets` | off | Downgrade the secret gate from failure to warning |
| `-SkipBicep` | off | ARM only, no Azure CLI needed |
| `-SkipPermissionReport` | off | Skip the resource types and permissions report |
| `-SkipRoleAssignments`, `-SkipLocks`, `-SkipPolicies` | off | Skip audit-only collection |
| `-GitCommit` | off | Commit the run locally (never pushes) |

Any parameter overrides the matching config value; anything omitted keeps the file's value.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Completed with issues — an export failure, Bicep that does not compile, or secrets allowed through. Artefacts were still written |
| `2` | Aborted — prerequisites failed, the secret gate fired, or an unhandled error |

---

## Output

```
<OutputPath>/<resource-group>/
  arm/
    main.json                        # whole RG, deployable
    main.parameters.sample.json
    resources/<type>_<name>.json     # one per resource, for review
  bicep/
    main.bicep                       # whole RG, deployable
    main.parameters.sample.json
    main.sample.bicepparam
    resources/<type>_<name>.bicep
  deploy/
    Deploy-Target.ps1                # what-if, then deploy, into a target RG
  reports/
    summary.md                       # start here
    portability-report.md            # what still needs your decision
    resources-and-permissions.md     # every type found, and the rights to deploy them
    diff-report.json                 # new / modified / removed, both levels
    redaction-report.json            # secrets removed (fingerprints, never values)
    rbac-locks-policy.json           # audit-only
  runs/<timestamp>/                  # historical copy of that run's reports
  state.json                         # fingerprints, for the next run's diff
```

---

## Secret handling

The ARM export of some resource types contains live secret material — SQL admin passwords, App Service connection strings, shared access keys, SAS tokens.

**Nothing is written to the output tree until the secret gate has passed.** The export lands in a private working folder, redaction and scanning happen in memory, and only then are templates written.

Detection is two-layered and configurable:

1. **Property name** — `connectionString`, `*accountKey`, `*password`, `*secret`, `sharedAccessKey`, `sasToken`…
2. **Value shape** — the text of a storage connection string, a `Password=` in a SQL connection string, a SAS `sig=`, a PEM key, a JWT. This catches secrets under innocuous property names.

Three cases are treated differently:

| Case | What happens |
|---|---|
| A literal secret | Replaced with a `@secure()` parameter; you supply it at deploy time |
| `[listKeys(...)]` / `[listSecrets(...)]` | **Left alone** — resolves at deploy time, carries no key material, and parameterising it would be a downgrade |
| An output returning `listKeys(...)` | Kept but **flagged** — outputs stay readable in deployment history |

**Deliberately never redacted:** names that *reference* a secret rather than containing one — `secretRef` (how Container Apps point an env var at a declared secret), `secretIdentifier`, `secretUri`, `secretName` — plus `administratorLogin`/`adminUsername` (usernames), `keyData` (an SSH *public* key), thumbprints. Redacting a reference silently breaks it, which is worse than not redacting.

**The gate:** after redaction the rendered ARM *and* the decompiled Bicep are re-scanned. Any hit aborts the run (exit 2) and writes `reports/secret-gate-failures.json`. Either add a pattern to `secrets.keyNamePatterns`/`valuePatterns`, or re-run with `-AllowResidualSecrets` once you have confirmed a false positive.

`redaction-report.json` records a SHA-256 **fingerprint** of each removed value, never the value.

---

## Drift detection

Every run answers what is new, what changed and what was deleted, at two levels.

**Level 1 — per resource.** `Get-AzResource -ExpandProperties` fingerprinted and compared with the previous `state.json`. Drives `-Mode Delta`.

**Level 2 — per resource inside the template.** `Get-AzResource` does not enumerate most child resources; on a real resource group it saw 21 of 56. Key Vault secrets, model deployments, ACR scope maps and DNS records were invisible to level 1. The whole-RG template is re-exported every run including Delta, so it is fingerprinted resource by resource as a second level.

**Unknown — the fourth state.** A resource whose properties could not be fetched is reported as Unknown, never as unchanged or modified. Transient failures are retried with backoff; if the fetch still fails no fingerprint is recorded and the resource is exported anyway. Reporting it as unchanged would hide drift; as modified it would cry wolf on every later run.

**Not covered:** RBAC, locks and policy assignments are captured each run but are not part of either fingerprint — diff them with `git diff` if you commit the output.

### Tracking drift in git

`-Mode Delta -GitCommit` makes each run a commit:

```
azure export [rg-prod] 20260827-113957 - mode:Delta new:1 modified:2 removed:0 redacted:4
```

`git log -p <OutputPath>/rg-prod/bicep/` then shows how the infrastructure changed over time. `-GitCommit` never pushes, and skips if `OutputPath` is not inside a repo. Because secrets are parameterised out, sanitised exports are safe to commit — **review your first export before the first push anyway.**

---

## Portability: automatic vs yours

**Automatic:** subscription id → `subscription().subscriptionId`; tenant id → `subscription().tenantId`; source RG in resource ids → `resourceGroup().name`; region → a `location` parameter; read-only runtime state stripped.

Rewriting happens at the ARM expression level, not by text replacement: an identifier embedded in a longer string becomes a `format()` call with escaped braces. Round-trip tested against the real Bicep CLI.

**Yours to decide** — all in `reports/portability-report.md`:

| Item | Why it can't be automatic |
|---|---|
| Globally unique names | Storage, Key Vault, ACR etc. must be unique across Azure |
| Key Vault secret values | Azure never exports them; the resource would deploy empty |
| Tenant-scoped principal ids | An `objectId` does not exist in another tenant |
| RBAC, locks, policy | Same reason — captured for audit, not generated as IaC |
| External dependencies | Resource ids outside the source RG; must already exist in the target |
| Types Azure cannot export | Listed with their error; need hand-authoring |
| SKU and zone availability | `-TargetLocation` checks type availability, not SKUs or zones |

Deploying is a two-step by design:

```powershell
# 1. Fill in every <SET-ME> in bicep/main.parameters.sample.json, then:
<OutputPath>/<rg>/deploy/Deploy-Target.ps1 -ResourceGroupName rg-target -Location westeurope -WhatIfOnly
# 2. Read the what-if output. Only then drop -WhatIfOnly.
```

`Deploy-Target.ps1` refuses to run while any `<SET-ME>` remains, and asks for typed confirmation before a real deployment.

---

## Template normalisation

Azure's export is faithful to what *exists*, not to what you would author. Three artefacts break real deployments, and all three are corrected — every correction counted and itemised in `portability-report.md`.

1. **Azure-managed children.** A Log Analytics workspace exports ~678 built-in table schemas plus default saved searches. On a four-workspace resource group that was ~2,900 resources, 96% of the template, past Bicep's hard limit of 800. Controlled by `resourceFilters.excludeChildTypes`.
2. **Children exported inline *and* standalone.** Subnets come back both ways, which decompiles to a dependency cycle (`BCP080`). Duplicates dropped, dependents re-pointed at the parent. Controlled by `portability.redundantInlineChildren`.
3. **Read-only ids on inline children.** A private endpoint's connection carries an `id` pointing at its own resource, so the Bicep self-references (`BCP079`). Stripped only where the object has its own `name` and the value is resource-id-shaped, so reference objects like `subnet: { id: … }` are untouched. Controlled by `portability.stripReadOnlyChildIds`.

---

## Configuration

Everything lives in [`config/export.config.json`](config/export.config.json), commented inline via `_comment`-style keys.

| Key | Controls |
|---|---|
| `mode` | `Full` or `Delta` |
| `output.*` | Output root, run-history retention, whether to keep the raw unsanitised export |
| `resourceFilters.includeTypes` / `excludeTypes` | Wildcard match on resource type |
| `resourceFilters.includeNamePattern` / `excludeNamePattern` | Regex match on resource name |
| `resourceFilters.excludeChildTypes` | Azure-managed children to drop from templates |
| `secrets.policy` | `RedactAndParameterize` or `Placeholder` |
| `secrets.failOnResidualSecret` | Whether the gate aborts or warns |
| `secrets.keyNamePatterns` / `valuePatterns` | The two detection layers |
| `secrets.allowKeyPatterns` | Names that must never be redacted — read the note in the file first |
| `portability.*` | Identifier rewriting, read-only stripping, region strategy, unique-name types |
| `supplemental.*` | Whether to collect RBAC / locks / policy |
| `permissions.*` | The permissions report, and whether to rank built-in roles |
| `validation.bicepBuild` | Recompile the generated Bicep as a check |
| `git.autoCommit` | Commit each run |

Copy the file and pass `-ConfigPath` for per-environment variants; `config/*.local.json` is git-ignored.

`output.keepRawExport` keeps the unredacted export for troubleshooting. **It writes live secrets to disk** — warned about at runtime, and git-ignored.

---

## Repository layout and tests

```
scripts/
  Export-AzResourceGroupIaC.ps1   # entry point: orchestration and reporting
  AzRgRevEng.psm1                 # every transform, and the only Azure calls
config/
  export.config.json              # all tunables
tests/
  Invoke-Tests.ps1                # 136 assertions, no Azure at all
  Invoke-EndToEndTest.ps1         # 40 assertions, full run against a mocked Azure
```

The transform logic is deliberately separated from the Azure calls so it can be tested without a subscription. Neither suite needs Pester; both exit non-zero on failure.

```powershell
./tests/Invoke-Tests.ps1           # ~2s
./tests/Invoke-EndToEndTest.ps1    # ~45s, needs the Bicep CLI
```

`Invoke-EndToEndTest.ps1` runs the real exporter against a fake resource group with the Az cmdlets replaced by functions in the global scope — built out of the awkward cases on purpose: a type Azure refuses to export, a `listKeys()` expression that must survive, a cross-resource-group reference, a type missing from the target region. It asserts no plaintext secret reaches the output.

Run both after touching any pattern in the config or any function in the module.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Connect-AzAccount: command not found` | It ran in bash. It is a PowerShell cmdlet |
| `Prerequisite check failed` | Not signed in, Az modules missing, or `az bicep install` not done. Each item is listed |
| `The current Azure context has no subscription id` | Fails fast by design — re-run `Connect-AzAccount` or pass `-SubscriptionId` |
| Inventory succeeds but every export fails | Almost certainly the export-template permission. See [Azure roles](#azure-roles-the-identity-needs) |
| Run aborted on the secret gate (exit 2) | Working as designed — see [Secret handling](#secret-handling) |
| Thousands of resources dropped from a small RG | Expected — Log Analytics contributes ~678 built-in table schemas per workspace. Every drop is itemised |
| `Error max-resources: limited to 800` | `excludeChildTypes` does not cover a noisy child type in this RG |
| `BCP079` / `BCP080` | The normalisations that fix these are disabled, or a type needs a new `redundantInlineChildren` rule |
| `main.bicep` doesn't compile | Errors are in `summary.md`; the ARM is still valid — decompilation is the best-effort half |
| A config property was wrongly redacted | Add it to `secrets.allowKeyPatterns` and add a regression case to the unit suite |
| **Every** resource shows as modified | Not organic change — the previous run stored degraded fingerprints. Check it for Unknown resources |
| Delta mode exports everything | No `state.json` yet, so the run is a baseline |
| A resource shows as modified every run | Its fingerprint includes a property Azure updates itself. Narrow with `resourceFilters`, or accept it |

---

## Status

Verified end to end against a live resource group: exports cleanly, `main.bicep` compiles, secret gate passes, and drift detection was confirmed against a real mutation (a tag added then removed — detected both ways, silent when idle).

**Not yet verified: that the generated templates actually deploy.** `main.bicep` compiling is a weaker claim than a successful `-WhatIfOnly` against a real target. Key Vault secrets with no exported value are the most likely thing to trip a first deployment.
