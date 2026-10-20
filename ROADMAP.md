# Roadmap

What is worth doing next, roughly in order of value. Each item says why, because several of them are judgement calls.

## Verify against a live subscription

The single most valuable next step, and a prerequisite for trusting everything below.

- Run `Export-AzResourceGroupIaC.ps1` against the same resource group the original was verified on, and compare: resource counts at both levels, redactions, findings, and whether every per-resource Bicep file compiles.
- Run `-Mode Delta` twice with nothing changed and confirm zero drift — on a resource group whose resources carry **two or more tags**, which is the case the canonical-fingerprint fix is about.
- Run `Deploy-Target.ps1 -WhatIfOnly` into an empty resource group in a sandbox subscription. That is the claim the README still cannot make: that the output deploys.
- Run `Export-AzSubscriptionIaC.ps1` over a whole subscription and note the slowest resource groups.

## Faster inventory

The inventory makes one `Get-AzResource -ExpandProperties` call per resource, serially. On a few hundred resources that is now the slowest part of a run, since the export is a single call.

- **Azure Resource Graph** (`Search-AzGraph`, module `Az.ResourceGraph`) returns every resource's properties for a whole resource group in one paged query. It would replace N calls with one or two. Its property shapes differ slightly from `Get-AzResource`, so it needs a fingerprint-format bump (the re-baseline path already exists) and should be opt-in until verified.
- Failing that, `ForEach-Object -Parallel` with a small throttle. Harder to test: the end-to-end suite's global-scope mocks do not reach other runspaces.

## Deployability

- **A deployment smoke test in CI**: a scheduled workflow that exports a small, purpose-built resource group in a sandbox subscription, deploys the result into a second one with what-if, then for real, and tears both down. Costly to set up, but it is the only thing that turns "compiles" into "deploys".
- **SKU and zone availability** for `-TargetLocation`: `Get-AzComputeResourceSku` covers VMs, disks and some PaaS. Today only type availability is checked.
- **Role assignments as opt-in IaC**: emit them with `principalId` as a parameter and the role definition resolved by name, for same-tenant moves where the principals do exist. Off by default; cross-tenant they cannot work.
- **Which role the identity holds**: the permissions report matches assignments by sign-in name, which never matches a service principal. Matching by object id needs one Graph call.

## Quality

- **PSScriptAnalyzer** in CI with a settings file. `Write-Host` is deliberate here (an IDE-first tool), so that rule needs excluding, and the existing findings need a first pass before the check can gate.
- **Pester**: the two suites deliberately need nothing installed, which matters for "clone and run". Moving to Pester would buy better failure output and isolation of the global-scope mocks, at that cost. Worth it if the suites keep growing.
- **A JSON schema for the config**, so editors autocomplete and flag typos while editing. The startup validation covers the same ground at run time.

## Multi-cloud: separate tools, shared conventions

AWS and GCP are worth supporting, but **not in this tool**. Almost nothing below the surface is shared:

| | Azure | AWS | GCP |
|---|---|---|---|
| Unit of export | resource group | account + region (no native grouping; tags or CloudFormation stacks at best) | project |
| Native export | `Export-AzResourceGroup` → ARM | none for arbitrary resources; CloudFormation IaC generator for supported types | `gcloud beta resource-config bulk-export` → Terraform/KRM |
| Target language | ARM / Bicep | CloudFormation, or Terraform | Terraform, or KRM |
| Identifier rewriting | ARM expressions (`subscription()`, `resourceGroup()`) | intrinsic functions (`AWS::AccountId`, `AWS::Region`) | Terraform variables |
| Secret shapes | connection strings, SAS, account keys | access keys, Secrets Manager ARNs | service-account JSON keys |
| Auth | `Az.Accounts` context | AWS profiles / SSO | `gcloud` application default credentials |

Every transform in `AzRgRevEng.psm1` — the ARM expression parser, the portability rewriter, the normalisations, the splitter — is specific to ARM. A shared core would be a thin abstraction over three different programs.

What *is* worth sharing is the shape, so a second tool feels familiar:

- the run model: inventory → fingerprint → diff → export → redact → gate → emit → report;
- the output layout (`reports/summary.md` + `summary.json`, `state.json`, `runs/<timestamp>/`) and the exit codes `0/1/2/3`;
- the secret gate semantics (nothing written until it passes; fingerprints, never values);
- the drift states, including Unknown;
- generic value-shape secret patterns (PEM keys, JWTs, third-party tokens), which could move into a small shared file.

Suggested layout when it happens: sibling repositories or sibling folders (`azure/`, `aws/`, `gcp/`), each self-contained with its own config and tests, plus a short `CONVENTIONS.md` that pins the output contract above. A pipeline then consumes `summary.json` without caring which cloud produced it.
