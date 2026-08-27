#Requires -Version 7.3
<#
    AzRgRevEng - helper functions for reverse-engineering an Azure Resource
    Group into portable, secret-free ARM + Bicep.

    Nothing here writes to the console except Write-RevEngLog, and the pure
    transform functions (secret redaction, portability rewriting, ARM string
    handling) have no Azure dependency, so they are unit-tested offline by
    tests/Invoke-Tests.ps1.

    Collection convention: functions that return a list emit it unrolled, the
    PowerShell norm. Wrap a call in @() before using .Count or an index, since a
    single result arrives as a bare scalar. (Returning ,$array instead would fix
    that but make an empty result look like one bogus item - worse.)

    Dictionary note: templates are loaded with ConvertFrom-Json -AsHashtable,
    which yields OrderedHashtable (order-preserving, and IS-A hashtable). Maps
    created here use New-RevEngOrderedMap for the same reason - never [ordered]@{},
    which produces an OrderedDictionary that silently degrades to an unordered
    Hashtable when bound to a [hashtable] parameter. Key existence is always
    tested with .Contains(), the one method both types share.
#>

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

$script:LogColors = @{
    Step = 'Cyan'
    Info = 'Gray'
    Ok   = 'Green'
    Warn = 'Yellow'
    Err  = 'Red'
}

function Write-RevEngLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [ValidateSet('Step', 'Info', 'Ok', 'Warn', 'Err')][string]$Level = 'Info',
        [int]$Indent = 0
    )
    $prefix = switch ($Level) {
        'Step'  { "`n=== " }
        'Ok'    { '  [ok]   ' }
        'Warn'  { '  [warn] ' }
        'Err'   { '  [FAIL] ' }
        default { '  ' }
    }
    $suffix = if ($Level -eq 'Step') { ' ===' } else { '' }
    $pad = ' ' * ($Indent * 2)
    Write-Host ('{0}{1}{2}{3}' -f $prefix, $pad, $Message, $suffix) -ForegroundColor $script:LogColors[$Level]
}

# ---------------------------------------------------------------------------
# Dictionary / small utilities
# ---------------------------------------------------------------------------

function New-RevEngOrderedMap {
    [CmdletBinding()]
    param([hashtable]$From)
    $map = [System.Management.Automation.OrderedHashtable]::new()
    if ($From) { foreach ($k in $From.Keys) { $map[$k] = $From[$k] } }
    return $map
}

function Test-RevEngIsDictionary {
    param($Node)
    return ($Node -is [System.Collections.IDictionary])
}

function Test-RevEngIsList {
    param($Node)
    return ($Node -is [System.Collections.IList] -and $Node -isnot [string])
}

function Test-RevEngHasKey {
    param($Node, [string]$Key)
    if (-not (Test-RevEngIsDictionary $Node)) { return $false }
    return $Node.Contains($Key)
}

function Get-RevEngConfigValue {
    <# Safe dotted-path read out of a config tree, with a default. #>
    [CmdletBinding()]
    param(
        $Config,
        [Parameter(Mandatory)][string]$Path,
        $Default = $null
    )
    $node = $Config
    foreach ($part in ($Path -split '\.')) {
        if (-not (Test-RevEngHasKey $node $part)) { return $Default }
        $node = $node[$part]
    }
    if ($null -eq $node) { return $Default }
    return $node
}

function ConvertTo-RevEngSafeName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    $safe = $Name -replace '[^A-Za-z0-9\-_]', '_'
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'unnamed' }
    if ($safe.Length -gt 120) { $safe = $safe.Substring(0, 120) }
    return $safe
}

function ConvertTo-RevEngParameterName {
    <# ARM/Bicep identifier: letter first, then letters/digits/underscore. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    $clean = ($Name -replace '[^A-Za-z0-9]', '_') -replace '_+', '_'
    $clean = $clean.Trim('_')
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'value' }
    if ($clean -notmatch '^[A-Za-z]') { $clean = "p_$clean" }
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80).Trim('_') }
    return $clean
}

function Get-RevEngResourceLabel {
    <#
    .SYNOPSIS
        A human-readable label for a resource whose ARM name is usually an
        expression like [parameters('sites_app1_name')]. Used for generated
        parameter names and report readability.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()][string]$Name,
        [AllowEmptyString()][AllowNull()][string]$Type
    )

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        if (-not (Test-RevEngArmExpression -Value $Name)) { return $Name }

        # '[parameters('sites_app1_name')]' -> 'sites_app1'
        $m = [regex]::Match($Name, "^\[parameters\('([^']+)'\)\]$")
        if ($m.Success) { return ($m.Groups[1].Value -replace '_name$', '') }

        # Child resources come out as
        # '[concat(parameters('vaults_kv1_name'), '/app-environment')]'. Keeping the
        # trailing literal segments is what distinguishes one child from its
        # siblings - without them, eight Key Vault secrets collapse into one row.
        $base = ''
        $pm = [regex]::Match($Name, "parameters\('([^']+)'\)")
        if ($pm.Success) { $base = $pm.Groups[1].Value -replace '_name$', '' }

        $segments = @([regex]::Matches($Name, "'/([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        if ($segments.Count -gt 0) {
            $tail = ($segments -join '_') -replace '/', '_'
            return $(if ($base) { "${base}_$tail" } else { $tail })
        }
        if ($base) { return $base }
    }
    if (-not [string]::IsNullOrWhiteSpace($Type)) {
        return (($Type -split '/')[-1])
    }
    return 'resource'
}

function Get-RevEngShortHash {
    <# Stable, non-reversible fingerprint. Lets a report point at a redacted
       value without ever recording the value. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [int]$Length = 12
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        $hex = [System.BitConverter]::ToString($bytes) -replace '-', ''
        return $hex.Substring(0, [Math]::Min($Length, $hex.Length)).ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-RevEngObjectHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$InputObject)
    $json = $InputObject | ConvertTo-Json -Depth 25 -Compress
    if ($null -eq $json) { $json = '' }
    return Get-RevEngShortHash -Value ([string]$json) -Length 64
}

function Copy-RevEngJsonObject {
    <# Deep clone via JSON round-trip so transforms never mutate the caller's tree. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -AsHashtable -Depth 64)
}

# ---------------------------------------------------------------------------
# Generic JSON tree visitor
# ---------------------------------------------------------------------------

function Invoke-RevEngTreeVisit {
    <#
    .SYNOPSIS
        Depth-first walk over a dictionary/array tree, letting the visitor
        replace or remove nodes.
    .DESCRIPTION
        The visitor is invoked as & $Visitor $name $path $node and returns either
        $null (keep walking) or a hashtable with:
            Handled = $true  -> use .Value verbatim, do not recurse into it
            Remove  = $true  -> delete this node from its parent
        Because the visitor scriptblock is created in the caller's scope, it can
        accumulate findings straight into the caller's variables.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Node,
        [string]$Path = '$',
        [string]$Name = '',
        [Parameter(Mandatory)][scriptblock]$Visitor
    )

    $decision = & $Visitor $Name $Path $Node
    if ($decision -is [System.Collections.IDictionary]) {
        if ($decision.Contains('Remove') -and $decision['Remove']) {
            return @{ Remove = $true }
        }
        if ($decision.Contains('Handled') -and $decision['Handled']) {
            return @{ Remove = $false; Value = $decision['Value'] }
        }
    }

    if (Test-RevEngIsDictionary $Node) {
        foreach ($key in @($Node.Keys)) {
            $res = Invoke-RevEngTreeVisit -Node $Node[$key] -Path "$Path.$key" -Name ([string]$key) -Visitor $Visitor
            if ($res['Remove']) { $Node.Remove($key) } else { $Node[$key] = $res['Value'] }
        }
        return @{ Remove = $false; Value = $Node }
    }

    if (Test-RevEngIsList $Node) {
        $out = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Node.Count; $i++) {
            $res = Invoke-RevEngTreeVisit -Node $Node[$i] -Path "$Path[$i]" -Name $Name -Visitor $Visitor
            if (-not $res['Remove']) { $out.Add($res['Value']) }
        }
        return @{ Remove = $false; Value = $out.ToArray() }
    }

    return @{ Remove = $false; Value = $Node }
}

# ---------------------------------------------------------------------------
# ARM expression handling
# ---------------------------------------------------------------------------

function Test-RevEngArmExpression {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.StartsWith('[[')) { return $false }   # '[[' escapes a literal '['
    return ($Value.StartsWith('[') -and $Value.EndsWith(']'))
}

function Split-RevEngArmExpressionBody {
    <#
    .SYNOPSIS
        Splits an ARM expression body into literal and non-literal segments.
    .OUTPUTS
        Array of @{ IsLiteral = <bool>; Text = <string> }. Literal segment text
        is unescaped (doubled quotes collapsed to one).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Body)

    $quote = [char]0x27
    $segments = [System.Collections.Generic.List[hashtable]]::new()
    $buffer = [Text.StringBuilder]::new()
    $i = 0

    while ($i -lt $Body.Length) {
        if ($Body[$i] -eq $quote) {
            if ($buffer.Length -gt 0) {
                $segments.Add(@{ IsLiteral = $false; Text = $buffer.ToString() })
                [void]$buffer.Clear()
            }
            $i++
            $lit = [Text.StringBuilder]::new()
            while ($i -lt $Body.Length) {
                if ($Body[$i] -eq $quote) {
                    if (($i + 1) -lt $Body.Length -and $Body[$i + 1] -eq $quote) {
                        [void]$lit.Append($quote)
                        $i += 2
                        continue
                    }
                    $i++
                    break
                }
                [void]$lit.Append($Body[$i])
                $i++
            }
            $segments.Add(@{ IsLiteral = $true; Text = $lit.ToString() })
            continue
        }
        [void]$buffer.Append($Body[$i])
        $i++
    }

    if ($buffer.Length -gt 0) {
        $segments.Add(@{ IsLiteral = $false; Text = $buffer.ToString() })
    }
    return $segments.ToArray()
}

function ConvertTo-RevEngArmLiteral {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $quote = [string][char]0x27
    return $quote + ($Value -replace $quote, ($quote + $quote)) + $quote
}

function ConvertTo-RevEngArmFragment {
    <#
    .SYNOPSIS
        Renders a literal string as an ARM expression *fragment*, swapping any
        environment tokens for runtime expressions (via format() when the token
        is embedded in surrounding text).
    .PARAMETER Replacements
        Array of @{ Token = '<literal>'; Expression = '<armExpr>'; Label = '<name>' }
    .OUTPUTS
        @{ Fragment = <string>; Hits = @('<label>', ...) }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Literal,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Replacements
    )

    $hits = [System.Collections.Generic.List[string]]::new()
    $formatArgs = [System.Collections.Generic.List[string]]::new()
    $format = [Text.StringBuilder]::new()
    $remaining = $Literal

    while ($true) {
        $bestIndex = -1
        $best = $null
        foreach ($r in $Replacements) {
            if ([string]::IsNullOrEmpty($r.Token)) { continue }
            $idx = $remaining.IndexOf([string]$r.Token, [StringComparison]::OrdinalIgnoreCase)
            if ($idx -ge 0 -and ($bestIndex -lt 0 -or $idx -lt $bestIndex)) {
                $bestIndex = $idx
                $best = $r
            }
        }
        if ($bestIndex -lt 0) { break }

        $head = $remaining.Substring(0, $bestIndex)
        [void]$format.Append(($head -replace '\{', '{{' -replace '\}', '}}'))
        [void]$format.Append('{' + $formatArgs.Count + '}')
        $formatArgs.Add([string]$best.Expression)
        $hits.Add([string]$best.Label)
        $remaining = $remaining.Substring($bestIndex + ([string]$best.Token).Length)
    }

    if ($formatArgs.Count -eq 0) {
        return @{ Fragment = (ConvertTo-RevEngArmLiteral -Value $Literal); Hits = @() }
    }

    [void]$format.Append(($remaining -replace '\{', '{{' -replace '\}', '}}'))
    $formatString = $format.ToString()

    # Whole literal was a single token: no format() wrapper needed.
    if ($formatArgs.Count -eq 1 -and $formatString -eq '{0}') {
        return @{ Fragment = $formatArgs[0]; Hits = @($hits.ToArray() | Select-Object -Unique) }
    }

    return @{
        Fragment = 'format({0}, {1})' -f (ConvertTo-RevEngArmLiteral -Value $formatString), ($formatArgs -join ', ')
        Hits     = @($hits.ToArray() | Select-Object -Unique)
    }
}

function Convert-RevEngPortableString {
    <#
    .SYNOPSIS
        Rewrites environment-specific literals (subscription id, tenant id,
        source resource group) inside a plain string or an ARM expression so the
        template resolves correctly in the target RG / subscription / tenant.
    .OUTPUTS
        @{ Value = <string>; Hits = @('<label>', ...) }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Replacements
    )

    if ([string]::IsNullOrEmpty($Value) -or $Replacements.Count -eq 0) {
        return @{ Value = $Value; Hits = @() }
    }

    $hasToken = $false
    foreach ($r in $Replacements) {
        if ([string]::IsNullOrEmpty($r.Token)) { continue }
        if ($Value.IndexOf([string]$r.Token, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasToken = $true; break }
    }
    if (-not $hasToken) { return @{ Value = $Value; Hits = @() } }

    $hits = [System.Collections.Generic.List[string]]::new()

    if (Test-RevEngArmExpression -Value $Value) {
        $body = $Value.Substring(1, $Value.Length - 2)
        $rebuilt = [Text.StringBuilder]::new()
        foreach ($seg in (Split-RevEngArmExpressionBody -Body $body)) {
            if (-not $seg.IsLiteral) {
                [void]$rebuilt.Append($seg.Text)
                continue
            }
            $frag = ConvertTo-RevEngArmFragment -Literal $seg.Text -Replacements $Replacements
            [void]$rebuilt.Append($frag.Fragment)
            foreach ($h in $frag.Hits) { $hits.Add($h) }
        }
        return @{ Value = '[' + $rebuilt.ToString() + ']'; Hits = @($hits.ToArray() | Select-Object -Unique) }
    }

    $frag = ConvertTo-RevEngArmFragment -Literal $Value -Replacements $Replacements
    foreach ($h in $frag.Hits) { $hits.Add($h) }
    return @{ Value = '[' + $frag.Fragment + ']'; Hits = @($hits.ToArray() | Select-Object -Unique) }
}

# ---------------------------------------------------------------------------
# Template normalisation
#
# Azure's export is faithful to what exists, not to what you would author. Two
# artefacts of that break real deployments, both found on a live resource group:
#   - Azure-managed child resources are exported in bulk (a Log Analytics
#     workspace brings ~1350 built-in table schemas), pushing the template past
#     Bicep's 800-resource limit and burying the resources you care about.
#   - Subnets come out BOTH inline on the virtual network AND as separate child
#     resources, which decompiles to Bicep with a dependency cycle.
# ---------------------------------------------------------------------------

function Update-RevEngDependsOn {
    <#
    .SYNOPSIS
        Repairs dependsOn arrays after resources have been dropped: entries that
        reference a dropped type are either re-pointed or removed, so nothing is
        left dangling (a dangling dependsOn decompiles to an undefined Bicep
        symbol, which is exactly what BCP062 complains about).
    .PARAMETER Replacement
        Map of dropped type -> replacement dependsOn expression. A $null value
        means "just remove the entry".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DroppedType,
        [hashtable]$Replacement = @{}
    )

    if ($DroppedType.Count -eq 0 -or -not (Test-RevEngHasKey $Template 'resources')) { return 0 }
    $repaired = 0

    foreach ($res in @($Template['resources'])) {
        if (-not (Test-RevEngIsDictionary $res)) { continue }
        if (-not (Test-RevEngHasKey $res 'dependsOn')) { continue }

        $kept = [System.Collections.Generic.List[string]]::new()
        $changed = $false

        foreach ($entry in @($res['dependsOn'])) {
            $text = [string]$entry
            $hitType = $null
            foreach ($t in $DroppedType) {
                if ($text -imatch [regex]::Escape("'$t'")) { $hitType = $t; break }
            }

            if (-not $hitType) {
                if (-not $kept.Contains($text)) { $kept.Add($text) }
                continue
            }

            $changed = $true
            $repaired++
            $swap = $null
            if ($Replacement.ContainsKey($hitType)) {
                # Several parents can share a child type; pick the one this entry names.
                foreach ($candidate in @($Replacement[$hitType])) {
                    if ($candidate.Match -and $text -imatch [regex]::Escape($candidate.Match)) { $swap = $candidate.Expression; break }
                }
                if (-not $swap -and @($Replacement[$hitType]).Count -eq 1) { $swap = @($Replacement[$hitType])[0].Expression }
            }
            if ($swap -and -not $kept.Contains($swap)) { $kept.Add($swap) }
        }

        if ($changed) {
            if ($kept.Count -gt 0) { $res['dependsOn'] = $kept.ToArray() } else { $res.Remove('dependsOn') }
        }
    }
    return $repaired
}

function Remove-RevEngNoiseResource {
    <#
    .SYNOPSIS
        Drops Azure-managed child resources that are created automatically and
        cannot meaningfully be redeployed (built-in Log Analytics table schemas,
        default saved searches, and so on).
    .OUTPUTS
        @{ Template = <hashtable>; Removed = @(); DependenciesRepaired = <int> }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [AllowEmptyCollection()][string[]]$ExcludeType = @()
    )

    $removed = [System.Collections.Generic.List[object]]::new()
    if ($ExcludeType.Count -eq 0 -or -not (Test-RevEngHasKey $Template 'resources')) {
        return @{ Template = $Template; Removed = @(); DependenciesRepaired = 0 }
    }

    $kept = [System.Collections.Generic.List[object]]::new()
    $droppedTypes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($res in @($Template['resources'])) {
        $type = if (Test-RevEngHasKey $res 'type') { [string]$res['type'] } else { '' }
        $isNoise = $false
        foreach ($pattern in $ExcludeType) {
            if ($type -ilike $pattern) { $isNoise = $true; break }
        }
        if ($isNoise) {
            $removed.Add([pscustomobject]@{ Type = $type; Name = $(if (Test-RevEngHasKey $res 'name') { [string]$res['name'] } else { '' }) })
            [void]$droppedTypes.Add($type)
        } else {
            $kept.Add($res)
        }
    }

    $Template['resources'] = $kept.ToArray()
    # Nothing meaningful depends on these, so the entries are simply removed.
    $repaired = Update-RevEngDependsOn -Template $Template -DroppedType @($droppedTypes)

    return @{ Template = $Template; Removed = $removed.ToArray(); DependenciesRepaired = $repaired }
}

function Remove-RevEngRedundantInlineChild {
    <#
    .SYNOPSIS
        Where a parent resource already declares its children inline, drops the
        duplicate standalone child resources and re-points anything that depended
        on them at the parent.
    .PARAMETER Rule
        Array of @{ parentType; childType; inlineProperty }.
    .OUTPUTS
        @{ Template = <hashtable>; Removed = @(); DependenciesRepaired = <int> }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [AllowEmptyCollection()][array]$Rule = @()
    )

    $removed = [System.Collections.Generic.List[object]]::new()
    $repaired = 0
    if ($Rule.Count -eq 0 -or -not (Test-RevEngHasKey $Template 'resources')) {
        return @{ Template = $Template; Removed = @(); DependenciesRepaired = 0 }
    }

    foreach ($r in $Rule) {
        $parentType = [string]$r.parentType
        $childType = [string]$r.childType
        $inlineProp = [string]$r.inlineProperty

        # Parents that genuinely declare children inline.
        $inlineParents = [System.Collections.Generic.List[object]]::new()
        foreach ($res in @($Template['resources'])) {
            if (-not (Test-RevEngIsDictionary $res)) { continue }
            if (([string]$res['type']) -ine $parentType) { continue }
            if (-not (Test-RevEngHasKey $res 'properties')) { continue }
            $inline = $res['properties'][$inlineProp]
            if (-not (Test-RevEngIsList $inline) -or @($inline).Count -eq 0) { continue }

            $rawName = [string]$res['name']
            # '[parameters('x')]' -> "parameters('x')", which is the fragment the
            # child's own name expression embeds.
            $nameInner = if ($rawName -match '^\[(.*)\]$') { $Matches[1] } else { $rawName }
            $inlineParents.Add([pscustomobject]@{
                NameInner  = $nameInner
                Expression = "[resourceId('$parentType', $nameInner)]"
            })
        }
        if ($inlineParents.Count -eq 0) { continue }

        $kept = [System.Collections.Generic.List[object]]::new()
        $anyDropped = $false
        foreach ($res in @($Template['resources'])) {
            $type = if (Test-RevEngHasKey $res 'type') { [string]$res['type'] } else { '' }
            $drop = $false
            if ($type -ieq $childType) {
                $childName = [string]$res['name']
                foreach ($p in $inlineParents) {
                    if ($childName -imatch [regex]::Escape($p.NameInner)) { $drop = $true; break }
                }
            }
            if ($drop) {
                $anyDropped = $true
                $removed.Add([pscustomobject]@{ Type = $type; Name = [string]$res['name']; ParentType = $parentType })
            } else {
                $kept.Add($res)
            }
        }
        if (-not $anyDropped) { continue }

        $Template['resources'] = $kept.ToArray()

        # Dependents move to the parent: inline children come into existence with it.
        $replacement = @{ $childType = @($inlineParents | ForEach-Object { [pscustomobject]@{ Match = $_.NameInner; Expression = $_.Expression } }) }
        $repaired += Update-RevEngDependsOn -Template $Template -DroppedType @($childType) -Replacement $replacement
    }

    return @{ Template = $Template; Removed = $removed.ToArray(); DependenciesRepaired = $repaired }
}

# ---------------------------------------------------------------------------
# Secret detection / redaction
# ---------------------------------------------------------------------------

function Test-RevEngDynamicSecretReference {
    <# True when the value is an ARM expression that resolves secret material at
       deploy time (listKeys/listSecrets/...). These are good: portable, and they
       carry no key material, so they are left alone. #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not (Test-RevEngArmExpression -Value $Value)) { return $false }
    return ($Value -match '(?i)\b(listKeys|listSecrets|listAccountSas|listServiceSas|listConnectionStrings|listQueryKeys|listAdminKeys|listCallbackUrl|listClusterAdminCredential)\s*\(')
}

function Get-RevEngSecretVerdict {
    <#
    .SYNOPSIS
        Decides whether one property value is secret material.
    .OUTPUTS
        @{ IsSecret = <bool>; Reason = <string>; Kind = 'Literal'|'Dynamic'|'None' }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [AllowNull()]$Value,
        [Parameter(Mandatory)]$SecretConfig
    )

    $none = @{ IsSecret = $false; Reason = ''; Kind = 'None' }
    if ($Value -isnot [string]) { return $none }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $none }

    foreach ($allow in @(Get-RevEngConfigValue -Config $SecretConfig -Path 'allowKeyPatterns' -Default @())) {
        if ($Name -match $allow) { return @{ IsSecret = $false; Reason = "allow-list:$allow"; Kind = 'None' } }
    }

    # A literal secret embedded inside an expression still leaks, so value shapes
    # are checked before anything else.
    foreach ($vp in @(Get-RevEngConfigValue -Config $SecretConfig -Path 'valuePatterns' -Default @())) {
        if ($Value -match $vp.pattern) {
            return @{ IsSecret = $true; Reason = "value-shape:$($vp.name)"; Kind = 'Literal' }
        }
    }

    if (Test-RevEngDynamicSecretReference -Value $Value) {
        return @{ IsSecret = $false; Reason = 'dynamic-reference'; Kind = 'Dynamic' }
    }

    # Any other ARM expression (parameters(), concat() of non-secrets, ...) holds
    # no literal key material, so a suspicious name alone is not enough.
    if (Test-RevEngArmExpression -Value $Value) {
        return @{ IsSecret = $false; Reason = 'arm-expression'; Kind = 'None' }
    }

    foreach ($ph in @(Get-RevEngConfigValue -Config $SecretConfig -Path 'placeholderValues' -Default @())) {
        if ($Value -eq $ph) { return @{ IsSecret = $false; Reason = 'already-placeholder'; Kind = 'None' } }
    }

    foreach ($kp in @(Get-RevEngConfigValue -Config $SecretConfig -Path 'keyNamePatterns' -Default @())) {
        if ($Name -match $kp) {
            return @{ IsSecret = $true; Reason = "key-name:$kp"; Kind = 'Literal' }
        }
    }

    return $none
}

function Remove-RevEngSecretMaterial {
    <#
    .SYNOPSIS
        Replaces literal secret values in an ARM template with secure parameter
        references (or a placeholder, per policy) and reports every hit.
    .OUTPUTS
        @{ Template = <hashtable>; Redactions = @(); DynamicReferences = @(); OutputRisks = @() }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [Parameter(Mandatory)]$SecretConfig,
        [ValidateSet('RedactAndParameterize', 'Placeholder')][string]$Policy = 'RedactAndParameterize',
        [string]$Placeholder = '__REDACTED__'
    )

    $template = $Template
    $redactions = [System.Collections.Generic.List[object]]::new()
    $dynamic = [System.Collections.Generic.List[object]]::new()
    $outputRisks = [System.Collections.Generic.List[object]]::new()
    $usedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    if (Test-RevEngHasKey $template 'parameters') {
        foreach ($k in @($template['parameters'].Keys)) { [void]$usedNames.Add([string]$k) }
    }

    $context = @{ ResourceName = '(template)'; ResourceType = '(template)'; ItemLabel = $null }

    $visitor = {
        param($name, $path, $node)

        # Name/value pairs (appSettings, connectionStrings, ...) name their secret
        # after the setting rather than the generic 'value' key. Tracking it on
        # dictionary entry is accurate for that shape because the walk is
        # depth-first: a dict's children are visited straight after the dict.
        if (Test-RevEngIsDictionary $node) {
            $context.ItemLabel = if (($node.Contains('name')) -and ($node['name'] -is [string]) -and
                                     -not (Test-RevEngArmExpression -Value ([string]$node['name']))) {
                [string]$node['name']
            } else {
                $null
            }
        }

        $verdict = Get-RevEngSecretVerdict -Name $name -Value $node -SecretConfig $SecretConfig

        if ($verdict.Kind -eq 'Dynamic') {
            $dynamic.Add([pscustomobject]@{
                Path         = $path
                Property     = $name
                ResourceName = $context.ResourceName
                ResourceType = $context.ResourceType
                Note         = 'Resolved at deploy time; no key material stored in the template.'
            })
            return @{ Handled = $true; Value = $node }
        }
        if (-not $verdict.IsSecret) { return $null }

        $fingerprint = Get-RevEngShortHash -Value ([string]$node)

        if ($Policy -eq 'Placeholder') {
            $redactions.Add([pscustomobject]@{
                Path             = $path
                Property         = $name
                ResourceName     = $context.ResourceName
                ResourceType     = $context.ResourceType
                Reason           = $verdict.Reason
                Action           = 'Placeholder'
                ParameterName    = $null
                ValueFingerprint = $fingerprint
            })
            return @{ Handled = $true; Value = $Placeholder }
        }

        $leaf = if ($context.ItemLabel -and $name -imatch '^(value|connectionString|secretValue)$') { $context.ItemLabel } else { $name }
        $base = ConvertTo-RevEngParameterName -Name ('secret_{0}_{1}' -f $context.ResourceName, $leaf)
        $paramName = $base
        $n = 2
        while (-not $usedNames.Add($paramName)) {
            $paramName = '{0}_{1}' -f $base, $n
            $n++
        }

        if (-not (Test-RevEngHasKey $template 'parameters')) {
            $template['parameters'] = New-RevEngOrderedMap
        }
        $template['parameters'][$paramName] = New-RevEngOrderedMap @{
            type     = 'securestring'
            metadata = New-RevEngOrderedMap @{
                description = ('Redacted from {0} ({1}) at {2}. Supply this value at deploy time.' -f $context.ResourceName, $context.ResourceType, $path)
            }
        }

        $redactions.Add([pscustomobject]@{
            Path             = $path
            Property         = $name
            ResourceName     = $context.ResourceName
            ResourceType     = $context.ResourceType
            Reason           = $verdict.Reason
            Action           = 'Parameterized'
            ParameterName    = $paramName
            ValueFingerprint = $fingerprint
        })

        return @{ Handled = $true; Value = "[parameters('$paramName')]" }
    }

    if (Test-RevEngHasKey $template 'resources') {
        $resources = @($template['resources'])
        for ($i = 0; $i -lt $resources.Count; $i++) {
            $res = $resources[$i]
            if (Test-RevEngIsDictionary $res) {
                $rawName = if ($res.Contains('name')) { [string]$res['name'] } else { '' }
                $context.ResourceType = if ($res.Contains('type')) { [string]$res['type'] } else { 'unknown' }
                $context.ResourceName = Get-RevEngResourceLabel -Name $rawName -Type $context.ResourceType
                if ([string]::IsNullOrWhiteSpace($context.ResourceName)) { $context.ResourceName = "resource$i" }
            }
            $walked = Invoke-RevEngTreeVisit -Node $res -Path "resources[$i]" -Name '' -Visitor $visitor
            $resources[$i] = $walked['Value']
        }
        $template['resources'] = $resources
    }

    # Deployment outputs persist in the deployment history for anyone with read
    # access on the RG, so flag secret-bearing outputs rather than shipping them.
    if (Test-RevEngHasKey $template 'outputs') {
        foreach ($outName in @($template['outputs'].Keys)) {
            $out = $template['outputs'][$outName]
            $outValue = if (Test-RevEngHasKey $out 'value') { [string]$out['value'] } else { '' }
            if (Test-RevEngDynamicSecretReference -Value $outValue) {
                $outputRisks.Add([pscustomobject]@{
                    Output = [string]$outName
                    Note   = 'Output resolves secret material (listKeys/listSecrets); it stays readable in deployment history. Consider removing it.'
                })
            }
        }
        $context.ResourceName = '(outputs)'
        $context.ResourceType = '(outputs)'
        $walked = Invoke-RevEngTreeVisit -Node $template['outputs'] -Path 'outputs' -Name '' -Visitor $visitor
        $template['outputs'] = $walked['Value']
    }

    return @{
        Template          = $template
        Redactions        = $redactions.ToArray()
        DynamicReferences = $dynamic.ToArray()
        OutputRisks       = $outputRisks.ToArray()
    }
}

function Test-RevEngSecretLeak {
    <#
    .SYNOPSIS
        Final gate: scans rendered text for literal secret shapes. Because it
        runs on the emitted ARM/Bicep, it also catches what the structural pass
        cannot see - decompiler artefacts, comments, JSON-inside-a-string.
    .OUTPUTS
        Array of @{ File; Line; Pattern }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [Parameter(Mandatory)]$SecretConfig,
        [string]$Source = '(in-memory)'
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $patterns = @(Get-RevEngConfigValue -Config $SecretConfig -Path 'valuePatterns' -Default @())
    $lines = $Content -split "`r?`n"

    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($vp in $patterns) {
            if ($lines[$i] -match $vp.pattern) {
                $findings.Add([pscustomobject]@{
                    File    = $Source
                    Line    = $i + 1
                    Pattern = [string]$vp.name
                })
            }
        }
    }
    return $findings.ToArray()
}

# ---------------------------------------------------------------------------
# Portability
# ---------------------------------------------------------------------------

function Convert-RevEngTemplateForPortability {
    <#
    .SYNOPSIS
        Makes an exported ARM template deployable into another RG / subscription
        / tenant: strips read-only runtime state, rewrites environment-specific
        identifiers, and reports what still needs a human decision.
    .OUTPUTS
        @{ Template = <hashtable>; Findings = @(); Stripped = @() }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [Parameter(Mandatory)]$PortabilityConfig,
        [string]$SourceSubscriptionId,
        [string]$SourceTenantId,
        [string]$SourceResourceGroupName,
        [string]$PrimaryLocation
    )

    $template = $Template
    $findings = [System.Collections.Generic.List[object]]::new()
    $stripped = [System.Collections.Generic.List[object]]::new()

    $parameterize = [bool](Get-RevEngConfigValue -Config $PortabilityConfig -Path 'parameterizeEnvironmentIds' -Default $true)
    $stripReadOnly = [bool](Get-RevEngConfigValue -Config $PortabilityConfig -Path 'stripReadOnlyProperties' -Default $true)
    $stripChildIds = [bool](Get-RevEngConfigValue -Config $PortabilityConfig -Path 'stripReadOnlyChildIds' -Default $true)
    $locationStrategy = [string](Get-RevEngConfigValue -Config $PortabilityConfig -Path 'locationStrategy' -Default 'parameter')
    $readOnly = @(Get-RevEngConfigValue -Config $PortabilityConfig -Path 'readOnlyProperties' -Default @())
    $identityReadOnly = @(Get-RevEngConfigValue -Config $PortabilityConfig -Path 'identityReadOnlyProperties' -Default @())
    $principalPatterns = @(Get-RevEngConfigValue -Config $PortabilityConfig -Path 'principalIdProperties' -Default @())
    $globallyUnique = @(Get-RevEngConfigValue -Config $PortabilityConfig -Path 'globallyUniqueTypes' -Default @())

    $quote = [string][char]0x27
    $replacements = @()
    if ($parameterize) {
        if ($SourceSubscriptionId) {
            $replacements += @{ Token = $SourceSubscriptionId; Expression = 'subscription().subscriptionId'; Label = 'subscriptionId' }
        }
        if ($SourceTenantId) {
            $replacements += @{ Token = $SourceTenantId; Expression = 'subscription().tenantId'; Label = 'tenantId' }
        }
        if ($SourceResourceGroupName) {
            # Scoped to the resource-id form on purpose: a bare RG-name match
            # would also rewrite resource names that happen to embed it.
            $replacements += @{
                Token      = "/resourceGroups/$SourceResourceGroupName/"
                Expression = "concat(${quote}/resourceGroups/${quote}, resourceGroup().name, ${quote}/${quote})"
                Label      = 'resourceGroupName'
            }
        }
    }

    $useLocationParam = ($locationStrategy -eq 'parameter' -and $PrimaryLocation)
    if ($useLocationParam) {
        if (-not (Test-RevEngHasKey $template 'parameters')) { $template['parameters'] = New-RevEngOrderedMap }
        if (-not $template['parameters'].Contains('location')) {
            $template['parameters']['location'] = New-RevEngOrderedMap @{
                type         = 'string'
                defaultValue = $PrimaryLocation
                metadata     = New-RevEngOrderedMap @{ description = 'Target region. Defaults to the source region of the exported resource group.' }
            }
        }
    }

    $context = @{ ResourceName = '(template)'; ResourceType = '(template)' }

    $visitor = {
        param($name, $path, $node)

        # An inline child object (one with its own 'name') also comes back with the
        # 'id' Azure assigned it. That is read-only input, and when it points at the
        # enclosing resource the decompiled Bicep self-references (BCP079). Objects
        # that merely *reference* something - subnet: { id: ... } - have no sibling
        # 'name', so they are left alone. Removing the key here is safe: the walker
        # snapshots the key list after this visitor runs.
        if ($stripChildIds -and (Test-RevEngIsDictionary $node) -and $node.Contains('id') -and $node.Contains('name')) {
            $idValue = $node['id']
            if ($idValue -is [string] -and ($idValue -imatch 'resourceId\s*\(' -or $idValue -match '^/subscriptions/')) {
                $stripped.Add([pscustomobject]@{
                    Path = "$path.id"; Property = 'id'; ResourceName = $context.ResourceName; Reason = 'read-only-child-id'
                })
                $node.Remove('id')
            }
        }

        if ($stripReadOnly -and $name) {
            foreach ($ro in $readOnly) {
                if ($name -match $ro) {
                    $stripped.Add([pscustomobject]@{
                        Path = $path; Property = $name; ResourceName = $context.ResourceName; Reason = "read-only:$ro"
                    })
                    return @{ Remove = $true }
                }
            }
            if ($path -match '(?i)\.identity(\.|\[)') {
                foreach ($ro in $identityReadOnly) {
                    if ($name -match $ro) {
                        $stripped.Add([pscustomobject]@{
                            Path = $path; Property = $name; ResourceName = $context.ResourceName; Reason = "identity-runtime:$ro"
                        })
                        return @{ Remove = $true }
                    }
                }
            }
        }

        if ($node -isnot [string]) { return $null }

        if ($name) {
            foreach ($pp in $principalPatterns) {
                if ($name -match $pp -and $node -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                    $findings.Add([pscustomobject]@{
                        Severity     = 'Action required'
                        Category     = 'Tenant-specific principal'
                        ResourceName = $context.ResourceName
                        ResourceType = $context.ResourceType
                        Path         = $path
                        Detail       = "'$name' holds a directory object id that does not exist in another tenant. Map it to the target tenant's principal before deploying."
                    })
                    break
                }
            }
        }

        if ($useLocationParam -and $name -eq 'location' -and
            ($node -replace '\s', '') -ieq ($PrimaryLocation -replace '\s', '')) {
            return @{ Handled = $true; Value = "[parameters('location')]" }
        }

        if ($replacements.Count -gt 0) {
            $rewritten = Convert-RevEngPortableString -Value $node -Replacements $replacements
            if ($rewritten.Value -ne $node) {
                $findings.Add([pscustomobject]@{
                    Severity     = 'Rewritten'
                    Category     = 'Environment identifier'
                    ResourceName = $context.ResourceName
                    ResourceType = $context.ResourceType
                    Path         = $path
                    Detail       = ('Replaced {0} with a runtime expression.' -f (@($rewritten.Hits) -join ', '))
                })
                return @{ Handled = $true; Value = $rewritten.Value }
            }
        }

        return $null
    }

    if (Test-RevEngHasKey $template 'resources') {
        $resources = @($template['resources'])
        for ($i = 0; $i -lt $resources.Count; $i++) {
            $res = $resources[$i]
            if (Test-RevEngIsDictionary $res) {
                $rawName = if ($res.Contains('name')) { [string]$res['name'] } else { '' }
                $context.ResourceType = if ($res.Contains('type')) { [string]$res['type'] } else { 'unknown' }
                $context.ResourceName = Get-RevEngResourceLabel -Name $rawName -Type $context.ResourceType
                if ([string]::IsNullOrWhiteSpace($context.ResourceName)) { $context.ResourceName = "resource$i" }

                if ($res.Contains('location') -and $PrimaryLocation -and $res['location'] -is [string]) {
                    $loc = [string]$res['location']
                    if ($loc -notmatch '^\[' -and $loc -ine 'global' -and
                        ($loc -replace '\s', '') -ine ($PrimaryLocation -replace '\s', '')) {
                        $findings.Add([pscustomobject]@{
                            Severity     = 'Review'
                            Category     = 'Non-primary region'
                            ResourceName = $context.ResourceName
                            ResourceType = $context.ResourceType
                            Path         = "resources[$i].location"
                            Detail       = "Pinned to '$loc' rather than the primary region '$PrimaryLocation'. Confirm that is intentional for the target environment."
                        })
                    }
                }

                # Azure never exports the *value* of a secret-bearing child
                # resource, so the exported resource would deploy as an empty
                # secret - or fail outright. Flag it rather than let it surprise.
                foreach ($vt in @(Get-RevEngConfigValue -Config $PortabilityConfig -Path 'requireValueTypes' -Default @())) {
                    if ($context.ResourceType -ine ([string]$vt)) { continue }
                    $hasValue = (Test-RevEngHasKey $res 'properties') -and (Test-RevEngHasKey $res['properties'] 'value')
                    if (-not $hasValue) {
                        $findings.Add([pscustomobject]@{
                            Severity     = 'Action required'
                            Category     = 'Secret value not exported'
                            ResourceName = $context.ResourceName
                            ResourceType = $context.ResourceType
                            Path         = "resources[$i]"
                            Detail       = 'Azure does not export secret values, so this resource has no value to deploy. Supply it at deploy time (Key Vault reference or a secure parameter) or remove the resource from the template.'
                        })
                    }
                }

                foreach ($gu in $globallyUnique) {
                    if ($context.ResourceType -ilike $gu) {
                        $findings.Add([pscustomobject]@{
                            Severity     = 'Action required'
                            Category     = 'Globally unique name'
                            ResourceName = $context.ResourceName
                            ResourceType = $context.ResourceType
                            Path         = "resources[$i].name"
                            Detail       = 'This name must be globally unique across Azure - override its name parameter for the target environment.'
                        })
                        break
                    }
                }
            }
            $walked = Invoke-RevEngTreeVisit -Node $res -Path "resources[$i]" -Name '' -Visitor $visitor
            $resources[$i] = $walked['Value']
        }
        $template['resources'] = $resources
    }

    return @{
        Template = $template
        Findings = $findings.ToArray()
        Stripped = $stripped.ToArray()
    }
}

function Get-RevEngExternalDependency {
    <# Resource ids referenced by the template that live outside the source RG.
       The exported template will not create these - they must already exist in
       the target environment. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$TemplateJson,
        [Parameter(Mandatory)][string]$SourceResourceGroupName
    )
    $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rx = '(?i)/subscriptions/[0-9a-f-]{36}/resourceGroups/([^/"''\\\[\]]+)/providers/([^"''\\\[\]]+)'
    foreach ($m in [regex]::Matches($TemplateJson, $rx)) {
        if ($m.Groups[1].Value -ine $SourceResourceGroupName) {
            [void]$found.Add($m.Value)
        }
    }
    # Emitted unrolled, per the module convention above: wrap with @() to index
    # or count. A leading comma would make the empty case look like one item.
    return @($found)
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

function Get-RevEngExportConfig {
    <#
    .SYNOPSIS
        Loads the JSON config file and applies command-line overrides.
    .PARAMETER Overrides
        Flat map of dotted keys, e.g. @{ 'secrets.policy' = 'Placeholder' }.
        Null / empty values are ignored, so unspecified script parameters keep
        whatever the config file says.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Overrides = @{}
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found: $Path"
    }
    $config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 32

    foreach ($key in $Overrides.Keys) {
        $value = $Overrides[$key]
        if ($null -eq $value) { continue }
        if ($value -is [string] -and [string]::IsNullOrEmpty($value)) { continue }

        $parts = $key -split '\.'
        $node = $config
        for ($i = 0; $i -lt $parts.Count - 1; $i++) {
            if (-not (Test-RevEngHasKey $node $parts[$i])) { $node[$parts[$i]] = New-RevEngOrderedMap }
            $node = $node[$parts[$i]]
        }
        $node[$parts[-1]] = $value
    }

    return $config
}

# ---------------------------------------------------------------------------
# Azure interaction
# ---------------------------------------------------------------------------

function Assert-RevEngPrerequisite {
    [CmdletBinding()]
    param([switch]$RequireBicep)

    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($m in @('Az.Accounts', 'Az.Resources')) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            $problems.Add("PowerShell module '$m' is not installed. Run: Install-Module Az -Scope CurrentUser")
        }
    }

    $context = $null
    try { $context = Get-AzContext -ErrorAction Stop } catch { }
    if (-not $context -or -not $context.Account) {
        $problems.Add('Not signed in to Azure. Run: Connect-AzAccount')
    }

    if ($RequireBicep) {
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
            $problems.Add('Azure CLI (az) not found on PATH - required for Bicep decompilation. Install: winget install Microsoft.AzureCLI')
        } else {
            $null = & az bicep version 2>&1
            if ($LASTEXITCODE -ne 0) {
                $problems.Add('Bicep CLI not available. Run: az bicep install')
            }
        }
    }

    if ($problems.Count -gt 0) {
        throw ("Prerequisite check failed:`n  - " + ($problems -join "`n  - "))
    }
    return $context
}

function Get-RevEngResourceInventory {
    <# Current resources plus a content hash of their deployable surface, used
       for delta detection between runs. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        $Filters,
        [int]$MaxAttempt = 3
    )

    $resources = Get-AzResource -ResourceGroupName $ResourceGroupName

    $include = @(Get-RevEngConfigValue -Config $Filters -Path 'includeTypes' -Default @())
    $exclude = @(Get-RevEngConfigValue -Config $Filters -Path 'excludeTypes' -Default @())
    $includeName = [string](Get-RevEngConfigValue -Config $Filters -Path 'includeNamePattern' -Default '')
    $excludeName = [string](Get-RevEngConfigValue -Config $Filters -Path 'excludeNamePattern' -Default '')

    $inventory = New-RevEngOrderedMap
    foreach ($r in ($resources | Sort-Object ResourceType, Name)) {
        if ($include.Count -gt 0 -and -not (@($include | Where-Object { $r.ResourceType -ilike $_ }).Count)) { continue }
        if ($exclude.Count -gt 0 -and (@($exclude | Where-Object { $r.ResourceType -ilike $_ }).Count)) { continue }
        if ($includeName -and $r.Name -notmatch $includeName) { continue }
        if ($excludeName -and $r.Name -match $excludeName) { continue }

        # The expanded properties ARE the fingerprint. Retry transient failures
        # (throttling is common on a large RG), and if it still fails record no
        # hash at all rather than one built from whatever did come back.
        # Fingerprinting a fallback shape was a real bug: the fallback was
        # Location-only, so every affected resource got the SAME hash - they all
        # showed as modified on the next run, and while degraded a genuine
        # configuration change was invisible.
        $full = $null
        $fingerprintError = $null
        for ($attempt = 1; $attempt -le $MaxAttempt; $attempt++) {
            try {
                $full = Get-AzResource -ResourceId $r.ResourceId -ExpandProperties -ErrorAction Stop
                $fingerprintError = $null
                break
            } catch {
                $fingerprintError = $_.Exception.Message
                if ($attempt -lt $MaxAttempt) { Start-Sleep -Seconds ([Math]::Pow(2, $attempt)) }
            }
        }

        $entry = New-RevEngOrderedMap @{
            name     = $r.Name
            type     = $r.ResourceType
            location = $r.Location
            hash     = $(if ($full) { Get-RevEngObjectHash -InputObject ($full | Select-Object Sku, Kind, Properties, Tags, Location) } else { '' })
        }
        if ($fingerprintError) { $entry['fingerprintError'] = $fingerprintError }
        $inventory[$r.ResourceId] = $entry
    }
    return $inventory
}

function Get-RevEngPreviousState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return New-RevEngOrderedMap @{ schemaVersion = 2; resources = (New-RevEngOrderedMap) }
    }

    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 32
    if (Test-RevEngHasKey $raw 'schemaVersion') { return $raw }

    # v1 state (the original s.ps1) was a flat map of resourceId -> {Name,Hash,...}
    $migrated = New-RevEngOrderedMap @{ schemaVersion = 2; resources = (New-RevEngOrderedMap) }
    foreach ($k in $raw.Keys) {
        $v = $raw[$k]
        $migrated['resources'][$k] = New-RevEngOrderedMap @{
            name     = if (Test-RevEngHasKey $v 'Name')         { $v['Name'] }         else { [string]$k }
            type     = if (Test-RevEngHasKey $v 'ResourceType') { $v['ResourceType'] } else { 'unknown' }
            location = if (Test-RevEngHasKey $v 'Location')     { $v['Location'] }     else { '' }
            hash     = if (Test-RevEngHasKey $v 'Hash')         { $v['Hash'] }         else { '' }
        }
    }
    return $migrated
}

function Get-RevEngTemplateResourceMap {
    <#
    .SYNOPSIS
        Fingerprints every resource *inside* an exported template, children
        included, keyed by type and name.
    .DESCRIPTION
        Get-AzResource only enumerates top-level resources and a few child types,
        so the per-resource fingerprint is blind to most children - Key Vault
        secrets, Cognitive Services deployments, ACR scope maps, DNS records. On
        a real resource group that was 35 of 56 resources. The whole-RG template
        is re-exported on every run regardless of mode, so hashing what is in it
        closes the gap.

        Runs on the sanitised, normalised template, so redaction and portability
        rewriting are already applied and the hash is stable between runs.
    .OUTPUTS
        OrderedHashtable of "<type>|<name>" -> @{ name; type; hash }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Template)

    $map = New-RevEngOrderedMap
    if (-not (Test-RevEngHasKey $Template 'resources')) { return $map }

    foreach ($res in @($Template['resources'])) {
        if (-not (Test-RevEngIsDictionary $res)) { continue }
        $type = if ($res.Contains('type')) { [string]$res['type'] } else { 'unknown' }
        $name = if ($res.Contains('name')) { [string]$res['name'] } else { '' }
        $key = '{0}|{1}' -f $type, $name
        if ($map.Contains($key)) { continue }   # keep the first of any duplicate
        $map[$key] = New-RevEngOrderedMap @{
            name = $name
            type = $type
            hash = Get-RevEngObjectHash -InputObject $res
        }
    }
    return $map
}

function Compare-RevEngSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Current,
        [Parameter(Mandatory)]$Previous
    )
    $currentIds = @($Current.Keys)
    $previousIds = @($Previous.Keys)

    $new = @($currentIds | Where-Object { $_ -notin $previousIds })
    $removed = @($previousIds | Where-Object { $_ -notin $currentIds })
    $common = @($currentIds | Where-Object { $_ -in $previousIds })

    # A missing hash on either side means "we could not tell", which is neither
    # unchanged nor modified. Calling it either way is a lie: unchanged hides a
    # possible drift, modified cries wolf on every subsequent run.
    $unknown = @($common | Where-Object {
        [string]::IsNullOrEmpty([string]$Current[$_]['hash']) -or
        [string]::IsNullOrEmpty([string]$Previous[$_]['hash'])
    })
    $comparable = @($common | Where-Object { $_ -notin $unknown })
    $modified = @($comparable | Where-Object { $Current[$_]['hash'] -ne $Previous[$_]['hash'] })
    $unchanged = @($comparable | Where-Object { $_ -notin $modified })

    return [pscustomobject]@{
        New       = $new
        Modified  = $modified
        Removed   = $removed
        Unchanged = $unchanged
        Unknown   = $unknown
    }
}

function Export-RevEngArmTemplate {
    <#
    .SYNOPSIS
        Wraps Export-AzResourceGroup, reporting success/failure instead of
        throwing, so one unsupported resource type cannot abort the whole run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ResourceId,
        [switch]$SkipNameParameterization
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }

    $splat = @{
        ResourceGroupName            = $ResourceGroupName
        Path                         = $Path
        IncludeParameterDefaultValue = $true
        Force                        = $true
        ErrorAction                  = 'Stop'
        WarningAction                = 'SilentlyContinue'
    }
    if ($ResourceId) { $splat['Resource'] = $ResourceId }
    if ($SkipNameParameterization) { $splat['SkipResourceNameParameterization'] = $true }

    try {
        $result = Export-AzResourceGroup @splat
        $errors = @()
        if ($result -and ($result.PSObject.Properties.Name -contains 'Error') -and $result.Error) {
            $errors = @($result.Error | ForEach-Object { [string]$_ })
        }
        if (-not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject]@{ Success = $false; Path = $Path; Errors = @('Export produced no file.') + $errors }
        }
        return [pscustomobject]@{ Success = $true; Path = $Path; Errors = $errors }
    } catch {
        return [pscustomobject]@{ Success = $false; Path = $Path; Errors = @($_.Exception.Message) }
    }
}

function Convert-RevEngArmToBicep {
    <# az bicep decompile writes next to the source file; move the result to the
       requested destination and surface stderr on failure. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArmPath,
        [Parameter(Mandatory)][string]$BicepPath
    )

    $sibling = [IO.Path]::ChangeExtension($ArmPath, '.bicep')
    if (Test-Path -LiteralPath $sibling) { Remove-Item -LiteralPath $sibling -Force }

    $output = & az bicep decompile --file $ArmPath --force 2>&1
    $exit = $LASTEXITCODE

    if (-not (Test-Path -LiteralPath $sibling)) {
        return [pscustomobject]@{ Success = $false; Path = $BicepPath; Message = (($output | Out-String).Trim()) }
    }

    $destDir = Split-Path -Parent $BicepPath
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    if ((Resolve-Path -LiteralPath $sibling).Path -ne $BicepPath) {
        Move-Item -LiteralPath $sibling -Destination $BicepPath -Force
    }

    # Decompiler warnings are normal and non-fatal; keep them for the report.
    return [pscustomobject]@{
        Success = $true
        Path    = $BicepPath
        Message = if ($exit -ne 0) { (($output | Out-String).Trim()) } else { '' }
    }
}

function Test-RevEngBicepBuild {
    <# Round-trip check: does the emitted Bicep still compile? #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BicepPath)

    $output = & az bicep build --file $BicepPath --stdout 2>&1
    $ok = ($LASTEXITCODE -eq 0)
    $lines = (($output | Out-String) -split "`r?`n")
    return [pscustomobject]@{
        Success  = $ok
        Errors   = @($lines | Where-Object { $_ -match '(?i)\berror\b' } | Select-Object -First 20)
        Warnings = @($lines | Where-Object { $_ -match '(?i)\bwarning\b' } | Select-Object -First 20)
    }
}

function Get-RevEngSupplementalInventory {
    <# RBAC, locks and policy assignments: drift-relevant, and deliberately NOT
       emitted as IaC because principal ids are scoped to the source tenant. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [switch]$IncludeRoleAssignments,
        [switch]$IncludeLocks,
        [switch]$IncludePolicyAssignments
    )

    $result = New-RevEngOrderedMap
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

    if ($IncludeRoleAssignments) {
        try {
            $result['roleAssignments'] = @(Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
                Select-Object DisplayName, SignInName, ObjectId, ObjectType, RoleDefinitionName, Scope, CanDelegate)
        } catch {
            $result['roleAssignments'] = @{ error = $_.Exception.Message }
        }
    }
    if ($IncludeLocks) {
        try {
            $result['locks'] = @(Get-AzResourceLock -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
                Select-Object Name, ResourceId,
                    @{ n = 'Level'; e = { $_.Properties.level } },
                    @{ n = 'Notes'; e = { $_.Properties.notes } })
        } catch {
            $result['locks'] = @{ error = $_.Exception.Message }
        }
    }
    if ($IncludePolicyAssignments) {
        try {
            # Az.Resources moved these from .Properties.X to top-level X in v7;
            # read whichever this machine's module version exposes.
            $flat = {
                param($obj, $name)
                if ($obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
                if ($obj.PSObject.Properties.Name -contains 'Properties') { return $obj.Properties.$name }
                return $null
            }
            $result['policyAssignments'] = @(Get-AzPolicyAssignment -Scope $scope -ErrorAction Stop |
                Select-Object Name, ResourceId,
                    @{ n = 'DisplayName';        e = { & $flat $_ 'DisplayName' } },
                    @{ n = 'PolicyDefinitionId'; e = { & $flat $_ 'PolicyDefinitionId' } },
                    @{ n = 'Scope';              e = { & $flat $_ 'Scope' } })
        } catch {
            $result['policyAssignments'] = @{ error = $_.Exception.Message }
        }
    }
    return $result
}

function Test-RevEngRegionSupport {
    <# Answers "can these resource types even be created in <TargetLocation>?"
       before you find out the hard way mid-deployment. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ResourceType,
        [Parameter(Mandatory)][string]$TargetLocation
    )

    $target = ($TargetLocation -replace '\s', '').ToLowerInvariant()
    $providerCache = @{}
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($rt in ($ResourceType | Where-Object { $_ } | Sort-Object -Unique)) {
        $parts = $rt -split '/', 2
        if ($parts.Count -lt 2) { continue }
        $ns = $parts[0]
        $sub = $parts[1]

        if (-not $providerCache.ContainsKey($ns)) {
            try { $providerCache[$ns] = Get-AzResourceProvider -ProviderNamespace $ns -ErrorAction Stop }
            catch { $providerCache[$ns] = $null }
        }
        $provider = $providerCache[$ns]
        if (-not $provider) {
            $results.Add([pscustomobject]@{ ResourceType = $rt; Supported = 'unknown'; Detail = "Could not query provider '$ns'." })
            continue
        }

        $typeInfo = $provider.ResourceTypes | Where-Object { $_.ResourceTypeName -ieq $sub } | Select-Object -First 1
        if (-not $typeInfo) {
            $results.Add([pscustomobject]@{ ResourceType = $rt; Supported = 'unknown'; Detail = 'Not reported by the provider (usually a child type, which inherits its parent region).' })
            continue
        }

        $locations = @($typeInfo.Locations | ForEach-Object { ($_ -replace '\s', '').ToLowerInvariant() })
        # Region-independent types report either nothing or the literal 'global'
        # (private DNS zones, for instance). Both mean "available everywhere".
        if ($locations.Count -eq 0 -or $locations -contains 'global') {
            $results.Add([pscustomobject]@{ ResourceType = $rt; Supported = 'global'; Detail = 'Region-independent resource type.' })
        } elseif ($locations -contains $target) {
            $results.Add([pscustomobject]@{ ResourceType = $rt; Supported = 'yes'; Detail = '' })
        } else {
            $shown = @($typeInfo.Locations | Select-Object -First 12) -join ', '
            if ($typeInfo.Locations.Count -gt 12) { $shown += ', ...' }
            $results.Add([pscustomobject]@{ ResourceType = $rt; Supported = 'NO'; Detail = "Available in: $shown" })
        }
    }
    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------

function Write-RevEngTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [Parameter(Mandatory)][string]$Path
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding utf8NoBOM
}

function Write-RevEngJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 64
    )
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    if ($null -eq $json) { $json = 'null' }
    Write-RevEngTextFile -Content ([string]$json) -Path $Path
    return [string]$json
}

function New-RevEngParameterFile {
    <#
    .SYNOPSIS
        Emits an ARM parameter file (plus a .bicepparam twin) from the template's
        parameter block. Secure parameters get an explicit SET-ME sentinel so a
        deployment fails loudly instead of quietly using a blank secret.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Template,
        [Parameter(Mandatory)][string]$JsonPath,
        [string]$BicepParamPath,
        [string]$BicepTemplateName = 'main.bicep',
        [string]$Sentinel = '<SET-ME>'
    )

    $params = New-RevEngOrderedMap
    $secure = [System.Collections.Generic.List[string]]::new()

    if (Test-RevEngHasKey $Template 'parameters') {
        foreach ($name in @($Template['parameters'].Keys)) {
            $def = $Template['parameters'][$name]
            $type = if (Test-RevEngHasKey $def 'type') { [string]$def['type'] } else { 'string' }
            if ($type -match '(?i)^secure') {
                $params[$name] = New-RevEngOrderedMap @{ value = $Sentinel }
                $secure.Add([string]$name)
            } elseif (Test-RevEngHasKey $def 'defaultValue') {
                $params[$name] = New-RevEngOrderedMap @{ value = $def['defaultValue'] }
            } else {
                $params[$name] = New-RevEngOrderedMap @{ value = $Sentinel }
            }
        }
    }

    Write-RevEngJsonFile -Path $JsonPath -InputObject (New-RevEngOrderedMap @{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters     = $params
    }) | Out-Null

    if ($BicepParamPath) {
        $q = [string][char]0x27
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("using ${q}${BicepTemplateName}${q}")
        $lines.Add('')
        $lines.Add('// Values marked <SET-ME> must be supplied for the target environment.')
        $lines.Add('// Prefer Key Vault for secrets, e.g.:')
        $lines.Add('//   param mySecret = az.getSecret(<subId>, <rg>, <vaultName>, <secretName>)')
        $lines.Add('')
        foreach ($name in @($params.Keys)) {
            $v = $params[$name]['value']
            $rendered =
                if ($null -eq $v) { "${q}${q}" }
                elseif ($v -is [bool]) { $v.ToString().ToLowerInvariant() }
                elseif ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { [string]$v }
                elseif ((Test-RevEngIsList $v) -or (Test-RevEngIsDictionary $v)) { ($v | ConvertTo-Json -Depth 32 -Compress) }
                else { $q + ([string]$v -replace $q, ($q + $q)) + $q }
            $lines.Add("param $name = $rendered")
        }
        Write-RevEngTextFile -Content ($lines -join [Environment]::NewLine) -Path $BicepParamPath
    }

    return [pscustomobject]@{ SecureParameters = $secure.ToArray(); ParameterCount = $params.Count }
}

function New-RevEngDeployScript {
    <# A ready-to-run what-if/deploy helper next to the generated templates. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $content = @'
#Requires -Version 7.3
<#
.SYNOPSIS
    Deploys the exported template into a TARGET resource group, optionally in a
    different subscription or tenant.
.DESCRIPTION
    Run with -WhatIfOnly first and read the output. A generated template is a
    starting point, not a guarantee: globally unique names, tenant-scoped
    principal ids and regional SKU availability all need review first. See
    ../reports/portability-report.md.
.EXAMPLE
    ./Deploy-Target.ps1 -ResourceGroupName rg-target -Location westeurope -WhatIfOnly
.EXAMPLE
    ./Deploy-Target.ps1 -ResourceGroupName rg-target -Location westeurope `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -TenantId 11111111-1111-1111-1111-111111111111
#>
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [string]$Location,
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$TemplateFile,
    [string]$ParameterFile,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

if (-not $TemplateFile)  { $TemplateFile  = Join-Path $PSScriptRoot '../bicep/main.bicep' }
if (-not $ParameterFile) { $ParameterFile = Join-Path $PSScriptRoot '../bicep/main.parameters.sample.json' }

if ($TenantId -and $SubscriptionId) {
    Connect-AzAccount -TenantId $TenantId -Subscription $SubscriptionId | Out-Null
} elseif ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

if ((Get-Content -LiteralPath $ParameterFile -Raw) -match '<SET-ME>') {
    throw "Parameter file '$ParameterFile' still contains <SET-ME> placeholders. Fill them in (secrets included) before deploying."
}

if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    if (-not $Location) { throw 'Target resource group does not exist - pass -Location so it can be created.' }
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

$splat = @{
    ResourceGroupName     = $ResourceGroupName
    TemplateFile          = $TemplateFile
    TemplateParameterFile = $ParameterFile
    Mode                  = 'Incremental'
}

Write-Host 'Running what-if...' -ForegroundColor Cyan
New-AzResourceGroupDeployment @splat -WhatIf

if ($WhatIfOnly) {
    Write-Host 'What-if only - nothing was deployed.' -ForegroundColor Yellow
    return
}

if ((Read-Host "Proceed with deployment to '$ResourceGroupName'? (type YES)") -ne 'YES') {
    Write-Host 'Aborted.' -ForegroundColor Yellow
    return
}

New-AzResourceGroupDeployment @splat -Name ('import-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) -Verbose
'@

    Write-RevEngTextFile -Content $content -Path $Path
}

function Invoke-RevEngGitCommit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Message
    )
    Push-Location $Path
    try {
        $inside = & git rev-parse --is-inside-work-tree 2>$null
        if ($LASTEXITCODE -ne 0 -or $inside -ne 'true') {
            return [pscustomobject]@{ Committed = $false; Reason = "'$Path' is not inside a git repository." }
        }
        & git add -A 2>&1 | Out-Null
        if ([string]::IsNullOrWhiteSpace((& git status --porcelain | Out-String))) {
            return [pscustomobject]@{ Committed = $false; Reason = 'No file changes to commit.' }
        }
        & git commit -m $Message 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ Committed = $false; Reason = 'git commit failed - check hooks and user.name/user.email.' }
        }
        return [pscustomobject]@{ Committed = $true; Reason = $Message }
    } finally { Pop-Location }
}

# ---------------------------------------------------------------------------
# Permissions
#
# Derived from Azure's own provider operation catalogue rather than guessed, so
# the report stays correct as providers change. The catalogue is not exhaustive
# though - the resource-group-level exportTemplate action is documented by
# Microsoft but absent from it - so every row carries its provenance.
# ---------------------------------------------------------------------------

function Get-RevEngRequiredPermission {
    <#
    .SYNOPSIS
        The control-plane actions needed to read, create and delete each
        resource type, looked up in Azure's provider operation catalogue.
    .OUTPUTS
        Array of @{ ResourceType; Read; Write; Delete; Source }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ResourceType)

    $cache = @{}
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($rt in (@($ResourceType) | Where-Object { $_ } | Sort-Object -Unique)) {
        $ns = ($rt -split '/')[0]
        if (-not $cache.ContainsKey($ns)) {
            # One call per namespace, not per type.
            try { $cache[$ns] = @(Get-AzProviderOperation "$ns/*" -ErrorAction Stop) }
            catch { $cache[$ns] = $null }
        }
        $ops = $cache[$ns]
        if ($null -eq $ops -or $ops.Count -eq 0) {
            $results.Add([pscustomobject]@{
                ResourceType = $rt; Read = $null; Write = $null; Delete = $null
                Source = 'provider-catalogue-unavailable'
            })
            continue
        }

        $lookup = {
            param($verb)
            $hit = $ops | Where-Object { $_.Operation -ieq "$rt/$verb" -and -not $_.IsDataAction } | Select-Object -First 1
            if ($hit) { [string]$hit.Operation } else { $null }
        }

        $results.Add([pscustomobject]@{
            ResourceType = $rt
            Read         = (& $lookup 'read')
            Write        = (& $lookup 'write')
            Delete       = (& $lookup 'delete')
            Source       = 'provider-catalogue'
        })
    }
    return $results.ToArray()
}

function Get-RevEngBuiltInRoleSuggestion {
    <#
    .SYNOPSIS
        Built-in roles whose Actions cover the required actions, ranked so the
        narrowest sufficient role comes first.
    .DESCRIPTION
        Role actions are wildcard patterns ('Microsoft.Storage/*'), so each is
        turned into a regex and matched against every required action, with
        NotActions subtracted. Ranked by coverage, then by preferring roles
        without a bare '*', then by fewest actions - so least privilege wins.
    .OUTPUTS
        Array of @{ Name; Covered; Total; Breadth; GrantsEverything }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequiredAction,
        [int]$Top = 6
    )

    $required = @(@($RequiredAction) | Where-Object { $_ } | Select-Object -Unique)
    if ($required.Count -eq 0) { return @() }

    try { $roles = @(Get-AzRoleDefinition -ErrorAction Stop | Where-Object { -not $_.IsCustom }) }
    catch { return @() }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($role in $roles) {
        $actions = @($role.Actions)
        if ($actions.Count -eq 0) { continue }

        # Split on the wildcard and escape the literal pieces. Escaping first
        # and then un-escaping the '*' needs a backslash-heavy pattern that is
        # easy to get wrong: one lost backslash means "zero or more
        # backslashes", which matches the empty string everywhere and makes
        # every role look like it grants everything.
        $toPattern = {
            param($action)
            '^' + ((($action -split '\*') | ForEach-Object { [regex]::Escape($_) }) -join '.*') + '$'
        }
        $allow = @($actions            | ForEach-Object { & $toPattern $_ })
        $deny  = @(@($role.NotActions) | ForEach-Object { & $toPattern $_ })

        $covered = 0
        foreach ($req in $required) {
            $ok = $false
            foreach ($p in $allow) { if ($req -imatch $p) { $ok = $true; break } }
            if ($ok) { foreach ($n in $deny) { if ($req -imatch $n) { $ok = $false; break } } }
            if ($ok) { $covered++ }
        }
        if ($covered -eq 0) { continue }

        $out.Add([pscustomobject]@{
            Name             = [string]$role.Name
            Covered          = $covered
            Total            = $required.Count
            Breadth          = $actions.Count
            GrantsEverything = [bool](@($actions | Where-Object { $_ -eq '*' }).Count)
        })
    }

    return @($out |
        Sort-Object @{ Expression = 'Covered'; Descending = $true },
                    @{ Expression = 'GrantsEverything'; Descending = $false },
                    @{ Expression = 'Breadth'; Descending = $false } |
        Select-Object -First $Top)
}

Export-ModuleMember -Function @(
    'Write-RevEngLog'
    'New-RevEngOrderedMap'
    'Test-RevEngIsDictionary'
    'Test-RevEngIsList'
    'Test-RevEngHasKey'
    'Get-RevEngConfigValue'
    'ConvertTo-RevEngSafeName'
    'ConvertTo-RevEngParameterName'
    'Get-RevEngResourceLabel'
    'Get-RevEngShortHash'
    'Get-RevEngObjectHash'
    'Copy-RevEngJsonObject'
    'Invoke-RevEngTreeVisit'
    'Test-RevEngArmExpression'
    'Split-RevEngArmExpressionBody'
    'ConvertTo-RevEngArmLiteral'
    'ConvertTo-RevEngArmFragment'
    'Convert-RevEngPortableString'
    'Update-RevEngDependsOn'
    'Remove-RevEngNoiseResource'
    'Remove-RevEngRedundantInlineChild'
    'Test-RevEngDynamicSecretReference'
    'Get-RevEngSecretVerdict'
    'Remove-RevEngSecretMaterial'
    'Test-RevEngSecretLeak'
    'Convert-RevEngTemplateForPortability'
    'Get-RevEngExternalDependency'
    'Get-RevEngExportConfig'
    'Assert-RevEngPrerequisite'
    'Get-RevEngResourceInventory'
    'Get-RevEngPreviousState'
    'Get-RevEngTemplateResourceMap'
    'Compare-RevEngSnapshot'
    'Export-RevEngArmTemplate'
    'Convert-RevEngArmToBicep'
    'Test-RevEngBicepBuild'
    'Get-RevEngSupplementalInventory'
    'Test-RevEngRegionSupport'
    'Get-RevEngRequiredPermission'
    'Get-RevEngBuiltInRoleSuggestion'
    'Write-RevEngTextFile'
    'Write-RevEngJsonFile'
    'New-RevEngParameterFile'
    'New-RevEngDeployScript'
    'Invoke-RevEngGitCommit'
)
