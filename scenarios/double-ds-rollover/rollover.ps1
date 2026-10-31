param(
    [ValidateRange(0, 300)]
    [int]$ObservationDurationSeconds = 5
)

. (Join-Path $PSScriptRoot 'common.ps1')

Push-Location $script:RepoRoot
try {
    docker compose @script:ComposeArgs build registrar | Out-Host
    Assert-ExitCode 'build registrar'
    docker compose @script:ComposeArgs up -d | Out-Host
    Assert-ExitCode 'start lab'

    & (Join-Path $script:RepoRoot 'lab\reset-double-ds-rollover.ps1') -ObservationDurationSeconds 0
    if ($LASTEXITCODE -ne 0) { throw "Scenario 3 reset failed with exit code $LASTEXITCODE" }

    $baselineTag = Assert-StableLiveState
    $baselineParent = Get-ParentSnapshot
    Write-Host "PHASE baseline: parent OLD-only, stable tag=$baselineTag, AD=true"

    $begin = Invoke-Rollover 'begin'
    $oldLine = @($begin | Where-Object { $_ -match '^OLD_TAG=\d+$' } | Select-Object -Last 1)
    $newLine = @($begin | Where-Object { $_ -match '^NEW_TAG=\d+$' } | Select-Object -Last 1)
    if ($oldLine.Count -ne 1 -or $newLine.Count -ne 1) { throw 'Could not parse predecessor and successor tags from begin' }
    $oldTag = [int]($oldLine[0] -replace '^OLD_TAG=', '')
    $newTag = [int]($newLine[0] -replace '^NEW_TAG=', '')
    if ($oldTag -ne $baselineTag -or $oldTag -eq $newTag) { throw 'BIND returned inconsistent rollover identities' }

    $publicationChild = Get-ChildSnapshot
    $publicationParent = Get-ParentSnapshot
    Assert-Tags $publicationChild.Tags @($oldTag, $newTag) 'published child DNSKEYs'
    Assert-ExactParentDs $publicationChild $publicationParent @($oldTag)
    if ($publicationChild.SignerTags -notcontains $oldTag) { throw 'Predecessor does not authenticate the successor DNSKEY publication' }
    Assert-BindKeyState -Tag $oldTag -Published yes | Out-Null
    Assert-BindKeyState -Tag $newTag -Published yes | Out-Null
    Assert-ParentNs 'ns.victim.test.'
    Assert-ValidatedAddress 'successor DNSKEY publication'
    Write-Host "PHASE successor-published: child OLD+NEW, parent OLD-only, new=$newTag"

    $publicationSafety = $publicationChild.Ttl + $script:PolicyPropagationMarginSeconds
    Wait-VerifiedWindow -Label 'authenticated successor DNSKEY prepublication' `
        -RequiredSeconds $publicationSafety -ObservationSeconds $ObservationDurationSeconds -Invariant {
            $child = Get-ChildSnapshot
            $parent = Get-ParentSnapshot
            Assert-Tags $child.Tags @($oldTag, $newTag) 'prepublication child keys'
            Assert-ExactParentDs $child $parent @($oldTag)
            if ($child.SignerTags -notcontains $oldTag) { throw 'OLD stopped authenticating the DNSKEY RRset during prepublication' }
            Assert-BindKeyState -Tag $newTag -Published yes | Out-Null
            Assert-ValidatedAddress 'DNSKEY prepublication hold'
        }

    Invoke-Registrar @('sync-provider-ds') | Out-Null
    $overlapParent = Get-ParentSnapshot
    $overlapChild = Get-ChildSnapshot
    Assert-Tags $overlapChild.Tags @($oldTag, $newTag) 'double-DS child keys'
    Assert-ExactParentDs $overlapChild $overlapParent @($oldTag, $newTag)
    Assert-ParentNs 'ns.victim.test.'
    Assert-ValidatedAddress 'double-DS publication'
    Write-Host "PHASE double-ds: parent publishes exactly OLD=$oldTag and NEW=$newTag"

    $overlapSafety = [Math]::Max($overlapParent.Ttl, $overlapChild.Ttl) + $script:PolicyPropagationMarginSeconds
    Wait-VerifiedWindow -Label 'signed parent double-DS overlap' `
        -RequiredSeconds $overlapSafety -ObservationSeconds $ObservationDurationSeconds -Invariant {
            $child = Get-ChildSnapshot
            $parent = Get-ParentSnapshot
            Assert-Tags $child.Tags @($oldTag, $newTag) 'double-DS child keys'
            Assert-ExactParentDs $child $parent @($oldTag, $newTag)
            if ($child.SignerTags -notcontains $oldTag) { throw 'OLD no longer authenticates DNSKEY during double-DS overlap' }
            Assert-BindKeyState -Tag $newTag -Published yes | Out-Null
            Assert-ParentNs 'ns.victim.test.'
            Assert-ValidatedAddress 'double-DS safety hold'
        }

    Invoke-Rollover 'acknowledge-published' | Out-Null
    $activeChild = Get-ChildSnapshot
    $activeParent = Get-ParentSnapshot
    Assert-ExactParentDs $activeChild $activeParent @($oldTag, $newTag)
    if ($activeChild.SignerTags -notcontains $newTag) { throw 'Successor does not sign the authenticated DNSKEY RRset after activation' }
    $newBlock = Assert-BindKeyState -Tag $newTag -Published yes -KeySigning yes
    if ($newBlock -notmatch '(?m)^\s*- ds:\s+omnipresent\b') { throw 'BIND has not accepted the successor DS as published' }
    Assert-ValidatedAddress 'successor signing activation'
    Write-Host "PHASE successor-active: NEW=$newTag signs DNSKEY and BIND accepts its DS"

    Invoke-Registrar @('sync-provider-ds', '--key-tag', "$newTag") | Out-Null
    $newOnlyParent = Get-ParentSnapshot
    $newOnlyChild = Get-ChildSnapshot
    Assert-Tags $newOnlyChild.Tags @($oldTag, $newTag) 'pre-retirement child keys'
    Assert-ExactParentDs $newOnlyChild $newOnlyParent @($newTag)
    if ($newOnlyChild.SignerTags -notcontains $newTag) { throw 'Authenticated successor DNSKEY signature is missing before OLD retirement' }
    Assert-BindKeyState -Tag $newTag -Published yes -KeySigning yes | Out-Null
    Assert-ParentNs 'ns.victim.test.'
    Assert-ValidatedAddress 'old DS withdrawal'
    Write-Host "PHASE old-ds-withdrawn: parent publishes NEW=$newTag only"

    $withdrawalSafety = [Math]::Max($newOnlyParent.Ttl, $newOnlyChild.Ttl) + $script:PolicyPropagationMarginSeconds
    Wait-VerifiedWindow -Label 'successor-only parent propagation' `
        -RequiredSeconds $withdrawalSafety -ObservationSeconds 0 -Invariant {
            $child = Get-ChildSnapshot
            $parent = Get-ParentSnapshot
            Assert-Tags $child.Tags @($oldTag, $newTag) 'pre-retirement child keys'
            Assert-ExactParentDs $child $parent @($newTag)
            if ($child.SignerTags -notcontains $newTag) { throw 'NEW stopped signing DNSKEY during withdrawal safety hold' }
            Assert-BindKeyState -Tag $newTag -Published yes -KeySigning yes | Out-Null
            Assert-ValidatedAddress 'successor-only propagation hold'
        }

    Complete-WithdrawnWithExtendedRecovery -OldTag $oldTag -NewTag $newTag
    $finalTag = Assert-StableLiveState
    if ($finalTag -ne $newTag) { throw "Completion stabilized on unexpected key $finalTag instead of $newTag" }
    Write-Host "PHASE complete: NEW=$newTag is the sole stable CSK and parent DS"

    docker compose @script:ComposeArgs exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
    Assert-ExitCode '12-check DNSSEC baseline regression'
    Invoke-Rollover 'reconcile' | Out-Null
    $metadata = Get-RolloverMetadata
    if ($metadata.Phase -ne 'not-started') { throw 'Completed rollover metadata did not reconcile to not-started' }
    Write-Host "PASS: legitimate Double-DS rollover completed: $oldTag -> $newTag"
}
finally {
    Pop-Location
}
