param(
    [ValidateRange(0, 300)]
    [int]$ObservationDurationSeconds = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'scenarios\double-ds-rollover\common.ps1')

Push-Location $script:RepoRoot
try {
    docker compose @script:ComposeArgs up -d | Out-Host
    Assert-ExitCode 'start lab for recovery'

    $metadata = Get-RolloverMetadata
    $child = Get-ChildSnapshot
    $parent = Get-ParentSnapshot

    if ($child.Tags.Count -eq 1 -and $parent.Tags.Count -eq 1 -and $child.Tags[0] -eq $parent.Tags[0]) {
        if ($metadata.Phase -eq 'new-key-active' -and $metadata.NewTag -eq $child.Tags[0]) {
            # A late acknowledge-withdrawn timeout can leave OLD already absent
            # while the shared controller has not restored the 30-second zone
            # TTL or saved completion. Finish that idempotent tail before
            # clearing metadata.
            Complete-WithdrawnWithExtendedRecovery -OldTag $metadata.OldTag -NewTag $metadata.NewTag -InitialAttemptAlreadyFailed
        }
        $stableTag = Assert-StableLiveState
        if ($metadata.Phase -ne 'not-started') { Invoke-Rollover 'reconcile' | Out-Null }
        Write-Host "Recovery complete: stable CSK/DS tag $stableTag."
        return
    }

    if ($metadata.Phase -eq 'not-started') {
        throw 'Live DNS is transitional but no saved rollover metadata exists; refusing to infer ownership. Inspect ksk-rollover status, child DNSKEY, and parent DS.'
    }

    $oldTag = $metadata.OldTag
    $newTag = $metadata.NewTag
    if ($newTag -eq 0) {
        if ($child.Tags.Count -ne 2 -or $child.Tags -notcontains $oldTag -or $parent.Tags.Count -ne 1 -or $parent.Tags[0] -ne $oldTag) {
            throw "Saved baseline has no successor identity and live state is not an authenticated OLD-only parent with two child keys. phase=$($metadata.Phase) old=$oldTag child=$($child.Tags -join ',') parent=$($parent.Tags -join ',')"
        }
        Assert-ExactParentDs $child $parent @($oldTag)
        if ($child.SignerTags -notcontains $oldTag) { throw 'OLD does not authenticate the two-key DNSKEY RRset; refusing resume-begin' }
        foreach ($candidate in $child.Tags) { Assert-BindKeyState -Tag $candidate -Published yes | Out-Null }
        Invoke-Rollover 'resume-begin' | Out-Null
        $metadata = Get-RolloverMetadata
        $newTag = $metadata.NewTag
        if ($newTag -eq 0) { throw 'resume-begin did not persist a successor identity' }
    }

    if ($child.Tags -notcontains $oldTag -or $child.Tags -notcontains $newTag) {
        throw "Saved OLD/NEW identities do not match live transitional DNSKEYs. old=$oldTag new=$newTag child=$($child.Tags -join ',')"
    }
    Assert-BindKeyState -Tag $oldTag -Published yes | Out-Null
    Assert-BindKeyState -Tag $newTag -Published yes | Out-Null

    if ($parent.Tags.Count -eq 1 -and $parent.Tags[0] -eq $oldTag) {
        if ($metadata.Phase -ne 'new-key-published') {
            throw "OLD-only parent is inconsistent with saved phase $($metadata.Phase); refusing to acknowledge or rewrite DS"
        }
        Assert-ExactParentDs $child $parent @($oldTag)
        if ($child.SignerTags -notcontains $oldTag) { throw 'OLD does not authenticate successor publication during recovery' }
        $hold = $child.Ttl + $script:PolicyPropagationMarginSeconds
        Wait-VerifiedWindow -Label 'recovery successor prepublication' -RequiredSeconds $hold -ObservationSeconds $ObservationDurationSeconds -Invariant {
            $c = Get-ChildSnapshot; $p = Get-ParentSnapshot
            Assert-ExactParentDs $c $p @($oldTag)
            if ($c.SignerTags -notcontains $oldTag) { throw 'OLD DNSKEY signature disappeared during recovery' }
            Assert-ValidatedAddress 'recovery prepublication'
        }
        Invoke-Registrar @('sync-provider-ds') | Out-Null
        $parent = Get-ParentSnapshot
    }

    if (($parent.Tags -join ',') -eq ((@($oldTag, $newTag) | Sort-Object) -join ',')) {
        Assert-ExactParentDs (Get-ChildSnapshot) $parent @($oldTag, $newTag)
        if ($metadata.Phase -eq 'new-key-published') {
            $hold = [Math]::Max($parent.Ttl, (Get-ChildSnapshot).Ttl) + $script:PolicyPropagationMarginSeconds
            Wait-VerifiedWindow -Label 'recovery double-DS overlap' -RequiredSeconds $hold -ObservationSeconds $ObservationDurationSeconds -Invariant {
                $c = Get-ChildSnapshot; $p = Get-ParentSnapshot
                Assert-ExactParentDs $c $p @($oldTag, $newTag)
                if ($c.SignerTags -notcontains $oldTag) { throw 'OLD DNSKEY signature disappeared during recovery overlap' }
                Assert-ValidatedAddress 'recovery double-DS overlap'
            }
            Invoke-Rollover 'acknowledge-published' | Out-Null
            $metadata = Get-RolloverMetadata
        }
        if ($metadata.Phase -ne 'new-key-active') {
            throw "Double-DS parent cannot safely advance from saved phase $($metadata.Phase)"
        }
        $active = Get-ChildSnapshot
        if ($active.SignerTags -notcontains $newTag) { throw 'NEW does not sign authenticated DNSKEY after saved activation' }
        Assert-BindKeyState -Tag $newTag -Published yes -KeySigning yes | Out-Null
        Invoke-Registrar @('sync-provider-ds', '--key-tag', "$newTag") | Out-Null
        $parent = Get-ParentSnapshot
    }

    if ($parent.Tags.Count -eq 1 -and $parent.Tags[0] -eq $newTag) {
        if ($metadata.Phase -ne 'new-key-active') {
            throw "NEW-only parent is inconsistent with saved phase $($metadata.Phase); refusing predecessor retirement"
        }
        $child = Get-ChildSnapshot
        Assert-ExactParentDs $child $parent @($newTag)
        if ($child.SignerTags -notcontains $newTag) { throw 'NEW does not authenticate DNSKEY under NEW-only parent' }
        Assert-BindKeyState -Tag $newTag -Published yes -KeySigning yes | Out-Null
        $hold = [Math]::Max($parent.Ttl, $child.Ttl) + $script:PolicyPropagationMarginSeconds
        Wait-VerifiedWindow -Label 'recovery successor-only propagation' -RequiredSeconds $hold -ObservationSeconds 0 -Invariant {
            $c = Get-ChildSnapshot; $p = Get-ParentSnapshot
            Assert-ExactParentDs $c $p @($newTag)
            if ($c.SignerTags -notcontains $newTag) { throw 'NEW DNSKEY signature disappeared during recovery' }
            Assert-ValidatedAddress 'recovery successor-only state'
        }
        $oldBlock = Get-BindKeyBlock $oldTag
        $partial = $oldBlock -match '(?m)^\s*- ds:\s+hidden\b'
        if ($partial) {
            Complete-WithdrawnWithExtendedRecovery -OldTag $oldTag -NewTag $newTag -InitialAttemptAlreadyFailed
        } else {
            Complete-WithdrawnWithExtendedRecovery -OldTag $oldTag -NewTag $newTag
        }
    } else {
        throw "Parent DS state is ambiguous: $($parent.Tags -join ','). No recovery mutation was attempted."
    }

    $stableTag = Assert-StableLiveState
    if ($stableTag -ne $newTag) { throw "Recovery completed on $stableTag instead of saved successor $newTag" }
    Invoke-Rollover 'reconcile' | Out-Null
    Write-Host "Recovery complete at successor CSK/DS tag $newTag; predecessor was not restored."
}
finally {
    Pop-Location
}
