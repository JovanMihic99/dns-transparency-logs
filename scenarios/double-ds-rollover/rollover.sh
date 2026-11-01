#!/usr/bin/env bash
# Bash port of scenarios/double-ds-rollover/rollover.ps1: legitimate double-DS rollover (scenario 3).
# Lab only. Usage: sudo bash scenarios/double-ds-rollover/rollover.sh [observation-seconds 0-300, default 5]
#   With a running collector use 25, so each phase is held across at least two polls.
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
cd "$REPO_ROOT"

OBS="${1:-5}"
case "$OBS" in ''|*[!0-9]*) die "observation seconds must be a number 0-300";; esac
[ "$OBS" -le 300 ] || die "observation seconds must be 0-300"

inv_prepublication() {
  get_child_snapshot; get_parent_snapshot
  assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "prepublication child keys"
  assert_exact_parent_ds "$OLD_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD stopped authenticating the DNSKEY RRset during prepublication"
  assert_bind_key_state "$NEW_TAG" yes either either ""
  assert_validated_address "DNSKEY prepublication hold"
}

inv_double_ds() {
  get_child_snapshot; get_parent_snapshot
  assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "double-DS child keys"
  assert_exact_parent_ds "$OLD_TAG $NEW_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD no longer authenticates DNSKEY during double-DS overlap"
  assert_bind_key_state "$NEW_TAG" yes either either ""
  assert_parent_ns "ns.victim.test."
  assert_validated_address "double-DS safety hold"
}

inv_withdrawal() {
  get_child_snapshot; get_parent_snapshot
  assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "pre-retirement child keys"
  assert_exact_parent_ds "$NEW_TAG"
  in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "NEW stopped signing DNSKEY during withdrawal safety hold"
  assert_bind_key_state "$NEW_TAG" yes yes either ""
  assert_validated_address "successor-only propagation hold"
}

max() { echo $(( $1 > $2 ? $1 : $2 )); }

dc build registrar || die "build registrar failed"
dc up -d || die "start lab failed"
bash "$REPO_ROOT/lab/reset-double-ds-rollover.sh" 0 || die "Scenario 3 reset failed with exit code $?"

assert_stable_live_state
BASELINE_TAG="$STABLE_TAG"
echo "PHASE baseline: parent OLD-only, stable tag=$BASELINE_TAG, AD=true"

invoke_rollover begin
OLD_TAG=$(grep -E '^OLD_TAG=[0-9]+$' <<<"$ROLLOVER_OUT" | tail -n 1 | cut -d= -f2 || true)
NEW_TAG=$(grep -E '^NEW_TAG=[0-9]+$' <<<"$ROLLOVER_OUT" | tail -n 1 | cut -d= -f2 || true)
[ -n "$OLD_TAG" ] && [ -n "$NEW_TAG" ] || die "could not parse predecessor and successor tags from begin"
[ "$OLD_TAG" = "$BASELINE_TAG" ] && [ "$OLD_TAG" != "$NEW_TAG" ] || die "BIND returned inconsistent rollover identities"

get_child_snapshot; get_parent_snapshot
assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "published child DNSKEYs"
assert_exact_parent_ds "$OLD_TAG"
in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "predecessor does not authenticate the successor DNSKEY publication"
PUBLICATION_SAFETY=$(( CHILD_TTL + POLICY_MARGIN ))
assert_bind_key_state "$OLD_TAG" yes either either ""
assert_bind_key_state "$NEW_TAG" yes either either ""
assert_parent_ns "ns.victim.test."
assert_validated_address "successor DNSKEY publication"
echo "PHASE successor-published: child OLD+NEW, parent OLD-only, new=$NEW_TAG"
wait_verified_window "authenticated successor DNSKEY prepublication" "$PUBLICATION_SAFETY" "$OBS" inv_prepublication

invoke_registrar sync-provider-ds
get_parent_snapshot; get_child_snapshot
assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "double-DS child keys"
assert_exact_parent_ds "$OLD_TAG $NEW_TAG"
OVERLAP_SAFETY=$(( $(max "$PARENT_TTL" "$CHILD_TTL") + POLICY_MARGIN ))
assert_parent_ns "ns.victim.test."
assert_validated_address "double-DS publication"
echo "PHASE double-ds: parent publishes exactly OLD=$OLD_TAG and NEW=$NEW_TAG"
wait_verified_window "signed parent double-DS overlap" "$OVERLAP_SAFETY" "$OBS" inv_double_ds

invoke_rollover acknowledge-published
get_child_snapshot; get_parent_snapshot
assert_exact_parent_ds "$OLD_TAG $NEW_TAG"
in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "successor does not sign the authenticated DNSKEY RRset after activation"
assert_bind_key_state "$NEW_TAG" yes yes either ""
block_has '^[[:space:]]*- ds:[[:space:]]+omnipresent\b' || die "BIND has not accepted the successor DS as published"
assert_validated_address "successor signing activation"
echo "PHASE successor-active: NEW=$NEW_TAG signs DNSKEY and BIND accepts its DS"

invoke_registrar sync-provider-ds --key-tag "$NEW_TAG"
get_parent_snapshot; get_child_snapshot
assert_tags "$CHILD_TAGS" "$OLD_TAG $NEW_TAG" "pre-retirement child keys"
assert_exact_parent_ds "$NEW_TAG"
in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "authenticated successor DNSKEY signature is missing before OLD retirement"
WITHDRAWAL_SAFETY=$(( $(max "$PARENT_TTL" "$CHILD_TTL") + POLICY_MARGIN ))
assert_bind_key_state "$NEW_TAG" yes yes either ""
assert_parent_ns "ns.victim.test."
assert_validated_address "old DS withdrawal"
echo "PHASE old-ds-withdrawn: parent publishes NEW=$NEW_TAG only"
wait_verified_window "successor-only parent propagation" "$WITHDRAWAL_SAFETY" 0 inv_withdrawal

complete_withdrawn_with_extended_recovery "$OLD_TAG" "$NEW_TAG"
assert_stable_live_state
[ "$STABLE_TAG" = "$NEW_TAG" ] || die "completion stabilized on unexpected key $STABLE_TAG instead of $NEW_TAG"
echo "PHASE complete: NEW=$NEW_TAG is the sole stable CSK and parent DS"

dc exec -T root sh /opt/lab/test-dnssec.sh || die "12-check DNSSEC baseline regression failed"
invoke_rollover reconcile
get_rollover_metadata
[ "$META_PHASE" = "not-started" ] || die "completed rollover metadata did not reconcile to not-started"
echo "PASS: legitimate Double-DS rollover completed: $OLD_TAG -> $NEW_TAG"
