#!/usr/bin/env bash
# Bash port of reset-double-ds-rollover.ps1: conservative recovery of a partial double-DS rollover.
# Moves forward only from states it can identify; anything ambiguous is refused without changes.
# Lab only. Usage: sudo bash lab/reset-double-ds-rollover.sh [observation-seconds 0-300, default 5]
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/scenarios/double-ds-rollover/common.sh"
cd "$REPO_ROOT"

OBS="${1:-5}"
case "$OBS" in ''|*[!0-9]*) die "observation seconds must be a number 0-300";; esac
[ "$OBS" -le 300 ] || die "observation seconds must be 0-300"

max() { echo $(( $1 > $2 ? $1 : $2 )); }
count_tags() { tr ',' '\n' <<<"$1" | grep -c . || true; }

inv_rec_prepub() {
  get_child_snapshot; get_parent_snapshot
  assert_exact_parent_ds "$OLD_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD DNSKEY signature disappeared during recovery"
  assert_validated_address "recovery prepublication"
}
inv_rec_overlap() {
  get_child_snapshot; get_parent_snapshot
  assert_exact_parent_ds "$OLD_TAG $NEW_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD DNSKEY signature disappeared during recovery overlap"
  assert_validated_address "recovery double-DS overlap"
}
inv_rec_newonly() {
  get_child_snapshot; get_parent_snapshot
  assert_exact_parent_ds "$NEW_TAG"
  in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "NEW DNSKEY signature disappeared during recovery"
  assert_validated_address "recovery successor-only state"
}

dc up -d || die "start lab for recovery failed"
get_rollover_metadata
PHASE="$META_PHASE"; OLD_TAG="$META_OLD"; NEW_TAG="$META_NEW"
get_child_snapshot
get_parent_snapshot

if [ "$(count_tags "$CHILD_TAGS")" -eq 1 ] && [ "$(count_tags "$PARENT_TAGS")" -eq 1 ] && [ "$CHILD_TAGS" = "$PARENT_TAGS" ]; then
  if [ "$PHASE" = "new-key-active" ] && [ "$NEW_TAG" = "$CHILD_TAGS" ]; then
    # A late acknowledge-withdrawn failure can leave OLD absent before completion was saved; finish that idempotent tail.
    complete_withdrawn_with_extended_recovery "$OLD_TAG" "$NEW_TAG" already-failed
  fi
  assert_stable_live_state
  [ "$PHASE" = "not-started" ] || invoke_rollover reconcile
  echo "Recovery complete: stable CSK/DS tag $STABLE_TAG."
  exit 0
fi

[ "$PHASE" != "not-started" ] \
  || die "live DNS is transitional but no saved rollover metadata exists; refusing to infer ownership. Inspect ksk-rollover status, child DNSKEY, and parent DS."

if [ "$NEW_TAG" = "0" ]; then
  if [ "$(count_tags "$CHILD_TAGS")" -ne 2 ] || ! in_list "$CHILD_TAGS" "$OLD_TAG" || [ "$PARENT_TAGS" != "$OLD_TAG" ]; then
    die "saved baseline has no successor identity and live state is not an authenticated OLD-only parent with two child keys. phase=$PHASE old=$OLD_TAG child=$CHILD_TAGS parent=$PARENT_TAGS"
  fi
  assert_exact_parent_ds "$OLD_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD does not authenticate the two-key DNSKEY RRset; refusing resume-begin"
  for candidate in ${CHILD_TAGS//,/ }; do assert_bind_key_state "$candidate" yes either either ""; done
  invoke_rollover resume-begin
  get_rollover_metadata
  PHASE="$META_PHASE"; NEW_TAG="$META_NEW"
  [ "$NEW_TAG" != "0" ] || die "resume-begin did not persist a successor identity"
fi

in_list "$CHILD_TAGS" "$OLD_TAG" && in_list "$CHILD_TAGS" "$NEW_TAG" \
  || die "saved OLD/NEW identities do not match live transitional DNSKEYs. old=$OLD_TAG new=$NEW_TAG child=$CHILD_TAGS"
assert_bind_key_state "$OLD_TAG" yes either either ""
assert_bind_key_state "$NEW_TAG" yes either either ""

if [ "$PARENT_TAGS" = "$OLD_TAG" ]; then
  [ "$PHASE" = "new-key-published" ] \
    || die "OLD-only parent is inconsistent with saved phase $PHASE; refusing to acknowledge or rewrite DS"
  assert_exact_parent_ds "$OLD_TAG"
  in_list "$CHILD_SIGNERS" "$OLD_TAG" || die "OLD does not authenticate successor publication during recovery"
  wait_verified_window "recovery successor prepublication" $(( CHILD_TTL + POLICY_MARGIN )) "$OBS" inv_rec_prepub
  invoke_registrar sync-provider-ds
  get_parent_snapshot
fi

OVERLAP=$(printf '%s\n' "$OLD_TAG" "$NEW_TAG" | sort -n | paste -sd, -)
if [ "$PARENT_TAGS" = "$OVERLAP" ]; then
  P_TTL="$PARENT_TTL"
  get_child_snapshot
  assert_exact_parent_ds "$OLD_TAG $NEW_TAG"
  if [ "$PHASE" = "new-key-published" ]; then
    wait_verified_window "recovery double-DS overlap" $(( $(max "$P_TTL" "$CHILD_TTL") + POLICY_MARGIN )) "$OBS" inv_rec_overlap
    invoke_rollover acknowledge-published
    get_rollover_metadata
    PHASE="$META_PHASE"
  fi
  [ "$PHASE" = "new-key-active" ] || die "double-DS parent cannot safely advance from saved phase $PHASE"
  get_child_snapshot
  in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "NEW does not sign authenticated DNSKEY after saved activation"
  assert_bind_key_state "$NEW_TAG" yes yes either ""
  invoke_registrar sync-provider-ds --key-tag "$NEW_TAG"
  get_parent_snapshot
fi

if [ "$PARENT_TAGS" = "$NEW_TAG" ]; then
  [ "$PHASE" = "new-key-active" ] \
    || die "NEW-only parent is inconsistent with saved phase $PHASE; refusing predecessor retirement"
  get_child_snapshot
  assert_exact_parent_ds "$NEW_TAG"
  in_list "$CHILD_SIGNERS" "$NEW_TAG" || die "NEW does not authenticate DNSKEY under NEW-only parent"
  assert_bind_key_state "$NEW_TAG" yes yes either ""
  wait_verified_window "recovery successor-only propagation" $(( $(max "$PARENT_TTL" "$CHILD_TTL") + POLICY_MARGIN )) 0 inv_rec_newonly
  get_bind_key_block "$OLD_TAG"
  if block_has '^[[:space:]]*- ds:[[:space:]]+hidden\b'; then
    complete_withdrawn_with_extended_recovery "$OLD_TAG" "$NEW_TAG" already-failed
  else
    complete_withdrawn_with_extended_recovery "$OLD_TAG" "$NEW_TAG"
  fi
else
  die "parent DS state is ambiguous: $PARENT_TAGS. No recovery mutation was attempted."
fi

assert_stable_live_state
[ "$STABLE_TAG" = "$NEW_TAG" ] || die "recovery completed on $STABLE_TAG instead of saved successor $NEW_TAG"
invoke_rollover reconcile
echo "Recovery complete at successor CSK/DS tag $NEW_TAG; predecessor was not restored."
