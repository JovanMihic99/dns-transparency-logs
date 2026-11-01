# shellcheck shell=bash
# Bash port of scenarios/double-ds-rollover/common.ps1: shared helpers for scenario 3.
# Source it from the scenario scripts: source "<repo>/scenarios/double-ds-rollover/common.sh"
# Functions fill globals (CHILD_*, PARENT_*, META_*, BIND_BLOCK, ...) and stop the script on a failed check.
export LC_ALL=C

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$COMMON_DIR/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/lab/docker-compose.yml"
ZONE="victim.test."
PROVIDER="172.30.0.12"
TLD="172.30.0.11"
UNBOUND="172.30.0.14"
POLICY_MARGIN=5

die() { echo "ERROR: $*" >&2; exit 1; }
dc() { docker compose -p lab -f "$COMPOSE_FILE" "$@"; }
in_list() { [[ ",$1," == *",$2,"* ]]; }   # $1 = comma list, $2 = item

invoke_rollover() {  # shows output on stderr, keeps it in ROLLOVER_OUT
  local rc=0
  ROLLOVER_OUT=$(dc run --rm --no-deps -T ksk-rollover "$1") || rc=$?
  ROLLOVER_OUT=$(printf '%s\n' "$ROLLOVER_OUT" | tr -d '\r')
  printf '%s\n' "$ROLLOVER_OUT" >&2
  [ "$rc" -eq 0 ] || die "ksk-rollover $1 failed with exit code $rc"
}

invoke_registrar() {  # shows output on stderr, keeps it in REGISTRAR_OUT
  local rc=0
  REGISTRAR_OUT=$(dc run --rm --no-deps -T registrar "$@") || rc=$?
  REGISTRAR_OUT=$(printf '%s\n' "$REGISTRAR_OUT" | tr -d '\r')
  printf '%s\n' "$REGISTRAR_OUT" >&2
  [ "$rc" -eq 0 ] || die "registrar $* failed with exit code $rc"
}

canonical_ds() {  # stdin: dig/dnssec-dsfromkey lines -> sorted unique "tag alg type DIGEST"
  awk '{
    for (i = 1; i <= NF - 5; i++)
      if ($i == "IN" && $(i+1) == "DS" && $(i+2) ~ /^[0-9]+$/ && $(i+3) ~ /^[0-9]+$/ \
          && $(i+4) ~ /^[0-9]+$/ && $(i+5) ~ /^[0-9A-Fa-f]+$/) {
        print $(i+2), $(i+3), $(i+4), toupper($(i+5)); break
      }
  }' | sort -u
}

tags_of_ds() { printf '%s\n' "$1" | awk 'NF {print $1}' | sort -n -u | paste -sd, -; }

assert_ad_response() {  # $1 = dig output, $2 = label
  grep -Eq 'status:[[:space:]]+NOERROR' <<<"$1" && grep -Eq 'flags:.*\bad\b' <<<"$1" \
    || die "$2 was not authenticated by Unbound (NOERROR and AD=true required)"
}

get_child_snapshot() {  # sets CHILD_TAGS CHILD_DS CHILD_SIGNERS CHILD_TTL
  local answer ksk_lines n derived
  dc exec -T unbound unbound-control flush_zone "$ZONE" >/dev/null \
    || die "flush Unbound before authenticated child DNSKEY query failed"
  answer=$(dc exec -T root dig "@$UNBOUND" "$ZONE" DNSKEY +dnssec +noall +comments +answer +nosplit) \
    || die "query authenticated child DNSKEY failed"
  assert_ad_response "$answer" "Child DNSKEY RRset"
  ksk_lines=$(grep -E '[[:space:]]DNSKEY[[:space:]]+257[[:space:]]+3[[:space:]]+13[[:space:]]' <<<"$answer" || true)
  [ -n "$ksk_lines" ] || die "authenticated child response contains no ECDSAP256SHA256 flag-257 DNSKEY"
  n=$(printf '%s\n' "$ksk_lines" | grep -c .)
  CHILD_TTL=$(awk '$3 == "IN" && $4 == "DNSKEY" && $2 ~ /^[0-9]+$/ {print $2}' <<<"$ksk_lines" | sort -n | tail -n 1)
  [ -n "$CHILD_TTL" ] || die "could not determine authenticated DNSKEY TTL"
  CHILD_SIGNERS=$(awk '$4 == "RRSIG" && $5 == "DNSKEY" {print $11}' <<<"$answer" | sort -n -u | paste -sd, -)
  [ -n "$CHILD_SIGNERS" ] || die "authenticated child DNSKEY response contains no DNSKEY RRSIG signer"
  derived=$(dc exec -T root sh -c \
    "dig '@$UNBOUND' '$ZONE' DNSKEY +dnssec +noall +answer +nosplit | dnssec-dsfromkey -2 -f - '$ZONE'") \
    || die "derive DS from authenticated child DNSKEY failed"
  CHILD_DS=$(printf '%s\n' "$derived" | canonical_ds)
  [ "$(printf '%s\n' "$CHILD_DS" | grep -c . || true)" -eq "$n" ] \
    || die "derived DS count does not match authenticated SEP DNSKEY count $n"
  CHILD_TAGS=$(tags_of_ds "$CHILD_DS")
}

get_parent_snapshot() {  # sets PARENT_TAGS PARENT_DS PARENT_TTL PARENT_NS
  local direct validated vds ns_answer
  direct=$(dc exec -T root dig "@$TLD" "$ZONE" DS +dnssec +noall +answer +nosplit) \
    || die "query authoritative parent DS failed"
  PARENT_DS=$(printf '%s\n' "$direct" | canonical_ds)
  [ -n "$PARENT_DS" ] || die "parent publishes no DS records"
  grep -Eq '[[:space:]]RRSIG[[:space:]]+DS[[:space:]]' <<<"$direct" || die "parent DS RRset has no RRSIG"
  PARENT_TTL=$(awk '$3 == "IN" && $4 == "DS" && $2 ~ /^[0-9]+$/ {print $2}' <<<"$direct" | sort -n | tail -n 1)
  [ -n "$PARENT_TTL" ] || die "could not determine parent DS TTL"
  dc exec -T unbound unbound-control flush_zone "$ZONE" >/dev/null \
    || die "flush Unbound before authenticated parent DS query failed"
  validated=$(dc exec -T root dig "@$UNBOUND" "$ZONE" DS +dnssec +noall +comments +answer +nosplit) \
    || die "query authenticated parent DS failed"
  assert_ad_response "$validated" "Parent DS RRset"
  vds=$(printf '%s\n' "$validated" | canonical_ds)
  [ "$PARENT_DS" = "$vds" ] || die "authoritative parent DS and Unbound-authenticated parent DS differ"
  ns_answer=$(dc exec -T root dig "@$TLD" "$ZONE" NS +noall +answer +authority) \
    || die "query parent NS delegation failed"
  PARENT_NS=$(awk '$4 == "NS" {print tolower($5)}' <<<"$ns_answer" | sort -u | paste -sd, -)
  PARENT_TAGS=$(tags_of_ds "$PARENT_DS")
}

get_bind_key_block() {  # $1 = tag; sets BIND_BLOCK (rndc status, or the .state file as fallback)
  local status path state dnskey krrsig zrrsig ds goal published keysigning zonesigning
  status=$(dc exec -T provider rndc -s "$PROVIDER" -p 953 -k /opt/lab/rollover-control.key dnssec -status "$ZONE") \
    || die "query BIND DNSSEC key state failed"
  BIND_BLOCK=$(awk -v tag="$1" '/^key:[[:space:]]+[0-9]+/ {split($0, a, /[[:space:]]+/); inb = (a[2] == tag)} inb' <<<"$status")
  [ -n "$BIND_BLOCK" ] && return 0

  # A newly generated key can be published before rndc lists it; the .state file is BIND's own record.
  path=$(printf '/var/lib/bind/keys/Kvictim.test.+013+%05d.state' "$1")
  state=$(dc exec -T provider sh -c "test -s '$path' && cat '$path'" 2>/dev/null) \
    || die "BIND exposes neither rndc status nor persistent key state for $1"
  [ -n "$state" ] || die "BIND exposes neither rndc status nor persistent key state for $1"
  dnskey=$(sed -n 's/^DNSKEYState:[[:space:]]*//p' <<<"$state");  [ -n "$dnskey" ] || die "key $1 state lacks DNSKEYState"
  krrsig=$(sed -n 's/^KRRSIGState:[[:space:]]*//p' <<<"$state");  [ -n "$krrsig" ] || die "key $1 state lacks KRRSIGState"
  zrrsig=$(sed -n 's/^ZRRSIGState:[[:space:]]*//p' <<<"$state");  [ -n "$zrrsig" ] || die "key $1 state lacks ZRRSIGState"
  ds=$(sed -n 's/^DSState:[[:space:]]*//p' <<<"$state");          [ -n "$ds" ] || die "key $1 state lacks DSState"
  goal=$(sed -n 's/^GoalState:[[:space:]]*//p' <<<"$state");      [ -n "$goal" ] || die "key $1 state lacks GoalState"
  case "$dnskey" in rumoured|omnipresent) published=yes ;; *) published=no ;; esac
  case "$krrsig" in rumoured|omnipresent) keysigning=yes ;; *) keysigning=no ;; esac
  case "$zrrsig" in rumoured|omnipresent) zonesigning=yes ;; *) zonesigning=no ;; esac
  BIND_BLOCK="key: $1 (persistent KASP state fallback)
  published:      $published
  key signing:    $keysigning
  zone signing:   $zonesigning
  - goal:           $goal
  - dnskey:         $dnskey
  - ds:             $ds
  - zone rrsig:     $zrrsig
  - key rrsig:      $krrsig"
}

block_has() { grep -Eq "$1" <<<"$BIND_BLOCK"; }

assert_bind_key_state() {  # $1 tag, $2 published, $3 key-signing, $4 zone-signing (yes|no|either), $5 goal or ""
  get_bind_key_block "$1"
  [ "$2" = either ] || block_has "^[[:space:]]*published:[[:space:]]+$2\b"    || die "BIND key $1 published state is not '$2'"
  [ "$3" = either ] || block_has "^[[:space:]]*key signing:[[:space:]]+$3\b"  || die "BIND key $1 key-signing state is not '$3'"
  [ "$4" = either ] || block_has "^[[:space:]]*zone signing:[[:space:]]+$4\b" || die "BIND key $1 zone-signing state is not '$4'"
  [ -z "${5:-}" ]   || block_has "^[[:space:]]*- goal:[[:space:]]+$5\b"      || die "BIND key $1 goal is not '$5'"
}

assert_stable_bind_key() {  # $1 tag
  local s
  assert_bind_key_state "$1" yes yes yes omnipresent
  if block_has 'persistent KASP state fallback'; then
    for s in 'dnskey' 'ds' 'zone rrsig' 'key rrsig'; do
      block_has "^[[:space:]]*- $s:[[:space:]]+omnipresent\b" || die "BIND key $1 $s state is not omnipresent"
    done
  else
    block_has 'No rollover scheduled' || die "BIND key $1 still has a rollover scheduled"
    block_has '^[[:space:]]*- ds:[[:space:]]+omnipresent\b' || die "BIND key $1 DS state is not omnipresent"
  fi
}

assert_validated_address() {  # $1 phase
  local answer
  dc exec -T unbound unbound-control flush_zone "$ZONE" >/dev/null || die "flush Unbound during $1 failed"
  answer=$(dc exec -T root dig "@$UNBOUND" "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound during $1 failed"
  assert_ad_response "$answer" "Provider A response during $1"
  grep -Eq 'A[[:space:]]+192\.0\.2\.10' <<<"$answer" || die "provider address changed during $1"
}

assert_tags() {  # $1 actual comma list, $2 expected (space separated), $3 label
  local expected
  expected=$(printf '%s\n' $2 | sort -n | paste -sd, -)
  [ "$1" = "$expected" ] || die "$3 expected [$expected], found [$1]"
}

assert_exact_parent_ds() {  # uses the current CHILD_* and PARENT_*; $1 = expected tags (space separated)
  local t missing="" expected
  for t in $1; do in_list "$CHILD_TAGS" "$t" || missing="$missing $t"; done
  [ -z "$missing" ] || die "parent expects DS for unpublished authenticated child key tag(s):$missing"
  assert_tags "$PARENT_TAGS" "$1" "parent DS tags"
  expected=$(printf '%s\n' "$CHILD_DS" | awk -v want=" $1 " 'NF && index(want, " " $1 " ") {print}' | sort)
  [ "$expected" = "$(printf '%s\n' "$PARENT_DS" | sort)" ] \
    || die "parent DS RDATA does not cryptographically match authenticated child DNSKEYs. Expected [$expected], found [$PARENT_DS]"
}

assert_parent_ns() {  # $1 expected NS
  get_parent_snapshot
  [ "$PARENT_NS" = "$(tr '[:upper:]' '[:lower:]' <<<"$1")" ] || die "parent NS changed; expected $1, found $PARENT_NS"
}

wait_verified_window() {  # $1 label, $2 required seconds, $3 observation seconds, $4 invariant function name
  local duration=$(( $2 > $3 ? $2 : $3 )) started elapsed deadline
  started=$(date +%s)
  deadline=$(( started + duration + 120 ))
  while :; do
    "$4"
    elapsed=$(( $(date +%s) - started ))
    echo "VERIFY: $1 elapsed=${elapsed}s required=${duration}s"
    [ "$elapsed" -ge "$duration" ] && return 0
    sleep 1
    [ "$(date +%s)" -lt "$deadline" ] || break
  done
  die "$1 did not remain valid for the required $duration seconds"
}

get_rollover_metadata() {  # sets META_PHASE META_OLD META_NEW
  local out
  out=$(dc run --rm --no-deps -T ksk-rollover phase 2>/dev/null) || die "could not read saved rollover phase"
  META_PHASE=$(printf '%s\n' "$out" | tr -d '\r' \
    | grep -E '^(not-started|baseline|new-key-published|new-key-active|complete)$' | tail -n 1 || true)
  [ -n "$META_PHASE" ] || die "could not parse saved rollover phase"
  if [ "$META_PHASE" = "not-started" ]; then META_OLD=0; META_NEW=0; return 0; fi
  out=$(dc run --rm --no-deps -T ksk-rollover old-tag 2>/dev/null) || die "could not read saved predecessor tag"
  META_OLD=$(printf '%s\n' "$out" | tr -d '\r' | grep -E '^[0-9]+$' | tail -n 1 || true)
  out=$(dc run --rm --no-deps -T ksk-rollover new-tag 2>/dev/null) || die "could not read saved successor tag"
  META_NEW=$(printf '%s\n' "$out" | tr -d '\r' | grep -E '^[0-9]+$' | tail -n 1 || true)
  [ -n "$META_OLD" ] && [ -n "$META_NEW" ] || die "saved rollover metadata is malformed"
}

assert_stable_live_state() {  # sets STABLE_TAG
  get_child_snapshot
  get_parent_snapshot
  [[ "$CHILD_TAGS" != *,* && "$PARENT_TAGS" != *,* ]] \
    || die "stable state requires exactly one child key and one parent DS"
  assert_exact_parent_ds "$CHILD_TAGS"
  assert_stable_bind_key "$CHILD_TAGS"
  assert_parent_ns "ns.victim.test."
  assert_validated_address "stable-state verification"
  STABLE_TAG="$CHILD_TAGS"
}

get_a_signer_tags() {  # sets A_SIGNERS (comma list)
  local answer
  answer=$(dc exec -T root dig "@$PROVIDER" "$ZONE" A +dnssec +noall +answer +nosplit) \
    || die "query authoritative A signatures failed"
  A_SIGNERS=$(awk '$4 == "RRSIG" && $5 == "A" {print $11}' <<<"$answer" | sort -n -u | paste -sd, -)
}

assert_all_authoritative_signed_by() {  # $1 tag: every RRset in the zone has an RRSIG from this key
  local lines missing
  lines=$(dc exec -T root dig "@$PROVIDER" "$ZONE" AXFR +dnssec +nosplit) \
    || die "transfer authoritative zone for signature coverage failed"
  missing=$(awk -v tag="$1" '
    /^[[:space:]]*;/ {next}
    NF >= 4 && $2 ~ /^[0-9]+$/ && $3 == "IN" {
      owner = tolower($1); type = toupper($4)
      if (type == "RRSIG") { if (NF >= 11 && $11 == tag) signed[owner "|" toupper($5)] = 1 }
      else data[owner "|" type] = 1
    }
    END { for (k in data) if (!(k in signed)) print k }' <<<"$lines" | sort | paste -sd, -)
  [ -z "$missing" ] || die "successor $1 does not yet sign every authoritative RRset: $missing"
}

assert_partial_withdrawal_state() {  # $1 old tag, $2 new tag
  local old_block new_block
  get_rollover_metadata
  [ "$META_PHASE" = "new-key-active" ] && [ "$META_OLD" = "$1" ] && [ "$META_NEW" = "$2" ] \
    || die "saved metadata is not the expected partial withdrawal: phase=$META_PHASE old=$META_OLD new=$META_NEW"
  get_child_snapshot
  get_parent_snapshot
  local overlap
  overlap=$(printf '%s\n' "$1" "$2" | sort -n | paste -sd, -)
  [ "$CHILD_TAGS" = "$overlap" ] || [ "$CHILD_TAGS" = "$2" ] \
    || die "partial withdrawal child keys must be OLD+NEW or NEW-only; found [$CHILD_TAGS]"
  assert_exact_parent_ds "$2"
  in_list "$CHILD_SIGNERS" "$2" || die "NEW does not authenticate DNSKEY in partial withdrawal state"
  get_bind_key_block "$1"; old_block="$BIND_BLOCK"
  get_bind_key_block "$2"; new_block="$BIND_BLOCK"
  grep -Eq '^[[:space:]]*- ds:[[:space:]]+hidden\b' <<<"$old_block" \
    && grep -Eq '^[[:space:]]*- key rrsig:[[:space:]]+hidden\b' <<<"$old_block" \
    || die "OLD does not show the expected completed DS-withdrawal/key-signing side effects"
  grep -Eq '^[[:space:]]*- ds:[[:space:]]+omnipresent\b' <<<"$new_block" \
    && grep -Eq '^[[:space:]]*- key rrsig:[[:space:]]+omnipresent\b' <<<"$new_block" \
    || die "NEW DS/key-signing state is not omnipresent during partial withdrawal"
  if [ "$CHILD_TAGS" = "$2" ]; then
    grep -Eq '^[[:space:]]*published:[[:space:]]+no\b' <<<"$old_block" \
      && grep -Eq '^[[:space:]]*key signing:[[:space:]]+no\b' <<<"$old_block" \
      && grep -Eq '^[[:space:]]*zone signing:[[:space:]]+no\b' <<<"$old_block" \
      && grep -Eq '^[[:space:]]*- dnskey:[[:space:]]+(hidden|unretentive)\b' <<<"$old_block" \
      || die "OLD live removal is inconsistent with the NEW-only late partial checkpoint"
  fi
  assert_parent_ns "ns.victim.test."
  assert_validated_address "partial withdrawal audit"
}

wait_for_successor_ordinary_signing() {  # $1 old, $2 new; sets SAFETY_WINDOW
  local maxttl maximum deadline overlap t unexpected state remaining
  get_child_snapshot
  get_parent_snapshot
  maxttl=$(( CHILD_TTL > PARENT_TTL ? CHILD_TTL : PARENT_TTL ))
  maximum=$(( 300 + maxttl + POLICY_MARGIN ))
  deadline=$(( $(date +%s) + maximum ))
  overlap=$(printf '%s\n' "$1" "$2" | sort -n | paste -sd, -)
  while :; do
    get_child_snapshot
    get_parent_snapshot
    [ "$CHILD_TAGS" = "$overlap" ] || [ "$CHILD_TAGS" = "$2" ] \
      || die "unexpected child key set during extended recovery: [$CHILD_TAGS]"
    assert_exact_parent_ds "$2"
    in_list "$CHILD_SIGNERS" "$2" || die "NEW DNSKEY authentication disappeared during extended recovery"
    get_a_signer_tags
    unexpected=""
    for t in ${A_SIGNERS//,/ }; do [ "$t" = "$1" ] || [ "$t" = "$2" ] || unexpected="$unexpected $t"; done
    [ -z "$unexpected" ] || die "unexpected A RRSIG signer(s):$unexpected"
    get_bind_key_block "$2"
    state=$(sed -nE 's/^[[:space:]]*- zone rrsig:[[:space:]]+(rumoured|omnipresent)\b.*/\1/p' <<<"$BIND_BLOCK" | head -n 1)
    [ -n "$state" ] || state="unexpected"
    assert_parent_ns "ns.victim.test."
    assert_validated_address "extended successor-signing poll"
    remaining=$(( deadline - $(date +%s) )); [ "$remaining" -ge 0 ] || remaining=0
    echo "POLL: NEW=$2 A-signer=$(in_list "$A_SIGNERS" "$2" && echo True || echo False) ZRRSIG-state=$state remaining=${remaining}s"
    if in_list "$A_SIGNERS" "$2" && [ "$state" != "unexpected" ]; then
      assert_all_authoritative_signed_by "$2"
      SAFETY_WINDOW=$(( maxttl + POLICY_MARGIN ))
      return 0
    fi
    sleep 2
    [ "$(date +%s)" -lt "$deadline" ] || break
  done
  die "NEW $2 did not become an omnipresent ordinary-data signer within ${maximum}s"
}

_final_hold_invariant() {  # used by complete_withdrawn_with_extended_recovery
  assert_partial_withdrawal_state "$_CW_OLD" "$_CW_NEW"
  get_a_signer_tags
  in_list "$A_SIGNERS" "$_CW_NEW" || die "NEW A signature disappeared during final cache-safety hold"
  get_bind_key_block "$_CW_NEW"
  block_has '^[[:space:]]*- zone rrsig:[[:space:]]+(rumoured|omnipresent)\b' \
    || die "NEW ZRRSIG state became unsafe during final cache-safety hold"
  assert_all_authoritative_signed_by "$_CW_NEW"
}

complete_withdrawn_with_extended_recovery() {  # $1 old, $2 new, $3 = "already-failed" to skip the first attempt
  if [ "${3:-}" != "already-failed" ]; then
    if ( invoke_rollover acknowledge-withdrawn ); then return 0; fi
    echo "Initial shared-controller completion failed; auditing partial side effects before extended recovery."
  fi
  assert_partial_withdrawal_state "$1" "$2"
  wait_for_successor_ordinary_signing "$1" "$2"
  _CW_OLD="$1"; _CW_NEW="$2"
  wait_verified_window "successor ordinary-signature cache safety" "$SAFETY_WINDOW" 0 _final_hold_invariant
  # The earlier attempt's completed steps are idempotent; repeating is allowed only after the strict audit above.
  invoke_rollover acknowledge-withdrawn
}
