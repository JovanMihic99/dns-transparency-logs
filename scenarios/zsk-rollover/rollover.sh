#!/bin/sh
set -eu

provider=172.30.0.12
tld=172.30.0.11
unbound=172.30.0.14
zone=victim.test.
control_key=/opt/zsk/rollover-control.key
state_file=/zsk-state/scenario/current.env
events_file=/zsk-state/scenario/events.jsonl

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

rndc_provider() {
    rndc -s "$provider" -p 953 -k "$control_key" "$@"
}

load_state() {
    [ -s "$state_file" ] || fail "Scenario state is missing; run zsk-prepare first"
    . "$state_file"
}

save_state() {
    phase=$1
    tmp="$state_file.tmp"
    {
        echo "RUN_ID=$RUN_ID"
        echo "BASE_KSK_TAG=$BASE_KSK_TAG"
        echo "BASE_DS_ALGORITHM=$BASE_DS_ALGORITHM"
        echo "BASE_DS_DIGEST_TYPE=$BASE_DS_DIGEST_TYPE"
        echo "BASE_DS_DIGEST=$BASE_DS_DIGEST"
        echo "OLD_ZSK_TAG=$OLD_ZSK_TAG"
        echo "NEW_ZSK_TAG=$NEW_ZSK_TAG"
        echo "PHASE=$phase"
        echo "RETIRE_SAFE_AFTER=$RETIRE_SAFE_AFTER"
    } > "$tmp"
    mv "$tmp" "$state_file"
    PHASE=$phase
}

csv() {
    awk 'BEGIN {first=1} NF {if (!first) printf ","; printf "%s", $0; first=0} END {print ""}'
}

contains_line() {
    needle=$1
    grep -qx "$needle"
}

all_dnskey_tags() {
    dig "@$provider" "$zone" DNSKEY +noall +answer |
        dnssec-dsfromkey -A -2 -f - "$zone" 2>/dev/null |
        awk '{print $4}' | sort -n -u
}

ksk_tags() {
    dig "@$provider" "$zone" DNSKEY +noall +answer |
        dnssec-dsfromkey -2 -f - "$zone" 2>/dev/null |
        awk '{print $4}' | sort -n -u
}

zsk_tags() {
    ksks=$(ksk_tags)
    for tag in $(all_dnskey_tags); do
        if ! echo "$ksks" | contains_line "$tag"; then
            echo "$tag"
        fi
    done | sort -n -u
}

signature_tags() {
    covered=$1
    dig "@$provider" "$zone" "$covered" +dnssec +noall +answer |
        awk -v covered="$covered" '$4 == "RRSIG" && $5 == covered {print $11}' |
        sort -n -u
}

parent_ds() {
    dig "@$tld" "$zone" DS +noall +answer +nosplit |
        awk '$4 == "DS" {printf "%s %s %s %s", $5, $6, $7, toupper($8)}'
}

parent_ns() {
    dig "@$tld" "$zone" NS +noall +answer +authority |
        awk '$4 == "NS" {print $5}' | sort -u
}

assert_parent_unchanged() {
    expected="$BASE_KSK_TAG $BASE_DS_ALGORITHM $BASE_DS_DIGEST_TYPE $BASE_DS_DIGEST"
    [ "$(parent_ds)" = "$expected" ] || fail "Parent DS changed during ZSK scenario"
    [ "$(parent_ns)" = "ns.victim.test." ] || fail "Parent NS delegation changed during ZSK scenario"
}

assert_ksk_unchanged() {
    [ "$(ksk_tags)" = "$BASE_KSK_TAG" ] || fail "KSK identity changed during ZSK scenario"
    [ "$(signature_tags DNSKEY)" = "$BASE_KSK_TAG" ] ||
        fail "DNSKEY RRset is not signed exclusively by the retained KSK"
}

assert_ad() {
    answer=$(dig "@$unbound" www.victim.test. A +dnssec +noall +comments +answer)
    echo "$answer" | grep -q 'status: NOERROR' || fail "Unbound did not return NOERROR"
    echo "$answer" | grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]' || fail "Unbound did not return AD=true"
    echo "$answer" | grep -Eq 'www\.victim\.test\..*A[[:space:]]+192\.0\.2\.10' ||
        fail "Unbound did not return the legitimate provider address"
}

assert_invariants() {
    assert_parent_unchanged
    assert_ksk_unchanged
    assert_ad
}

key_file() {
    tag=$1
    printf '/zsk-state/current/keys/Kvictim.test.+013+%05d.key\n' "$tag"
}

max_authoritative_ttl() {
    dig "@$provider" "$zone" AXFR +dnssec |
        awk '!/^;/ && NF >= 4 && $2 ~ /^[0-9]+$/ {if ($2 > max) max=$2} END {print max+0}'
}

dnskey_ttl() {
    dig "@$provider" "$zone" DNSKEY +noall +answer |
        awk '$4 == "DNSKEY" {print $2; exit}'
}

assert_ttl_bounds() {
    zone_ttl=$(max_authoritative_ttl)
    key_ttl=$(dnskey_ttl)
    [ "$zone_ttl" -gt 0 ] || fail "Could not determine authoritative TTL"
    [ "$key_ttl" -gt 0 ] || fail "Could not determine DNSKEY TTL"
    [ "$zone_ttl" -le 30 ] || fail "Authoritative TTL exceeds lab maximum: $zone_ttl"
    [ "$key_ttl" -le 30 ] || fail "DNSKEY TTL exceeds lab maximum: $key_ttl"
}

ordinary_signature_tags() {
    dig "@$provider" "$zone" AXFR +dnssec |
        awk '$4 == "RRSIG" && $5 != "DNSKEY" && $5 != "CDS" && $5 != "CDNSKEY" && $5 != "TYPE65534" {print $11}' |
        sort -n -u
}

verify_all_ordinary_signed_by() {
    wanted=$1
    dig "@$provider" "$zone" AXFR +dnssec |
        awk -v wanted="$wanted" '
            /^;/ || NF < 4 {next}
            $4 == "RRSIG" {
                if ($5 != "DNSKEY" && $5 != "CDS" && $5 != "CDNSKEY" && $5 != "TYPE65534" && $11 == wanted)
                    signed[$1 "|" $5] = 1
                next
            }
            $4 != "DNSKEY" && $4 != "CDS" && $4 != "CDNSKEY" && $4 != "TYPE65534" {
                data[$1 "|" $4] = 1
            }
            END {
                missing=0
                for (item in data) if (!signed[item]) {
                    print "Missing ZSK " wanted " signature for " item > "/dev/stderr"
                    missing=1
                }
                exit missing
            }
        '
}

wait_for_zsk_set() {
    expected=$1
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        if [ "$(zsk_tags | csv)" = "$expected" ]; then return 0; fi
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for ZSK set $expected"
}

wait_for_all_new_signatures() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        if verify_all_ordinary_signed_by "$NEW_ZSK_TAG"; then return 0; fi
        rndc_provider sign "$zone" >/dev/null 2>&1 || true
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for successor ZSK to sign every ordinary RRset"
}

wait_for_old_signatures_to_leave() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        tags=$(ordinary_signature_tags)
        if verify_all_ordinary_signed_by "$NEW_ZSK_TAG" && ! echo "$tags" | contains_line "$OLD_ZSK_TAG"; then
            return 0
        fi
        rndc_provider sign "$zone" >/dev/null 2>&1 || true
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for predecessor ZSK signatures to expire"
}

refresh_zone_data() {
    ttl=$1
    nsupdate -k "$control_key" <<EOF
server $provider 53
zone $zone
update delete victim.test. NS
update add victim.test. $ttl IN NS ns.victim.test.
update delete victim.test. A
update add victim.test. $ttl IN A 192.0.2.10
update delete ns.victim.test. A
update add ns.victim.test. $ttl IN A 172.30.0.12
update delete www.victim.test. A
update add www.victim.test. $ttl IN A 192.0.2.10
update add a.victim.test. $ttl IN TXT "zsk-rollover-marker"
update add t.victim.test. $ttl IN TXT "zsk-rollover-marker"
update add z.victim.test. $ttl IN TXT "zsk-rollover-marker"
send
EOF
    nsupdate -k "$control_key" <<EOF
server $provider 53
zone $zone
update delete a.victim.test. TXT
update delete t.victim.test. TXT
update delete z.victim.test. TXT
send
EOF
}

record_state() {
    phase=$1
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    zsk=$(zsk_tags | csv)
    signers=$(ordinary_signature_tags | csv)
    if dig "@$unbound" www.victim.test. A +dnssec +noall +comments +answer |
        grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]'; then ad=true; else ad=false; fi
    line=$(printf '{"timestamp":"%s","run_id":"%s","scenario":"legitimate-zsk-rollover","phase":"%s","ksk_tag":"%s","zsk_tags":"%s","ordinary_rrsig_tags":"%s","parent_ds_tag":"%s","ad":%s}' \
        "$timestamp" "$RUN_ID" "$phase" "$BASE_KSK_TAG" "$zsk" "$signers" "$BASE_KSK_TAG" "$ad")
    echo "$line" | tee -a "$events_file"
}

establish_baseline() {
    load_state
    [ "$PHASE" = "split-prepared" ] || fail "Expected split-prepared phase, found $PHASE"
    wait_for_zsk_set "$OLD_ZSK_TAG"
    [ "$(ordinary_signature_tags)" = "$OLD_ZSK_TAG" ] || fail "Initial ordinary RRsets are not signed only by the ZSK"
    assert_ttl_bounds
    assert_invariants
    save_state split-baseline
    record_state split-baseline
}

begin() {
    load_state
    [ "$PHASE" = "split-baseline" ] || fail "begin requires split-baseline; found $PHASE"
    new_file=$(dnssec-keygen -q -K /zsk-state/current/keys -a ECDSAP256SHA256 -n ZONE -L 30 -P now -A none "$zone")
    NEW_ZSK_TAG=$(printf '%s' "$new_file" | sed 's/.*+0*//')
    chown bind:bind "/zsk-state/current/keys/$new_file.key" "/zsk-state/current/keys/$new_file.private"
    rndc_provider loadkeys "$zone"
    expected=$(printf '%s\n%s\n' "$OLD_ZSK_TAG" "$NEW_ZSK_TAG" | sort -n | csv)
    wait_for_zsk_set "$expected"
    assert_invariants
    save_state new-zsk-published
    record_state new-zsk-published
    echo "OLD_ZSK_TAG=$OLD_ZSK_TAG"
    echo "NEW_ZSK_TAG=$NEW_ZSK_TAG"
}

activate() {
    load_state
    [ "$PHASE" = "new-zsk-published" ] || fail "activate requires new-zsk-published; found $PHASE"
    new_key=$(key_file "$NEW_ZSK_TAG")
    dnssec-settime -A now "$new_key" >/dev/null
    chown bind:bind "${new_key%.key}.key" "${new_key%.key}.private"
    rndc_provider loadkeys "$zone"
    refresh_zone_data 29
    wait_for_all_new_signatures
    refresh_zone_data 30
    wait_for_all_new_signatures
    assert_ttl_bounds
    assert_invariants
    save_state zsk-signature-overlap
    record_state zsk-signature-overlap
}

retire() {
    load_state
    [ "$PHASE" = "zsk-signature-overlap" ] || fail "retire requires zsk-signature-overlap; found $PHASE"
    verify_all_ordinary_signed_by "$NEW_ZSK_TAG" || fail "Successor does not yet cover every ordinary RRset"
    old_key=$(key_file "$OLD_ZSK_TAG")
    dnssec-settime -I now "$old_key" >/dev/null
    chown bind:bind "${old_key%.key}.key" "${old_key%.key}.private"
    rndc_provider loadkeys "$zone"
    refresh_zone_data 29
    wait_for_old_signatures_to_leave
    refresh_zone_data 30
    wait_for_old_signatures_to_leave
    assert_ttl_bounds
    zone_ttl=$(max_authoritative_ttl)
    key_ttl=$(dnskey_ttl)
    safety_ttl=$zone_ttl
    [ "$key_ttl" -le "$safety_ttl" ] || safety_ttl=$key_ttl
    RETIRE_SAFE_AFTER=$(( $(date +%s) + safety_ttl + 5 ))
    assert_invariants
    save_state old-zsk-retired
    record_state old-zsk-retired
    echo "cache_safe_after=$RETIRE_SAFE_AFTER ttl=$safety_ttl margin=5"
}

complete() {
    load_state
    [ "$PHASE" = "old-zsk-retired" ] || fail "complete requires old-zsk-retired; found $PHASE"
    attempts=0
    while [ "$(date +%s)" -lt "$RETIRE_SAFE_AFTER" ]; do
        verify_all_ordinary_signed_by "$NEW_ZSK_TAG" || fail "Successor signature coverage regressed during cache wait"
        if ordinary_signature_tags | contains_line "$OLD_ZSK_TAG"; then
            fail "Predecessor signature reappeared during cache wait"
        fi
        assert_invariants
        attempts=$((attempts + 1))
        [ "$attempts" -lt 90 ] || fail "Cache-safety wait exceeded bound"
        sleep 1
    done
    old_key=$(key_file "$OLD_ZSK_TAG")
    dnssec-settime -D now "$old_key" >/dev/null
    chown bind:bind "${old_key%.key}.key" "${old_key%.key}.private"
    rndc_provider loadkeys "$zone"
    wait_for_zsk_set "$NEW_ZSK_TAG"
    verify_all_ordinary_signed_by "$NEW_ZSK_TAG" || fail "Final ordinary signature coverage is incomplete"
    assert_ttl_bounds
    assert_invariants
    save_state complete
    record_state complete
}

status() {
    load_state
    echo "phase=$PHASE run_id=$RUN_ID ksk=$BASE_KSK_TAG old_zsk=$OLD_ZSK_TAG new_zsk=$NEW_ZSK_TAG"
    record_state status
}

case "${1:-}" in
    establish-baseline) establish_baseline ;;
    begin) begin ;;
    activate) activate ;;
    retire) retire ;;
    complete) complete ;;
    status) status ;;
    phase) load_state; echo "$PHASE" ;;
    events) [ -f "$events_file" ] && cat "$events_file" || true ;;
    *) fail "Usage: rollover.sh {establish-baseline|begin|activate|retire|complete|status|phase|events}" ;;
esac
