#!/bin/sh
set -eu

provider=172.30.0.12
tld=172.30.0.11
unbound=172.30.0.14
zone=victim.test.
control_key=/opt/lab/rollover-control.key
state_file=/state/current.env
events_file=/state/events.jsonl
RUN_ID=none

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

rndc_provider() {
    rndc -s "$provider" -p 953 -k "$control_key" "$@"
}

child_tags() {
    dig "@$provider" "$zone" DNSKEY +noall +answer |
        dnssec-dsfromkey -2 -f - "$zone" 2>/dev/null |
        awk '{print $4}' | sort -n -u
}

parent_tags() {
    dig "@$tld" "$zone" DS +short | awk '{print $1}' | sort -n -u
}

signature_tags() {
    covered=$1
    dig "@$provider" "$zone" "$covered" +dnssec +noall +answer |
        awk -v covered="$covered" '$4 == "RRSIG" && $5 == covered {print $11}' |
        sort -n -u
}

csv() {
    awk 'BEGIN { first=1 } { if (!first) printf ","; printf "%s", $0; first=0 } END { print "" }'
}

contains_line() {
    needle=$1
    grep -qx "$needle"
}

assert_ad() {
    answer=$(dig "@$unbound" www.victim.test. A +dnssec +noall +comments +answer)
    echo "$answer" | grep -q 'status: NOERROR' || fail "Unbound did not return NOERROR"
    echo "$answer" | grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]' || fail "Unbound did not return AD=true"
    echo "$answer" | grep -Eq 'www\.victim\.test\..*A[[:space:]]+192\.0\.2\.10' ||
        fail "Unbound did not return the provider address"
}

load_state() {
    [ -s "$state_file" ] || fail "No rollover is in progress; run begin first"
    # The file is generated locally using numeric values and fixed phase names.
    . "$state_file"
    RUN_ID=${RUN_ID:-legacy}
}

save_state() {
    phase=$1
    tmp="$state_file.tmp"
    {
        echo "OLD_TAG=$OLD_TAG"
        echo "NEW_TAG=$NEW_TAG"
        echo "PHASE=$phase"
        echo "RUN_ID=$RUN_ID"
    } > "$tmp"
    mv "$tmp" "$state_file"
    PHASE=$phase
}

record_state() {
    phase=$1
    dnskeys=$(child_tags | csv)
    parent_ds=$(parent_tags | csv)
    dnskey_signers=$(signature_tags DNSKEY | csv)
    a_signers=$(signature_tags A | csv)
    if dig "@$unbound" www.victim.test. A +dnssec +noall +comments +answer |
        grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]'; then
        ad=true
    else
        ad=false
    fi
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    line=$(printf '{"timestamp":"%s","run_id":"%s","scenario":"legitimate-double-ksk-rollover","phase":"%s","dnskey_tags":"%s","parent_ds_tags":"%s","dnskey_rrsig_tags":"%s","a_rrsig_tags":"%s","ad":%s}' \
        "$timestamp" "$RUN_ID" "$phase" "$dnskeys" "$parent_ds" "$dnskey_signers" "$a_signers" "$ad")
    echo "$line" | tee -a "$events_file"
}

past_time() {
    past=$(( $(date +%s) - 259200 ))
    date -u -d "@$past" +%Y%m%d%H%M%S
}

wait_for_two_keys() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        tags=$(child_tags)
        count=$(echo "$tags" | awk 'NF {count++} END {print count+0}')
        if [ "$count" -eq 2 ] && echo "$tags" | contains_line "$OLD_TAG"; then
            NEW_TAG=$(echo "$tags" | awk -v old="$OLD_TAG" '$1 != old {print; exit}')
            [ -n "$NEW_TAG" ] && return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for old and new DNSKEYs"
}

wait_for_signature() {
    covered=$1
    key_tag=$2
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        if signature_tags "$covered" | contains_line "$key_tag"; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for key $key_tag to sign $covered"
}

wait_for_only_new_key() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        tags=$(child_tags)
        if [ "$tags" = "$NEW_TAG" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for old DNSKEY $OLD_TAG to retire"
}

wait_for_old_zone_signing_to_stop() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        status=$(rndc_provider dnssec -status "$zone")
        old_status=$(echo "$status" | awk -v tag="$OLD_TAG" '
            $1 == "key:" && $2 == tag {inside=1; next}
            $1 == "key:" && inside {exit}
            inside {print}
        ')
        if echo "$old_status" | grep -Eq 'zone signing:[[:space:]]+no'; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    fail "Timed out waiting for predecessor $OLD_TAG to stop zone signing"
}

verify_all_rrsets_signed_by() {
    key_tag=$1
    if ! dig "@$provider" "$zone" AXFR +dnssec |
        awk -v tag="$key_tag" '
            /^[;]/ || NF < 4 {next}
            $4 == "RRSIG" {
                if ($11 == tag) signed[$1 "|" $5] = 1
                next
            }
            { data[$1 "|" $4] = 1 }
            END {
                missing = 0
                for (item in data) {
                    if (!signed[item]) {
                        print "Missing successor signature for " item > "/dev/stderr"
                        missing = 1
                    }
                }
                exit missing
            }
        '; then
        fail "Successor $key_tag does not sign every authoritative RRset"
    fi
}

key_file() {
    key_tag=$1
    printf '/provider-state/keys/Kvictim.test.+013+%05d.key\n' "$key_tag"
}

advance_test_states() {
    new_key=$(key_file "$NEW_TAG")
    old_key=$(key_file "$OLD_TAG")
    [ -f "$new_key" ] || fail "Missing successor key file $new_key"
    [ -f "$old_key" ] || fail "Missing predecessor key file $old_key"

    # This is deliberate time compression for the isolated test lab. It runs
    # only after live DNS proof shows every RRset is signed by the successor.
    dnssec-settime -s -z OMNIPRESENT now "$new_key" >/dev/null
    dnssec-settime -s -z UNRETENTIVE now -k UNRETENTIVE now "$old_key" >/dev/null
    chown bind:bind "${new_key%.key}.key" "${new_key%.key}.private" "${new_key%.key}.state"
    chown bind:bind "${old_key%.key}.key" "${old_key%.key}.private" "${old_key%.key}.state"
    rndc_provider loadkeys "$zone"
}

refresh_zone_data() {
    # A one-second TTL change preserves the address while forcing replacement
    # of any long-lived signature inherited from the former policy.
    nsupdate -k "$control_key" <<EOF
server $provider 53
zone $zone
update delete victim.test. NS
update add victim.test. 29 IN NS ns.victim.test.
update delete victim.test. A
update add victim.test. 29 IN A 192.0.2.10
update delete ns.victim.test. A
update add ns.victim.test. 29 IN A 172.30.0.12
update delete www.victim.test. A
update add www.victim.test. 29 IN A 192.0.2.10
send
EOF
}

restore_zone_ttl() {
    nsupdate -k "$control_key" <<EOF
server $provider 53
zone $zone
update delete victim.test. NS
update add victim.test. 30 IN NS ns.victim.test.
update delete victim.test. A
update add victim.test. 30 IN A 192.0.2.10
update delete ns.victim.test. A
update add ns.victim.test. 30 IN A 172.30.0.12
update delete www.victim.test. A
update add www.victim.test. 30 IN A 192.0.2.10
send
EOF
}

touch_nsec_chain() {
    # The three temporary names cover the apex->ns, ns->www, and www->apex
    # lexical intervals. Separate add/delete transactions rebuild the stable
    # NSEC chain under the currently active signer set.
    nsupdate -k "$control_key" <<EOF
server $provider 53
zone $zone
update add a.victim.test. 30 IN TXT "rollover-marker"
update add t.victim.test. 30 IN TXT "rollover-marker"
update add z.victim.test. 30 IN TXT "rollover-marker"
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

begin() {
    tags=$(child_tags)
    parent=$(parent_tags)
    child_count=$(echo "$tags" | awk 'NF {count++} END {print count+0}')
    parent_count=$(echo "$parent" | awk 'NF {count++} END {print count+0}')
    [ "$child_count" -eq 1 ] || fail "Expected one stable child DNSKEY, found: $tags"
    [ "$parent_count" -eq 1 ] || fail "Expected one stable parent DS, found: $parent"
    [ "$tags" = "$parent" ] || fail "Stable child DNSKEY and parent DS key tags differ"
    assert_ad

    OLD_TAG=$tags
    NEW_TAG=0
    RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$OLD_TAG
    save_state baseline
    record_state baseline

    # Start at the real current time so BIND must expose the successor while
    # the predecessor remains present. Backdating this first step would allow
    # KASP to compress away the observable Double-KSK state.
    rndc_provider dnssec -rollover -key "$OLD_TAG" "$zone"
    wait_for_two_keys
    wait_for_signature DNSKEY "$OLD_TAG"
    save_state new-key-published
    assert_ad
    record_state new-key-published
    echo "OLD_TAG=$OLD_TAG"
    echo "NEW_TAG=$NEW_TAG"
}

ack_published() {
    load_state
    parent=$(parent_tags)
    echo "$parent" | contains_line "$OLD_TAG" || fail "Parent no longer contains old DS $OLD_TAG"
    echo "$parent" | contains_line "$NEW_TAG" || fail "Parent does not contain new DS $NEW_TAG"
    assert_ad
    record_state parent-double-ds

    rndc_provider dnssec -checkds -key "$NEW_TAG" -when "$(past_time)" published "$zone"
    wait_for_signature DNSKEY "$NEW_TAG"
    save_state new-key-active
    assert_ad
    record_state new-key-active
}

ack_withdrawn() {
    load_state
    parent=$(parent_tags)
    [ "$parent" = "$NEW_TAG" ] || fail "Parent DS must contain only new key $NEW_TAG; found: $parent"
    assert_ad
    record_state old-ds-withdrawn

    rndc_provider dnssec -checkds -key "$OLD_TAG" -when "$(past_time)" withdrawn "$zone"
    refresh_zone_data
    touch_nsec_chain
    wait_for_signature A "$NEW_TAG"
    verify_all_rrsets_signed_by "$NEW_TAG"
    advance_test_states
    wait_for_old_zone_signing_to_stop
    restore_zone_ttl
    touch_nsec_chain
    wait_for_signature A "$NEW_TAG"
    wait_for_only_new_key
    save_state complete
    assert_ad
    record_state complete
}

status() {
    if [ -s "$state_file" ]; then
        load_state
        echo "phase=$PHASE old_tag=$OLD_TAG new_tag=$NEW_TAG"
    else
        echo "phase=not-started"
    fi
    record_state status
    rndc_provider dnssec -status "$zone"
}

reconcile() {
    load_state
    tags=$(child_tags)
    parent=$(parent_tags)
    child_count=$(echo "$tags" | awk 'NF {count++} END {print count+0}')
    parent_count=$(echo "$parent" | awk 'NF {count++} END {print count+0}')
    if [ "$child_count" -eq 1 ] && [ "$parent_count" -eq 1 ] && [ "$tags" = "$parent" ]; then
        assert_ad
        rm -f "$state_file"
        record_state reset-stable
        echo "Stable single-key state confirmed; pending scenario state cleared."
        return 0
    fi
    if [ "$tags" = "$NEW_TAG" ] && [ "$parent" = "$NEW_TAG" ]; then
        save_state complete
        assert_ad
        record_state recovered-complete
        echo "Stable post-rollover state confirmed."
        return 0
    fi
    fail "Rollover is still transitional and requires the documented reset sequence"
}

case "${1:-}" in
    begin) begin ;;
    acknowledge-published) ack_published ;;
    acknowledge-withdrawn) ack_withdrawn ;;
    status) status ;;
    old-tag) load_state; echo "$OLD_TAG" ;;
    new-tag) load_state; echo "$NEW_TAG" ;;
    events) [ -f "$events_file" ] && cat "$events_file" || true ;;
    phase) if [ -s "$state_file" ]; then load_state; echo "$PHASE"; else echo not-started; fi ;;
    reconcile) reconcile ;;
    *) fail "Usage: rollover.sh {begin|acknowledge-published|acknowledge-withdrawn|status|old-tag|new-tag|events|phase|reconcile}" ;;
esac
