#!/bin/sh
set -u

root_server=172.30.0.10
tld_server=172.30.0.11
provider_server=172.30.0.12
unbound_server=172.30.0.14
failures=0
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

check_dnskey_and_signature() {
    label=$1; server=$2; zone=$3
    answer=$(dig "@$server" "$zone" DNSKEY +dnssec +noall +answer)
    if echo "$answer" | grep -Eq '[[:space:]]DNSKEY[[:space:]]'; then
        pass "$label publishes DNSKEY"
    else
        fail "$label does not publish DNSKEY"
    fi
    if echo "$answer" | grep -Eq '[[:space:]]RRSIG[[:space:]]+DNSKEY[[:space:]]'; then
        pass "$label publishes an RRSIG over DNSKEY"
    else
        fail "$label does not publish an RRSIG over DNSKEY"
    fi
}

check_ds_matches_child() {
    label=$1; parent_server=$2; child_server=$3; child_zone=$4
    key_file="$work_dir/$label.dnskey"
    dig "@$child_server" "$child_zone" DNSKEY +noall +answer > "$key_file"
    expected=$(dnssec-dsfromkey -2 -f "$key_file" "$child_zone" |
        awk '{ digest=""; for (i=7; i<=NF; i++) digest=digest $i; print $4, $5, $6, digest }' | sort)
    actual=$(dig "@$parent_server" "$child_zone" DS +short |
        awk '{ digest=""; for (i=4; i<=NF; i++) digest=digest $i; print $1, $2, $3, digest }' | sort)
    if [ -n "$expected" ] && [ "$actual" = "$expected" ]; then
        pass "$label DS matches the child KSK/CSK"
    else
        fail "$label DS mismatch (expected '$expected', got '$actual')"
    fi
}

check_dnskey_and_signature "private root" "$root_server" .
check_dnskey_and_signature "test." "$tld_server" test.
check_dnskey_and_signature "victim.test." "$provider_server" victim.test.
check_ds_matches_child "test" "$root_server" "$tld_server" test.
check_ds_matches_child "victim" "$tld_server" "$provider_server" victim.test.

root_anchor=$(awk '$4 == "DNSKEY" && $5 == "257" { print $5, $6, $7, $8 }' /trust-anchor/root.key 2>/dev/null)
live_root_anchor=$(dig "@$root_server" . DNSKEY +noall +answer |
    awk '$4 == "DNSKEY" && $5 == "257" { print $5, $6, $7, $8 }')
if [ -n "$root_anchor" ] && [ "$root_anchor" = "$live_root_anchor" ]; then
    pass "Unbound trust-anchor file matches the private root KSK/CSK"
else
    fail "Unbound trust-anchor file does not match the private root"
fi

validated=$(dig "@$unbound_server" www.victim.test. A +dnssec +noall +comments +answer)
if echo "$validated" | grep -q 'status: NOERROR'; then
    pass "Unbound returns NOERROR for www.victim.test"
else
    fail "Unbound did not return NOERROR for www.victim.test"
fi
if echo "$validated" | grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]'; then
    pass "Unbound sets the AD flag"
else
    fail "Unbound response does not contain the AD flag"
fi
if echo "$validated" | grep -Eq 'www\.victim\.test\..*A[[:space:]]+192\.0\.2\.10'; then
    pass "Validated answer is 192.0.2.10"
else
    fail "Validated answer is not 192.0.2.10"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures DNSSEC check(s) failed." >&2
    exit 1
fi
echo "All DNSSEC baseline checks passed."

