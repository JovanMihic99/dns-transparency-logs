#!/bin/sh
set -eu

root_server=172.30.0.10
tld_server=172.30.0.11
provider_server=172.30.0.12
marker=/trust-anchor/.chain-initialized
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

wait_for_dnskey() {
    server=$1
    zone=$2
    attempts=0
    while [ "$attempts" -lt 60 ]; do
        if dig "@$server" "$zone" DNSKEY +short | grep -q .; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    echo "Timed out waiting for DNSKEY at $zone on $server" >&2
    return 1
}

write_root_anchor() {
    anchor_tmp="$work_dir/root.key"
    dig "@$root_server" . DNSKEY +noall +answer |
        awk '$4 == "DNSKEY" && $5 == "257" { print }' > "$anchor_tmp"
    if [ ! -s "$anchor_tmp" ]; then
        echo "The private root did not publish a KSK/CSK trust anchor" >&2
        return 1
    fi
    cp "$anchor_tmp" /trust-anchor/root.key
    chmod 0644 /trust-anchor/root.key
}

ds_rdata() {
    server=$1
    zone=$2
    output=$3
    dig "@$server" "$zone" DNSKEY +noall +answer > "$output"
    dnssec-dsfromkey -2 -f "$output" "$zone" | awk '{ print $4, $5, $6, $7 }'
}

install_ds() {
    server=$1
    parent_zone=$2
    owner=$3
    rdata=$4
    key_file=$5
    nsupdate -k "$key_file" <<EOF
server $server 53
zone $parent_zone
update delete $owner DS
update add $owner 30 IN DS $rdata
send
EOF
}

wait_for_signed_ds() {
    server=$1
    owner=$2
    attempts=0
    while [ "$attempts" -lt 30 ]; do
        answer=$(dig "@$server" "$owner" DS +dnssec +noall +answer)
        if echo "$answer" | grep -Eq '[[:space:]]DS[[:space:]]' &&
           echo "$answer" | grep -Eq '[[:space:]]RRSIG[[:space:]]+DS[[:space:]]'; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    echo "Timed out waiting for the parent to sign $owner DS" >&2
    return 1
}

wait_for_dnskey "$root_server" .
wait_for_dnskey "$tld_server" test.
wait_for_dnskey "$provider_server" victim.test.
write_root_anchor

# Do not overwrite registrar state on ordinary restarts or future exercises.
if [ -f "$marker" ]; then
    echo "DNSSEC chain was already initialized; preserved existing parent data."
    exit 0
fi

test_ds=$(ds_rdata "$tld_server" test. "$work_dir/test.dnskey")
victim_ds=$(ds_rdata "$provider_server" victim.test. "$work_dir/victim.dnskey")

install_ds "$root_server" . test. "$test_ds" /opt/lab/root-bootstrap.key
install_ds "$tld_server" test. victim.test. "$victim_ds" /opt/lab/registrar.key
wait_for_signed_ds "$root_server" test.
wait_for_signed_ds "$tld_server" victim.test.

touch "$marker"
echo "Installed test. and victim.test. DS records and private-root trust anchor."

