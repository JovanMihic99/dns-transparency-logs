#!/bin/sh
set -eu

tld=172.30.0.11
zone=victim.test.
source=/source-provider
target=/target
base_zone=/opt/zsk/base.zone

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

parent_ds=$(dig "@$tld" "$zone" DS +noall +answer +nosplit |
    awk '$4 == "DS" {print $5, $6, $7, toupper($8)}')
ds_count=$(echo "$parent_ds" | awk 'NF {count++} END {print count+0}')
[ "$ds_count" -eq 1 ] || fail "Expected exactly one stable parent DS, found: $parent_ds"

set -- $parent_ds
ksk_tag=$1
algorithm=$2
digest_type=$3
digest=$(printf '%s' "$4" | tr '[:lower:]' '[:upper:]')
[ "$algorithm" -eq 13 ] || fail "Expected ECDSAP256SHA256 parent DS, found algorithm $algorithm"
[ "$digest_type" -eq 2 ] || fail "Expected SHA-256 parent DS, found digest type $digest_type"

key_base=$(printf 'Kvictim.test.+013+%05d' "$ksk_tag")
source_key="$source/keys/$key_base.key"
source_private="$source/keys/$key_base.private"
[ -s "$source_key" ] || fail "Trusted KSK public file is missing: $source_key"
[ -s "$source_private" ] || fail "Trusted KSK private file is missing: $source_private"

derived=$(dnssec-dsfromkey -2 "$source_key" | awk '{print $4, $5, $6, toupper($7)}')
[ "$derived" = "$ksk_tag $algorithm $digest_type $digest" ] ||
    fail "Source key does not derive the currently trusted parent DS"

flags=$(awk '$4 == "DNSKEY" {print $5}' "$source_key")
[ "$flags" = "257" ] || fail "Source key is not an eligible flag-257 KSK/CSK"

run_base=$(date -u +%Y%m%dT%H%M%SZ)-$ksk_tag
run_id=$run_base
suffix=0
while [ -e "$target/runs/$run_id" ]; do
    suffix=$((suffix + 1))
    run_id=$run_base-$suffix
done
run_dir="$target/runs/$run_id"
mkdir -p "$run_dir/keys" "$target/scenario"
cp "$base_zone" "$run_dir/db.victim.test"
cp "$source_key" "$source_private" "$run_dir/keys/"

ksk_file="$run_dir/keys/$key_base.key"
dnssec-settime -P now -A now -I none -D none "$ksk_file" >/dev/null
zsk_file=$(dnssec-keygen -q -K "$run_dir/keys" -a ECDSAP256SHA256 -n ZONE -L 30 "$zone")
zsk_tag=$(printf '%s' "$zsk_file" | sed 's/.*+0*//')

cat > "$target/scenario/current.env" <<EOF
RUN_ID=$run_id
BASE_KSK_TAG=$ksk_tag
BASE_DS_ALGORITHM=$algorithm
BASE_DS_DIGEST_TYPE=$digest_type
BASE_DS_DIGEST=$digest
OLD_ZSK_TAG=$zsk_tag
NEW_ZSK_TAG=0
PHASE=split-prepared
RETIRE_SAFE_AFTER=0
EOF

ln -sfn "runs/$run_id" "$target/current"
chown -R bind:bind "$run_dir" "$target/scenario"
echo "Prepared isolated split-key state: KSK=$ksk_tag ZSK=$zsk_tag run_id=$run_id"
