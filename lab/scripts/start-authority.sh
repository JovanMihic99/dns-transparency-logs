#!/bin/sh
set -eu

state_dir=/var/lib/bind
zone_file=${ZONE_FILE:?ZONE_FILE must name the writable zone file}

mkdir -p "$state_dir/keys"

# Seed a new named volume once. Existing zone journals, signed state, and keys
# remain authoritative on every later restart.
if [ ! -s "$state_dir/$zone_file" ]; then
    cp /opt/lab/base.zone "$state_dir/$zone_file"
fi

chown -R bind:bind "$state_dir"
exec /usr/sbin/named -u bind -g -c /etc/bind/named.conf

