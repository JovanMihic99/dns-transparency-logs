#!/bin/sh
set -eu

state=/var/lib/bind
[ -L "$state/current" ] || {
    echo "Scenario ZSK state has not been prepared" >&2
    exit 1
}
[ -s "$state/current/db.victim.test" ] || {
    echo "Scenario zone file is missing" >&2
    exit 1
}

chown -R bind:bind "$state"
exec /usr/sbin/named -u bind -g -c /etc/bind/named.conf
