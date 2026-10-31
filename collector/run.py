"""LoKey collector loop: poll watched domains, diff, emit events (spec sections 3 and 4).

Each event is one line of JSON in the spec section 4 format ({"observation", "assessment"}),
appended to --out (default events.jsonl) and printed. P3's log reads that file.
Run from the repo root:  python -m collector.run victim.test
"""
import argparse
import json
import os
import sys
import time

from collector.snapshot import CollectorError, diff, take_snapshot_live

DS_CHANGES = {"DS_ADDED", "DS_REMOVED", "DS_ALL_REMOVED", "DS_REPLACED"}


def assess(obs):
    """PLACEHOLDER until scoring/ has rules v1. Too strict: a valid DS rollover scores high."""
    ch = set(obs["changes"])
    if ch & {"DS_REPLACED", "DS_ALL_REMOVED"} or ("NS_CHANGED" in ch and ch & DS_CHANGES):
        risk, reason = "high", "placeholder: DS replaced/removed, or NS and DS changed together"
    elif "NS_CHANGED" in ch:
        risk, reason = "medium", "placeholder: NS changed"
    else:
        risk, reason = "low", "placeholder: no DS or NS change"
    return {"risk": risk, "reasons": [reason], "rules_version": "v0-stub"}


def emit(event, path):
    line = json.dumps(event, sort_keys=True, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def main():
    p = argparse.ArgumentParser(description="LoKey collector loop")
    p.add_argument("domains", nargs="+", help="domains to watch, e.g. victim.test")
    p.add_argument("--tld", default=os.environ.get("LOKEY_TLD_IP", "172.30.0.11"))
    p.add_argument("--interval", type=float, default=10.0, help="seconds between polls (spec: 10)")
    p.add_argument("--out", default=os.environ.get("LOKEY_EVENTS", "events.jsonl"))
    args = p.parse_args()

    last = {}
    log(f"watching {args.domains} via tld {args.tld}, every {args.interval}s -> {args.out}")
    while True:
        started = time.monotonic()
        for domain in args.domains:
            try:
                snap = take_snapshot_live(domain, args.tld)
            except CollectorError as e:
                log(f"[skip] {domain}: {e}")  # never treat a failed poll as a change
                continue
            if domain not in last:
                log(f"[baseline] {domain} ns={snap['ns']} ds={[d.split()[0] for d in snap['ds']]}")
            obs = diff(last.get(domain), snap)
            last[domain] = snap
            if obs:
                emit({"observation": obs, "assessment": assess(obs)}, args.out)
        time.sleep(max(0.0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped")