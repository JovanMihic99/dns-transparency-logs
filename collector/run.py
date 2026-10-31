"""LoKey collector loop: poll watched domains, diff, emit events (spec sections 3 and 4).

Each event ({"observation", "assessment"}, spec section 4) is appended to --out as a local
backup (JSON Lines) and POSTed to P3's log at --log-url. The last snapshot per domain is
saved to --state, so a restart resumes from the last known state instead of re-baselining.
Run from the repo root:  python -m collector.run victim.test --log-url http://127.0.0.1:5000/events
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from collector.snapshot import CollectorError, diff, take_snapshot_live

DS_CHANGES = {"DS_ADDED", "DS_REMOVED", "DS_ALL_REMOVED", "DS_REPLACED"}
STATE_FIELDS = ("domain", "observed_at", "ns", "ds", "dnskey", "cds")


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


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def post(event_json, url):
    req = urllib.request.Request(url, data=event_json.encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            log(f"[log] {r.status} {r.read(300).decode(errors='replace')}")
    except urllib.error.HTTPError as e:
        log(f"[log] HTTP {e.code}: {e.read(300).decode(errors='replace')}")
    except urllib.error.URLError as e:
        log(f"[log] unreachable ({e.reason}); event kept in the local file")
    except Exception as e:  # e.g. a raw timeout: never let the log kill the collector
        log(f"[log] failed ({e!r}); event kept in the local file")


def emit(event, out_path, log_url):
    line = json.dumps(event, sort_keys=True, ensure_ascii=False)
    try:
        with open(out_path, "a", encoding="utf-8") as f:  # local backup
            f.write(line + "\n")
    except OSError as e:  # a broken backup must not stop the event reaching the log
        log(f"[backup] cannot write {out_path}: {e}")
    print(line, flush=True)
    if log_url:
        post(line, log_url)


def load_state(path):
    """Last saved snapshot per domain (spec fields only), or {} if there is none."""
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log(f"[state] WARNING: cannot read {path} ({e}); starting with fresh baselines")
        return {}
    for domain, snap in state.items():
        log(f"[resume] {domain} ns={snap['ns']} ds={[d.split()[0] for d in snap['ds']]} "
            f"(last seen {snap['observed_at']})")
    return state


def save_state(path, last):
    data = {d: {k: s[k] for k in STATE_FIELDS} for d, s in last.items()}
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True, ensure_ascii=False)
        os.replace(tmp, path)  # atomic: never leaves a half-written state file
    except OSError as e:
        log(f"[state] WARNING: cannot save {path}: {e}")


def main():
    p = argparse.ArgumentParser(description="LoKey collector loop")
    p.add_argument("domains", nargs="+", help="domains to watch, e.g. victim.test")
    p.add_argument("--tld", default=os.environ.get("LOKEY_TLD_IP", "172.30.0.11"))
    p.add_argument("--interval", type=float, default=10.0, help="seconds between polls (spec: 10)")
    p.add_argument("--out", default=os.environ.get("LOKEY_EVENTS", "events.jsonl"))
    p.add_argument("--log-url", default=os.environ.get("LOKEY_LOG_URL", ""),
                   help="P3's log endpoint, e.g. http://127.0.0.1:5000/events (empty = file only)")
    p.add_argument("--state", default=os.environ.get("LOKEY_STATE", "collector_state.json"),
                   help="file with the last snapshot per domain, survives restarts")
    args = p.parse_args()

    last = load_state(args.state)
    log(f"watching {args.domains} via tld {args.tld}, every {args.interval}s "
        f"-> {args.out}" + (f" + {args.log_url}" if args.log_url else "") + f", state {args.state}")
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
            if obs:
                emit({"observation": obs, "assessment": assess(obs)}, args.out, args.log_url)
            last[domain] = snap
            save_state(args.state, last)  # after emit: a crash re-sends, never loses, the event
        time.sleep(max(0.0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped")