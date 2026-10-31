"""LoKey collector loop: poll watched domains, diff, score, emit events (spec sections 3-5).

Each event ({"observation", "assessment"}, spec section 4) is appended to --out as a local
backup (JSON Lines) and POSTed to P3's log at --log-url. The last snapshot and the scoring
history per domain are saved to --state, so a restart resumes instead of re-baselining.
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
from scoring.rules import RULES_VERSION, empty_history, score, update_history

STATE_FIELDS = ("domain", "observed_at", "ns", "ds", "dnskey", "cds")


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


def safe_score(obs, history, snap, pre):
    """Fail safe: if scoring itself breaks, report the change as high instead of hiding it."""
    try:
        return score(obs, history, snap, pre)
    except Exception as e:
        log(f"[score] ERROR {e!r}; reporting as high")
        return {"risk": "high", "reasons": [f"scoring error: {e!r}"], "rules_version": RULES_VERSION}


def load_preannouncements(path):
    """List of {domain, new_ns, new_ds (optional), valid_until}; reread every poll."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        log(f"[pre] WARNING: cannot read {path} ({e}); ignoring pre-announcements")
        return []


def load_state(path):
    """(snapshots, histories) per domain, or ({}, {}) if there is no state file."""
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return {}, {}
    except (OSError, ValueError) as e:
        log(f"[state] WARNING: cannot read {path} ({e}); starting with fresh baselines")
        return {}, {}
    if "snapshots" in state:
        snaps, hist = state["snapshots"], state.get("history", {})
    else:  # old format: snapshots only
        snaps, hist = state, {}
    for domain, snap in snaps.items():
        log(f"[resume] {domain} ns={snap['ns']} ds={[d.split()[0] for d in snap['ds']]} "
            f"(last seen {snap['observed_at']}, history {'yes' if domain in hist else 'no'})")
    return snaps, hist


def save_state(path, last, history):
    data = {"snapshots": {d: {k: s[k] for k in STATE_FIELDS} for d, s in last.items()},
            "history": history}
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
                   help="last snapshot + scoring history per domain, survives restarts")
    p.add_argument("--preannouncements",
                   default=os.environ.get("LOKEY_PREANNOUNCEMENTS", "preannouncements.json"))
    args = p.parse_args()

    last, history = load_state(args.state)
    log(f"watching {args.domains} via tld {args.tld}, every {args.interval}s "
        f"-> {args.out}" + (f" + {args.log_url}" if args.log_url else "")
        + f", state {args.state}, scoring {RULES_VERSION}")
    while True:
        started = time.monotonic()
        pre = load_preannouncements(args.preannouncements)
        for domain in args.domains:
            try:
                snap = take_snapshot_live(domain, args.tld)
            except CollectorError as e:
                log(f"[skip] {domain}: {e}")  # never treat a failed poll as a change
                continue
            if domain not in last:
                log(f"[baseline] {domain} ns={snap['ns']} ds={[d.split()[0] for d in snap['ds']]}")
            hist = history.get(domain, empty_history())
            obs = diff(last.get(domain), snap)
            risk = None
            if obs:  # score with the history from EARLIER polls only
                assessment = safe_score(obs, hist, snap, pre)
                risk = assessment["risk"]
                emit({"observation": obs, "assessment": assessment}, args.out, args.log_url)
            try:
                history[domain] = update_history(hist, snap, risk)
            except Exception as e:
                log(f"[score] ERROR updating history for {domain}: {e!r}; keeping the old history")
            last[domain] = snap
            save_state(args.state, last, history)  # after emit: a crash re-sends, never loses
        time.sleep(max(0.0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped")


# ---------- v1.1: trust gained through a high-risk change ----------

def test_rehijack_after_restore_has_no_trail():
    prov, att = Key(), Key()
    out = feed([snap(0, PROV, [prov], [prov]),
                snap(1, ATT, [att], [att]),      # hijack
                snap(2, ATT, [att], [att]),      # attacker holds the domain for a while
                snap(3, PROV, [prov], [prov]),   # restore
                snap(4, ATT, [att], [att])])     # hijack again
    last = out[-1][1]
    assert last["risk"] == "high"
    assert "DS replaced with no trail signed by the previously trusted key" in last["reasons"]


def test_dnskey_change_signed_only_by_quarantined_key_is_medium():
    prov, att, att2 = Key(), Key(), Key()
    out = run([snap(0, PROV, [prov], [prov]),
               snap(1, ATT, [att], [att]),          # hijack
               snap(2, ATT, [att], [att, att2])])   # attacker changes "its" DNSKEY set
    assert out == [(["NS_CHANGED", "DS_REPLACED", "DNSKEY_CHANGED"], "high"),
                   (["DNSKEY_CHANGED"], "medium")]