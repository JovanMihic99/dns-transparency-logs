"""Dev check: live registrar hijack in P1's lab -> diff() must catch it.

Lab only (internal Docker network, .test domains). Always restores the provider.
Run from the repo root:  python -m collector.live_hijack_check
"""
import os
import subprocess
import time
from pathlib import Path

from collector.snapshot import diff, take_snapshot_live

LAB = Path(os.environ.get("LOKEY_LAB_DIR", "~/HAKATON/lab-docker/lab")).expanduser()
TLD = os.environ.get("LOKEY_TLD_IP", "172.30.0.11")
DOMAIN = "victim.test"


def registrar(cmd):
    subprocess.run(["docker", "compose", "run", "--rm", "registrar", cmd], cwd=LAB, check=True)


def show(title, obs):
    print(f"\n== {title}")
    if obs is None:
        print("no change detected")
        return
    print("changes:", obs["changes"])
    print("ns:", obs["before"]["ns"], "->", obs["after"]["ns"])
    print("ds tags:", [d.split()[0] for d in obs["before"]["ds"]],
          "->", [d.split()[0] for d in obs["after"]["ds"]])


def main():
    base = take_snapshot_live(DOMAIN, TLD)
    hijacked = None
    try:
        registrar("hijack")
        time.sleep(2)  # give the tld server a moment to re-sign the new DS
        hijacked = take_snapshot_live(DOMAIN, TLD)
        show("hijack", diff(base, hijacked))
    finally:
        registrar("restore")

    time.sleep(2)
    restored = take_snapshot_live(DOMAIN, TLD)
    if hijacked:
        show("restore", diff(hijacked, restored))
    print("\nback to baseline (ns+ds):", restored["ns"] == base["ns"] and restored["ds"] == base["ds"])


if __name__ == "__main__":
    main()