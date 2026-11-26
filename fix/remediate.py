#!/usr/bin/env python3
"""Sentinel's second job: fix what it finds.

Design note, from a real incident: "Sentinel has two jobs, he finds the problem, and then fixes
it, there's no just reporting, there's problem seeking solution driving
protocols."

This replaces the old stance in `sentinel/CLAUDE.md` that "fixing a finding
happens in the project that owns it". Reporting a finding and moving on is how
the same three criticals survived from 2026-09-06 to 2026-09-07 while a patrol
ran daily and told nobody anything new.

THREE TIERS, because "fix it" cannot mean the same thing for a .gitignore line
and for revoking a production credential.

  AUTO     safe, reversible, no credential, no restart, no data loss.
           Applied on the spot and logged. A backup is written first.
  STAGED   correct and known, but it stops a service, spends a credential, or
           rewrites history. The exact command is emitted, ready to paste, with
           its rollback beside it. Never run by this script.
  OWNER    only the operator can do it: a vendor console, an elevated shell, a
           decision about money or risk. Emitted with what he needs to know.

The tier is a property of the REMEDIATION, not of the finding's severity. A
critical can be AUTO and a low can be OWNER.

    python remediate.py              # report what it would do
    python remediate.py --apply      # apply the AUTO tier, stage the rest
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SENTINEL = HERE.parent
LOG = SENTINEL / "state" / "remediation_log.jsonl"
FKB = Path(r"C:\Users\the-operator\ops\your-repo")

AUTO, STAGED, OWNER = "AUTO", "STAGED", "OWNER"


def log(entry: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({**entry, "at": datetime.now(timezone.utc).isoformat()},
                           ensure_ascii=False) + "\n")


# --------------------------------------------------------------- AUTO fixes --

def fix_gitignore(apply: bool) -> dict:
    """Secrets and preview dumps must not be commitable in the repo that leaked.

    your-repo's .gitignore covers `state/` but not `.env` itself, and not the
    `*_preview.json` dumps that carried the Anthropic key into two commits. The
    working-tree copies are clean today; nothing stops the next dump.
    """
    gi = FKB / ".gitignore"
    want = [".env", "*.env", "*_preview.json", "*_wf.json", "*.backup.json"]
    have = gi.read_text(encoding="utf-8").splitlines() if gi.exists() else []
    missing = [w for w in want if w not in have]
    if not missing:
        return {"id": "gitignore-secrets", "tier": AUTO, "changed": False,
                "detail": "all secret patterns already ignored"}
    if apply:
        shutil.copyfile(gi, gi.with_suffix(".gitignore.bak")) if gi.exists() else None
        with gi.open("a", encoding="utf-8") as f:
            f.write("\n# Added by sentinel/fix/remediate.py 2026-09-07: these shapes\n"
                    "# carried a live Anthropic key into pushed history.\n")
            for m in missing:
                f.write(m + "\n")
    return {"id": "gitignore-secrets", "tier": AUTO, "changed": bool(apply),
            "detail": f"added {missing}" if apply else f"would add {missing}",
            "rollback": "restore .gitignore.gitignore.bak, or delete the appended block"}


PRE_COMMIT = '''#!/bin/sh
# Installed by sentinel/fix/remediate.py 2026-09-07.
# Blocks a commit that carries a credential shape. The Anthropic key that sits
# in this repo's pushed history got there through an ordinary commit; this is
# the check that would have stopped it.
# Bypass deliberately with: git commit --no-verify
if git diff --cached -U0 | grep -nE '(sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})' >/dev/null; then
  echo ""
  echo "BLOCKED: this commit contains something shaped like a live credential."
  echo "Sentinel installed this hook because a key in this repo's history is"
  echo "still live. Move it to ops/_lib/secret_vault.py and commit again."
  echo ""
  exit 1
fi
exit 0
'''


def fix_precommit(apply: bool) -> dict:
    """The class fix. A scrub cleans one file; a hook stops the next one."""
    hook = FKB / ".git" / "hooks" / "pre-commit"
    if hook.exists() and "sentinel/fix/remediate.py" in hook.read_text(
            encoding="utf-8", errors="replace"):
        return {"id": "precommit-secret-guard", "tier": AUTO, "changed": False,
                "detail": "guard already installed"}
    if apply:
        if hook.exists():
            shutil.copyfile(hook, hook.with_name("pre-commit.bak"))
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(PRE_COMMIT, encoding="utf-8", newline="\n")
    return {"id": "precommit-secret-guard", "tier": AUTO, "changed": bool(apply),
            "detail": ("installed a pre-commit credential guard" if apply
                       else "would install a pre-commit credential guard"),
            "rollback": "delete .git/hooks/pre-commit (or restore pre-commit.bak)"}


# ------------------------------------------------------- STAGED and OWNER ---

def stage_shim_restart() -> dict:
    """:9999 binds every interface; the source is already fixed, the process is old."""
    return {
        "id": "shim-9999-restart", "tier": STAGED,
        "detail": ("your-llm-proxy.py is bound to 0.0.0.0 and ::, PID predates the "
                   "loopback fix already committed in source. The active network is "
                   "PUBLIC and python.exe has an inbound any-port allow on Public, so "
                   "this is reachable by other devices on that network. It is an "
                   "unauthenticated proxy that spends the Claude SUBSCRIPTION."),
        "commands": ["taskkill /PID <pid> /F",
                     'schtasks /Run /TN "YourBackgroundService"',
                     "netstat -ano | findstr :9999   # expect ::1 only"],
        "rollback": "none needed; the previous state was the exposure. Restart the task again if it fails.",
        "why_not_auto": ("stops a running service, and automation here is blocked from "
                         "terminating processes"),
    }


def owner_key_rotation() -> dict:
    return {
        "id": "anthropic-key-rotation", "tier": OWNER,
        "detail": ("key fingerprint <fingerprint> is in 3 blobs across commits <commit> "
                   "and <commit>, both on origin/master and origin/account-first-onboarding, "
                   "AND in 3 live .env files, and the vendor returns HTTP 200. Contained: "
                   "private repo, 1 collaborator, 0 forks, 0 deploy keys."),
        "commands": ["1. issue a new key in the Anthropic console, revoke ...<fingerprint>",
                     "2. update your-repo/state/.env, another-repo/state/.env, "
                     "third-repo/state/.env in the same sitting",
                     "3. then either git filter-repo + force-push, OR record it in "
                     "sentinel/allow.json as accepted, which costs nothing once revoked"],
        "rollback": "keep the old key live until one call succeeds from each of the three services",
        "why_not_auto": "the operator's vendor console credential; nothing here can reach it",
    }


def owner_firewall() -> dict:
    return {
        "id": "python-public-allow", "tier": OWNER,
        "detail": ("python.exe and pythonw.exe each hold an inbound ALLOW for ANY port on "
                   "the PUBLIC profile. That is what turns every wildcard bind on this "
                   "machine into a live opening while on a public network, not just :9999."),
        "commands": ['# elevated PowerShell:',
                     'Get-NetFirewallRule -DisplayName "python*" -Direction Inbound '
                     '-Action Allow | Disable-NetFirewallRule',
                     '# or scope the room Wi-Fi to Private instead of Public:',
                     'Set-NetConnectionProfile -Name "YOUR-WIFI-SSID" -NetworkCategory Private'],
        "rollback": "Enable-NetFirewallRule on the same rules; reset the profile category",
        "why_not_auto": "requires an elevated shell; this session is not elevated",
    }


AUTO_FIXES = [fix_gitignore, fix_precommit]
STAGED_FIXES = [stage_shim_restart]
OWNER_FIXES = [owner_key_rotation, owner_firewall]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    print("=" * 74)
    print(f"AUTO tier {'(APPLYING)' if a.apply else '(dry run)'}")
    applied = 0
    for fn in AUTO_FIXES:
        r = fn(a.apply)
        mark = "APPLIED" if r["changed"] else ("would apply" if not r.get("changed") and a.apply is False else "no change needed")
        print(f"  [{mark:16}] {r['id']}: {r['detail']}")
        if r["changed"]:
            applied += 1
            log(r)

    print("\n" + "=" * 74)
    print("STAGED tier: correct, known, and NOT run by this script")
    for fn in STAGED_FIXES:
        r = fn()
        print(f"\n  {r['id']}  ({r['why_not_auto']})")
        print(f"  {r['detail']}")
        for c in r["commands"]:
            print(f"      {c}")
        print(f"  rollback: {r['rollback']}")

    print("\n" + "=" * 74)
    print("OWNER tier: only the operator can do these")
    for fn in OWNER_FIXES:
        r = fn()
        print(f"\n  {r['id']}  ({r['why_not_auto']})")
        print(f"  {r['detail']}")
        for c in r["commands"]:
            print(f"      {c}")
        print(f"  rollback: {r['rollback']}")

    print(f"\n{'=' * 74}\n{applied} auto fix(es) applied"
          f"{'; log at state/remediation_log.jsonl' if applied else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
