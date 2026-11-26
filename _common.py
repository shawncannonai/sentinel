"""Shared finding shape and helpers for every sentinel stage.

A finding is one thing wrong, at one place, with one fix. Its id is stable
across runs (stage + title + where), so the ledger in state/findings.jsonl can
say first_seen / last_seen / resolved instead of re-reporting the same defect
every day as if it were new. Severity words are fixed; scripts never invent
their own.

Secrets are NEVER written anywhere by this package. A hit is identified by a
fingerprint (sha1 of the matched text, first 12 hex) so the same leak can be
acknowledged in allow.json without the secret itself appearing in any file.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
ALLOW = ROOT / "allow.json"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SCAN_ROOTS = [Path("<REPO_ROOT>"), Path("<HOME>/projects")]
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "site-packages", "__pycache__",
             "dist", "build", ".next", "instantly_exports", "_superseded", "_wt", ".cache",
             "state/backups", "backups"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fingerprint(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12]


def finding(stage: str, severity: str, title: str, where: str, detail: str, fix: str,
            control: str = "", fp: str = "") -> dict:
    assert severity in SEVERITIES, severity
    fid = hashlib.sha1(f"{stage}|{title}|{where}|{fp}".encode()).hexdigest()[:12]
    return {"id": fid, "stage": stage, "severity": severity, "title": title, "where": where,
            "detail": detail, "fix": fix, "control": control, "fp": fp}


def load_allow() -> dict:
    """allow.json: {fingerprint_or_finding_id: {"reason": ..., "by": ..., "on": ...}}.
    An entry silences a finding but the run still counts it as 'accepted' so the
    number of accepted risks is visible, never zero by omission."""
    try:
        return json.loads(ALLOW.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def apply_allow(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    allow = load_allow()
    live, accepted = [], []
    for f in findings:
        key = f["fp"] if f["fp"] in allow else (f["id"] if f["id"] in allow else None)
        if key:
            accepted.append(f | {"accepted": allow[key].get("reason", "")})
        else:
            live.append(f)
    return live, accepted


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str]:
    """Run a command, never raise; returns (rc, stdout). rc -1 = timed out."""
    try:
        r = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError:
        return -2, ""


def powershell(script: str, timeout: int = 60) -> tuple[int, str]:
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)


def git_repos() -> list[Path]:
    """Every git work tree under the scan roots, two levels deep plus client dirs."""
    out = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for d in root.iterdir():
            if d.is_dir() and (d / ".git").exists():
                out.append(d)
        for extra in (root / "client-work" / "clients",):
            if extra.exists():
                out.extend(d for d in extra.iterdir() if d.is_dir() and (d / ".git").exists())
    return out


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return True
    rel = path.as_posix()
    return "/state/backups/" in rel or "/backups/" in rel


def emit(stage: str, findings: list[dict], extra: dict | None = None) -> int:
    """Stage scripts print one JSON document so run.py can compose them, and a
    human summary to stderr so running a stage alone still tells you something."""
    doc = {"stage": stage, "as_of": now_iso(), "findings": findings} | (extra or {})
    print(json.dumps(doc, ensure_ascii=False))
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    sys.stderr.write(f"{stage}: {len(findings)} findings {by}\n")
    for f in sorted(findings, key=lambda x: SEVERITIES.index(x["severity"]))[:12]:
        sys.stderr.write(f"  [{f['severity']:8}] {f['title']}  @ {f['where']}\n")
    return 0
