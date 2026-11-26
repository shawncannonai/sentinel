"""Untrack secrets/state already committed to a repo, and log the exposure.

    python untrack_sensitive.py <repo_path> [<repo_path> ...]

For each repo: `git rm --cached` every tracked .env* (except .env.example),
*.sqlite/*.sqlite3/*.db, and anything under state/, appends matching ignore
patterns to .gitignore, commits 'untrack secrets/state', and pushes.

Untracking does not rewrite history. Every repo this runs against has a
GitHub remote, so anything matching these patterns that was ever added in
any branch's history already sat on that remote — this script cannot
un-leak it, only stop making it worse. Every such path (current or
historical) is logged to sentinel/state/leaked.json as LEAKED so the
patrol's SOC 2 evidence has a record; it is an append-only log, never
edited by hand.

Fixing a finding happens in the project that owns it; this is that fix,
run once per repo named by the patrol. It is not a scheduled stage.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LEAKED_FILE = Path(__file__).resolve().parents[1] / "state" / "leaked.json"

IGNORE_PATTERNS = [".env*", "!.env.example", "*.sqlite", "*.sqlite3", "*.db", "state/"]

EXEMPT_WORDS = ("example", "sample", "template")


def is_sensitive(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if any(w in name.lower() for w in EXEMPT_WORDS):
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if name.endswith((".sqlite", ".sqlite3", ".db")):
        return True
    if path == "state" or path.startswith("state/") or "/state/" in path:
        return True
    return False


def git(repo: Path, *args: str, timeout: int = 180) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", *args], cwd=str(repo), capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)
    except subprocess.TimeoutExpired:
        return -1, "timed out"
    except FileNotFoundError:
        return -2, "git not found"


def has_remote(repo: Path) -> bool:
    rc, out = git(repo, "remote")
    return rc == 0 and bool(out.strip())


def tracked_sensitive(repo: Path) -> list[str]:
    rc, out = git(repo, "ls-files")
    if rc != 0:
        return []
    return [f for f in out.splitlines() if f.strip() and is_sensitive(f)]


def historical_sensitive(repo: Path) -> set[str]:
    """Every path ever added in any branch's history, matching the sensitive
    shapes. A file untracked in an earlier run still sat in pushed history,
    so it is still a leak even though `git ls-files` no longer shows it."""
    rc, out = git(repo, "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:")
    if rc != 0:
        return set()
    return {p.strip() for p in out.splitlines() if p.strip() and is_sensitive(p.strip())}


def append_gitignore(repo: Path) -> bool:
    gi = repo / ".gitignore"
    existing = gi.read_text(encoding="utf-8", errors="replace").splitlines() if gi.exists() else []
    existing_set = {l.strip() for l in existing}
    to_add = [p for p in IGNORE_PATTERNS if p not in existing_set]
    if not to_add:
        return False
    with gi.open("a", encoding="utf-8") as fh:
        if existing and existing[-1].strip():
            fh.write("\n")
        fh.write("\n".join(to_add) + "\n")
    return True


def log_leaked(repo: Path, paths: set[str]) -> None:
    if not paths:
        return
    LEAKED_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(LEAKED_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    already = {(e["repo"], e["path"]) for e in data}
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    for p in sorted(paths):
        if (repo.name, p) in already:
            continue
        data.append({
            "repo": repo.name, "path": p, "status": "LEAKED",
            "reason": "matched a sensitive pattern and was added to a repo with a GitHub "
                      "remote; untracking does not rewrite history",
            "logged": now,
        })
    LEAKED_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fix_repo(repo: Path) -> None:
    repo = repo.resolve()
    if not (repo / ".git").exists():
        print(f"{repo.name}: not a git repo, skipping")
        return
    remote = has_remote(repo)
    now_tracked = tracked_sensitive(repo)
    for f in now_tracked:
        rc, out = git(repo, "rm", "--cached", "--", f)
        print(f"{repo.name}: git rm --cached {f} -> rc={rc}" + (f" {out.strip()[:200]}" if rc else ""))

    gi_changed = append_gitignore(repo)
    if gi_changed:
        git(repo, "add", ".gitignore")

    if now_tracked or gi_changed:
        rc, out = git(repo, "commit", "-m", "untrack secrets/state")
        print(f"{repo.name}: commit rc={rc} {out.strip()[:300]}")
    else:
        print(f"{repo.name}: nothing to untrack, .gitignore already covers it")

    if remote:
        rc, out = git(repo, "push")
        print(f"{repo.name}: push rc={rc} {out.strip()[:500]}")
        leaked = historical_sensitive(repo) | set(now_tracked)
        log_leaked(repo, leaked)
        if leaked:
            print(f"{repo.name}: logged LEAKED: {sorted(leaked)}")
    else:
        print(f"{repo.name}: no remote, skipping push and leak log")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: untrack_sensitive.py <repo_path> [<repo_path> ...]")
        return 1
    for arg in sys.argv[1:]:
        fix_repo(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
