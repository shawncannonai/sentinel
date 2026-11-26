"""Find credentials on disk and in pushed git history. Prints findings, never secrets.

    python scan_secrets.py            full scan, JSON on stdout, summary on stderr
    python scan_secrets.py --no-history   skip the git history pass (fast)

Severity is about BLAST RADIUS, not about the key:
  critical  the secret is in a commit that exists on a remote (already left the laptop)
  high      tracked by git in a repo that has a remote (will leave on next push)
  medium    tracked by git in a local-only repo, or a .env file (vault rule: no .env)
  low       loose on disk outside any repo

The 2026-09-06 case this exists for: a live Anthropic key was in state/.env AND in
three files already pushed on origin/account-first-onboarding. It was found by
accident while reading something else. Nothing looked for it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _common import (SCAN_ROOTS, emit, finding, fingerprint, git_repos, run,  # noqa: E402
                     should_skip)

PATTERNS = {
    "anthropic":  r"sk-ant-[A-Za-z0-9_\-]{30,}",
    "openai":     r"sk-(?:proj-)?[A-Za-z0-9]{32,}",
    "stripe":     r"[sr]k_live_[0-9A-Za-z]{24,}",
    "aws":        r"AKIA[0-9A-Z]{16}",
    "github":     r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack":      r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    "telnyx":     r"KEY[0-9A-F]{32}_[A-Za-z0-9]{20,}",
    "retell":     r"key_[0-9a-f]{32}",
    "google":     r"AIza[0-9A-Za-z_\-]{35}",
    "plaid":      r"access-(?:sandbox|development|production)-[0-9a-f\-]{36}",
    # A Twilio Account SID (AC...) is an identifier, not a secret: useless without
    # the auth token, and it appears in every Twilio code sample. Verified in
    # your-repo 2026-09-06, where the SID sat beside AUTH = ''. Only the API key
    # SID (SK...) travels with a secret worth finding.
    "twilio":     r"\bSK[0-9a-f]{32}\b",
    "sendgrid":   r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "jwt":        r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
    "privkey":    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "generic":    r"(?i:\b(?:api[_\-]?key|secret[_\-]?key|client[_\-]?secret|password|passwd|token)\b)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+=]{20,})['\"]?",
}
COMBINED = re.compile("|".join(f"(?P<{k}>{v})" for k, v in PATTERNS.items()))
# Values that match the shapes above but are not secrets. Kept short and literal.
NOISE = re.compile(r"(?i)(example|placeholder|your[_\-]?key|xxxx|changeme|<.*>|\$\{|os\.environ|getenv|get_secret|REDACTED|sk-ant-api03-\.\.\.)")
TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".md", ".txt", ".yml", ".yaml", ".toml",
            ".ini", ".cfg", ".env", ".ps1", ".sh", ".vbs", ".html", ".sql", ".csv", ".xml", ".bat", ""}
MAX_BYTES = 2_000_000


def scan_text(text: str) -> list[tuple[str, str]]:
    hits = []
    for m in COMBINED.finditer(text):
        kind = m.lastgroup
        raw = m.group(kind)
        if NOISE.search(raw) or NOISE.search(text[max(0, m.start() - 40):m.end() + 10]):
            continue
        if kind == "generic":
            val = m.group(m.lastindex) if m.lastindex else raw
            if not re.search(r"\d", val) or not re.search(r"[A-Za-z]", val):
                continue                      # a password of only letters is more likely a word
            raw = val
        hits.append((kind, fingerprint(raw)))
    return hits


def repo_for(path: Path, repos: list[Path]) -> Path | None:
    for r in sorted(repos, key=lambda p: -len(p.parts)):
        if r in path.parents:
            return r
    return None


def tracked_files(repo: Path) -> set[str]:
    rc, out = run(["git", "ls-files"], cwd=repo, timeout=60)
    return set(out.split("\n")) if rc == 0 else set()


def has_remote(repo: Path) -> bool:
    rc, out = run(["git", "remote"], cwd=repo, timeout=20)
    return rc == 0 and bool(out.strip())


def scan_disk(repos: list[Path]) -> tuple[list[dict], dict]:
    findings, stats = [], {"files": 0, "skipped_large": 0}
    tracked = {r: tracked_files(r) for r in repos}
    remote = {r: has_remote(r) for r in repos}
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or should_skip(p) or p.suffix.lower() not in TEXT_EXT:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    stats["skipped_large"] += 1
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            stats["files"] += 1
            hits = scan_text(text)
            if not hits:
                continue
            repo = repo_for(p, repos)
            rel = p.relative_to(repo).as_posix() if repo else p.as_posix()
            is_tracked = bool(repo) and rel in tracked[repo]
            is_env = p.name.startswith(".env") or p.suffix == ".env"
            if repo and is_tracked and remote[repo]:
                sev, why = "high", "tracked in a repo with a remote: leaves the laptop on the next push"
            elif repo and is_tracked:
                sev, why = "medium", "tracked in a local-only repo"
            elif is_env:
                sev, why = "medium", "a .env file: the standing rule is every key lives in _lib/secret_vault.py"
            elif repo:
                sev, why = "low", "inside a repo but untracked (gitignore is doing its job)"
            else:
                sev, why = "low", "loose on disk outside any repo"
            for kind, fp in dict.fromkeys(hits):
                findings.append(finding(
                    "secrets", sev, f"{kind} credential in {p.name}", p.as_posix(),
                    f"{why}. fingerprint {fp}.",
                    "Move it into secret_vault.py (set_secret) and delete it here; if it was ever "
                    "tracked or pushed, ROTATE it at the vendor, the scrub does not un-leak it.",
                    control="CC6.1", fp=fp))
    return findings, stats


def scan_history(repos: list[Path]) -> tuple[list[dict], dict]:
    """Only remotes matter here: a secret in local-only history has not left.
    -G runs the regex over the diff; we then re-scan the + lines so the finding
    carries the kind and fingerprint, never the value."""
    findings, stats = [], {"repos": 0, "timed_out": []}
    # git -G takes a POSIX ERE, not a Python regex: no (?:...), no (?i). The
    # first version passed the Python shapes, git rejected the regex with rc 128,
    # and the pass reported "no findings" over a repo with a known pushed key.
    rx = "|".join(v for k, v in PATTERNS.items() if k not in ("generic", "jwt")).replace("(?:", "(")
    for repo in repos:
        if not has_remote(repo):
            continue
        stats["repos"] += 1
        rc, out = run(["git", "log", "--remotes", "-p", "--diff-filter=AM", "-E", "-G", rx,
                       "--format=COMMIT %H %cs", "--", "."], cwd=repo, timeout=150)
        if rc not in (0, -1):
            findings.append(finding("secrets", "info", "history scan failed", repo.as_posix(),
                                    f"git log returned rc {rc}; the pass produced nothing and that is not a clean result",
                                    "run the command by hand and fix the regex or the repo", control="CC6.1"))
            continue
        if rc == -1:
            stats["timed_out"].append(repo.name)
            findings.append(finding("secrets", "info", "history scan timed out", repo.as_posix(),
                                    "the pushed-history pass did not finish in 150s; run it by hand",
                                    f"git -C {repo} log --remotes -p -G'<pattern>'", control="CC6.1"))
            continue
        commit = file = None
        seen = set()
        for line in out.split("\n"):
            if line.startswith("COMMIT "):
                _, commit, date = line.split(" ", 2)
            elif line.startswith("diff --git"):
                file = line.split(" b/", 1)[-1]
            elif line.startswith("+") and not line.startswith("+++"):
                for kind, fp in scan_text(line[1:]):
                    key = (file, fp)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(finding(
                        "secrets", "critical", f"{kind} credential in pushed history",
                        f"{repo.name}:{file}",
                        f"commit {commit[:10]} ({date}) exists on the remote. fingerprint {fp}. "
                        f"Deleting the file now does not remove it from history.",
                        "Rotate at the vendor today. Then either rewrite history (git filter-repo) "
                        "and force-push, or accept the repo is private and record that in allow.json.",
                        control="CC6.1", fp=fp))
    return findings, stats


def main() -> int:
    repos = git_repos()
    disk, dstats = scan_disk(repos)
    if "--no-history" in sys.argv:
        hist, hstats = [], {"skipped": True}
    else:
        hist, hstats = scan_history(repos)
    return emit("secrets", disk + hist, {"disk": dstats, "history": hstats, "repos": len(repos)})


if __name__ == "__main__":
    sys.exit(main())
