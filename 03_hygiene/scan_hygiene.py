"""Host and repository hygiene: the boring controls an auditor asks about first.

    python scan_hygiene.py

Measured, per item, with the PowerShell cmdlet that owns the fact:
  Defender real-time protection and signature age   Get-MpComputerStatus
  Firewall on for every profile                     Get-NetFirewallProfile
  Disk encryption on C:                             Get-BitLockerVolume (may need admin; reported as unknown, not as ok)
  Last Windows update install                       Get-HotFix
  Repos: .env or state/ or *.sqlite tracked by git; repos dirty for a long time
  Backups: the newest file under any */state/backups is younger than 7 days

"Unknown" is a valid answer and is reported as such. It is never rounded to ok.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _common import SCAN_ROOTS, emit, finding, git_repos, powershell, run, should_skip  # noqa: E402

PS_HOST = r"""
$o = [ordered]@{}
try { $m = Get-MpComputerStatus; $o.defender_rt = $m.RealTimeProtectionEnabled; $o.sig_age_days = $m.AntivirusSignatureAge } catch { $o.defender_rt = $null }
try { $o.firewall = @(Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled} }) } catch { $o.firewall = $null }
try { $b = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop; $o.bitlocker = $b.ProtectionStatus.ToString(); $o.bitlocker_pct = $b.EncryptionPercentage } catch { $o.bitlocker = 'unknown' }
try { $h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; $o.last_hotfix = $h.InstalledOn.ToString('yyyy-MM-dd') } catch { $o.last_hotfix = $null }
$o | ConvertTo-Json -Compress -Depth 4
"""


def host_facts() -> dict:
    rc, out = powershell(PS_HOST, timeout=90)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return {"error": f"powershell rc={rc}"}


PUBLIC_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_")


def public_build_env(path: Path) -> bool:
    """A .env holding only VITE_/NEXT_PUBLIC_ style vars is public by design: those
    values are compiled into the browser bundle, so committing them leaks nothing.
    Verified 2026-09-06 on a web app's .env.production (API URL, Google client
    id) and another app's .env (Supabase URL and publishable key, where RLS
    is the real boundary). Flagging them trains the reader to ignore the report."""
    try:
        lines = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines()]
    except OSError:
        return False
    assigns = [l for l in lines if "=" in l and not l.startswith("#")]
    return bool(assigns) and all(l.split("=", 1)[0].strip().startswith(PUBLIC_PREFIXES) for l in assigns)


def repo_facts(repo: Path) -> dict:
    rc, files = run(["git", "ls-files"], cwd=repo, timeout=60)
    tracked = files.split("\n") if rc == 0 else []
    bad = [f for f in tracked
           if (f.endswith(".env") or "/.env" in f or f.startswith(".env")
               or f.endswith((".sqlite", ".sqlite3", ".db")) or f.startswith("state/") or "/state/" in f)
           and not any(w in f.lower() for w in ("example", "sample", "template"))
           and not public_build_env(repo / f)]
    rc, status = run(["git", "status", "--porcelain"], cwd=repo, timeout=60)
    dirty = len([l for l in status.split("\n") if l.strip()]) if rc == 0 else -1
    rc, last = run(["git", "log", "-1", "--format=%cs"], cwd=repo, timeout=20)
    rc2, remote = run(["git", "remote"], cwd=repo, timeout=20)
    return {"repo": repo.name, "tracked_sensitive": bad[:20], "dirty": dirty,
            "last_commit": last.strip() or None, "remote": bool(remote.strip())}


def newest_backup_age_days() -> float | None:
    """Age of the real backup, which is the offsite one.

    The first version scanned `*/state/backups` and reported "35 days". Those two
    directories hold hand-made snapshots taken before August migrations; treating
    them as the backup meant the finding understated the problem, which was that
    no backup job existed at all. The authority is now `ops/backup`'s manifest,
    and a run that copied nothing is caught by its own row counts, not by this."""
    manifest = Path("<REPO_ROOT>/backup/state/last_backup.json")
    if manifest.exists():
        try:
            d = json.loads(manifest.read_text(encoding="utf-8"))
            ts = datetime.fromisoformat(d["as_of"])
            if d["totals"]["failed"]:
                return 999.0            # a failing backup is worse than an old one
            return (datetime.now(timezone.utc) - ts).total_seconds() / 86400
        except Exception:
            return None
    return None


def main() -> int:
    findings = []
    host = host_facts()
    if host.get("defender_rt") is False:
        findings.append(finding("hygiene", "high", "Defender real-time protection is off", "host",
                                "Get-MpComputerStatus.RealTimeProtectionEnabled = False",
                                "turn it on in Windows Security", control="CC6.8"))
    if (host.get("sig_age_days") or 0) > 3:
        findings.append(finding("hygiene", "medium", "Defender signatures are stale", "host",
                                f"{host['sig_age_days']} days old", "run Update-MpSignature", control="CC6.8"))
    for fw in host.get("firewall") or []:
        if not fw.get("enabled"):
            findings.append(finding("hygiene", "high", f"firewall off for the {fw['name']} profile", "host",
                                    "Get-NetFirewallProfile shows Enabled=False",
                                    "Set-NetFirewallProfile -Profile <name> -Enabled True", control="CC6.6"))
    bl = host.get("bitlocker")
    if bl == "Off":
        findings.append(finding("hygiene", "high", "C: is not encrypted", "host",
                                "BitLocker ProtectionStatus=Off on a laptop that travels through three countries",
                                "enable BitLocker; back the recovery key up to the vault, not to a Microsoft account",
                                control="CC6.1"))
    elif bl == "unknown":
        findings.append(finding("hygiene", "info", "disk encryption state unknown", "host",
                                "Get-BitLockerVolume needs an elevated shell",
                                "run scan_hygiene.py once from an admin PowerShell and record the answer in evidence/",
                                control="CC6.1"))
    lh = host.get("last_hotfix")
    if lh:
        age = (datetime.now() - datetime.strptime(lh, "%Y-%m-%d")).days
        if age > 45:
            findings.append(finding("hygiene", "medium", "Windows updates are behind", "host",
                                    f"last hotfix installed {lh} ({age} days ago)", "install pending updates", control="CC7.1"))
    repos = [repo_facts(r) for r in git_repos()]
    for r in repos:
        if r["tracked_sensitive"]:
            sev = "high" if r["remote"] else "medium"
            findings.append(finding("hygiene", sev, "sensitive paths tracked by git", r["repo"],
                                    "tracked: " + ", ".join(r["tracked_sensitive"][:6]),
                                    "git rm --cached them, add to .gitignore, and if a remote exists treat contents as leaked",
                                    control="CC6.1"))
        if r["dirty"] > 40:
            findings.append(finding("hygiene", "low", f"{r['dirty']} uncommitted paths", r["repo"],
                                    f"last commit {r['last_commit']}", "commit or discard; a month of drift is how Lovable and GitHub diverged",
                                    control="CC8.1"))
    age = newest_backup_age_days()
    if age is None:
        findings.append(finding("hygiene", "high", "no verified backup", "ops/backup/state/last_backup.json",
                                "ops/backup has never written a manifest, or the last run failed",
                                "run ops/backup/backup.py and check the Ops-Backup scheduled task", control="A1.2"))
    elif age > 7:
        findings.append(finding("hygiene", "medium", "newest backup is old", "ops/backup",
                                f"{age:.1f} days", "check the backup task is still scheduled and writing", control="A1.2"))
    return emit("hygiene", findings, {"host": host, "repos": repos, "backup_age_days": age})


if __name__ == "__main__":
    sys.exit(main())
