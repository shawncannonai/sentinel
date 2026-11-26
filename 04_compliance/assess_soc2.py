"""Score SOC 2 readiness from measured facts and dated evidence files.

    python assess_soc2.py <secrets.json> <exposure.json> <hygiene.json>
    python assess_soc2.py            (reads the last patrol's stage outputs from state/)

Every 'auto' control reads a fact another stage measured this run. Every
'evidence' control needs a file a human wrote; the file must contain a line
'reviewed: YYYY-MM-DD' under 180 days old or the control is 'stale', not
'satisfied'. The point is a readiness number that only moves when something
real moves, so that when a buyer or a customer asks "are you SOC 2 ready" the
answer is a percentage with a gap list, not a feeling.

Also regenerates evidence/vendors.json from the vault's configured secret
names: the list of everyone we hold a credential for IS the subprocessor list,
and it cannot drift because it is derived.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, "<REPO_ROOT>/_lib")
from _common import STATE, emit, finding, now_iso  # noqa: E402

CONTROLS = json.loads((HERE / "controls.json").read_text(encoding="utf-8"))["controls"]
EVIDENCE_MAX_AGE = timedelta(days=180)
JOB_ARTIFACTS = Path("<REPO_ROOT>/conductor/state/job_artifacts.json")


def load_stage(name: str, argv_path: str | None) -> dict:
    p = Path(argv_path) if argv_path else STATE / f"stage_{name}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"findings": [], "missing": True}


def vendors_from_vault() -> list[str]:
    """The subprocessor list is every credential we hold, wherever it lives.

    The first version read only the vault and reported 7 vendors. The vault held
    7 names; eight .env files held the other forty, including Stripe live, a voice
    platform, Twilio, Supabase service keys and Cloudflare. An inventory derived from
    the tidy half of the estate is worse than none, because it reads as complete.
    So: vault names, plus the variable NAMES (never values) found in .env files.
    """
    names = set()
    try:
        import secret_vault
        names |= {f"vault:{n}" for n in secret_vault.list_configured_names()}
    except Exception as e:
        names.add(f"(vault unreadable: {e})")
    for root in (Path("<REPO_ROOT>"), Path("<HOME>/projects")):
        if not root.exists():
            continue
        for env in root.rglob(".env"):
            if any(x in env.parts for x in ("node_modules", "venv", ".git", "_superseded")):
                continue
            try:
                text = env.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = env.relative_to(root.parent).as_posix()
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key = line.split("=", 1)[0].strip()
                # Price and link ids are configuration, not credentials.
                if not key or key.startswith(("STRIPE_PRICE_", "STRIPE_LINK_", "VITE_", "RETELL_FLOW_")):
                    continue
                if any(w in key for w in ("KEY", "SECRET", "TOKEN", "PASSWORD", "SID", "DB_URL", "CLIENT_ID")):
                    names.add(f"{rel}:{key}")
    return sorted(names)


def write_vendors(names: list[str]) -> Path:
    out = HERE / "evidence" / "vendors.json"
    out.parent.mkdir(exist_ok=True)
    prev = {}
    if out.exists():
        try:
            prev = {v["credential"]: v for v in json.loads(out.read_text(encoding="utf-8")).get("vendors", [])}
        except Exception:
            prev = {}
    doc = {"generated": now_iso(), "source": "secret_vault.list_configured_names()",
           "_doc": "Derived, do not hand-edit the credential column. Fill holds_customer_data / dpa / soc2 per row; those survive regeneration.",
           "vendors": [{"credential": n,
                        "holds_customer_data": prev.get(n, {}).get("holds_customer_data"),
                        "dpa": prev.get(n, {}).get("dpa"), "soc2": prev.get(n, {}).get("soc2")} for n in names]}
    out.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return out


def evidence_status(rel: str) -> tuple[str, str]:
    p = HERE / rel
    if not p.exists():
        return "gap", "no file"
    m = re.search(r"reviewed:\s*(\d{4}-\d{2}-\d{2})", p.read_text(encoding="utf-8", errors="replace"))
    if not m:
        return "stale", "file exists but has no 'reviewed: YYYY-MM-DD' line"
    d = datetime.strptime(m.group(1), "%Y-%m-%d")
    if datetime.now() - d > EVIDENCE_MAX_AGE:
        return "stale", f"last reviewed {m.group(1)}"
    return "satisfied", f"reviewed {m.group(1)}"


def sev_count(stage: dict, *sevs: str) -> int:
    return sum(1 for f in stage.get("findings", []) if f["severity"] in sevs and not f.get("accepted"))


def auto_status(key: str, s: dict, e: dict, h: dict, vendors: list[str]) -> tuple[str, str]:
    host = h.get("host", {})
    if key == "patrol_scheduled":
        try:
            ja = json.loads(JOB_ARTIFACTS.read_text(encoding="utf-8"))
            return ("satisfied", "Sentinel-Patrol registered with an artifact") if "Sentinel-Patrol" in ja else ("gap", "no job_artifacts entry")
        except Exception:
            return "gap", "job_artifacts.json unreadable"
    if key == "vendor_inventory":
        return ("satisfied", f"{len(vendors)} credentials inventoried") if vendors and not vendors[0].startswith("(") else ("gap", vendors[0] if vendors else "empty")
    if key == "no_secret_findings":
        n = sev_count(s, "critical", "high")
        return ("satisfied", "none") if n == 0 and not s.get("missing") else ("gap", f"{n} critical/high secrets findings")
    if key == "disk_encrypted":
        bl = host.get("bitlocker")
        return ("satisfied", "BitLocker on") if bl == "On" else ("gap" if bl == "Off" else "unknown", f"bitlocker={bl}")
    if key == "no_exposure_findings":
        n = sev_count(e, "critical", "high")
        return ("satisfied", "none") if n == 0 and not e.get("missing") else ("gap", f"{n} services bound to every interface")
    if key == "tunnel_tls":
        probes = e.get("probes", {})
        bad = [k for k, v in probes.items() if v.get("status") is None]
        return ("satisfied", f"{len(probes)} hostnames answer over HTTPS") if probes and not bad else ("gap", f"unreachable: {bad}" if bad else "no tunnel hostnames")
    if key == "defender_ok":
        sig = host.get("sig_age_days")
        ok = host.get("defender_rt") is True and sig is not None and sig <= 3
        return ("satisfied", "on and current") if ok else ("gap", f"rt={host.get('defender_rt')} sig_age={host.get('sig_age_days')}")
    if key == "patched":
        lh = host.get("last_hotfix")
        if not lh:
            return "unknown", "Get-HotFix gave nothing"
        age = (datetime.now() - datetime.strptime(lh, "%Y-%m-%d")).days
        return ("satisfied", f"last hotfix {lh}") if age <= 45 else ("gap", f"{age} days since a hotfix")
    if key == "job_liveness":
        try:
            ja = json.loads(JOB_ARTIFACTS.read_text(encoding="utf-8"))
            n = len([k for k in ja if not k.startswith("_")])
            return ("satisfied", f"{n} jobs verified by artifact") if n >= 5 else ("gap", f"only {n} jobs verified")
        except Exception:
            return "gap", "no job_artifacts.json"
    if key == "findings_ledger":
        return ("satisfied", "ledger present") if (STATE / "findings.jsonl").exists() else ("gap", "first patrol has not written the ledger")
    if key == "repos_committed":
        dirty = [r["repo"] for r in h.get("repos", []) if r.get("dirty", 0) > 40]
        return ("satisfied", "every repo within 40 paths of committed") if not dirty else ("gap", f"drifting: {', '.join(dirty)}")
    if key == "backups_fresh":
        age = h.get("backup_age_days")
        return ("satisfied", f"{age:.1f} days") if age is not None and age <= 7 else ("gap", f"backup age {age}")
    return "unknown", f"no evaluator for {key}"


def main() -> int:
    args = sys.argv[1:]
    s = load_stage("secrets", args[0] if len(args) > 0 else None)
    e = load_stage("exposure", args[1] if len(args) > 1 else None)
    h = load_stage("hygiene", args[2] if len(args) > 2 else None)
    vendors = vendors_from_vault()
    write_vendors(vendors)
    rows, findings = [], []
    for c in CONTROLS:
        if c["check"] == "auto":
            status, why = auto_status(c["auto"], s, e, h, vendors)
        else:
            status, why = evidence_status(c["evidence"])
        rows.append({"id": c["id"], "name": c["name"], "status": status, "why": why, "closes_with": c["closes_with"]})
        if status in ("gap", "stale"):
            findings.append(finding("compliance", "low" if c["check"] == "evidence" else "medium",
                                    f"{c['id']} {status}: {c['name']}", c.get("evidence") or c.get("auto"),
                                    why, c["closes_with"], control=c["id"]))
    sat = sum(1 for r in rows if r["status"] == "satisfied")
    score = round(100 * sat / len(rows))
    return emit("compliance", findings, {"score": score, "satisfied": sat, "total": len(rows), "controls": rows,
                                         "vendors": len(vendors)})


if __name__ == "__main__":
    sys.exit(main())
