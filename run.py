"""The patrol. Runs every stage, keeps the ledger, writes what the screen shows.

    python run.py              full patrol (secrets incl. pushed history, exposure, hygiene, compliance)
    python run.py --fast       skip the git-history pass; for a quick re-check after a fix
    python run.py --print      also print the report to stdout

Outputs, all under state/:
  stage_<name>.json   raw output of each stage this run (assess_soc2 reads these)
  findings.jsonl      the ledger: one line per finding id, first_seen / last_seen / resolved_at
  sentinel.json       the summary the Conductor pane and job_liveness read

A finding that was present last run and absent this run is marked resolved
with the time, which is the audit trail an assessor wants: not "we have no
findings" but "here is every finding we ever had and when each closed".
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from _common import SEVERITIES, STATE, apply_allow, now_iso  # noqa: E402

STAGES = [
    ("secrets", HERE / "01_secrets" / "scan_secrets.py"),
    ("exposure", HERE / "02_exposure" / "scan_exposure.py"),
    ("hygiene", HERE / "03_hygiene" / "scan_hygiene.py"),
]
LEDGER = STATE / "findings.jsonl"
OUT = STATE / "sentinel.json"
#: The last FULL pushed-history result, kept so a `--fast` run cannot erase it.
HISTORY_CACHE = STATE / "last_full_history.json"


def carry_history(docs: dict, fast: bool) -> list[dict]:
    """Keep the pushed-history findings alive across a `--fast` run.

    A key in pushed history does not stop being in pushed history because this
    run skipped looking. But `--fast` writes the same `sentinel.json` the full
    patrol writes, so on 2026-09-06 a manual fast re-check at 12:59 overwrote the
    05:15 full patrol and the screen read **0 criticals** on a repo carrying four,
    including a live Anthropic key. Nothing was wrong with the scheduled run; the
    quick re-check simply erased its most important result, and the summary said
    `history_timed_out: []`, which reads as "checked, nothing wrong".

    So: a full run banks its history findings here, and a fast run reloads them
    and marks them `carried_from` the run that actually measured them. Findings
    resurface as themselves, with stable ids, so the ledger is undisturbed.
    """
    hist = [f for f in docs.get("secrets", {}).get("findings", [])
            if "pushed history" in f.get("title", "")]
    if not fast:
        HISTORY_CACHE.write_text(
            json.dumps({"as_of": now_iso(), "findings": hist}, indent=1,
                       ensure_ascii=False), encoding="utf-8")
        return []
    if not HISTORY_CACHE.exists():
        return []
    try:
        cached = json.loads(HISTORY_CACHE.read_text(encoding="utf-8"))
    except Exception:                                            # noqa: BLE001
        return []
    for f in cached.get("findings", []):
        f["carried_from"] = cached.get("as_of")
    return cached.get("findings", [])


def run_stage(name: str, script: Path, extra: list[str]) -> dict:
    r = subprocess.run([sys.executable, str(script), *extra], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=900)
    sys.stderr.write(r.stderr)
    try:
        doc = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        doc = {"stage": name, "findings": [], "error": f"rc={r.returncode}: {r.stderr[-400:]}"}
    (STATE / f"stage_{name}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    return doc


def load_ledger() -> dict:
    rows = {}
    if LEDGER.exists():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                rows[r["id"]] = r
    return rows


def update_ledger(live: list[dict], accepted: list[dict]) -> dict:
    ledger, ts = load_ledger(), now_iso()
    seen = set()
    for f in live + accepted:
        seen.add(f["id"])
        row = ledger.get(f["id"]) or {"id": f["id"], "first_seen": ts}
        row.update({k: f[k] for k in ("stage", "severity", "title", "where", "control", "fp")})
        row["last_seen"] = ts
        row["accepted"] = f.get("accepted", "")
        row.pop("resolved_at", None)
        ledger[f["id"]] = row
    for fid, row in ledger.items():
        if fid not in seen and not row.get("resolved_at"):
            row["resolved_at"] = ts
    LEDGER.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in ledger.values()) + "\n", encoding="utf-8")
    return ledger


def main() -> int:
    STATE.mkdir(exist_ok=True)
    fast = "--fast" in sys.argv
    docs = {}
    for name, script in STAGES:
        docs[name] = run_stage(name, script, ["--no-history"] if fast and name == "secrets" else [])
    # Carry BEFORE compliance runs, and fold the result back into the secrets
    # stage on disk. `assess_soc2` re-reads `state/stage_secrets.json` and scores
    # `no_secret_findings` from its critical/high count, so a fast run that kept
    # the criticals in memory but not in the file still scored the control as
    # satisfied: 3 criticals on screen next to SOC 2 86%, which is the same
    # false all-clear one layer down. One merged secrets doc means every
    # consumer sees the same findings.
    carried = carry_history(docs, fast)
    if carried:
        docs["secrets"].setdefault("findings", []).extend(carried)
        (STATE / "stage_secrets.json").write_text(
            json.dumps(docs["secrets"], indent=1, ensure_ascii=False),
            encoding="utf-8")
    docs["compliance"] = run_stage("compliance", HERE / "04_compliance" / "assess_soc2.py", [])

    all_findings = [f for d in docs.values() for f in d.get("findings", [])]
    live, accepted = apply_allow(all_findings)
    ledger = update_ledger(live, accepted)
    live.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["stage"], f["title"]))
    counts = {s: sum(1 for f in live if f["severity"] == s) for s in SEVERITIES}
    resolved = sum(1 for r in ledger.values() if r.get("resolved_at"))

    comp = docs["compliance"]
    state = {
        "as_of": now_iso(), "fast": fast,
        "counts": counts, "accepted": len(accepted), "resolved_total": resolved,
        "soc2": {"score": comp.get("score"), "satisfied": comp.get("satisfied"), "total": comp.get("total"),
                 "gaps": [r for r in comp.get("controls", []) if r["status"] != "satisfied"][:12]},
        "stage_errors": {k: d["error"] for k, d in docs.items() if d.get("error")},
        "top": [{k: f[k] for k in ("id", "severity", "stage", "title", "where", "fix")} for f in live[:20]],
        "exposure": docs["exposure"].get("wildcard_ours", []),
        "secrets_scanned_files": docs["secrets"].get("disk", {}).get("files"),
        "history_timed_out": docs["secrets"].get("history", {}).get("timed_out", []),
        # Say plainly whether the pushed-history pass actually ran this time.
        # An empty `history_timed_out` used to be the only signal, and empty
        # reads as "checked, nothing wrong" when it can equally mean "never
        # looked". Anything consuming this file must be able to tell.
        "history_scanned": not fast,
        "history_carried": len(carried),
        "history_measured_at": (None if not fast else
                                (carried[0].get("carried_from") if carried else None)),
    }
    # Sentinel's SECOND job. Design note, from a real incident: "he finds the problem, and then
    # fixes it, there's no just reporting." The AUTO tier is safe, reversible
    # and applied every patrol, which also means it REPAIRS drift: if a
    # .gitignore line or a pre-commit guard is removed, the next run puts it
    # back rather than opening a finding nobody reads. Failure here must not
    # lose the scan that just succeeded, so it cannot raise past this point.
    try:
        from fix.remediate import AUTO_FIXES
        state["auto_fixed"] = [r for fn in AUTO_FIXES
                               if (r := fn(True)).get("changed")]
    except Exception as exc:                                     # noqa: BLE001
        state["auto_fixed"] = []
        state["remediation_error"] = f"{type(exc).__name__}: {exc}"

    OUT.write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")
    if state.get("auto_fixed"):
        print(f"  auto-remediated {len(state['auto_fixed'])}: "
              + ", ".join(r["id"] for r in state["auto_fixed"]))
    if state.get("remediation_error"):
        print(f"  REMEDIATION DID NOT RUN: {state['remediation_error']}")

    print(f"sentinel {state['as_of']}  {'FAST ' if fast else ''}findings {counts}  accepted {len(accepted)}  "
          f"resolved-ever {resolved}  SOC2 {comp.get('score')}% ({comp.get('satisfied')}/{comp.get('total')})")
    if fast:
        if carried:
            print(f"  history NOT rescanned; carrying {len(carried)} pushed-history "
                  f"finding(s) measured {state['history_measured_at']}")
        else:
            print("  history NOT rescanned and nothing banked from a full run, so "
                  "pushed-history status is UNKNOWN, not clean. Run without --fast.")
    for f in live[:15]:
        print(f"  [{f['severity']:8}] {f['title']}  @ {f['where']}")
    if state["stage_errors"]:
        print("  STAGE ERRORS:", state["stage_errors"])
    # Exit 2 on anything critical so a scheduler or a shell loop can see it.
    return 2 if counts["critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
