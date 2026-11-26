#!/usr/bin/env python3
"""Does the firewall actually PERMIT what is bound, and on what kind of network?

The gap this closes. `scan_exposure` reported "bound to every interface" as a
flat high for months. That is one fact short of a decision, because a wildcard
bind behind a firewall that drops the port is a tidy-up, while the same bind on a
network Windows calls PUBLIC, with an allow rule covering it, is a live opening
to strangers. Same finding text, two very different Saturdays.

Worked example, 2026-09-07. `your-llm-proxy.py` on :9999 is an unauthenticated
proxy that spends the operator's Claude SUBSCRIPTION (it strips ANTHROPIC_API_KEY so the
CLI bills the OAuth session). It was bound to 0.0.0.0. The missing facts were
that the active network "YOUR-WIFI-SSID" is categorised PUBLIC, and that python.exe
carries an inbound TCP any-port ALLOW on the Public profile. Together those turn
a housekeeping note into a room full of strangers who can spend the subscription.

Also worth recording as a method lesson: connecting to your OWN LAN address from
the same host proves nothing. It loops back internally and never crosses the
firewall. Reachability has to be reasoned from the rules, not from a self-probe.

Read-only. Runs no netsh writes, changes no rules.
"""

from __future__ import annotations

import json
import subprocess

PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


#: Sentinel meaning "the question could not be answered", which must never be
#: confused with "the answer is none". Returning None for both made a PowerShell
#: TIMEOUT read as "no inbound allow rules", i.e. as safe, on the one machine
#: where the rules existed and the network was Public. Found 2026-09-07 when two
#: consecutive runs of the same command disagreed.
UNKNOWN = object()


def _ps(script: str, timeout: int = 240):
    try:
        r = subprocess.run(PS + [script], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return UNKNOWN
    except Exception:                                            # noqa: BLE001
        return UNKNOWN
    if r.returncode != 0:
        return UNKNOWN
    out = (r.stdout or "").strip()
    if not out:
        return []                                                # genuinely none
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return UNKNOWN


def network_categories() -> list[str]:
    """Public / Private / DomainAuthenticated per connected network."""
    d = _ps("Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Json -Compress")
    if d is UNKNOWN or d is None:
        return []
    rows = d if isinstance(d, list) else [d]
    # ConvertTo-Json serialises the NetworkCategory enum as its INTEGER, so a
    # naive read reports "YOUR-WIFI-SSID=0" and a string comparison against
    # "Public" silently fails, which flipped this whole check from critical to
    # medium on its first run. 0=Public, 1=Private, 2=DomainAuthenticated.
    names = {0: "Public", 1: "Private", 2: "DomainAuthenticated"}
    out = []
    for r in rows:
        c = r.get("NetworkCategory")
        out.append(f"{r.get('Name')}={names.get(c, c) if isinstance(c, int) else c}")
    return out


def on_public() -> bool:
    return any(c.endswith("=Public") for c in network_categories())


def allowed_inbound(proc_name: str, port: int) -> list[str]:
    """Enabled inbound ALLOW rules that would let this process serve this port.

    Two shapes both count: a rule naming the port, and the far more common one, a
    per-application rule with LocalPort 'Any' created when Windows first prompted
    about that executable. The second is why a port nobody ever opened
    deliberately can still be open.
    """
    # Built by substitution, not by f-string. The PowerShell body is full of
    # braces and dollar signs; interpolating into it produced a script that
    # returned nothing at all, which read as "no allow rules" and understated a
    # live exposure. Placeholders keep the two languages apart.
    script = (
        # One bulk fetch of each filter type, joined in memory. The previous
        # shape piped every rule through Get-NetFirewallApplicationFilter
        # individually, which took long enough to blow the timeout on some runs.
        "$r=Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -EA SilentlyContinue; "
        "$ap=@{}; Get-NetFirewallApplicationFilter -All -EA SilentlyContinue | "
        "ForEach-Object { $ap[$_.InstanceID]=$_.Program }; "
        "$po=@{}; Get-NetFirewallPortFilter -All -EA SilentlyContinue | "
        "ForEach-Object { $po[$_.InstanceID]=[string]$_.LocalPort }; "
        "$out=@(); foreach ($x in $r) { "
        "$prog=$ap[$x.InstanceID]; $port=$po[$x.InstanceID]; "
        "if (($prog -and $prog -match '@@PROC@@') -or ($port -eq '@@PORT@@')) { "
        "$out+=[pscustomobject]@{name=$x.DisplayName;profile=[string]$x.Profile;"
        "port=$port;prog=$prog} } }; "
        "$out | ConvertTo-Json -Compress"
    ).replace("@@PROC@@", proc_name).replace("@@PORT@@", str(port))
    d = _ps(script)
    if d is UNKNOWN:
        return UNKNOWN
    if not d:
        return []
    rows = d if isinstance(d, list) else [d]
    return [f"{r.get('name')} [{r.get('profile')}] port={r.get('port')}" for r in rows]


def assess(proc: str, port: int) -> dict:
    """Is a wildcard bind on this port actually reachable by a stranger?"""
    cats = network_categories()
    rules = allowed_inbound(proc, port)
    public = any(c.endswith("=Public") for c in cats)

    # Unknown is not safe. If the firewall could not be read, the finding keeps
    # the severity it would have had without this check rather than being
    # quietly downgraded by a failed query.
    if rules is UNKNOWN:
        return {"networks": cats, "public": public, "allow_rules": [],
                "verdict": "firewall rules COULD NOT BE READ, so reachability is unknown; "
                           "treating as exposed until it can be",
                "severity": "critical" if public else "high"}

    if rules and public:
        verdict, sev = "REACHABLE by other devices on a PUBLIC network", "critical"
    elif rules:
        verdict, sev = "reachable by other devices on this private network", "high"
    else:
        verdict, sev = ("bound, but no inbound allow rule was found, so the firewall "
                        "should be dropping it"), "medium"
    return {"networks": cats, "public": public, "allow_rules": rules,
            "verdict": verdict, "severity": sev}


if __name__ == "__main__":
    import sys
    proc = sys.argv[1] if len(sys.argv) > 1 else "python"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    a = assess(proc, port)
    print(f"networks : {a['networks']}")
    print(f"allow    : {a['allow_rules'] or 'none found'}")
    print(f"verdict  : {a['verdict']}  -> {a['severity']}")
