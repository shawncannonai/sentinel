"""What is reachable from outside the laptop, and by whom.

    python scan_exposure.py

Three views, all measured, none assumed:
  1. Listening sockets. Anything of OURS (python, node, pythonw) bound to 0.0.0.0
     or :: is reachable by every device on the same Wi-Fi: hotel, cafe, airport.
     Loopback is fine. Windows system services on wildcard are inventory only.
  2. Cloudflare tunnel hostnames from ~/.cloudflared/config.yml, each probed with
     an unauthenticated GET so we know what a stranger gets. The probe is a fact,
     not a verdict: a webhook that answers 404 at / is correct.
  3. The port allowlist, exposure_allow.json: {port: reason}. A wildcard bind of
     ours is a finding unless the port is there WITH a reason.

The 2026-09-06 first run: the Claude CLI shim on :9999 (spends the subscription)
was on 0.0.0.0 alongside four other python services. Nobody had looked.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _common import emit, finding  # noqa: E402

try:
    import psutil
except ImportError:                 # the project venv has it; say so if not
    psutil = None

OURS = {"python.exe", "pythonw.exe", "node.exe", "cloudflared.exe", "ollama.exe"}
import firewall  # noqa: E402  sibling module, read-only

WILDCARD = {"0.0.0.0", "::"}
ALLOW_FILE = Path(__file__).with_name("exposure_allow.json")
CF_CONFIG = Path.home() / ".cloudflared" / "config.yml"


def listeners() -> list[dict]:
    if psutil is None:
        return []
    rows, seen = [], set()
    for c in psutil.net_connections("inet"):
        if c.status != "LISTEN" or (c.laddr.ip, c.laddr.port) in seen:
            continue
        seen.add((c.laddr.ip, c.laddr.port))
        try:
            proc = psutil.Process(c.pid)
            name, cmd = proc.name(), " ".join(proc.cmdline())[:160]
        except Exception:
            name, cmd = "?", ""
        rows.append({"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "proc": name, "cmd": cmd})
    return sorted(rows, key=lambda r: r["port"])


def tunnel_hosts() -> list[dict]:
    if not CF_CONFIG.exists():
        return []
    text = CF_CONFIG.read_text(encoding="utf-8", errors="replace")
    out, host = [], None
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"-\s*hostname:\s*(\S+)", s)
        if m:
            host = m.group(1)
            continue
        m = re.match(r"service:\s*(\S+)", s)
        if m and host:
            out.append({"host": host, "service": m.group(1)})
            host = None
    return out


def local_ip() -> str | None:
    """The address this laptop has on the Wi-Fi it is joined to, which is the
    address an attacker on the same network reaches us at. A UDP connect picks
    the right interface without sending a packet."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def probe_http(ip: str, port: int) -> dict:
    req = urllib.request.Request(f"http://{ip}:{port}/", headers={"User-Agent": "sentinel-probe"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(800).decode("utf-8", "replace")
            return {"status": r.status, "listing": "Directory listing for" in body or "Index of" in body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "listing": False}
    except Exception as e:
        return {"status": None, "error": type(e).__name__}


def probe(host: str) -> dict:
    req = urllib.request.Request(f"https://{host}/", headers={"User-Agent": "sentinel-probe"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(600).decode("utf-8", "replace")
            return {"status": r.status, "server": r.headers.get("server", ""),
                    "listing": "Index of" in body or "Directory listing" in body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "server": e.headers.get("server", ""), "listing": False}
    except Exception as e:
        return {"status": None, "error": type(e).__name__}


def main() -> int:
    try:
        allow = json.loads(ALLOW_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        allow = {}
    findings = []
    rows = listeners()
    if psutil is None:
        findings.append(finding("exposure", "info", "psutil missing, sockets not read", "python",
                                "run this with the project venv python", "pip install psutil"))
    for r in rows:
        if r["ip"] not in WILDCARD or r["proc"] not in OURS:
            continue
        reason = allow.get(str(r["port"]))
        if reason:
            continue
        # A wildcard bind is one fact short of a decision. Behind a firewall that
        # drops the port it is housekeeping; on a network Windows calls PUBLIC
        # with an allow rule covering it, strangers can reach the service. Ask
        # the firewall rather than guessing, and let the answer set the severity.
        # Added 2026-09-07 after :9999, an unauthenticated proxy that spends the
        # Claude SUBSCRIPTION, sat at a flat "high" while the laptop was on a
        # Public room Wi-Fi with python.exe allowed inbound on any port.
        fw = firewall.assess(r["proc"], r["port"])
        detail = (f"pid {r['pid']}: {r['cmd'] or '(cmdline unreadable)'}. "
                  f"Networks: {', '.join(fw['networks']) or 'unknown'}. "
                  f"Firewall: {fw['verdict']}.")
        if fw["allow_rules"]:
            detail += " Inbound allow rules: " + "; ".join(fw["allow_rules"][:3]) + "."
        findings.append(finding(
            "exposure", fw["severity"],
            f"{r['proc']} on port {r['port']} is bound to every interface",
            f"{r['ip']}:{r['port']}", detail,
            "Bind to 127.0.0.1 (cloudflared reaches localhost fine), or restart the process if "
            "the source is already fixed, or add the port to exposure_allow.json with the reason "
            "it must be public. On a Public network this is the first thing to close.",
            control="CC6.6"))
    # Probe our own wildcard-bound ports over the LAN address, exactly as a stranger
    # on the same Wi-Fi would. The bind alone was already a finding; what the port
    # SERVES is the finding that matters. On 2026-09-06 a python -m http.server left
    # running since the 3rd was serving a browsable directory listing of a
    # client proposal that was still on hold, to the whole network.
    lan = local_ip()
    probed_ports = set()
    for r in rows:
        if r["ip"] not in WILDCARD or r["proc"] not in OURS or not lan:
            continue
        # One port, one finding. A dual-stack service listens on both 0.0.0.0 and
        # ::, which is two rows and one problem.
        if r["port"] in probed_ports:
            continue
        probed_ports.add(r["port"])
        p = probe_http(lan, r["port"])
        if p.get("listing"):
            findings.append(finding(
                "exposure", "critical", f"directory listing served on the local network: port {r['port']}",
                f"{lan}:{r['port']}",
                f"GET http://{lan}:{r['port']}/ returns a browsable file index. pid {r['pid']}: {r['cmd'][:120]}. "
                f"Every device on this Wi-Fi can read those files.",
                "Stop the process. If a preview server is needed, bind it to 127.0.0.1.", control="CC6.6"))
        elif p.get("status") and p["status"] < 400:
            findings.append(finding(
                "exposure", "high", f"port {r['port']} answers on the local network",
                f"{lan}:{r['port']}",
                f"HTTP {p['status']} to an unauthenticated request from the LAN address. pid {r['pid']}: {r['cmd'][:120]}",
                "Bind to 127.0.0.1, or add the port to exposure_allow.json with the reason it must be reachable.",
                control="CC6.6"))
    hosts = tunnel_hosts()
    probes = {}
    for h in {x["host"] for x in hosts}:
        probes[h] = probe(h)
        if probes[h].get("listing"):
            findings.append(finding("exposure", "critical", "directory listing served publicly", h,
                                    "an unauthenticated GET / returned a file index",
                                    "disable autoindex on the service behind the tunnel", control="CC6.6"))
        if probes[h].get("status") is None:
            findings.append(finding("exposure", "medium", "public hostname does not answer", h,
                                    f"GET https://{h}/ failed: {probes[h].get('error')}. Either DNS is missing "
                                    f"or the tunnel is not serving it; the config routes it either way",
                                    "Root-caused for api.example.com on 2026-09-06: example.com's nameservers are at "
                                    "name.com, not Cloudflare, so its CNAME to <tunnel-id>.cfargotunnel.com can never "
                                    "resolve. A cfargotunnel CNAME only works inside a Cloudflare-hosted zone with the "
                                    "record proxied. Fix is to move the zone to Cloudflare (nameserver change at name.com), "
                                    "not to re-add the record. The frontend already routes around it via "
                                    "hook.example.com, which is why nothing looked broken.",
                                    control="CC6.7"))
        if probes[h].get("status") == 500:
            findings.append(finding("exposure", "medium", "public hostname answers 500", h,
                                    "the service behind the tunnel is erroring on a plain GET",
                                    "read the service log; a 500 at / usually means a crashed app", control="CC7.2"))
    # A tunnel hostname pointing at a port nothing listens on is a silent outage.
    open_ports = {r["port"] for r in rows}
    for x in hosts:
        m = re.search(r":(\d+)$", x["service"])
        if m and int(m.group(1)) not in open_ports:
            findings.append(finding("exposure", "medium", f"tunnel target not listening: {x['host']}",
                                    x["service"], "config.yml routes here but no process holds the port",
                                    "start the service or remove the route", control="A1.2"))
    return emit("exposure", findings, {
        "listeners": [r for r in rows if r["proc"] in OURS],
        "wildcard_ours": [f"{r['proc']}:{r['port']}" for r in rows if r["ip"] in WILDCARD and r["proc"] in OURS],
        "tunnel": hosts, "probes": probes, "allow": allow})


if __name__ == "__main__":
    sys.exit(main())
