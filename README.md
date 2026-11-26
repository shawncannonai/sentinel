# Sentinel

A security patrol for people who run their own infrastructure. It looks for the
things that actually go wrong on a working machine — a credential committed
months ago and still live, a service quietly listening on every interface, a
file that should never have been tracked — and then it fixes what it safely can.

It is built around one idea: **a finding that is only reported is not done.**

## Why another scanner

Most scanners tell you about a secret in your working tree. That is the easy
half. The hard half is the secret you removed from the working tree six weeks
ago that is still sitting in pushed history, still valid at the vendor, and
still cloneable by anyone with repo access. Sentinel scans **git history**, not
just the checkout, and it checks whether what it finds is still live.

The other half is honesty about what a finding means. "Bound to 0.0.0.0" is not
a severity by itself: behind a firewall that drops the port it is housekeeping,
and on a network the OS calls PUBLIC with a matching allow rule it is a stranger
on your machine. Sentinel asks the firewall, and grades accordingly.

## What it checks

| Stage | What it answers |
|---|---|
| `01_secrets` | Credentials in the working tree **and in pushed git history**, with a live-or-dead check against the vendor. Reports fingerprints, never key material. |
| `02_exposure` | What is listening, on which interfaces, and whether the firewall would actually let a stranger reach it — including the network's Public/Private category. |
| `03_hygiene` | Files that are tracked and should not be; the shapes that carry secrets into commits. |
| `04_compliance` | A SOC 2 readiness read against `controls.json`, scored from evidence rather than asserted. |

## Fixing, not just reporting

`fix/remediate.py` sorts every remediation into three tiers, and the tier is a
property of **the fix**, not of the severity. A critical can be AUTO and a low
can be OWNER.

- **AUTO** — safe, reversible, no credential, no restart. Applied immediately,
  backup written first, logged.
- **STAGED** — correct and known, but it stops a service or rewrites history.
  The exact command is printed with its rollback. Never run automatically.
- **OWNER** — needs a vendor console, an elevated shell, or a decision about
  money or risk. Emitted with the context needed to act.

The AUTO tier runs on every patrol, which means it also **repairs drift**: delete
the `.gitignore` line it added and tomorrow's run puts it back, rather than
opening a finding nobody reads.

## Design notes worth reading

The comments in this codebase record real failures. A sample:

- **`UNKNOWN` is not `none`.** A PowerShell timeout once returned "no firewall
  rules found", which read as *safe* on the one machine where the rules existed
  and the network was public. Unknown and none now have different return values.
- **Unpriced is not zero.** Anything that could not be measured is a hole in the
  measurement, never a zero in the total.
- **Verify the reporting, not just the code.** A `--fast` flag once dropped the
  pushed-history stage and the screen cheerfully showed 0 criticals. Empty
  because nothing was wrong and empty because nothing looked are the same
  picture; the state file now says which.
- **A self-probe proves nothing.** Connecting to your own LAN address from the
  same host loops back internally and never crosses the firewall. Reachability
  has to be reasoned from the rules.

## Getting started

```
cp config.example.json config.json     # edit: point it at your repos
python run.py                          # full patrol, ~7 min with history
python run.py --fast                   # skip pushed history for a re-check
python fix/remediate.py                # show what it would fix
python fix/remediate.py --apply        # apply the AUTO tier
```

`allow.json` records accepted risks. An accepted finding is **still counted on
the screen** — accepting is not hiding — and every entry needs a reason saying
how it was verified.

## What this is not

It is not a replacement for a real security programme, a pentest, or a vendor
scanner with a threat-intel feed. It is the patrol a solo operator can actually
run every morning, that tells the truth about what it did and did not check.

## Licence

MIT. Use it, fork it, tell me what it missed.
