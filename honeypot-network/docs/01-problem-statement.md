# 01 — Problem Statement

---

## 1.1 The detection problem

A defender watching network traffic faces a signal-to-noise problem that never goes away. A busy server logs millions of events a day, and somewhere in that flood are the handful that matter. Intrusion detection systems ([this project's sibling](../../intrusion-detection-system/)) work hard to separate the two, and their central difficulty is false positives: flag too much and the operator drowns; flag too little and the attack gets through.

A honeypot sidesteps the problem entirely, with one structural trick.

## 1.2 A service with no users

> A honeypot is a system with **no legitimate purpose**. Nobody should ever connect to it. So anything that does is, by definition, unauthorised.

That single property changes everything about the signal.

An intrusion detection system has to decide whether traffic to a *real* server is hostile — hard, because most of it is legitimate. A honeypot has no legitimate traffic to hide in. There is no baseline of normal activity to model, no threshold to tune, no false positives to suppress.

**Every connection is a finding.** A honeypot's output is not "here are some events, decide which are attacks" — it is "here is a list of attacks."

## 1.3 What that buys you

**Zero false positives.** Not "few". Zero, by construction. If something connected, it had no legitimate reason to.

**High-value data.** Because there is no noise, every recorded byte is worth analysing. The credentials tried against a honeypot are *exactly* the credentials attackers are trying right now — not a guess, a measurement.

**Early warning.** An attacker scanning your network will often hit the honeypot before the real target. A honeypot on an internal network that suddenly lights up means something has already gotten inside and is looking around.

**Attacker intelligence.** You learn *who* (source addresses, client fingerprints), *what* (which vulnerabilities they probe), and *how* (their tools and payloads) — from the attackers themselves, in real time.

## 1.4 Where honeypots sit among defences

A honeypot is not a replacement for anything. It is a specific instrument for a specific job.

| Defence | Job | Blind spot a honeypot fills |
|---|---|---|
| Firewall | Block unwanted connections | Says nothing about *who* tried or *what* they wanted |
| IDS/IPS | Detect attacks in real traffic | Drowns in false positives; a honeypot has none |
| Antivirus | Catch known-bad files | Reactive; a honeypot catches novel campaigns |
| SIEM | Correlate logs | A honeypot is a clean, high-value *source* for it |
| **Honeypot** | **Attract and study attackers** | — |

The honeypot's unique contribution is **intelligence about the attacker**, gathered with no noise. Everything else defends; the honeypot *listens*.

## 1.5 The two kinds of honeypot

This is the central design decision, and it is a genuine trade-off rather than a matter of quality.

### Low-interaction (this project)

Emulate services just well enough to record the attack. Fast, safe, and cannot be compromised because there is nothing behind the banner.

- **Captures:** the attacker's first move — the credential, the path, the first command.
- **Cannot capture:** anything after that, because there is nothing to break into.
- **Risk:** essentially none. It's a program that reads bytes and writes canned responses.

### High-interaction

A real operating system, usually in a VM, that an attacker can genuinely break into and use.

- **Captures:** the entire attack, including post-exploitation — what they install, where they pivot, what they exfiltrate.
- **Risk:** severe. A compromised high-interaction honeypot is a real compromised machine. It can be used to attack third parties, and **you are legally responsible for what launches from your address.** Operating one safely needs strict network containment, monitoring, and legal care.

**This project is deliberately low-interaction**, and [doc 02](02-design.md) argues that choice at length. For coursework, for an internal early-warning sensor, and for measuring what botnets are doing right now, low-interaction is the correct — and responsible — choice.

## 1.6 What this project claims

> Emulate seven commonly-attacked services convincingly enough to be probed, record and classify every interaction, and do so without ever executing attacker input or exposing the operator to risk.

### Objectives

1. Run multiple emulated services concurrently in one process. → [doc 03](03-architecture.md)
2. Capture the intelligence that matters for each protocol — credentials, paths, commands, client fingerprints. → [doc 04](04-services.md)
3. Classify raw bytes into named threats using signatures from real campaigns. → [doc 04](04-services.md)
4. Store everything queryably, and defend the store against its own input. → [doc 02](02-design.md)
5. Score and rank sessions so an operator's attention goes to the right place.
6. Never execute, never touch the filesystem, never expose by accident. → [doc 02](02-design.md)

## 1.7 Scope

| Out of scope | Why |
|---|---|
| High-interaction emulation | The operational risk is out of proportion to a study project ([doc 02](02-design.md)) |
| Being undetectable to a determined attacker | A perfect emulation is an endless arms race; Cowrie and commercial products go further |
| Automated blocking / response | Acting on honeypot data belongs in a firewall or SIEM, not the sensor |
| Threat-intel enrichment | Valuable, and a natural extension ([doc 08](08-future-work.md)) |
| Malware collection & analysis | A high-interaction concern |

## 1.8 Success criteria

- Every connection recorded with zero false positives ✅ (by construction)
- Seven services emulated concurrently in one process ✅
- Attacks classified into named threats from real signatures ✅
- The honeypot cannot be compromised through its own input ✅ (ten safety tests)
- The whole thing is demonstrable without exposing a real port ✅ (`demo`)
- A returning operator can see at a glance what happened ✅ (report + dashboard)

The fourth is the one that separates a good honeypot from a liability. A tool that processes hostile input for a living, and can be turned against its operator, is worse than not deploying one at all.

---

**Next:** [02 — Design & safety](02-design.md)
