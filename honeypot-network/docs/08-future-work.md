# 08 — Limitations & Future Work

---

## 8.1 Limitations

### L1 — Low-interaction is shallow

We see the attacker's first move and nothing after. The credential, the path, the first command — captured. What they'd do once "inside" — never, because there's nothing to be inside. This is the defining trade of low-interaction ([doc 02](02-design.md)), chosen deliberately for the safety it buys.

### L2 — The emulation is detectable

A determined human can fingerprint this as a honeypot: the SSH key exchange fails, the shell vocabulary is small, banners are static, the MySQL auth response is malformed. Fine against automated attacks (nearly all of them); a careful analyst can tell.

### L3 — The demo traffic is simulated

`simulate.py` plays the attacker so the project runs without exposing a port. The connections and byte sequences are real; only the source is synthetic. Real deployment is [doc 05](05-deployment.md).

### L4 — No threat-intel enrichment

Source IPs are recorded but not cross-referenced against reputation feeds. "Someone tried root/root" is less useful than "a known Mirai node tried root/root".

### L5 — SQLite won't scale to a busy internet-facing deployment

Fine for an internal sensor or a demo; a honeypot facing the open internet at scale needs PostgreSQL and probably a write buffer.

### L6 — No real-time alerting beyond the console

The `on_event` callback exists but isn't wired to anything. A production sensor needs email/Slack/SIEM alerts on high-threat sessions.

### L7 — English/ASCII assumptions in classification

The signature patterns assume Latin-script commands and paths. Mostly fine — attack tooling is overwhelmingly ASCII — but a gap.

---

## 8.2 What to build next

### Tier 1

#### 1. Threat-intelligence enrichment

The highest-value addition. Cross-reference every source IP against reputation feeds:

```python
def enrich(ip):
    return {
        "abuseipdb_score": abuseipdb_lookup(ip),      # 0-100 abuse confidence
        "greynoise": greynoise_lookup(ip),            # "known scanner" / "malicious"
        "asn": asn_lookup(ip),                        # the network it belongs to
        "geo": geo_lookup(ip),                        # country
        "tor_exit": is_tor_exit(ip),
    }
```

This turns raw data into intelligence: "a known Mirai node from AS-12345 in country X, flagged malicious by GreyNoise, tried root/xc3511". Cache aggressively (reputation changes slowly) and degrade gracefully when a feed is down.

*Effort: 2 days. Impact: the single biggest jump in the data's usefulness.*

#### 2. SIEM / alerting integration

Wire the `on_event` callback to real outputs:

- **Syslog / CEF** export for Splunk, Elastic, a generic SIEM
- **Webhook** on any session scoring `critical`
- **Correlation hook** — flag a source IP seen here *and* against real servers

The correlation is where honeypot data earns its keep: an IP that probes the honeypot and then your production login is a far stronger signal than either alone.

*Effort: 2 days.*

#### 3. Payload capture (carefully)

When an attacker runs `wget http://.../mirai.arm`, record the URL — already done — and optionally fetch the payload **in an isolated sandbox** for analysis, never on the honeypot itself.

This is the careful edge of low-interaction: the URL is intelligence, the binary is malware. Fetching it must happen somewhere disposable, with no path back to your network. Done wrong, it's how you get infected by your own honeypot.

*Effort: 3 days, and needs real sandbox infrastructure.*

---

### Tier 2

#### 4. Deeper shell emulation

A larger command vocabulary, believable filesystem state (a fake `/etc/passwd`, a fake `/proc/cpuinfo` that matches the claimed architecture), and session continuity. This is the road toward Cowrie's level of interaction while staying safe. Closes much of L2.

#### 5. More services

SIP (VoIP fraud), SMB (ransomware and EternalBlue probing), MQTT and Modbus (industrial/IoT), VNC and RDP (remote-desktop brute force). Each is a `Service` subclass and a signature list.

#### 6. Response variation

Vary the HTTP pages, randomise banner details within believable ranges, add realistic timing jitter. Makes fingerprinting harder without moving to high-interaction.

#### 7. Attack-pattern clustering

Group sessions into campaigns — same credentials, same paths, same payload URLs, same timing — to distinguish "one botnet hitting us 10,000 times" from "10,000 distinct attackers". Turns raw volume into a picture of *who*.

#### 8. GeoIP and time-series on the dashboard

A world map of sources, attacks-over-time charts, per-campaign drill-down. The data is already there; this is presentation.

---

### Tier 3

#### 9. Distributed sensor network

Multiple honeypots reporting to one collector. A credential seen across many sensors simultaneously is an active global campaign, datable to the hour. This is what large threat-intelligence networks (like the ones behind the public breach feeds) actually do.

#### 10. Adaptive responses

Use the interaction history to respond more convincingly — if an attacker's previous commands suggest a specific botnet, tailor the fake filesystem to what that botnet expects to find. An arms race, but an interesting one.

#### 11. High-interaction tier (with real containment)

A genuinely sandboxed VM behind a low-interaction front, so promising attackers can be "promoted" into an environment where their full behaviour is observed — with strict egress filtering so the box can never attack outward. This is a serious infrastructure and legal undertaking, and the point where you must fully accept the risks [doc 02](02-design.md) describes.

---

## 8.3 Suggested order

```
Week 1   Threat-intel enrichment + SIEM export
         └── turns raw captures into actionable intelligence

Week 2   Deeper shell emulation + more services
         └── catches more, and resists fingerprinting better

Week 3   Dashboard geo/time-series + campaign clustering
         └── makes the data legible to a human at a glance

Week 4+  Distributed sensors, or a properly-contained high-interaction tier
```

---

## 8.4 If you extend this

Four things to preserve, because they're what make it safe and credible:

1. **Keep the one rule.** Nothing an attacker sends is executed, ever. Every new service, every new feature, must hold that line. The moment it breaks, this stops being a honeypot and becomes a liability.

2. **Keep the safety tests, and add to them.** Ten of the twenty-four tests exist because a honeypot that can be turned against its operator is worse than none. Every new input path is a new place for an injection or an escape — test it as hostile.

3. **Keep the localhost default.** Exposing a honeypot is a deliberate act. Never make `0.0.0.0` the default, however convenient.

4. **Keep being honest about low- vs high-interaction.** The temptation, as you add shell depth, is to let the honeypot do a little real work — resolve a real path, run a real harmless command. Don't. The line is bright for a reason: on one side is a tool, on the other is a compromised machine you're operating for the attacker.

---

**Previous:** [07 — Viva questions](07-viva-questions.md) | **Back to:** [README](../README.md)
