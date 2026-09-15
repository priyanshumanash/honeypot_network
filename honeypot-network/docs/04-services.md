# 04 — The Services

*Each emulator, the real attack it catches, and how detectable it is.*

---

## 4.1 The principle

Each service imitates a real protocol just far enough to make an attacker reveal their intent, then stops. The design question for each is always: **what is the smallest emulation that captures the intelligence?**

For SSH, that's the client version string — sent before any password. For HTTP, the request line and headers. For telnet, the credentials and then the first shell command. Emulating one byte more than needed adds attack surface for no gain.

---

## 4.2 SSH (port 22)

The most attacked port on the internet, and the cheapest to emulate usefully.

```python
def greeting(self):
    return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
```

We send a version banner, read the client's banner, and then let the key exchange fail. That is enough, because **the client version string is one of the best fingerprints available and it arrives before a single password:**

| Client string | Almost always |
|---|---|
| `SSH-2.0-libssh_0.9.6` | a credential-stuffing botnet |
| `SSH-2.0-paramiko_2.11.0` | a Python script or scanner |
| `SSH-2.0-Go` | a mass scanner |
| `SSH-2.0-PuTTY_...` | an interactive Windows user |
| `SSH-2.0-OpenSSH_8.9` | a real client, or someone imitating one |

Botnets overwhelmingly use libssh, paramiko or Go clients — and they announce which before trying anything. A honeypot that captured *only* the SSH version string would still be worth running.

**Detectability:** high. A real SSH server completes key exchange; this one fails immediately. A careful attacker notices. Catching the version string first means we've already won before they can tell.

---

## 4.3 HTTP (port 80)

The richest source of intelligence here, because attackers probe web servers with **specific paths for specific vulnerabilities**, and the path names the campaign.

```python
HTTP_EXPLOIT_SIGNATURES = [
    (r"\.env",                    "environment file (credential harvesting)"),
    (r"wp-login|wp-admin",        "WordPress attack"),
    (r"\.git/",                   "exposed git repository"),
    (r"/shell|busybox",           "Mirai-family IoT worm"),
    (r"\.\./|%2e%2e",             "path traversal"),
    (r"actuator|/env\b",          "Spring Boot Actuator exposure"),
    (r"select.*from|union.*select","SQL injection attempt"),
    (r"\.aws/|credentials",       "cloud credential harvesting"),
    ...   # 14 in total
]
```

Every entry is a real, currently-active campaign. `/.env` harvests leaked framework credentials; `/actuator/env` targets a Spring Boot misconfiguration that dumps environment variables; the `busybox`/`/shell` paths are IoT worms looking for a command-injection foothold.

We record the full request — method, path, every header, User-Agent — and return a canned 404 or a fake login page. **Attacker input is never echoed into the response**, never used as a filesystem path, never rendered through a template. The path is treated as a string to classify, never as a path to open.

**Detectability:** moderate. The server always returns the same two pages and the `Server:` header never varies. Good enough to fool automated scanners, which is who sends these.

---

## 4.4 Telnet (port 23)

Where IoT botnets live. Mirai and its descendants spread almost entirely by **telnet brute force against a list of default credentials**, and a telnet honeypot fills with `root/xc3511`, `admin/admin`, `root/vizxv` within hours of exposure.

This one does something the others don't: **it lets the attacker "in" after three attempts**, so we can see what they run.

```python
if attempts >= 3:
    state["stage"] = "shell"
    return b"BusyBox v1.35.0 built-in shell (ash)\r\n\r\n# ", interaction
```

The shell executes **nothing**. Every command gets a canned reply from a lookup table:

```python
"whoami": b"root\r\n# ",
"wget":   b"Connecting to server... failed: Network unreachable\r\n# ",
"busybox": b"BusyBox v1.35.0 ... multi-call binary\r\n# ",
```

But we record the command, and the first one is gold — it reveals the payload:

```python
SHELL_PAYLOAD_SIGNATURES = [
    (r"wget|curl|tftp",        "downloading a payload"),
    (r"chmod\s+\+?x|777",      "making a payload executable"),
    (r"busybox\s+\w+",         "BusyBox applet probing (Mirai fingerprint)"),
    (r"nc\s|/dev/tcp",         "reverse shell"),
    (r"crontab|/etc/cron",     "establishing persistence"),
    (r"authorized_keys",       "installing an SSH key"),
    ...
]
```

A live capture reads like Mirai's playbook exactly: `cat /proc/cpuinfo` (identify the CPU so it can pick the right binary), `busybox MIRAI` (fingerprint the device), `wget http://.../mirai.arm` (fetch the payload), `chmod 777`, run, `rm` the dropper. We see all of it and run none of it.

**This is where low-interaction earns its keep.** We learn the full *intent* — recon, payload URL, persistence method — while the payload is never fetched or executed. The `wget` "fails" with a canned network error, and the attacker's own script moves on.

**Detectability:** moderate to high. The command vocabulary is small; an attacker who runs something not in the table gets `applet not found` and may suspect. But by then they've already told us their payload URL.

---

## 4.5 FTP (port 21)

Records USER/PASS pairs, then always rejects.

```python
if command == "PASS":
    return b"530 Login incorrect.\r\n", Interaction("auth", {...})
```

**Always rejecting is deliberate.** Accepting would mean emulating a filesystem — LIST, RETR, STOR, directory state — which is exactly where a low-interaction honeypot starts sliding toward high-interaction and its risks. The credentials are the intelligence; the filesystem is liability.

---

## 4.6 SMTP (port 25)

Catches **open-relay probing** — spammers scanning for mail servers that will relay to arbitrary destinations.

```python
if command == "RCPT":
    return b"554 5.7.1 Relay access denied\r\n", Interaction(...)
```

We accept the HELO and MAIL FROM, record who they're trying to reach, then refuse the relay. The refusal is the safe move: an open relay that actually relayed would be sending spam on the attacker's behalf.

---

## 4.7 Redis (port 6379)

Redis historically shipped with **no authentication, bound to all interfaces** — one of the most abused defaults on the internet. The classic attack writes an SSH key or a cron job through Redis's own persistence:

```
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "ssh-rsa AAAA... attacker@evil"
SAVE
```

The classifier flags exactly this sequence:

```python
if command in ("CONFIG", "SET", "SAVE", "SLAVEOF"):
    payload = "Redis persistence abuse (SSH key or cron injection)"
elif command in ("EVAL", "SCRIPT"):
    payload = "Lua sandbox escape attempt"
elif command == "MODULE":
    payload = "Redis module loading (remote code execution)"
```

We reply `+OK` to keep the attacker talking, and write nothing — there is no `dir`, no file, no key. The whole attack is recorded and entirely inert.

---

## 4.8 MySQL (port 3306)

The MySQL protocol is binary, so this one hand-builds a greeting packet and records whatever authentication attempt comes back.

```python
def greeting(self):
    # a hand-constructed MySQL 8.0 handshake packet
    return header + payload
```

We don't fully parse the binary auth packet — we extract any printable run (usually the username) and record that an authentication was attempted. Even that partial capture is useful: it confirms a database credential attack against this address.

**Detectability:** high, if the attacker completes the handshake and notices the auth response is malformed. But the mere attempt is already recorded.

---

## 4.9 A note on detectability

Every service here can be fingerprinted as a honeypot by a determined human: failed SSH key exchange, tiny shell vocabulary, static banners, malformed MySQL responses. This is a real limitation and it is not hidden.

Two things make it acceptable:

1. **The overwhelming majority of attacks are automated.** Scanners and botnets don't check whether they're in a honeypot — they run their script and move on. Against that traffic, which is nearly all of it, the emulation is more than good enough.

2. **We capture the intelligence before the point of detection.** The SSH version string, the HTTP path, the telnet payload URL — all recorded in the first interaction, before an attacker could confirm their suspicion and leave.

Making a honeypot undetectable to a careful human is an endless arms race that Cowrie and commercial products invest heavily in and still don't fully win. A low-interaction honeypot doesn't try. It optimises for the automated flood, captures the first move, and accepts that a patient human analyst can tell. [Doc 08](08-future-work.md) lists the improvements that would raise the bar.

---

**Previous:** [03 — Architecture](03-architecture.md) | **Next:** [05 — Deployment](05-deployment.md)
