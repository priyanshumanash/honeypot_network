# 02 — Design & Safety

*The low-interaction choice, and the measures that stop the honeypot being turned against its operator.*

---

## 2.1 The safety rule

Everything in this project follows from one rule:

> **Nothing an attacker sends is ever executed, parsed into code, written to a path they control, or passed to a shell.**

Every service handler does exactly three things:

```python
def respond(self, line: bytes, state: dict) -> tuple[bytes, Interaction | None]:
    # 1. read the bytes
    # 2. record what they represent
    # 3. return a canned response
```

There is no `os.system`, no `eval`, no `open(attacker_path)`, no `pickle.loads`, no template rendered with attacker input. The telnet "shell" has a lookup table of canned replies; the FTP server has no filesystem; the Redis port has no data store.

**This is the line between a honeypot and a compromised machine.** A honeypot that actually runs the commands typed into it is not a honeypot — it is a box the attacker owns, which you are now operating on their behalf.

## 2.2 Low-interaction, and why

### The spectrum

```
  low-interaction ─────────────────────────────────────── high-interaction
       │                                                        │
  emulate a banner                                    a real OS in a VM
  read bytes, reply canned                            the attacker truly breaks in
  cannot be compromised                               can be, and then it's a real
  see the first move only                             compromised machine
  zero risk                                           severe risk
       │                                                        │
   THIS PROJECT                                         Cowrie (partial), full VMs
```

### Why low-interaction is the right choice here

**The risk asymmetry is enormous.** A low-interaction honeypot's worst-case failure is a crash. A high-interaction honeypot's worst-case failure is a real machine, under attacker control, launching attacks from *your* IP address — for which you are legally liable. That is not a hypothetical: honeypot operators have had abuse complaints, takedowns, and worse.

**The intelligence gap is smaller than it looks.** For the questions this project answers — *what credentials are botnets trying? what vulnerabilities are being scanned? which campaigns are active?* — the attacker's first move is the whole answer. The Mirai credential list, the `/.env` probe, the `wget` of a payload URL: all captured in the first interaction, before any "break-in" would occur.

**What we genuinely give up:** post-exploitation behaviour. We see the attacker try `wget http://.../mirai.arm`; we don't see what the malware does, because we never fetch or run it. For *that*, you need a high-interaction honeypot in a sandbox — and you need to accept the risk that comes with it.

This is a real trade, stated plainly rather than hidden. For a study project and for an early-warning sensor, low-interaction is not a compromise — it is the correct engineering and ethical choice.

## 2.3 The honeypot must defend itself

A honeypot processes hostile input as its *entire purpose*. That makes it, ironically, one of the most-attacked pieces of software you could write — and a bug in it is not a bug, it is a compromise. Four classes of self-defence:

### Defence 1 — parameterised storage

Every value written to the database is attacker-controlled. String-formatted SQL would give the honeypot an SQL-injection hole — a genuinely embarrassing way to be owned.

```python
self.connection.execute(
    "INSERT INTO interactions (session_id, at, kind, detail, raw) "
    "VALUES (?, ?, ?, ?, ?)",
    (session_id, time.time(), kind, json.dumps(detail), raw[:2000]))
```

Bound parameters everywhere, no f-string SQL anywhere. An attacker whose username is `'; DROP TABLE sessions; --` has it stored as data:

```python
def test_sql_injection_is_stored_as_data():
    payload = "admin'; DROP TABLE sessions; --"
    store.add_interaction(session, "auth", {"username": payload, ...})
    assert len(store.sessions()) == 1          # table survives
    assert any(u == payload for u, p, n in store.credentials())
```

### Defence 2 — output escaping

Attacker text reaches three places: log files, the operator's terminal, and the HTML dashboard. Each needs different handling, and getting the dashboard wrong is the worst.

**The dashboard uses Jinja2 autoescaping.** An attacker who sends `<script>steal()</script>` as a username has it rendered as text, not executed. Without this, **your own honeypot would XSS you** — the attacker's payload running in the operator's browser, delivered by the tool built to catch them. There is no more ironic way to be compromised.

**Logs and the terminal get `_safe_text`:**

```python
def _safe_text(data, limit=2000):
    text = data[:limit].decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)     # ANSI escapes
    text = "".join(c if c.isprintable() or c in "\r\n\t"
                   else f"\\x{ord(c):02x}" for c in text)  # control chars
    return text.strip("\r\n")
```

Three attacks this stops:

- **Terminal escapes** — `\x1b[2J` clears an operator's screen; other sequences can move the cursor and overwrite text, or even (on some terminals) trigger a response. Stripped.
- **Log injection** — a `\r\n` plus a forged timestamp lets an attacker write fake log lines that hide their own activity. Contained.
- **Log flooding** — length-bounded, so a huge input can't fill the disk.

### Defence 3 — a service crash must not be a server crash

An attacker's whole job is finding the input you didn't consider. When they find it and a service raises, the honeypot must survive:

```python
try:
    reply, interaction = service.respond(line, state)
except Exception:
    logger.exception("service %s raised on input", listener.service_name)
    break          # drop this one connection, keep serving
```

One malformed connection ends that connection and nothing else. The other thousand keep going.

### Defence 4 — safe by default

```python
def __init__(self, store, bind="127.0.0.1", ...):
```

The server binds to **localhost by default**. A honeypot on `0.0.0.0` is a service you have deliberately made attractive to attackers — a serious decision that must be made on purpose, not stumbled into. Exposing it requires `--bind 0.0.0.0`, and that prints a warning.

```python
def test_default_bind_is_localhost():
    assert Honeypot(store).bind == "127.0.0.1"
```

## 2.4 Connection-level limits

Some limits are properties of the connection rather than the protocol, so they live in the server:

| Limit | Value | Stops |
|---|---|---|
| Bytes per connection | 64 KiB | A single connection filling the disk |
| Line length | 8 KiB | Unbounded buffering of a line with no newline |
| Idle timeout | 45 s | Dead connections holding resources |
| Concurrent connections | 500 | Resource exhaustion |

A honeypot attracts floods — it's advertising itself to exactly the machines that send them — so these are not theoretical.

## 2.5 What this design cannot defend against

Stated honestly:

- **Fingerprinting.** A determined attacker can tell this is a honeypot — the SSH key exchange fails, the shell vocabulary is tiny, the banners never change. [Doc 04](04-services.md) discusses detectability. Making it undetectable is an endless arms race that low-interaction honeypots don't try to win.
- **Resource exhaustion from a large botnet.** The limits above raise the bar; they don't make it infinite. A serious DDoS overwhelms this like anything else.
- **Attacks on the emulation logic itself.** The safety tests cover the classes of input I thought of. The whole history of security is attackers finding the input you didn't — which is exactly why defence 3 exists: to make sure that when they do, the cost is one dropped connection.

The design goal is not "unbreakable". It is "cannot be turned into a weapon against its operator or a third party" — and that is a property low-interaction honeypots can actually deliver.

---

**Previous:** [01 — Problem statement](01-problem-statement.md) | **Next:** [03 — Architecture](03-architecture.md)
