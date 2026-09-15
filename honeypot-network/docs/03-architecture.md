# 03 — Architecture

*asyncio, the service framework, threat scoring, and the storage schema.*

---

## 3.1 The shape

```
   seven listening sockets  (one asyncio task each)
            │
            ▼
   ┌──────────────────────────────────────────┐
   │  Honeypot._handle()                       │  one coroutine per connection
   │    open a session row                     │
   │    send the greeting                      │
   │    loop: read a line (with timeout)       │
   │          service.respond(line, state)     │
   │          record the interaction           │
   │          send the canned reply            │
   │    close: score the session               │
   └──────────────────────────────────────────┘
            │                    │
            ▼                    ▼
      store.py (SQLite)     live console + callback
```

## 3.2 Why asyncio

A honeypot's workload is **almost entirely waiting** — for a connection, for the next line, for a timeout to expire. There is essentially no CPU work: read some bytes, look up a canned response, write it back.

That is the textbook case for async IO. One process, one thread, an event loop that juggles thousands of concurrent connections by switching between them whenever one blocks on IO.

### Why not threads?

A thread-per-connection design is simpler to write and works fine at small scale. It falls over at exactly the scale a honeypot invites:

| | Thread per connection | asyncio |
|---|---|---|
| Memory per connection | ~8 MB (thread stack) | ~a few KB (coroutine) |
| 5,000 connections | ~40 GB — impossible | ~tens of MB |
| Context-switch cost | OS scheduler, expensive | event loop, cheap |
| Connection-flood resistance | poor | good |

A honeypot **advertises itself to the machines that send connection floods.** A design that needs a thread per connection is a design that falls over the first time a botnet finds it. asyncio is not a premature optimisation here — it is a correctness requirement for the threat model.

### The single-line core

```python
listener.server = await asyncio.start_server(
    self._make_handler(listener), self.bind, listener.port)
```

`asyncio.start_server` handles the accept loop, and each connection gets its own coroutine. All seven services run in one `asyncio.gather` over their `serve_forever()` calls. No thread pool, no process pool, no locks.

## 3.3 The service framework

Adding a service is deliberately trivial, because the server handles everything that isn't protocol-specific:

```python
class Service:
    name = "generic"
    default_port = 0
    description = "..."

    def greeting(self) -> bytes: ...                    # sent on connect
    def respond(self, line, state) -> (bytes, Interaction | None): ...
    def closing(self, state) -> bytes: ...
```

The server owns sockets, timeouts, byte limits, logging, scoring and storage. A service owns only its protocol. That is why `RedisService` is about 30 lines and `SSHService` about 40 — everything else is shared.

`state` is a plain dict that persists for the connection's lifetime, so a service can remember that it has seen the username and is now waiting for the password. No class instance per connection, no shared mutable state between connections.

## 3.4 Threat scoring

Every session gets a 0–100 score, so an operator's attention goes to the right rows:

```python
def score_session(service_name, interactions):
    score = 10                              # any connection at all
    for interaction in interactions:
        if interaction.kind == "auth":            score += 8
        if interaction.detail.get("success"):     score += 10
        if interaction.kind == "command":         score += 6
        if interaction.detail.get("exploit"):     score += 20
        if interaction.detail.get("payload"):     score += 25
        if "botnet" in interaction.detail.get("tool", ""):  score += 15
    return min(score, 100)
```

The weighting reflects how much each event reveals about *intent*:

- **Connecting** scores 10 on its own — a honeypot has no users, so every connection is already unsolicited.
- **A credential attempt** is routine botnet behaviour: +8.
- **A recognised exploit path** (`/.env`, path traversal) shows targeting: +20.
- **A payload** (`wget` of a binary, a Redis SSH-key write) is an actual attack in progress: +25.

This is a **triage heuristic, not a measurement.** Its only job is to sort sessions so the critical ones surface first. The bands (`low`/`medium`/`high`/`critical`) are chosen for that, and the scoring is deliberately simple and readable rather than tuned — a machine-learning threat score would be more accurate and far less inspectable, and inspectability is what an operator needs at 3 a.m.

## 3.5 Storage

SQLite, two tables:

```sql
sessions      one row per TCP connection
interactions  one row per thing the attacker did inside it
```

### Why normalise them apart

"How many connections" and "how many login attempts" are different questions, and one connection carries many attempts. Keeping sessions and interactions in separate tables means both questions are a simple query rather than a scan-and-count.

### Why SQLite

A honeypot's entire output is a queryable record, and grep over a text log stops being adequate the moment you want "top credentials by frequency" or "sessions from this IP touching more than one service". SQLite gives real queries with zero operational overhead — no server, one file, and it ships with Python.

For a high-volume deployment this becomes PostgreSQL, and the `Store` class isolates every query so that's a contained change. The indexes (`source_ip`, `service`, `started_at`, `kind`) are the ones the report and dashboard actually use.

### The threading note

```python
sqlite3.connect(self.path, check_same_thread=False)
```

The asyncio server and the Flask dashboard may touch the database from different threads. `check_same_thread=False` allows that; SQLite's own locking serialises the writes. This is a single-writer workload (the honeypot) with occasional readers (the dashboard), which is exactly what SQLite handles well.

## 3.6 Alerting

Two paths, so the honeypot is useful both live and after the fact:

**The live console** prints each interaction as it happens, with the classification inline:

```
!! 21:36:20  198.51.100.4  telnet  $ wget http://.../mirai.arm   <- downloading a payload
```

**A callback** (`on_event`) lets another system subscribe to interactions in real time — the hook a SIEM export or a real-time alerter would use ([doc 08](08-future-work.md)).

Both are best-effort and wrapped so that a failure in alerting can never affect capture. Recording the attack always takes priority over reporting it.

## 3.7 The data model

```python
@dataclass
class Interaction:
    kind: str          # "banner" | "auth" | "command" | "request"
    detail: dict       # structured, per-kind
    raw: str           # the defanged original bytes, for forensics
```

`detail` is stored as JSON, which keeps the schema flexible — an SSH banner and an HTTP request carry very different fields, and forcing them into fixed columns would mean either a very wide sparse table or a column per protocol. `raw` preserves the sanitised original for a human to inspect, because a classifier only captures what it was written to look for.

---

**Previous:** [02 — Design & safety](02-design.md) | **Next:** [04 — The services](04-services.md)
