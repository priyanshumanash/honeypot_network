"""
services.py
-----------
Protocol emulators. Each one imitates a real service convincingly enough that
an attacker's scanner believes it, while doing absolutely nothing.

THE CENTRAL SAFETY RULE
-----------------------
    NOTHING AN ATTACKER SENDS IS EVER EXECUTED, PARSED INTO CODE,
    WRITTEN TO A PATH THEY CONTROL, OR PASSED TO A SHELL.

Every handler here does exactly three things: read bytes, record them, write a
canned response. That is it. There is no file system, no command execution, no
deserialisation, no template rendering.

This constraint is what separates a honeypot from a compromised machine. A
"high-interaction" honeypot -- a real OS in a VM that an attacker can actually
break into -- gathers far richer intelligence and is genuinely dangerous to
operate: it can be used to attack other people, and you are liable for that.

This is a LOW-INTERACTION honeypot. It cannot be compromised because there is
nothing behind the banner. The trade-off is that we learn what an attacker
TRIED, never what they would have done next. docs/02-design.md argues that
trade honestly.

WHAT EACH SERVICE CAPTURES
--------------------------
  ssh     client version string (excellent tool fingerprint), auth attempts
  http    method, path, headers, User-Agent, body -- exploit paths are gold
  ftp     USER/PASS pairs, commands
  telnet  credentials, then whatever commands they type
  smtp    HELO name, MAIL FROM, RCPT TO -- spam relay probing
  mysql   handshake, then the auth packet
  redis   unauthenticated commands -- a very common real attack
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_LINE = 8192          # refuse absurd input rather than buffering it
MAX_SESSION_BYTES = 64 * 1024


@dataclass
class Interaction:
    """One thing the attacker did inside a session."""
    kind: str                       # "banner", "auth", "command", "request"
    detail: dict = field(default_factory=dict)
    raw: str = ""


def _safe_text(data: bytes, limit: int = 2000) -> str:
    """Decode attacker input for logging, defanged.

    Attacker input reaches log files, a terminal and an HTML dashboard. Three
    things have to be neutralised before it goes anywhere:

      - control characters, which can rewrite a terminal or forge log lines
      - ANSI escape sequences, which can do the same in colour
      - unbounded length, which is a cheap denial of service on the log

    This is not paranoia. Log injection is a real technique: an attacker who
    can write a newline plus a fake timestamp into your log can forge entries
    that hide their own activity.
    """
    text = data[:limit].decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)          # ANSI escapes
    # \r and \n pass through as real whitespace so callers can .strip() them;
    # every other control character is escaped so it cannot rewrite a terminal
    # or forge a log line. Trailing whitespace is then trimmed here.
    text = "".join(character if character.isprintable() or character in "\r\n\t"
                   else f"\\x{ord(character):02x}" for character in text)
    return text.strip("\r\n")


# ==========================================================================
# Base
# ==========================================================================

class Service:
    """A protocol emulator.

    Subclasses implement `greeting()` and `respond()`. The framework in
    honeypot.py handles sockets, timeouts and logging, so a new service is
    typically twenty lines.
    """

    name = "generic"
    default_port = 0
    description = "a generic service"

    def greeting(self) -> bytes:
        """Sent immediately on connection. Empty if the client speaks first."""
        return b""

    def respond(self, line: bytes, state: dict) -> tuple[bytes, Interaction | None]:
        """Handle one line of input.

        Returns the bytes to send back and, optionally, an Interaction worth
        recording. `state` persists for the lifetime of the connection.
        """
        return b"", None

    def closing(self, state: dict) -> bytes:
        return b""


# ==========================================================================
# SSH
# ==========================================================================

class SSHService(Service):
    """SSH on port 22 -- the single most attacked port on the internet.

    A real SSH handshake is complex, and we implement none of it. We send a
    version banner, read the client's version banner, and then fail the key
    exchange.

    That is enough, because the client's version string is one of the most
    useful fingerprints available:

        SSH-2.0-OpenSSH_8.9p1        a real client, or someone pretending
        SSH-2.0-libssh_0.9.6         very often a botnet
        SSH-2.0-Go                   Go tooling; often a mass scanner
        SSH-2.0-PUTTY                a human on Windows
        SSH-2.0-paramiko_2.11.0      a Python script

    Credential-stuffing botnets overwhelmingly use libssh, paramiko or Go
    clients, and they announce it before sending a single password.
    """

    name = "ssh"
    default_port = 22
    description = "OpenSSH 8.9p1 Ubuntu-3ubuntu0.4"

    def greeting(self) -> bytes:
        return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

    def respond(self, line: bytes, state: dict):
        if not state.get("client_version"):
            text = _safe_text(line, 255).strip()
            state["client_version"] = text
            # Fail key exchange. The attacker's tool logs "connection closed"
            # and moves on, having already told us what it is.
            return (b"", Interaction("banner",
                                     {"client_version": text,
                                      "tool": fingerprint_ssh_client(text)},
                                     raw=text))
        return b"", None


SSH_CLIENT_SIGNATURES = [
    (r"libssh", "libssh (commonly a credential-stuffing botnet)"),
    (r"paramiko", "Paramiko (Python automation or scanner)"),
    (r"Go\b|Go-http", "Go client (frequently a mass scanner)"),
    (r"PUTTY", "PuTTY (interactive Windows user)"),
    (r"JSCH", "JSch (Java automation)"),
    (r"russh|Rust", "Rust client"),
    (r"OpenSSH_[0-9]", "OpenSSH (a real client, or an imitation)"),
    (r"Nmap|zgrab|masscan", "network scanner"),
]


def fingerprint_ssh_client(version: str) -> str:
    for pattern, label in SSH_CLIENT_SIGNATURES:
        if re.search(pattern, version, re.IGNORECASE):
            return label
    return "unknown client"


# ==========================================================================
# HTTP
# ==========================================================================

class HTTPService(Service):
    """HTTP on 80/8080 -- the richest source of intelligence here.

    Attackers probe web servers with specific paths looking for specific
    vulnerabilities, and the path alone usually identifies the campaign:

        /.env                    leaked credentials (Laravel and friends)
        /wp-login.php            WordPress brute force
        /shell?cd+/tmp;wget      Mirai-family IoT worm
        /cgi-bin/.%2e/...        path traversal
        /actuator/env            Spring Boot Actuator exposure
        /.git/config             exposed git repository

    We record the request and return a plausible 404 or a fake login page.
    We never touch the filesystem, never render a template with attacker
    input, and never interpret the path as a path.
    """

    name = "http"
    default_port = 8080
    description = "Apache/2.4.52 (Ubuntu)"

    def respond(self, line: bytes, state: dict):
        text = _safe_text(line, MAX_LINE)

        if not state.get("request_line"):
            state["request_line"] = text.strip()
            state["headers"] = {}

            parts = state["request_line"].split()
            method = parts[0] if parts else "?"
            path = parts[1] if len(parts) > 1 else "/"
            state["method"], state["path"] = method, path
            return b"", None

        stripped = text.strip()
        if stripped:                          # still reading headers
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                state["headers"][key.strip().lower()] = value.strip()[:300]
            return b"", None

        # Blank line: headers are done. Respond and record.
        path = state.get("path", "/")
        headers = state.get("headers", {})
        interaction = Interaction("request", {
            "method": state.get("method", "?"),
            "path": path,
            "user_agent": headers.get("user-agent", ""),
            "host": headers.get("host", ""),
            "exploit": classify_http_path(path),
        }, raw=state["request_line"])

        return self._page(path), interaction

    def _page(self, path: str) -> bytes:
        """A canned response. Attacker input is never echoed into it."""
        lowered = path.lower()
        if any(marker in lowered for marker in
               ("wp-login", "admin", "login", "signin")):
            body = (b"<!doctype html><html><head><title>Login</title></head>"
                    b"<body><h2>Administrator Login</h2>"
                    b"<form method=post><input name=user placeholder=Username>"
                    b"<input name=pass type=password placeholder=Password>"
                    b"<button>Sign in</button></form></body></html>")
            status = b"200 OK"
        else:
            body = (b"<!doctype html><html><head><title>404 Not Found</title>"
                    b"</head><body><h1>Not Found</h1><hr>"
                    b"<address>Apache/2.4.52 (Ubuntu) Server</address>"
                    b"</body></html>")
            status = b"404 Not Found"

        return (b"HTTP/1.1 " + status + b"\r\n"
                b"Server: Apache/2.4.52 (Ubuntu)\r\n"
                b"Content-Type: text/html; charset=UTF-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body)


HTTP_EXPLOIT_SIGNATURES = [
    (r"\.env", "environment file (credential harvesting)"),
    (r"wp-login|wp-admin|xmlrpc\.php", "WordPress attack"),
    (r"\.git/", "exposed git repository"),
    (r"phpmyadmin|pma/", "phpMyAdmin probe"),
    (r"/shell|/cgi-bin/.*wget|busybox", "Mirai-family IoT worm"),
    (r"\.\./|%2e%2e|\.%2e", "path traversal"),
    (r"actuator|/env\b", "Spring Boot Actuator exposure"),
    (r"select.*from|union.*select|' or ", "SQL injection attempt"),
    (r"<script|javascript:|onerror=", "cross-site scripting attempt"),
    (r"/vendor/|composer", "PHP dependency probe"),
    (r"\.aws/|credentials", "cloud credential harvesting"),
    (r"solr|elasticsearch|/_search", "search-service probe"),
    (r"/config|\.ini|\.conf|\.bak|\.old", "configuration file probe"),
    (r"jenkins|/script", "Jenkins script console probe"),
]


def classify_http_path(path: str) -> str:
    for pattern, label in HTTP_EXPLOIT_SIGNATURES:
        if re.search(pattern, path, re.IGNORECASE):
            return label
    return ""


# ==========================================================================
# FTP
# ==========================================================================

class FTPService(Service):
    """FTP on 21. Records USER/PASS pairs and then rejects the login.

    Always rejecting is deliberate. Accepting would mean emulating a
    filesystem, which is where low-interaction honeypots start becoming
    high-interaction ones -- and dangerous.
    """

    name = "ftp"
    default_port = 21
    description = "vsFTPd 3.0.5"

    def greeting(self) -> bytes:
        return b"220 (vsFTPd 3.0.5)\r\n"

    def respond(self, line: bytes, state: dict):
        text = _safe_text(line, 512).strip()
        command, _, argument = text.partition(" ")
        command = command.upper()

        if command == "USER":
            state["username"] = argument
            return b"331 Please specify the password.\r\n", None

        if command == "PASS":
            username = state.get("username", "")
            return (b"530 Login incorrect.\r\n",
                    Interaction("auth", {"username": username,
                                         "password": argument,
                                         "success": False}, raw=text))

        if command == "QUIT":
            return b"221 Goodbye.\r\n", None
        if command in ("SYST",):
            return b"215 UNIX Type: L8\r\n", None
        if command in ("FEAT",):
            return b"211-Features:\r\n UTF8\r\n211 End\r\n", None

        return (b"530 Please login with USER and PASS.\r\n",
                Interaction("command", {"command": command,
                                        "argument": argument[:200]}, raw=text)
                if command else None)


# ==========================================================================
# Telnet
# ==========================================================================

class TelnetService(Service):
    """Telnet on 23 -- the port IoT botnets live on.

    Mirai and its descendants spread almost entirely by telnet brute force
    against a hardcoded list of default credentials. A telnet honeypot fills
    up with root/admin, admin/admin, root/xc3511 within hours of exposure.

    This one accepts the login after three attempts and then records the
    commands typed -- which is where the real intelligence is, because the
    first command reveals the payload URL.
    """

    name = "telnet"
    default_port = 23
    description = "BusyBox v1.35.0 login"

    def greeting(self) -> bytes:
        return b"\r\nDVR-2340 login: "

    def respond(self, line: bytes, state: dict):
        text = _safe_text(line, 512).strip()
        stage = state.get("stage", "username")

        if stage == "username":
            state["username"] = text
            state["stage"] = "password"
            return b"Password: ", None

        if stage == "password":
            username = state.get("username", "")
            attempts = state.get("attempts", 0) + 1
            state["attempts"] = attempts
            interaction = Interaction("auth", {"username": username,
                                               "password": text,
                                               "success": attempts >= 3},
                                      raw=f"{username}:{text}")
            if attempts >= 3:
                # Let them "in" so we can see what they run. Nothing is
                # executed -- every command gets a canned reply.
                state["stage"] = "shell"
                return (b"\r\n\r\nBusyBox v1.35.0 built-in shell (ash)\r\n"
                        b"\r\n# "), interaction
            state["stage"] = "username"
            return b"\r\nLogin incorrect\r\nDVR-2340 login: ", interaction

        # Shell stage: record the command, reply plausibly, execute nothing.
        return self._shell_reply(text), Interaction(
            "command", {"command": text[:400],
                        "payload": classify_shell_command(text)}, raw=text)

    @staticmethod
    def _shell_reply(command: str) -> bytes:
        word = command.split()[0] if command.split() else ""
        canned = {
            "": b"# ",
            "ls": b"bin  dev  etc  lib  mnt  proc  sys  tmp  usr  var\r\n# ",
            "pwd": b"/\r\n# ",
            "whoami": b"root\r\n# ",
            "id": b"uid=0(root) gid=0(root)\r\n# ",
            "uname": b"Linux DVR-2340 4.9.37 #1 SMP armv7l GNU/Linux\r\n# ",
            "cat": b"cat: can't open: No such file or directory\r\n# ",
            "wget": b"Connecting to server... failed: Network unreachable\r\n# ",
            "curl": b"curl: (6) Could not resolve host\r\n# ",
            "busybox": b"BusyBox v1.35.0 (2022-05-10) multi-call binary\r\n# ",
            "exit": b"logout\r\n",
        }
        return canned.get(word, f"{word}: applet not found\r\n# ".encode())


SHELL_PAYLOAD_SIGNATURES = [
    (r"wget|curl|tftp", "downloading a payload"),
    (r"chmod\s+\+?x|chmod\s+777", "making a payload executable"),
    (r"/dev/null|>\s*/dev", "hiding output"),
    (r"rm\s+-rf", "destructive command"),
    (r"nc\s|netcat|/dev/tcp", "reverse shell"),
    (r"crontab|/etc/cron", "establishing persistence"),
    (r"authorized_keys|\.ssh", "installing an SSH key"),
    (r"busybox\s+\w+", "BusyBox applet probing (Mirai fingerprint)"),
    (r"cat\s+/proc/cpuinfo|/proc/mounts", "system reconnaissance"),
    (r"iptables|firewall", "disabling defences"),
    (r"base64\s+-d|echo\s+-e\s+\\x", "obfuscated payload"),
]


def classify_shell_command(command: str) -> str:
    for pattern, label in SHELL_PAYLOAD_SIGNATURES:
        if re.search(pattern, command, re.IGNORECASE):
            return label
    return ""


# ==========================================================================
# SMTP
# ==========================================================================

class SMTPService(Service):
    """SMTP on 25. Catches open-relay probing.

    Spammers scan for mail servers that will relay to arbitrary destinations.
    This one accepts the conversation and then refuses the relay, recording
    who they were trying to mail.
    """

    name = "smtp"
    default_port = 2525
    description = "Postfix smtpd"

    def greeting(self) -> bytes:
        return b"220 mail.example.local ESMTP Postfix (Ubuntu)\r\n"

    def respond(self, line: bytes, state: dict):
        text = _safe_text(line, 512).strip()
        command = text.split()[0].upper() if text.split() else ""

        if command in ("HELO", "EHLO"):
            state["helo"] = text[5:].strip()
            return (b"250-mail.example.local\r\n250-SIZE 10240000\r\n"
                    b"250 AUTH LOGIN PLAIN\r\n",
                    Interaction("command", {"command": "EHLO",
                                            "argument": state["helo"]}, raw=text))
        if command == "MAIL":
            state["mail_from"] = text
            return b"250 2.1.0 Ok\r\n", None
        if command == "RCPT":
            return (b"554 5.7.1 Relay access denied\r\n",
                    Interaction("command", {"command": "RCPT",
                                            "argument": text[:200],
                                            "payload": "open relay probe"},
                                raw=text))
        if command == "AUTH":
            return (b"535 5.7.8 Authentication credentials invalid\r\n",
                    Interaction("auth", {"username": "(SMTP AUTH)",
                                         "password": text[:120],
                                         "success": False}, raw=text))
        if command == "QUIT":
            return b"221 2.0.0 Bye\r\n", None
        return b"502 5.5.2 Error: command not recognized\r\n", None


# ==========================================================================
# Redis
# ==========================================================================

class RedisService(Service):
    """Redis on 6379.

    Redis historically shipped with no authentication and bound to all
    interfaces, which made it one of the most abused services on the internet.
    The classic attack writes an SSH key or a cron job through Redis's own
    persistence mechanism -- so a honeypot here catches a very specific and
    very common campaign.
    """

    name = "redis"
    default_port = 6379
    description = "Redis 6.0.16"

    def respond(self, line: bytes, state: dict):
        text = _safe_text(line, 1024).strip()
        if not text:
            return b"", None

        # Accept both inline commands and a rough RESP array.
        words = [w for w in re.split(r"[\r\n ]+", text)
                 if w and not w.startswith(("*", "$"))]
        command = words[0].upper() if words else ""

        payload = ""
        if command in ("CONFIG", "SET", "SAVE", "BGSAVE", "SLAVEOF", "REPLICAOF"):
            payload = "Redis persistence abuse (SSH key or cron injection)"
        elif command in ("EVAL", "SCRIPT"):
            payload = "Lua sandbox escape attempt"
        elif command == "MODULE":
            payload = "Redis module loading (remote code execution)"

        interaction = Interaction("command", {"command": command,
                                              "argument": " ".join(words[1:])[:200],
                                              "payload": payload}, raw=text)

        replies = {
            "PING": b"+PONG\r\n",
            "INFO": (b"$92\r\n# Server\r\nredis_version:6.0.16\r\n"
                     b"os:Linux 5.15.0 x86_64\r\nprocess_id:1\r\n\r\n"),
            "CONFIG": b"+OK\r\n",
            "SET": b"+OK\r\n",
            "SAVE": b"+OK\r\n",
            "AUTH": b"-ERR Client sent AUTH, but no password is set\r\n",
        }
        return replies.get(command, b"-ERR unknown command\r\n"), interaction


# ==========================================================================
# MySQL
# ==========================================================================

class MySQLService(Service):
    """MySQL on 3306. Sends a greeting packet and records the login attempt.

    The MySQL protocol is binary, so we send a hand-built handshake packet
    and then simply record whatever comes back. Even without parsing it, the
    fact that something tried to authenticate is useful.
    """

    name = "mysql"
    default_port = 3306
    description = "MySQL 8.0.32-0ubuntu0.22.04.2"

    def greeting(self) -> bytes:
        version = b"8.0.32-0ubuntu0.22.04.2\x00"
        payload = (b"\x0a" + version + b"\x0b\x00\x00\x00"
                   + b"abcdefgh" + b"\x00" + b"\xff\xf7" + b"\x21"
                   + b"\x02\x00" + b"\xff\x81" + b"\x15"
                   + b"\x00" * 10 + b"ijklmnopqrst\x00"
                   + b"mysql_native_password\x00")
        header = bytes([len(payload) & 0xFF, (len(payload) >> 8) & 0xFF,
                        (len(payload) >> 16) & 0xFF, 0])
        return header + payload

    def respond(self, line: bytes, state: dict):
        if state.get("seen_auth"):
            return b"", None
        state["seen_auth"] = True
        # Extract any printable run -- usually the username.
        printable = re.findall(rb"[ -~]{3,}", line[:200])
        guess = printable[0].decode("ascii", "replace") if printable else ""
        return (b"\xff\x15\x04#28000Access denied for user\x00",
                Interaction("auth", {"username": guess, "password": "(binary)",
                                     "success": False},
                            raw=_safe_text(line, 120)))


# ==========================================================================
# Registry
# ==========================================================================

SERVICES: dict[str, type[Service]] = {
    "ssh": SSHService,
    "http": HTTPService,
    "ftp": FTPService,
    "telnet": TelnetService,
    "smtp": SMTPService,
    "redis": RedisService,
    "mysql": MySQLService,
}


def build(name: str) -> Service:
    if name not in SERVICES:
        raise KeyError(f"Unknown service '{name}'. "
                       f"Available: {', '.join(sorted(SERVICES))}")
    return SERVICES[name]()
