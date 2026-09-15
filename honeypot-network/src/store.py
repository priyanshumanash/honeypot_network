"""
store.py
--------
Event storage. SQLite, because a honeypot's whole output is a queryable
record and grep over a text log stops being adequate quickly.

SCHEMA
------
  sessions      one row per TCP connection
  interactions  one row per thing the attacker did inside a session

Normalising them apart matters: "how many connections" and "how many login
attempts" are different questions, and one connection can carry dozens of
attempts.

WHY EVERY WRITE IS PARAMETERISED
--------------------------------
Every value stored here is attacker-controlled. Building SQL with string
formatting would mean a honeypot -- a tool for studying attacks -- carrying an
SQL injection vulnerability, which would be a genuinely embarrassing way to be
compromised.

Every query in this file uses bound parameters. There is no f-string SQL
anywhere, and there is a test asserting an attacker string containing
`'; DROP TABLE sessions; --` is stored as data.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB = Path("logs/honeypot.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip     TEXT    NOT NULL,
    source_port   INTEGER,
    service       TEXT    NOT NULL,
    local_port    INTEGER,
    started_at    REAL    NOT NULL,
    ended_at      REAL,
    bytes_in      INTEGER DEFAULT 0,
    interactions  INTEGER DEFAULT 0,
    threat_score  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS interactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    at          REAL    NOT NULL,
    kind        TEXT    NOT NULL,
    detail      TEXT    NOT NULL,
    raw         TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip      ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_service ON sessions(service);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_interactions_sid ON interactions(session_id);
CREATE INDEX IF NOT EXISTS idx_interactions_kind ON interactions(kind);
"""


@dataclass
class SessionRow:
    id: int
    source_ip: str
    source_port: int
    service: str
    local_port: int
    started_at: float
    ended_at: float | None
    bytes_in: int
    interactions: int
    threat_score: int


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because the asyncio server and the Flask
        # dashboard may touch it from different threads. Writes are serialised
        # by SQLite's own locking; this is a single-writer workload.
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    # ---- writes ---------------------------------------------------------

    def open_session(self, source_ip: str, source_port: int,
                     service: str, local_port: int) -> int:
        cursor = self.connection.execute(
            "INSERT INTO sessions (source_ip, source_port, service, "
            "local_port, started_at) VALUES (?, ?, ?, ?, ?)",
            (source_ip, source_port, service, local_port, time.time()))
        self.connection.commit()
        return cursor.lastrowid

    def add_interaction(self, session_id: int, kind: str,
                        detail: dict, raw: str = "") -> None:
        self.connection.execute(
            "INSERT INTO interactions (session_id, at, kind, detail, raw) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, time.time(), kind, json.dumps(detail), raw[:2000]))
        self.connection.execute(
            "UPDATE sessions SET interactions = interactions + 1 WHERE id = ?",
            (session_id,))
        self.connection.commit()

    def close_session(self, session_id: int, bytes_in: int,
                      threat_score: int) -> None:
        self.connection.execute(
            "UPDATE sessions SET ended_at = ?, bytes_in = ?, threat_score = ? "
            "WHERE id = ?",
            (time.time(), bytes_in, threat_score, session_id))
        self.connection.commit()

    # ---- reads ----------------------------------------------------------

    def sessions(self, limit: int = 100, service: str | None = None,
                 source_ip: str | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM sessions WHERE 1=1"
        parameters: list = []
        if service:
            query += " AND service = ?"
            parameters.append(service)
        if source_ip:
            query += " AND source_ip = ?"
            parameters.append(source_ip)
        query += " ORDER BY started_at DESC LIMIT ?"
        parameters.append(limit)
        return self.connection.execute(query, parameters).fetchall()

    def interactions(self, session_id: int | None = None,
                     kind: str | None = None,
                     limit: int = 200) -> list[sqlite3.Row]:
        query = ("SELECT i.*, s.source_ip, s.service FROM interactions i "
                 "JOIN sessions s ON s.id = i.session_id WHERE 1=1")
        parameters: list = []
        if session_id is not None:
            query += " AND i.session_id = ?"
            parameters.append(session_id)
        if kind:
            query += " AND i.kind = ?"
            parameters.append(kind)
        query += " ORDER BY i.at DESC LIMIT ?"
        parameters.append(limit)
        return self.connection.execute(query, parameters).fetchall()

    def credentials(self, limit: int = 50) -> list[tuple[str, str, int]]:
        """The most-tried username/password pairs.

        This is the headline output of a honeypot. Real deployments fill up
        with root/root, admin/admin, root/xc3511 (a Mirai default) within
        hours -- a direct measurement of what botnets currently believe.
        """
        rows = self.connection.execute(
            "SELECT detail FROM interactions WHERE kind = 'auth'").fetchall()
        counts: dict[tuple[str, str], int] = {}
        for row in rows:
            detail = json.loads(row["detail"])
            key = (detail.get("username", ""), detail.get("password", ""))
            counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: -item[1])[:limit]
        return [(u, p, n) for (u, p), n in ranked]

    def top_attackers(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT source_ip, COUNT(*) AS sessions, "
            "       SUM(interactions) AS interactions, "
            "       MAX(threat_score) AS threat, "
            "       COUNT(DISTINCT service) AS services, "
            "       MIN(started_at) AS first_seen, "
            "       MAX(started_at) AS last_seen "
            "FROM sessions GROUP BY source_ip "
            "ORDER BY threat DESC, interactions DESC LIMIT ?",
            (limit,)).fetchall()

    def service_counts(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT service, COUNT(*) AS sessions, "
            "       SUM(interactions) AS interactions "
            "FROM sessions GROUP BY service ORDER BY sessions DESC").fetchall()

    def payload_counts(self, limit: int = 20) -> list[tuple[str, int]]:
        """Which attack types were seen, from the classifiers in services.py."""
        rows = self.connection.execute(
            "SELECT detail FROM interactions").fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            detail = json.loads(row["detail"])
            for field in ("payload", "exploit", "tool"):
                value = detail.get(field)
                if value:
                    counts[value] = counts.get(value, 0) + 1
        return sorted(counts.items(), key=lambda item: -item[1])[:limit]

    def summary(self) -> dict:
        row = self.connection.execute(
            "SELECT COUNT(*) AS sessions, "
            "       COUNT(DISTINCT source_ip) AS attackers, "
            "       SUM(interactions) AS interactions, "
            "       SUM(bytes_in) AS bytes_in, "
            "       MIN(started_at) AS first_seen, "
            "       MAX(started_at) AS last_seen "
            "FROM sessions").fetchone()
        auth = self.connection.execute(
            "SELECT COUNT(*) AS n FROM interactions WHERE kind = 'auth'"
        ).fetchone()
        return {
            "sessions": row["sessions"] or 0,
            "attackers": row["attackers"] or 0,
            "interactions": row["interactions"] or 0,
            "bytes_in": row["bytes_in"] or 0,
            "credential_attempts": auth["n"] or 0,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    def close(self) -> None:
        self.connection.close()
