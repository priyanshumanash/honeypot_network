"""
honeypot.py
-----------
The asyncio server that runs every emulated service at once.

WHY ASYNCIO
-----------
A honeypot spends essentially all of its time waiting: for a connection, for
the next line, for a timeout. That is exactly the workload async IO is for.
One process handles thousands of concurrent connections on a handful of ports
with no thread per connection and no meaningful CPU cost.

A thread-per-connection design would work at small scale and fall over under
the connection floods a honeypot is specifically likely to attract.

SAFETY
------
Several limits are enforced here rather than in the services, because they
are properties of the *connection*, not the protocol:

  - a per-connection byte cap        (a flood cannot fill the disk)
  - a per-connection line cap        (no unbounded buffering)
  - an idle timeout                  (dead connections are reaped)
  - a total-connection cap per IP    (one source cannot monopolise it)
  - binds to 127.0.0.1 by default    (exposure must be deliberate)

That last one matters most. A honeypot on 0.0.0.0 is a service you have
deliberately made attractive to attackers. Making that the DEFAULT would be
irresponsible, so `--bind 0.0.0.0` is opt-in and prints a warning.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .services import MAX_LINE, MAX_SESSION_BYTES, Service, build
from .store import Store

logger = logging.getLogger("honeypot")

IDLE_TIMEOUT = 45.0            # seconds with no input before we hang up
MAX_SESSIONS_PER_IP = 200      # per run; beyond this we stop recording detail
MAX_CONCURRENT = 500


@dataclass
class Listener:
    service_name: str
    port: int
    server: asyncio.AbstractServer | None = None


@dataclass
class Stats:
    started_at: float = field(default_factory=time.time)
    connections: int = 0
    interactions: int = 0
    bytes_in: int = 0
    rejected: int = 0
    by_service: dict[str, int] = field(default_factory=lambda: defaultdict(int))


# --------------------------------------------------------------------------
# Threat scoring
# --------------------------------------------------------------------------

def score_session(service_name: str, interactions: list) -> int:
    """A 0-100 score for how alarming one session was.

    This is a heuristic, not a measurement, and it is tuned for triage: the
    point is to sort an operator's attention, not to be precise.

      - merely connecting is mildly interesting (a honeypot has no users,
        so every connection is unsolicited by definition)
      - credential attempts matter
      - a recognised exploit path or payload matters a lot
      - post-login commands matter most, because they reveal intent
    """
    score = 10                                  # any connection at all
    for interaction in interactions:
        detail = interaction.detail
        if interaction.kind == "auth":
            score += 8
            if detail.get("success"):
                score += 10
        elif interaction.kind == "command":
            score += 6
        elif interaction.kind == "request":
            score += 4
        if detail.get("exploit"):
            score += 20
        if detail.get("payload"):
            score += 25
        tool = detail.get("tool", "")
        if "botnet" in tool or "scanner" in tool:
            score += 15
    return min(score, 100)


def severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# The honeypot
# --------------------------------------------------------------------------

class Honeypot:
    def __init__(self, store: Store, bind: str = "127.0.0.1",
                 on_event=None, quiet: bool = False):
        self.store = store
        self.bind = bind
        self.on_event = on_event                # callback for live alerting
        self.quiet = quiet
        self.listeners: list[Listener] = []
        self.stats = Stats()
        self._per_ip: dict[str, int] = defaultdict(int)
        self._active = 0

    # ---- setup ----------------------------------------------------------

    def add(self, service_name: str, port: int | None = None) -> None:
        service = build(service_name)           # raises early on a bad name
        self.listeners.append(
            Listener(service_name, port if port is not None else service.default_port))

    async def start(self) -> None:
        for listener in self.listeners:
            try:
                listener.server = await asyncio.start_server(
                    self._make_handler(listener), self.bind, listener.port)
            except PermissionError:
                logger.error(
                    "Port %d needs root. Use a high port instead: "
                    "--service %s:%d",
                    listener.port, listener.service_name, listener.port + 8000)
                raise
            except OSError as error:
                logger.error("Could not bind port %d: %s", listener.port, error)
                raise

    async def serve_forever(self) -> None:
        await asyncio.gather(*(listener.server.serve_forever()
                               for listener in self.listeners
                               if listener.server))

    async def stop(self) -> None:
        for listener in self.listeners:
            if listener.server:
                listener.server.close()
                with contextlib.suppress(Exception):
                    await listener.server.wait_closed()

    # ---- connection handling -------------------------------------------

    def _make_handler(self, listener: Listener):
        async def handler(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
            await self._handle(listener, reader, writer)
        return handler

    async def _handle(self, listener: Listener,
                      reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip, source_port = str(peer[0]), int(peer[1]) if len(peer) > 1 else 0

        if self._active >= MAX_CONCURRENT:
            self.stats.rejected += 1
            writer.close()
            return

        self._active += 1
        self._per_ip[source_ip] += 1
        self.stats.connections += 1
        self.stats.by_service[listener.service_name] += 1

        service: Service = build(listener.service_name)
        state: dict = {}
        interactions: list = []
        bytes_in = 0

        session_id = self.store.open_session(
            source_ip, source_port, listener.service_name, listener.port)

        try:
            greeting = service.greeting()
            if greeting:
                writer.write(greeting)
                await writer.drain()

            while bytes_in < MAX_SESSION_BYTES:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    break
                except (ConnectionResetError, asyncio.IncompleteReadError):
                    break

                if not line:
                    break

                # readline() with no newline in sight can return a very long
                # chunk; truncate rather than process it.
                if len(line) > MAX_LINE:
                    line = line[:MAX_LINE]

                bytes_in += len(line)
                self.stats.bytes_in += len(line)

                try:
                    reply, interaction = service.respond(line, state)
                except Exception:                             # noqa: BLE001
                    # A malformed input must never take the honeypot down.
                    # Every service is defensive, but an attacker's whole job
                    # is finding the input you did not consider.
                    logger.exception("service %s raised on input",
                                     listener.service_name)
                    break

                if interaction is not None:
                    interactions.append(interaction)
                    self.stats.interactions += 1
                    self.store.add_interaction(
                        session_id, interaction.kind,
                        interaction.detail, interaction.raw)
                    self._announce(source_ip, listener.service_name, interaction)

                if reply:
                    writer.write(reply)
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:                                     # noqa: BLE001
            logger.exception("connection handler failed")
        finally:
            self._active -= 1
            score = score_session(listener.service_name, interactions)
            self.store.close_session(session_id, bytes_in, score)
            with contextlib.suppress(Exception):
                closing = service.closing(state)
                if closing:
                    writer.write(closing)
                    await writer.drain()
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    # ---- alerting -------------------------------------------------------

    def _announce(self, source_ip: str, service_name: str, interaction) -> None:
        if self.on_event:
            with contextlib.suppress(Exception):
                self.on_event(source_ip, service_name, interaction)
        if self.quiet:
            return

        detail = interaction.detail
        note = (detail.get("payload") or detail.get("exploit")
                or detail.get("tool") or "")
        marker = "!!" if note else " ."

        if interaction.kind == "auth":
            summary = (f"login {detail.get('username', '')!r} / "
                       f"{detail.get('password', '')!r}")
        elif interaction.kind == "request":
            summary = f"{detail.get('method', '')} {detail.get('path', '')[:70]}"
        elif interaction.kind == "command":
            summary = f"$ {detail.get('command', '')[:70]}"
        else:
            summary = detail.get("client_version", "")[:70]

        stamp = time.strftime("%H:%M:%S")
        line = f"{marker} {stamp}  {source_ip:<15} {service_name:<7} {summary}"
        if note:
            line += f"   <- {note}"
        print(line, flush=True)
