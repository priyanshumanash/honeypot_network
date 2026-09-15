"""
cli.py
------
Command-line entry point.

    python -m src.cli run                       # start the honeypot (localhost)
    python -m src.cli run --bind 0.0.0.0        # expose it (prints a warning)
    python -m src.cli demo                       # run + simulate attacks + report
    python -m src.cli report                     # analyse whatever is in the DB
    python -m src.cli credentials                # top attempted logins
    python -m src.cli attackers                  # ranked source IPs
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from . import simulate
from .honeypot import Honeypot, severity
from .services import SERVICES
from .store import Store

DEFAULT_SERVICES = ["ssh", "http", "ftp", "telnet", "smtp", "redis", "mysql"]

# High ports by default, so the honeypot runs without root. Real deployments
# map the real low ports to these with a firewall rule (see docs/05-deployment.md).
DEFAULT_OFFSET = 8000


def _parse_services(specs: list[str], offset: int) -> dict[str, int]:
    """Turn ['ssh', 'http:9090'] into {'ssh': 8022, 'http': 9090}."""
    ports: dict[str, int] = {}
    for spec in specs:
        if ":" in spec:
            name, _, port = spec.partition(":")
            ports[name] = int(port)
        else:
            from .services import build
            ports[spec] = build(spec).default_port + offset
    return ports


def _bar(value: int, maximum: int, width: int = 30) -> str:
    filled = int(width * value / maximum) if maximum else 0
    return "#" * filled + "." * (width - filled)


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

async def _run(ports: dict[str, int], bind: str, db: str,
               duration: float | None = None) -> None:
    store = Store(db)
    honeypot = Honeypot(store, bind=bind)
    for name, port in ports.items():
        honeypot.add(name, port)

    await honeypot.start()

    print(f"\n  Honeypot listening on {bind}")
    for name, port in sorted(ports.items(), key=lambda item: item[1]):
        print(f"    {name:<8} port {port:<6} ({SERVICES[name].description})")
    if bind == "0.0.0.0":
        print("\n  !! Bound to 0.0.0.0 -- this is reachable from other machines.")
        print("     Only do this on a network you intend to expose. See docs.")
    print(f"\n  Logging to {db}. Ctrl+C to stop.\n")
    print("  " + "-" * 74)

    try:
        if duration:
            await asyncio.sleep(duration)
        else:
            await honeypot.serve_forever()
    finally:
        await honeypot.stop()
        store.close()


def command_run(args) -> int:
    ports = _parse_services(args.service or DEFAULT_SERVICES, args.offset)
    try:
        asyncio.run(_run(ports, args.bind, args.db, args.duration))
    except KeyboardInterrupt:
        print("\n  Stopped.")
    return 0


# --------------------------------------------------------------------------
# demo -- the self-contained showcase
# --------------------------------------------------------------------------

async def _demo(ports: dict[str, int], db: str, count: int, seed: int) -> None:
    # Fresh database so the demo is reproducible.
    Path(db).unlink(missing_ok=True)
    store = Store(db)
    honeypot = Honeypot(store, bind="127.0.0.1")
    for name, port in ports.items():
        honeypot.add(name, port)
    await honeypot.start()

    print(f"\n  Honeypot up on 127.0.0.1 ({len(ports)} services). "
          f"Simulating {count} attacks...\n")
    print("  " + "-" * 74)

    # Attackers connect for real; the honeypot records for real.
    await simulate.run("127.0.0.1", ports, count=count, seed=seed)
    await asyncio.sleep(0.5)          # let the last handlers finish writing

    await honeypot.stop()
    print("  " + "-" * 74)
    _print_report(store)
    store.close()


def command_demo(args) -> int:
    ports = _parse_services(args.service or DEFAULT_SERVICES, args.offset)
    asyncio.run(_demo(ports, args.db, args.count, args.seed))
    print(f"\n  Full record in {args.db}. Explore it with:")
    print(f"    python -m src.cli report")
    print(f"    python -m src.cli credentials")
    print(f"    python -m src.cli attackers")
    print(f"    python -m src.app          (dashboard)\n")
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def _print_report(store: Store) -> None:
    summary = store.summary()
    if not summary["sessions"]:
        print("\n  No activity recorded yet.\n")
        return

    print(f"\n  SUMMARY")
    print(f"    sessions          {summary['sessions']:,}")
    print(f"    distinct sources  {summary['attackers']:,}")
    print(f"    interactions      {summary['interactions']:,}")
    print(f"    credential tries  {summary['credential_attempts']:,}")
    print(f"    bytes received    {summary['bytes_in']:,}")

    services = store.service_counts()
    if services:
        peak = max(row["sessions"] for row in services)
        print(f"\n  BY SERVICE")
        for row in services:
            print(f"    {row['service']:<8} {row['sessions']:>4}  "
                  f"{_bar(row['sessions'], peak)}")

    payloads = store.payload_counts(12)
    if payloads:
        print(f"\n  WHAT ATTACKERS TRIED")
        for label, count in payloads:
            print(f"    {count:>4}x  {label}")

    credentials = store.credentials(10)
    if credentials:
        print(f"\n  TOP CREDENTIALS")
        for username, password, count in credentials:
            print(f"    {count:>4}x  {username!r} / {password!r}")

    attackers = store.top_attackers(8)
    if attackers:
        print(f"\n  TOP SOURCES (by threat)")
        for row in attackers:
            print(f"    {row['source_ip']:<16} "
                  f"threat {row['threat']:>3} ({severity(row['threat'])})  "
                  f"{row['sessions']} sessions  "
                  f"{row['services']} services")
    print()


def command_report(args) -> int:
    store = Store(args.db)
    _print_report(store)
    store.close()
    return 0


def command_credentials(args) -> int:
    store = Store(args.db)
    credentials = store.credentials(args.limit)
    if not credentials:
        print("\n  No credential attempts recorded.\n")
    else:
        print(f"\n  Top {len(credentials)} attempted logins:\n")
        peak = credentials[0][2]
        for username, password, count in credentials:
            print(f"  {count:>5}x  {_bar(count, peak, 20)}  "
                  f"{username!r} / {password!r}")
        print()
    store.close()
    return 0


def command_attackers(args) -> int:
    store = Store(args.db)
    attackers = store.top_attackers(args.limit)
    if not attackers:
        print("\n  No sources recorded.\n")
    else:
        print(f"\n  {'source':<18} {'threat':>7} {'sessions':>9} "
              f"{'services':>9} {'interactions':>13}")
        print("  " + "-" * 62)
        for row in attackers:
            print(f"  {row['source_ip']:<18} "
                  f"{row['threat']:>3} {severity(row['threat']):<8} "
                  f"{row['sessions']:>9} {row['services']:>9} "
                  f"{row['interactions'] or 0:>13}")
        print()
    store.close()
    return 0


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="A low-interaction honeypot network.")
    parser.add_argument("--db", default="logs/honeypot.db",
                        help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="start the honeypot")
    p.add_argument("--service", action="append",
                   help="service, optionally with :port (repeatable)")
    p.add_argument("--bind", default="127.0.0.1",
                   help="bind address (0.0.0.0 to expose -- be careful)")
    p.add_argument("--offset", type=int, default=DEFAULT_OFFSET,
                   help="add this to each default port (avoids needing root)")
    p.add_argument("--duration", type=float, help="stop after N seconds")
    p.set_defaults(func=command_run)

    p = sub.add_parser("demo", help="run, simulate attacks, and report")
    p.add_argument("--service", action="append")
    p.add_argument("--offset", type=int, default=DEFAULT_OFFSET)
    p.add_argument("--count", type=int, default=40, help="number of attacks")
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=command_demo)

    p = sub.add_parser("report", help="analyse the recorded activity")
    p.set_defaults(func=command_report)

    p = sub.add_parser("credentials", help="most-attempted logins")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=command_credentials)

    p = sub.add_parser("attackers", help="ranked source addresses")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=command_attackers)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
