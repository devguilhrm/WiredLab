from __future__ import annotations

import argparse
import threading

from wiredlab.scanners import arp, dns, icmp6, routes


def emit(lines):
    for line in lines:
        print(line, end="", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="WiredLab Python CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("arp-scan", "icmp6-scan", "dns-monitor"):
        command = subparsers.add_parser(name)
        command.add_argument("--interface", required=True)

    subparsers.add_parser("routes")
    args = parser.parse_args()
    stop_event = threading.Event()

    try:
        if args.command == "arp-scan":
            emit(arp.scan(args.interface, stop_event))
        elif args.command == "icmp6-scan":
            emit(icmp6.scan(args.interface, stop_event))
        elif args.command == "dns-monitor":
            emit(dns.monitor(args.interface, stop_event))
        elif args.command == "routes":
            emit(routes.inspect(stop_event))
        return 0
    except KeyboardInterrupt:
        stop_event.set()
        return 130
    except Exception as exc:
        print(f"[error] {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
