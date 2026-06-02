from __future__ import annotations

import random
import threading
from collections.abc import Iterator

from wiredlab.hostname import reverse_lookup
from wiredlab.vendor import lookup_vendor


def scan(interface: str, stop_event: threading.Event, timeout: float = 3.0) -> Iterator[str]:
    try:
        from scapy.all import Ether, ICMPv6EchoRequest, IPv6, srp
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run: pip install -r requirements.txt") from exc

    echo_id = random.randint(1, 65535)
    packet = (
        Ether(dst="33:33:00:00:00:01")
        / IPv6(dst="ff02::1")
        / ICMPv6EchoRequest(id=echo_id)
    )

    yield f"[info] ICMPv6 multicast scan on {interface}\n"

    try:
        answered, _ = srp(packet, iface=interface, timeout=timeout, multi=True, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("Permission denied. Run the server with sudo/root for raw packet access.") from exc

    seen: set[str] = set()
    for _, received in answered:
        if stop_event.is_set():
            break
        if IPv6 not in received:
            continue

        ip = str(received[IPv6].src)
        mac = str(received.src).lower()
        if ip in seen:
            continue
        seen.add(ip)

        hostname = reverse_lookup(ip)
        vendor = lookup_vendor(mac)
        parts = [f"IP: {ip}", f"MAC: {mac}"]
        if hostname:
            parts.append(f"Hostname: {hostname}")
        if vendor:
            parts.append(f"Vendor: {vendor}")
        yield " ".join(parts) + "\n"

    yield f"[info] ICMPv6 scan finished. Hosts found: {len(seen)}\n"
