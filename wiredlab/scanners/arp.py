from __future__ import annotations

import ipaddress
import itertools
import threading
from collections.abc import Iterator

from wiredlab.hostname import reverse_lookup
from wiredlab.interfaces import ipv4_network
from wiredlab.vendor import lookup_vendor


def scan(interface: str, stop_event: threading.Event, timeout: float = 2.0, max_hosts: int = 1024) -> Iterator[str]:
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run: pip install -r requirements.txt") from exc

    network = ipv4_network(interface)
    hosts = list(itertools.islice(network.hosts(), max_hosts + 1))

    if len(hosts) > max_hosts:
        yield f"[warn] Network {network} is larger than {max_hosts} hosts. Scanning first {max_hosts} hosts.\n"
        hosts = hosts[:max_hosts]

    if not hosts:
        yield f"[warn] No IPv4 hosts to scan on {network}.\n"
        return

    yield f"[info] ARP scan on {interface} targeting {network} ({len(hosts)} hosts)\n"
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=[str(host) for host in hosts])

    try:
        answered, _ = srp(packet, iface=interface, timeout=timeout, retry=1, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("Permission denied. Run the server with sudo/root for raw packet access.") from exc

    seen: set[tuple[str, str]] = set()
    for _, received in answered:
        if stop_event.is_set():
            break

        ip = str(received.psrc)
        mac = str(received.hwsrc).lower()
        key = (ip, mac)
        if key in seen or ipaddress.ip_address(ip) == network.network_address:
            continue
        seen.add(key)

        hostname = reverse_lookup(ip)
        vendor = lookup_vendor(mac)
        parts = [f"IP: {ip}", f"MAC: {mac}"]
        if hostname:
            parts.append(f"Hostname: {hostname}")
        if vendor:
            parts.append(f"Vendor: {vendor}")
        yield " ".join(parts) + "\n"

    yield f"[info] ARP scan finished. Hosts found: {len(seen)}\n"
