from __future__ import annotations

import queue
import threading
from collections.abc import Iterator


def monitor(interface: str, stop_event: threading.Event) -> Iterator[str]:
    try:
        from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, AsyncSniffer
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run: pip install -r requirements.txt") from exc

    events: queue.Queue[str] = queue.Queue(maxsize=1000)

    def handle_packet(packet):
        if DNS not in packet or DNSQR not in packet:
            return
        if int(packet[DNS].qr) != 0:
            return

        src_ip = ""
        if IP in packet:
            src_ip = str(packet[IP].src)
        elif IPv6 in packet:
            src_ip = str(packet[IPv6].src)
        if not src_ip:
            return

        src_mac = str(packet[Ether].src).lower() if Ether in packet else "00:00:00:00:00:00"
        transport = "UDP" if UDP in packet else "TCP" if TCP in packet else "DNS"

        query = packet[DNSQR].qname
        if isinstance(query, bytes):
            domain = query.decode("utf-8", errors="replace")
        else:
            domain = str(query)
        domain = domain.rstrip(".")
        if not domain:
            return

        line = f"DNSQuery SrcIP: {src_ip} SrcMAC: {src_mac} Transport: {transport} Domain: {domain}\n"
        try:
            events.put_nowait(line)
        except queue.Full:
            pass

    yield f"[info] DNS monitor listening on {interface}. Press Parar/Terminar to stop.\n"

    sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
    try:
        sniffer.start()
    except PermissionError as exc:
        raise RuntimeError("Permission denied. Run the server with sudo/root for raw packet access.") from exc

    try:
        while not stop_event.is_set():
            try:
                yield events.get(timeout=0.5)
            except queue.Empty:
                continue
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        yield "[info] DNS monitor stopped.\n"
