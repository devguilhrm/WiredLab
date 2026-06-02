from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    is_up: bool


def list_interfaces() -> list[NetworkInterface]:
    interfaces: list[NetworkInterface] = []
    sys_class = Path("/sys/class/net")

    if sys_class.exists():
        for path in sorted(sys_class.iterdir()):
            operstate = path / "operstate"
            state = operstate.read_text(encoding="utf-8").strip() if operstate.exists() else ""
            interfaces.append(NetworkInterface(path.name, state in {"up", "unknown"}))
        return interfaces

    return [NetworkInterface(name, True) for _, name in socket.if_nameindex()]


def interface_names() -> list[str]:
    return [interface.name for interface in list_interfaces()]


def run_json(command: list[str]) -> object:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return json.loads(result.stdout or "[]")


def ipv4_network(interface: str) -> ipaddress.IPv4Network:
    data = run_json(["ip", "-j", "-4", "addr", "show", "dev", interface])
    if not isinstance(data, list) or not data:
        raise RuntimeError(f"interface has no IPv4 address: {interface}")

    addr_info = data[0].get("addr_info", [])
    for item in addr_info:
        local = item.get("local")
        prefixlen = item.get("prefixlen")
        if local and prefixlen is not None:
            return ipaddress.IPv4Interface(f"{local}/{prefixlen}").network

    raise RuntimeError(f"interface has no IPv4 address: {interface}")
