#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
BIN_DIR = ROOT / "Bin"


TOOLS = {
    "arp_scan": {"label": "ARP Scan", "interface": True, "fields": []},
    "icmp6_scan": {"label": "ICMPv6 Scan", "interface": True, "fields": []},
    "dns_monitor": {"label": "DNS Monitor All Devices", "interface": True, "fields": []},
    "dns_scan": {"label": "DNS Capture", "interface": True, "fields": ["mac"]},
    "netlink": {"label": "Netlink Routes", "interface": False, "fields": []},
    "dns_rr": {"label": "DNS Query Demo", "interface": True, "fields": []},
    "dhcpv6": {"label": "DHCPv6 Demo", "interface": True, "fields": []},
    "dhcp_server": {"label": "DHCP Server Bind Demo", "interface": True, "fields": []},
    "release_fclients": {"label": "Release False Clients", "interface": True, "fields": []},
    "arp_spoofing": {"label": "ARP Spoofing", "interface": True, "fields": ["gateway", "host"], "dangerous": True},
    "ndp_spoofing": {"label": "NDP Spoofing", "interface": True, "fields": ["gateway", "host"], "dangerous": True},
    "dhcp": {"label": "DHCP Starvation", "interface": True, "fields": [], "dangerous": True},
}


class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.process: subprocess.Popen[str] | None = None
        self.current_tool = ""
        self.clients: list[queue.Queue[dict]] = []
        self.history: list[dict] = []

    def broadcast(self, event: dict):
        with self.lock:
            self.history.append(event)
            self.history = self.history[-200:]
            clients = list(self.clients)

        for client in clients:
            try:
                client.put_nowait(event)
            except queue.Full:
                pass

    def add_client(self) -> queue.Queue[dict]:
        client: queue.Queue[dict] = queue.Queue(maxsize=200)
        with self.lock:
            self.clients.append(client)
            history = list(self.history)

        for event in history:
            try:
                client.put_nowait(event)
            except queue.Full:
                break

        return client

    def remove_client(self, client: queue.Queue[dict]):
        with self.lock:
            if client in self.clients:
                self.clients.remove(client)

    def running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None


STATE = AppState()


def json_response(handler: BaseHTTPRequestHandler, status: int, data: dict | list):
    payload = json.dumps(data).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    return json.loads(handler.rfile.read(length).decode("utf-8"))


def command_for(tool: str, payload: dict) -> list[str]:
    if tool not in TOOLS:
        raise ValueError("Unknown tool")

    spec = TOOLS[tool]
    binary = BIN_DIR / tool
    if not binary.exists():
        raise ValueError(f"Binary not found: {binary}")

    command = [str(binary)]

    interface = str(payload.get("interface", "")).strip()
    if spec.get("interface"):
        if not interface:
            raise ValueError("Interface is required")
        command += ["--interface", interface]

    for field in spec.get("fields", []):
        value = str(payload.get(field, "")).strip()
        if not value:
            raise ValueError(f"{field} is required")
        command += [f"--{field}", value]

    if shutil.which("stdbuf"):
        command = ["stdbuf", "-oL", "-eL", *command]

    return command


def stream_process_output(process: subprocess.Popen[str], tool: str):
    assert process.stdout is not None

    for line in process.stdout:
        STATE.broadcast({"type": "log", "tool": tool, "text": line})

    code = process.wait()
    STATE.broadcast({"type": "exit", "tool": tool, "code": code, "text": f"[exit code {code}]\n"})

    with STATE.lock:
        if STATE.process is process:
            STATE.process = None
            STATE.current_tool = ""


def list_interfaces() -> list[str]:
    try:
        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=False)
    except OSError:
        return []

    names: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) >= 2:
            name = parts[1].strip()
            if name:
                names.append(name)
    return names


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args):
        return

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self.serve_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/static/styles.css":
            self.serve_file(WEB_DIR / "static" / "styles.css", "text/css; charset=utf-8")
        elif path == "/static/app.js":
            self.serve_file(WEB_DIR / "static" / "app.js", "application/javascript; charset=utf-8")
        elif path == "/api/tools":
            json_response(self, 200, TOOLS)
        elif path == "/api/interfaces":
            json_response(self, 200, {"interfaces": list_interfaces()})
        elif path == "/api/status":
            json_response(self, 200, {"running": STATE.running(), "tool": STATE.current_tool})
        elif path == "/api/events":
            self.serve_events()
        else:
            json_response(self, 404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path

        try:
            if path == "/api/run":
                self.handle_run()
            elif path == "/api/stop":
                self.handle_stop()
            elif path == "/api/kill":
                self.handle_kill()
            else:
                json_response(self, 404, {"error": "Not found"})
        except ValueError as exc:
            json_response(self, 400, {"error": str(exc)})
        except Exception as exc:
            json_response(self, 500, {"error": str(exc)})

    def serve_file(self, path: Path, content_type: str):
        if not path.exists():
            json_response(self, 404, {"error": "Not found"})
            return

        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_events(self):
        client = STATE.add_client()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        try:
            while True:
                try:
                    event = client.get(timeout=20)
                    data = json.dumps(event)
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            STATE.remove_client(client)

    def handle_run(self):
        payload = read_body(self)
        tool = str(payload.get("tool", "")).strip()
        command = command_for(tool, payload)

        with STATE.lock:
            if STATE.process is not None and STATE.process.poll() is None:
                raise ValueError(f"Tool already running: {STATE.current_tool}")

            process = subprocess.Popen(
                command,
                cwd=str(BIN_DIR),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
            STATE.process = process
            STATE.current_tool = tool

        STATE.broadcast({"type": "start", "tool": tool, "text": "$ " + " ".join(command) + "\n"})
        threading.Thread(target=stream_process_output, args=(process, tool), daemon=True).start()
        json_response(self, 200, {"ok": True, "tool": tool})

    def handle_stop(self):
        with STATE.lock:
            process = STATE.process

        if process is None or process.poll() is not None:
            json_response(self, 200, {"ok": True, "running": False})
            return

        try:
            if process.stdin:
                process.stdin.write("\n")
                process.stdin.flush()
        except OSError:
            pass

        STATE.broadcast({"type": "log", "tool": STATE.current_tool, "text": "[stop requested]\n"})
        json_response(self, 200, {"ok": True, "running": True})

    def handle_kill(self):
        with STATE.lock:
            process = STATE.process

        if process is None or process.poll() is not None:
            json_response(self, 200, {"ok": True, "running": False})
            return

        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
        except OSError:
            pass

        STATE.broadcast({"type": "log", "tool": STATE.current_tool, "text": "[terminate requested]\n"})
        json_response(self, 200, {"ok": True, "running": True})


def main():
    parser = argparse.ArgumentParser(description="WiredLab web dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address. Use 0.0.0.0 for LAN access.")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"WiredLab web dashboard: http://{args.host}:{args.port}")
    print("Use Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
