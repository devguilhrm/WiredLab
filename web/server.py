#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
sys.path.insert(0, str(ROOT))

from wiredlab.interfaces import interface_names  # noqa: E402
from wiredlab.scanners import arp, dns, icmp6, routes  # noqa: E402


TOOLS = {
    "arp_scan": {"label": "ARP Scan", "interface": True, "fields": []},
    "icmp6_scan": {"label": "ICMPv6 Scan", "interface": True, "fields": []},
    "dns_monitor": {"label": "DNS Monitor All Devices", "interface": True, "fields": []},
    "routes": {"label": "Network Routes", "interface": False, "fields": []},
}


def run_tool(tool: str, interface: str, stop_event: threading.Event) -> Iterator[str]:
    if tool == "arp_scan":
        yield from arp.scan(interface, stop_event)
    elif tool == "icmp6_scan":
        yield from icmp6.scan(interface, stop_event)
    elif tool == "dns_monitor":
        yield from dns.monitor(interface, stop_event)
    elif tool == "routes":
        yield from routes.inspect(stop_event)
    else:
        raise ValueError("Unknown tool")


class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.worker: threading.Thread | None = None
        self.stop_event: threading.Event | None = None
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
            return self.worker is not None and self.worker.is_alive()

    def clear_worker(self, worker: threading.Thread):
        with self.lock:
            if self.worker is worker:
                self.worker = None
                self.stop_event = None
                self.current_tool = ""


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


def worker_main(tool: str, interface: str, stop_event: threading.Event):
    worker = threading.current_thread()
    code = 0

    try:
        for line in run_tool(tool, interface, stop_event):
            if not line.endswith("\n"):
                line += "\n"
            STATE.broadcast({"type": "log", "tool": tool, "text": line})
    except Exception as exc:
        code = 1
        STATE.broadcast({"type": "log", "tool": tool, "text": f"[error] {exc}\n"})
    finally:
        STATE.broadcast({"type": "exit", "tool": tool, "code": code, "text": f"[exit code {code}]\n"})
        STATE.clear_worker(worker)


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
            json_response(self, 200, {"interfaces": interface_names()})
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
                self.handle_stop()
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
        if tool not in TOOLS:
            raise ValueError("Unknown tool")

        spec = TOOLS[tool]
        interface = str(payload.get("interface", "")).strip()
        if spec.get("interface") and not interface:
            raise ValueError("Interface is required")

        with STATE.lock:
            if STATE.worker is not None and STATE.worker.is_alive():
                raise ValueError(f"Tool already running: {STATE.current_tool}")

            stop_event = threading.Event()
            worker = threading.Thread(target=worker_main, args=(tool, interface, stop_event), daemon=True)
            STATE.worker = worker
            STATE.stop_event = stop_event
            STATE.current_tool = tool
            worker.start()

        command = f"python3 -m wiredlab.cli {tool.replace('_', '-')} --interface {interface}"
        if tool == "routes":
            command = "python3 -m wiredlab.cli routes"
        STATE.broadcast({"type": "start", "tool": tool, "text": "$ " + command + "\n"})
        json_response(self, 200, {"ok": True, "tool": tool})

    def handle_stop(self):
        with STATE.lock:
            stop_event = STATE.stop_event
            current_tool = STATE.current_tool
            running = STATE.worker is not None and STATE.worker.is_alive()

        if stop_event is not None:
            stop_event.set()

        if running:
            STATE.broadcast({"type": "log", "tool": current_tool, "text": "[stop requested]\n"})

        json_response(self, 200, {"ok": True, "running": running})


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
