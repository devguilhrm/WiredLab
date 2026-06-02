#!/usr/bin/env python3
"""
Graphical launcher for the NetworkLab tools.

Run from the project root:
    python3 tools/network_gui.py
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "Bin"

HOST_RE = re.compile(r"IP:\s+([0-9a-fA-F:.]+)\s+MAC:\s+([0-9a-fA-F:-]{17})(?:\s+Vendor:\s+(.+))?")
DNS_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)+[A-Za-z]{2,}\.?$")


class ProcessRunner:
    def __init__(self, on_output, on_exit):
        self.process: subprocess.Popen[str] | None = None
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.on_output = on_output
        self.on_exit = on_exit

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, command: list[str], cwd: Path):
        if self.running():
            raise RuntimeError("A process is already running")

        self.process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        threading.Thread(target=self._read_output, daemon=True).start()
        threading.Thread(target=self._wait_process, daemon=True).start()

    def _read_output(self):
        assert self.process and self.process.stdout
        for line in self.process.stdout:
            self.on_output(line)

    def _wait_process(self):
        assert self.process
        code = self.process.wait()
        self.on_exit(code)

    def send_stop(self):
        if not self.running():
            return

        assert self.process
        try:
            if self.process.stdin:
                self.process.stdin.write("\n")
                self.process.stdin.flush()
        except OSError:
            pass

    def terminate(self):
        if not self.running():
            return

        assert self.process
        self.process.terminate()


class NetworkGui(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("NetworkLab")
        self.geometry("1180x760")
        self.minsize(980, 620)

        self.runner = ProcessRunner(self.append_output_threadsafe, self.process_finished_threadsafe)

        self.interface_var = tk.StringVar()
        self.bin_dir_var = tk.StringVar(value=str(BIN_DIR))
        self.auth_var = tk.BooleanVar(value=False)

        self.gateway4_var = tk.StringVar()
        self.host4_var = tk.StringVar()
        self.gateway6_var = tk.StringVar()
        self.host6_var = tk.StringVar()
        self.mac_var = tk.StringVar()

        self.status_var = tk.StringVar(value="Idle")
        self.host_count_var = tk.StringVar(value="0")
        self.dns_count_var = tk.StringVar(value="0")
        self.run_count_var = tk.StringVar(value="0")
        self.alert_count_var = tk.StringVar(value="0")

        self.current_tool = ""
        self.hosts_seen: set[tuple[str, str]] = set()
        self.dns_seen: set[str] = set()
        self.run_count = 0
        self.alert_count = 0

        self.configure_style()
        self.build_layout()

    def configure_style(self):
        self.configure(bg="#f5f7f8")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f5f7f8")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f5f7f8", foreground="#1f2933")
        style.configure("Panel.TLabel", background="#ffffff", foreground="#1f2933")
        style.configure("Heading.TLabel", font=("Segoe UI", 16, "bold"), background="#f5f7f8")
        style.configure("Muted.TLabel", background="#f5f7f8", foreground="#64748b")
        style.configure("TButton", padding=(12, 7))
        style.configure("Danger.TButton", foreground="#7f1d1d")
        style.configure("TEntry", padding=5)
        style.configure("TNotebook", background="#f5f7f8")
        style.configure("TNotebook.Tab", padding=(14, 8))
        style.configure("Treeview", rowheight=26)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def build_layout(self):
        root = ttk.Frame(self, padding=18)
        root.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(root)
        header.pack(fill=tk.X)

        title_block = ttk.Frame(header)
        title_block.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(title_block, text="NetworkLab", style="Heading.TLabel").pack(anchor=tk.W)
        ttk.Label(
            title_block,
            text="GUI para build e execucao autorizada das ferramentas C++ de rede",
            style="Muted.TLabel",
        ).pack(anchor=tk.W, pady=(2, 0))

        ttk.Button(header, text="Build", command=self.run_build).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(header, text="Stop", command=self.stop_process).pack(side=tk.RIGHT)

        settings = ttk.Frame(root, style="Panel.TFrame", padding=14)
        settings.pack(fill=tk.X, pady=(14, 12))

        self.field(settings, "Interface", self.interface_var, 0, 0, width=20)
        self.field(settings, "Binarios", self.bin_dir_var, 0, 2, width=48)
        ttk.Checkbutton(settings, text="Elevar via pkexec", variable=self.auth_var).grid(
            row=0, column=4, padx=(16, 0), sticky=tk.W
        )
        ttk.Button(settings, text="Atualizar interfaces", command=self.load_interfaces).grid(
            row=0, column=5, padx=(16, 0), sticky=tk.E
        )
        settings.columnconfigure(3, weight=1)

        body = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, padding=(0, 0, 12, 0))
        right = ttk.Frame(body)
        body.add(left, weight=1)
        body.add(right, weight=2)

        self.build_tabs(left)
        self.build_dashboard(right)
        self.build_console(right)

        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel").pack(anchor=tk.W, pady=(10, 0))

        self.load_interfaces()

    def field(self, parent, label, variable, row, column, width=24):
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=column, sticky=tk.W)
        entry = ttk.Entry(parent, textvariable=variable, width=width)
        entry.grid(row=row, column=column + 1, padx=(8, 10), sticky=tk.EW)
        return entry

    def build_tabs(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)

        discovery = ttk.Frame(notebook, padding=14)
        dns = ttk.Frame(notebook, padding=14)
        spoofing = ttk.Frame(notebook, padding=14)
        dhcp = ttk.Frame(notebook, padding=14)

        notebook.add(discovery, text="Discovery")
        notebook.add(dns, text="DNS")
        notebook.add(spoofing, text="Spoofing")
        notebook.add(dhcp, text="DHCP")

        ttk.Button(discovery, text="ARP Scan", command=lambda: self.run_tool("arp_scan", ["--interface", self.interface()])).pack(fill=tk.X)
        ttk.Button(discovery, text="ICMPv6 Scan", command=lambda: self.run_tool("icmp6_scan", ["--interface", self.interface()])).pack(fill=tk.X, pady=(8, 0))
        ttk.Button(discovery, text="Netlink Routes", command=lambda: self.run_tool("netlink", [])).pack(fill=tk.X, pady=(8, 0))

        self.field(dns, "MAC alvo", self.mac_var, 0, 0, width=28)
        ttk.Button(
            dns,
            text="Capturar DNS",
            command=lambda: self.run_tool("dns_scan", ["--interface", self.interface(), "--mac", self.mac_var.get().strip()]),
        ).grid(row=1, column=0, columnspan=2, pady=(12, 0), sticky=tk.EW)
        ttk.Button(dns, text="Consulta DNS demo", command=lambda: self.run_tool("dns_rr", ["--interface", self.interface()])).grid(
            row=2, column=0, columnspan=2, pady=(8, 0), sticky=tk.EW
        )
        dns.columnconfigure(1, weight=1)

        self.field(spoofing, "Gateway IPv4", self.gateway4_var, 0, 0)
        self.field(spoofing, "Host IPv4", self.host4_var, 1, 0)
        ttk.Button(
            spoofing,
            text="Iniciar ARP Spoofing",
            style="Danger.TButton",
            command=self.run_arp_spoofing,
        ).grid(row=2, column=0, columnspan=2, pady=(12, 18), sticky=tk.EW)

        self.field(spoofing, "Gateway IPv6", self.gateway6_var, 3, 0)
        self.field(spoofing, "Host IPv6", self.host6_var, 4, 0)
        ttk.Button(
            spoofing,
            text="Iniciar NDP Spoofing",
            style="Danger.TButton",
            command=self.run_ndp_spoofing,
        ).grid(row=5, column=0, columnspan=2, pady=(12, 0), sticky=tk.EW)
        spoofing.columnconfigure(1, weight=1)

        ttk.Button(
            dhcp,
            text="DHCP Starvation",
            style="Danger.TButton",
            command=self.run_dhcp_starvation,
        ).pack(fill=tk.X)
        ttk.Button(
            dhcp,
            text="Release clientes falsos",
            command=lambda: self.run_tool("release_fclients", ["--interface", self.interface()]),
        ).pack(fill=tk.X, pady=(8, 0))
        ttk.Button(
            dhcp,
            text="DHCPv6 demo",
            command=lambda: self.run_tool("dhcpv6", ["--interface", self.interface()]),
        ).pack(fill=tk.X, pady=(8, 0))
        ttk.Button(
            dhcp,
            text="DHCP server bind demo",
            command=lambda: self.run_tool("dhcp_server", ["--interface", self.interface()]),
        ).pack(fill=tk.X, pady=(8, 0))

    def build_console(self, parent):
        console_frame = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(console_frame, style="Panel.TFrame")
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="Saida", style="Panel.TLabel").pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Limpar", command=self.clear_output).pack(side=tk.RIGHT)

        self.output = tk.Text(
            console_frame,
            wrap=tk.WORD,
            bg="#101820",
            fg="#e5edf3",
            insertbackground="#e5edf3",
            relief=tk.FLAT,
            font=("Consolas", 10),
        )
        self.output.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

    def build_dashboard(self, parent):
        dashboard = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        dashboard.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        toolbar = ttk.Frame(dashboard, style="Panel.TFrame")
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="Dashboard", style="Panel.TLabel").pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Limpar dashboard", command=self.clear_dashboard).pack(side=tk.RIGHT)

        metrics = ttk.Frame(dashboard, style="Panel.TFrame")
        metrics.pack(fill=tk.X, pady=(10, 8))

        self.metric_card(metrics, "Hosts", self.host_count_var, 0)
        self.metric_card(metrics, "DNS", self.dns_count_var, 1)
        self.metric_card(metrics, "Execucoes", self.run_count_var, 2)
        self.metric_card(metrics, "Alertas", self.alert_count_var, 3)

        table_frame = ttk.Frame(dashboard, style="Panel.TFrame")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("kind", "target", "mac", "vendor", "source", "time")
        self.events = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        self.events.heading("kind", text="Tipo")
        self.events.heading("target", text="IP/Dominio")
        self.events.heading("mac", text="MAC")
        self.events.heading("vendor", text="Vendor/Info")
        self.events.heading("source", text="Fonte")
        self.events.heading("time", text="Hora")

        self.events.column("kind", width=82, minwidth=72, stretch=False)
        self.events.column("target", width=190, minwidth=140)
        self.events.column("mac", width=130, minwidth=120, stretch=False)
        self.events.column("vendor", width=220, minwidth=140)
        self.events.column("source", width=110, minwidth=90, stretch=False)
        self.events.column("time", width=86, minwidth=76, stretch=False)

        self.events.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.events.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.events.configure(yscrollcommand=scrollbar.set)

    def metric_card(self, parent, label, variable, column):
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        frame.grid(row=0, column=column, sticky=tk.EW, padx=(0 if column == 0 else 8, 0))
        parent.columnconfigure(column, weight=1)

        ttk.Label(frame, text=label, style="Panel.TLabel").pack(anchor=tk.W)
        ttk.Label(frame, textvariable=variable, style="Panel.TLabel", font=("Segoe UI", 20, "bold")).pack(anchor=tk.W)

    def interface(self) -> str:
        return self.interface_var.get().strip()

    def binary_path(self, name: str) -> Path:
        return Path(self.bin_dir_var.get().strip()) / name

    def command_with_auth(self, command: list[str]) -> list[str]:
        if not self.auth_var.get():
            return command
        if os.name == "posix" and os.geteuid() == 0:
            return command
        if shutil.which("pkexec"):
            return ["pkexec", *command]
        return command

    def validate_interface(self) -> bool:
        if self.interface():
            return True
        messagebox.showerror("Interface", "Informe o nome da interface, por exemplo eth0 ou wlan0.")
        return False

    def run_tool(self, name: str, args: list[str], dangerous: bool = False):
        if name != "netlink" and not self.validate_interface():
            return

        if dangerous and not self.confirm_dangerous(name):
            return

        binary = self.binary_path(name)
        if not binary.exists():
            messagebox.showerror("Binario nao encontrado", f"Nao encontrei: {binary}\nUse o botao Build primeiro.")
            return

        command = self.command_with_auth([str(binary), *args])
        self.start_command(command, BIN_DIR, name)

    def start_command(self, command: list[str], cwd: Path, tool_name: str = "build"):
        try:
            self.current_tool = tool_name
            self.run_count += 1
            self.run_count_var.set(str(self.run_count))
            if tool_name in {"arp_spoofing", "ndp_spoofing", "dhcp"}:
                self.alert_count += 1
                self.alert_count_var.set(str(self.alert_count))
            self.append_output("$ " + " ".join(command) + "\n")
            self.runner.start(command, cwd)
            self.status_var.set("Running")
        except Exception as exc:
            messagebox.showerror("Erro ao executar", str(exc))

    def run_build(self):
        command = ["cmake", "-S", str(ROOT), "-B", str(ROOT / "build")]
        self.start_command(command, ROOT, "build")
        self.after(1500, self.run_build_step_2)

    def run_build_step_2(self):
        if self.runner.running():
            self.after(1000, self.run_build_step_2)
            return
        self.start_command(["cmake", "--build", str(ROOT / "build")], ROOT, "build")

    def run_arp_spoofing(self):
        args = ["--interface", self.interface(), "--gateway", self.gateway4_var.get().strip(), "--host", self.host4_var.get().strip()]
        if not self.gateway4_var.get().strip() or not self.host4_var.get().strip():
            messagebox.showerror("Parametros", "Informe gateway e host IPv4.")
            return
        self.run_tool("arp_spoofing", args, dangerous=True)

    def run_ndp_spoofing(self):
        args = ["--interface", self.interface(), "--gateway", self.gateway6_var.get().strip(), "--host", self.host6_var.get().strip()]
        if not self.gateway6_var.get().strip() or not self.host6_var.get().strip():
            messagebox.showerror("Parametros", "Informe gateway e host IPv6.")
            return
        self.run_tool("ndp_spoofing", args, dangerous=True)

    def run_dhcp_starvation(self):
        self.run_tool("dhcp", ["--interface", self.interface()], dangerous=True)

    def confirm_dangerous(self, name: str) -> bool:
        return messagebox.askyesno(
            "Confirmar uso autorizado",
            f"{name} pode interromper trafego ou alterar estado da rede.\n\nExecute somente em laboratorio ou rede autorizada. Continuar?",
        )

    def stop_process(self):
        if not self.runner.running():
            return
        self.runner.send_stop()
        self.after(2500, self.force_stop_if_needed)

    def force_stop_if_needed(self):
        if self.runner.running():
            self.runner.terminate()

    def clear_output(self):
        self.output.delete("1.0", tk.END)

    def append_output(self, text: str):
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.parse_output(text)

    def append_output_threadsafe(self, text: str):
        self.after(0, self.append_output, text)

    def process_finished_threadsafe(self, code: int):
        self.after(0, self.process_finished, code)

    def process_finished(self, code: int):
        self.status_var.set(f"Finished with exit code {code}")
        self.append_output(f"\n[exit code {code}]\n")
        self.current_tool = ""

    def clear_dashboard(self):
        self.hosts_seen.clear()
        self.dns_seen.clear()
        self.run_count = 0
        self.alert_count = 0
        self.host_count_var.set("0")
        self.dns_count_var.set("0")
        self.run_count_var.set("0")
        self.alert_count_var.set("0")
        for item in self.events.get_children():
            self.events.delete(item)

    def parse_output(self, text: str):
        for raw_line in text.replace("\r", "\n").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("$ ") or line.startswith("[exit code"):
                continue

            host_match = HOST_RE.search(line)
            if host_match:
                ip, mac, vendor = host_match.groups()
                self.record_host(ip, mac, vendor or "")
                continue

            if self.current_tool == "dns_scan" and DNS_RE.match(line):
                self.record_dns(line)

    def record_host(self, ip: str, mac: str, vendor: str):
        key = (ip, mac.lower())
        if key in self.hosts_seen:
            return

        self.hosts_seen.add(key)
        self.host_count_var.set(str(len(self.hosts_seen)))
        self.add_event("Host", ip, mac, vendor, self.current_tool or "scan")

    def record_dns(self, domain: str):
        normalized = domain.rstrip(".").lower()
        if normalized in self.dns_seen:
            return

        self.dns_seen.add(normalized)
        self.dns_count_var.set(str(len(self.dns_seen)))
        self.add_event("DNS", normalized, "", "query", "dns_scan")

    def add_event(self, kind: str, target: str, mac: str, vendor: str, source: str):
        now = datetime.now().strftime("%H:%M:%S")
        self.events.insert("", 0, values=(kind, target, mac, vendor, source, now))

    def load_interfaces(self):
        if os.name != "posix":
            return

        try:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=False)
        except OSError:
            return

        names = []
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                names.append(parts[1].strip())

        if names and not self.interface():
            for name in names:
                if name != "lo":
                    self.interface_var.set(name)
                    break


if __name__ == "__main__":
    app = NetworkGui()
    app.mainloop()
