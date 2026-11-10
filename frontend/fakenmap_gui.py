# -*- coding: utf-8 -*-
"""
Fake Nmap GUI - a Zenmap/Nmap-style graphical front end.

The Python UI talks to the Rust backend (fakenmap.exe / fakenmap) exactly the
way Zenmap talks to Nmap: it launches the engine, streams its output live into
the "Nmap Output" tab and, once the scan finishes, parses the structured JSON
it requests via -oJ to populate the Ports/Hosts, Topology and Host Details
tabs.

Requires: Python 3.8+ with tkinter (bundled with most installers).
Backends: a compiled ``fakenmap`` binary - searched in:
  1. $FAKENMAP_BIN
  2. <project>/backend/target/release/fakenmap(.exe)
  3. <project>/backend/target/debug/fakenmap(.exe)
  4.  fakenmap on PATH
"""

import os
import queue
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Fake Nmap"
VERSION = "1.0.0"

if sys.platform.startswith("win"):
    CREATE_NO_WINDOW = 0x08000000
else:
    CREATE_NO_WINDOW = 0


# ---------------------------------------------------------------------------
# Look & feel
# ---------------------------------------------------------------------------
class Palette:
    BG = "#f4f6fb"
    PANEL = "#e8ecf5"
    OU = "#ffffff"
    TEXT = "#1c2430"
    ACCENT = "#2b579a"
    ACCENT_DARK = "#1d3f73"
    HEADER_BG = "#dbe4f2"
    GREEN = "#2e7d32"
    RED = "#c62828"
    ORANGE = "#b26a00"
    BLUE = "#0d47a1"
    MUTED = "#5a6b7f"
    OUTPUT_BG = "#10161f"
    OUTPUT_FG = "#d8dee9"


PROFILES = {
    "Intense scan": "-T4 -A -v",
    "Intense scan plus UDP": "-sT -sU -T4 -A -v",
    "Intense scan, all TCP ports": '-p "1-65535" -T4 -A -v',
    "Intense scan, no ping": "-T4 -A -v -Pn",
    "Ping scan": "-sn",
    "Quick scan": "-T4 -F",
    "Quick scan plus": "-sV -T4 -O -F",
    "Quick scan (UDP ports)": "-sU -T4 -F",
    "Regular scan": "-sT",
    "Slow comprehensive scan": "-sT -sU -T4 -A -v",
    "custom": "",
}


def find_backend():
    env = os.environ.get("FAKENMAP_BIN")
    if env and os.path.isfile(env):
        return env
    root = Path(__file__).resolve().parent.parent
    exe = "fakenmap.exe" if sys.platform.startswith("win") else "fakenmap"
    cands = [
        root / "backend" / "target" / "release" / exe,
        root / "backend" / "target" / "debug" / exe,
        Path(__file__).parent / exe,
    ]
    for c in cands:
        if c.is_file():
            return str(c)
    return exe


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class FakeNmapApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("1080x720")
        self.minsize(900, 620)

        self.backend = find_backend()
        self.scan_process = None
        self.scan_started = None
        self._cancel_flag = threading.Event()
        self.output_queue = queue.Queue()
        self.current_scan_id = None
        self.current_json = None
        self.history = []          # list of dict(ts, command, target, json_path, text)
        self.topology_nodes = {}   # ip -> (x, y)

        self.option_add("*tearOff", False)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".",
                        background=Palette.BG,
                        foreground=Palette.TEXT,
                        fieldbackground="white")
        style.configure("TNotebook", background=Palette.BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        padding=(14, 6), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", Palette.ACCENT)],
                  foreground=[("selected", "white")])
        style.configure("Accent.TButton",
                        font=("Segoe UI", 10, "bold"),
                        foreground="white",
                        background=Palette.ACCENT,
                        padding=(16, 6))
        style.map("Accent.TButton",
                  background=[("active", Palette.ACCENT_DARK),
                              ("disabled", "#9db3d1")])
        style.configure("TButton", padding=(12, 4))
        style.configure("TCombobox", padding=3)
        style.configure("Treeview",
                        background="white", fieldbackground="white",
                        rowheight=22)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        self._build_menu()
        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(80, self._pump_queue)
        self.status("Ready. Pick a profile and target, then press Scan.")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self)

        m_file = tk.Menu(menubar)
        m_file.add_command(label="Save Output...", command=self.save_output)
        m_file.add_command(label="Save All Scans...", command=self.save_all)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=m_file)

        m_scan = tk.Menu(menubar)
        m_scan.add_command(label="Scan", accelerator="Ctrl+Shift+S",
                           command=self.start_scan)
        m_scan.add_command(label="Cancel Scan", accelerator="Ctrl+Shift+X",
                           command=self.cancel_scan)
        m_scan.add_separator()
        for name in PROFILES:
            m_scan.add_command(label=name,
                               command=lambda n=name: self.apply_profile(n))
        menubar.add_cascade(label="Scan", menu=m_scan)

        m_help = tk.Menu(menubar)
        m_help.add_command(label="About Fake Nmap", command=self.show_about)
        menubar.add_cascade(label="Help", menu=m_help)

        self.config(menu=menubar)
        self.bind_all("<Control-Shift-S>", lambda e: self.start_scan())
        self.bind_all("<Control-Shift-X>", lambda e: self.cancel_scan())
        self.bind_all("<Control-Return>", lambda e: self.start_scan())

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=Palette.PANEL, padx=12, pady=8)
        bar.pack(fill="x")

        self.logo = tk.Canvas(bar, width=34, height=34, bg=Palette.PANEL,
                              highlightthickness=0)
        self.logo.pack(side="left", padx=(0, 10))
        self._draw_logo()

        tk.Label(bar, text="Target:", bg=Palette.PANEL,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(bar, textvariable=self.target_var, width=26,
                                      font=("Consolas", 10))
        self.target_entry.pack(side="left", padx=(4, 12))

        tk.Label(bar, text="Profile:", bg=Palette.PANEL,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        self.profile_var = tk.StringVar(value="Quick scan")
        self.profile_box = ttk.Combobox(bar, textvariable=self.profile_var,
                                        values=list(PROFILES.keys()),
                                        state="readonly", width=22)
        self.profile_box.pack(side="left", padx=(4, 12))
        self.profile_box.bind("<<ComboboxSelected>>",
                              lambda e: self.apply_profile(self.profile_var.get()))

        tk.Label(bar, text="Command:", bg=Palette.PANEL,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(bar, textvariable=self.cmd_var,
                                   font=("Consolas", 10), width=30)
        self.cmd_entry.pack(side="left", padx=(4, 12), fill="x", expand=True)

        self.scan_btn = ttk.Button(bar, text="Scan", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.cancel_btn = ttk.Button(bar, text="Cancel", command=self.cancel_scan,
                                     state="disabled")
        self.cancel_btn.pack(side="left", padx=(6, 0))

        # Initial profile.
        self.apply_profile(self.profile_var.get())

    def _draw_logo(self):
        c = self.logo
        c.delete("all")
        accent = Palette.ACCENT
        c.create_polygon(17, 2, 32, 17, 17, 32, 2, 17,
                         outline=accent, width=2, fill=Palette.BG)
        c.create_text(17, 17, text="N", font=("Segoe UI", 15, "bold"),
                      fill=accent)

    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(6, 0))
        self._build_output_tab()
        self._build_ports_tab()
        self._build_topology_tab()
        self._build_details_tab()
        self._build_scans_tab()

    def _build_output_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" Nmap Output ")
        self.out_text = tk.Text(f, bg=Palette.OUTPUT_BG, fg=Palette.OUTPUT_FG,
                                insertbackground=Palette.OUTPUT_FG,
                                wrap="none", font=("Consolas", 9), padx=8, pady=6,
                                state="disabled")
        ys = ttk.Scrollbar(f, orient="vertical", command=self.out_text.yview)
        xs = ttk.Scrollbar(f, orient="horizontal", command=self.out_text.xview)
        self.out_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.out_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

        self._out_tags()

    def _out_tags(self):
        t = self.out_text
        t.tag_configure("start", foreground="#81a1c1", font=("Consolas", 9, "bold"))
        t.tag_configure("host", foreground="#88c0d0", font=("Consolas", 9, "bold"))
        t.tag_configure("up", foreground=Palette.GREEN, font=("Consolas", 9, "bold"))
        t.tag_configure("open", foreground="#7fd77f", font=("Consolas", 9, "bold"))
        t.tag_configure("closed", foreground="#e07b7b")
        t.tag_configure("filtered", foreground="#e5b36b")
        t.tag_configure("ws", foreground=Palette.OUTPUT_FG)
        t.tag_configure("done", foreground="#88c0d0", font=("Consolas", 9, "bold"))
        t.tag_configure("head", foreground="#d8dee9", font=("Consolas", 9, "bold"))
        t.tag_configure("warn", foreground="#e5b36b")

    def _build_ports_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" Ports / Hosts ")
        cols = ("proto", "port", "state", "reason", "service", "version")
        self.tree = ttk.Treeview(f, columns=cols, show="tree headings")
        for cid, text, w in (
                ("proto", "Protocol", 80),
                ("port", "Port", 70),
                ("state", "State", 90),
                ("reason", "Reason", 130),
                ("service", "Service", 160),
                ("version", "Version", 300)):
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w, anchor="w")
        self.tree.heading("#0", text="Host")
        self.tree.column("#0", width=270)
        self.tree.tag_configure("open", foreground=Palette.GREEN)
        self.tree.tag_configure("closed", foreground=Palette.RED)
        self.tree.tag_configure("filtered", foreground=Palette.ORANGE)
        self.tree.tag_configure("openfiltered", foreground=Palette.BLUE)
        self.tree.tag_configure("host_up", foreground=Palette.TEXT,
                                font=("Segoe UI", 10, "bold"))
        self.tree.tag_configure("host_down", foreground=Palette.MUTED)
        ys = ttk.Scrollbar(f, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

    def _build_topology_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" Topology ")
        self.topo = tk.Canvas(f, bg="white", highlightthickness=0)
        ys = ttk.Scrollbar(f, orient="vertical", command=self.topo.yview)
        xs = ttk.Scrollbar(f, orient="horizontal", command=self.topo.xview)
        self.topo.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.topo.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.topo.bind("<Button-1>", self._topo_click)
        self.topo.bind("<Configure>", lambda e: self.render_topology())

    def _build_details_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" Host Details ")
        pad = 10
        self.details = tk.Text(f, bg="#ffffff", fg=Palette.TEXT,
                               font=("Segoe UI", 9), padx=pad, pady=pad,
                               relief="flat", state="disabled")
        ys = ttk.Scrollbar(f, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=ys.set)
        self.details.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.details.tag_configure("h", font=("Segoe UI", 12, "bold"),
                                   foreground=Palette.ACCENT_DARK)
        self.details.tag_configure("l", font=("Segoe UI", 9, "bold"),
                                   foreground=Palette.MUTED)
        self.details.tag_configure("v", foreground=Palette.TEXT)
        self.details.tag_configure("green", foreground=Palette.GREEN)
        self.details.tag_configure("red", foreground=Palette.RED)
        self._write_details("Select a host in the Ports / Hosts tree or on the\nTopology map to inspect it here.")

    def _build_scans_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" Scans ")
        left = ttk.Frame(f)
        left.pack(side="left", fill="y", padx=8, pady=8)
        tk.Label(left, text="Scan history", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hist_list = tk.Listbox(left, width=48, height=18,
                                    font=("Consolas", 9),
                                    selectmode=tk.SINGLE)
        self.hist_list.pack(fill="both", expand=True, pady=4)
        btns = ttk.Frame(left)
        btns.pack(fill="x")
        ttk.Button(btns, text="Load", command=self.load_history).pack(side="left")
        ttk.Button(btns, text="Delete", command=self.delete_history).pack(side="left", padx=6)

        right = ttk.Frame(f)
        right.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=8)
        tk.Label(right, text="Info", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.hist_info = tk.Text(right, width=50, height=22, font=("Segoe UI", 9),
                                 state="disabled", relief="flat")
        self.hist_info.pack(fill="both", expand=True, pady=4)

    def _build_statusbar(self):
        self.status_var = tk.StringVar()
        bar = tk.Frame(self, bg=Palette.HEADER_BG, height=24)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status_var, bg=Palette.HEADER_BG,
                 anchor="w", padx=12, font=("Segoe UI", 9)).pack(fill="x")

    # ------------------------------------------------------------------
    # Profiles & commands
    # ------------------------------------------------------------------
    def apply_profile(self, name):
        self.profile_var.set(name)
        if name in PROFILES:
            self.cmd_var.set(PROFILES[name])

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def _build_args(self):
        cmd = self.cmd_var.get().strip()
        target = self.target_var.get().strip()
        tokens = shlex.split(cmd, posix=True)
        if not target:
            raise ValueError("No target specified.")
        # Append the target(s) at the end. If the user already typed targets
        # into the command field, use those instead.
        non_flag_targets = [t for t in tokens if not t.startswith("-")]
        tokens = [t for t in tokens if t.startswith("-")]
        if non_flag_targets:
            targets = non_flag_targets
        else:
            targets = shlex.split(target, posix=True)
        return tokens + targets

    def start_scan(self):
        if self.scan_process is not None and self.scan_process.poll() is None:
            messagebox.showinfo(APP_NAME, "A scan is already running.")
            return
        try:
            args = self._build_args()
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        if not os.path.isfile(self.backend):
            answer = messagebox.askyesno(
                APP_NAME,
                "The Rust backend was not found at:\n"
                f"    {self.backend}\n\n"
                "It must be built first, e.g.:\n"
                "    cd backend && cargo build --release\n\n"
                "Build it now?")
            if answer:
                if not self._build_backend():
                    return
            else:
                return

        # Fresh output.
        self._reset_output()
        self.status("Starting scan...")
        self.scan_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")

        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        json_path = tmp.name
        full = args + ["-oJ", json_path]
        display = "fakenmap " + " ".join(full)

        self._out_text_append("Starting Fake Nmap {v} ( https://fakenmap.local )\n".format(v=VERSION), "start")
        self._out_text_append(f"Backend   : {self.backend}\n", "head")
        self._out_text_append(f"Command   : {display}\n\n", "head")

        self._cancel_flag.clear()
        self.scan_started = time.time()
        self.current_json = json_path
        self._record_meta = {"command": display, "target": args[-1] if args else ""}
        self.current_scan_id = int(time.time())

        try:
            self.scan_process = subprocess.Popen(
                [self.backend] + full,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as e:
            self.status(f"Failed to launch backend: {e}")
            self._end_scan_run()
            return

        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        proc = self.scan_process
        assert proc.stdout is not None
        try:
            for raw in proc.stdout:
                text = raw.decode("utf-8", errors="replace")
                self.output_queue.put(("line", text))
        finally:
            code = proc.wait()
            self.output_queue.put(("done", code))

    def _pump_queue(self):
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "line":
                    self._append_colored(payload)
                elif kind == "done":
                    self._finalize(payload)
        except queue.Empty:
            pass
        self.after(80, self._pump_queue)

    def _finalize(self, code):
        elapsed = time.time() - (self.scan_started or time.time())
        self._end_scan_run()

        # Populate the structured tabs from JSON.
        data = None
        try:
            data = self._load_json(self.current_json)
            self._last_data = data
        except Exception as e:
            self.status(f"Scan finished in {elapsed:.2f}s but JSON parse failed: {e}")

        self._out_text_append(
            f"\nScan finished in {elapsed:.2f}s (exit code {code}).\n", "done")
        self.status(
            f"Scan finished in {elapsed:.2f}s ({self._summary_text()})")

        # Save to history.
        entry = {
            "id": self.current_scan_id,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
            "command": self._record_meta.get("command", ""),
            "target": self._record_meta.get("target", ""),
            "json": self.current_json,
            "data": data,
            "text": self._dump_output(),
        }
        self.history.append(entry)
        self._refresh_history()
        self.render_ports_tree(data)
        self.render_topology()

    def _end_scan_run(self):
        self.scan_process = None
        self.scan_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")

    def cancel_scan(self):
        if self.scan_process is None or self.scan_process.poll() is not None:
            return
        self.status("Cancelling scan...")
        try:
            if sys.platform.startswith("win"):
                subprocess.run(
                    ["taskkill", "/PID", str(self.scan_process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW)
            else:
                self.scan_process.kill()
        except Exception:
            try:
                self.scan_process.kill()
            except Exception:
                pass

    def _build_backend(self):
        root = Path(__file__).resolve().parent.parent
        self.status("Building the Rust backend (cargo build --release)...")
        p = subprocess.run(["cargo", "build", "--release"],
                           cwd=str(root / "backend"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode == 0:
            self.backend = find_backend()
            self.status("Backend built successfully.")
            return True
        messagebox.showerror(APP_NAME, "cargo build failed:\n" +
                             p.stdout.decode("utf-8", "replace")[-1500:])
        return False

    # ------------------------------------------------------------------
    # Output widget
    # ------------------------------------------------------------------
    def _reset_output(self):
        self.out_text.config(state="normal")
        self.out_text.delete("1.0", "end")
        self.out_text.config(state="disabled")

    def _dump_output(self):
        return self.out_text.get("1.0", "end")

    def _out_text_append(self, text, tag=None):
        self.out_text.config(state="normal")
        self.out_text.insert("end", text, tag or ())
        self.out_text.config(state="disabled")

    def _append_colored(self, line):
        line = line.rstrip("\n")
        if not line:
            self._out_text_append("\n")
            return
        low = line.lower()

        if low.startswith("starting fake nmap") or low.startswith("starting nmap"):
            tag = "start"
        elif low.startswith("nmap scan report"):
            tag = "host"
        elif low.startswith("host is up"):
            tag = "up"
        elif "open|filtered" in low or "closed|filtered" in low:
            tag = "filtered"
        elif "nmap done" in low or low.startswith("scan finished"):
            tag = "done"
        elif low.startswith("warning") or low.startswith("note:"):
            tag = "warn"
        elif "\t" in line or " /tcp" in line or "/tcp " in line or "/udp" in line:
            self._append_banner(line)
            return
        else:
            tag = "ws"
        self._out_text_append(line + "\n", tag)

    def _append_banner(self, line):
        for word in ("open|filtered", "open"):
            if word in line:
                self._out_text_append(line + "\n", "open")
                return
        if "closed" in line:
            self._out_text_append(line + "\n", "closed")
            return
        if "filtered" in line:
            self._out_text_append(line + "\n", "filtered")
            return
        self._out_text_append(line + "\n", "ws")

    def _summary_text(self):
        if not hasattr(self, "_last_data") or not self._last_data:
            return "0 hosts up"
        hs = self._last_data.get("hosts", [])
        up = [h for h in hs if h.get("status") == "up"]
        return f"{len(up)} hosts up"

    # ------------------------------------------------------------------
    # JSON handling
    # ------------------------------------------------------------------
    def _load_json(self, path):
        import json
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def render_ports_tree(self, data):
        self.tree.delete(*self.tree.get_children())
        if not data:
            return
        hosts = data.get("hosts", [])
        self._last_data = data
        iid = 0
        for h in hosts:
            iid += 1
            ip = h.get("ip", "")
            hostname = h.get("hostname", "")
            status = h.get("status", "down")
            label = f"{ip}" + (f" ({hostname})" if hostname else "")
            open_n = len([p for p in h.get("ports", [])
                          if p.get("state") in ("open", "open|filtered")])
            total = len(h.get("ports", []))
            text = f"{label}   [{status}, {open_n} open]"
            parent_iid = f"H{iid}"
            self.tree.insert(
                "", "end", iid=parent_iid, text=text, open=True,
                tags=("host_up" if status == "up" else "host_down",),
                values=("", "", status.upper(), "", "", ""))
            for p in h.get("ports", []):
                st = p.get("state", "")
                tag = "open" if st == "open" else (
                    "openfiltered" if st == "open|filtered" else (
                        "filtered" if st == "filtered" else "closed"))
                ver = p.get("product", "")
                vv = p.get("version", "")
                if ver:
                    ver = ver + (f" {vv}" if vv else "")
                self.tree.insert(
                    parent_iid, "end", text="",
                    values=(p.get("proto", ""), p.get("port", ""), st,
                            p.get("reason", ""), p.get("service", ""), ver),
                    tags=(tag,))
        self.tree.bind("<<TreeviewSelect>>", self._tree_selected)

    def _tree_selected(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith("H"):
            host_ip = self.tree.item(iid, "text").split()[0]
            self.show_host_details(host_ip.strip())
        else:
            parent = self.tree.parent(iid)
            if parent:
                host_ip = self.tree.item(parent, "text").split()[0]
                self.show_host_details(host_ip.strip())

    # ------------------------------------------------------------------
    # Host details
    # ------------------------------------------------------------------
    def _find_host(self, data, ip):
        if not data:
            return None
        for h in data.get("hosts", []):
            if h.get("ip") == ip:
                return h
        return None

    def show_host_details(self, ip):
        data = getattr(self, "_last_data", None)
        host = self._find_host(data, ip)
        self._write_details(self._host_details_string(host, ip) if host else
                            f"No details available for {ip}.")

    def _host_details_string(self, host, ip):
        lines = []
        lines.append(("h", f"{ip}\n"))
        lines.append(("v", f"Hostname: {host.get('hostname') or '(none)'}\n"))
        lines.append(("v", f"Status  : {host.get('status')}\n"))
        lat = host.get("latency") or "n/a"
        lines.append(("v", f"Latency : {lat}\n"))
        ports = host.get("ports", [])
        open_ports = [p for p in ports if p.get("state") in ("open", "open|filtered")]
        lines.append(("l", f"\nOpen ports ({len(open_ports)})\n"))
        for p in open_ports:
            st = p.get("state", "")
            color = "green" if st == "open" else "red"
            ver = ""
            if p.get("product"):
                ver = p["product"] + (" " + p.get("version", "") if p.get("version") else "")
            lines.append(("v", f"  {p.get('port')}/{p.get('proto')}  "))
            lines.append((color, st))
            lines.append(("v", f"  {p.get('service')} {ver}\n"))
        closed = [p for p in ports if p.get("state") == "closed"]
        filt = [p for p in ports if p.get("state") == "filtered"]
        lines.append(("l", f"\nOther ports\n"))
        lines.append(("v", f"  {len(closed)} closed, {len(filt)} filtered\n"))
        oslist = host.get("osnames") or []
        if oslist:
            lines.append(("l", "\nOperating System\n"))
            for o in oslist:
                lines.append(("v", f"  {o}\n"))
        return lines

    def _write_details(self, content):
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        if isinstance(content, str):
            self.details.insert("end", content)
        else:
            for tag, text in content:
                self.details.insert("end", text, tag)
        self.details.config(state="disabled")

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------
    def render_topology(self):
        self.topo.delete("all")
        w = max(self.topo.winfo_width(), 700)
        h = max(self.topo.winfo_height(), 480)
        data = getattr(self, "_last_data", None)
        hosts = (data or {}).get("hosts", [])
        up = [h for h in hosts if h.get("status") == "up"]
        dx, dy = 30, 40
        w = max(w, 2 * dx + 60)
        h = max(h, 2 * dy + 60)
        self.topo.config(scrollregion=(0, 0, w, h))

        # Scanner node in the middle.
        cx, cy = w / 2, h / 2
        self._draw_diamond(cx, cy, 30, "#2b579a")

        if not up:
            self.topo.create_text(cx, cy + 50, text="No hosts up - run a scan.",
                                  fill="#888888", font=("Segoe UI", 10, "italic"))
            return

        import math
        n = len(up)
        self.topology_nodes = {}
        for i, host in enumerate(up):
            angle = -math.pi / 2 + 2 * math.pi * i / n
            r = min(w, h) / 2.5
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            self.topology_nodes[host.get("ip", f"node{i}")] = (x, y)
            open_n = len([p for p in host.get("ports", [])
                          if p.get("state") == "open"])
            color = Palette.GREEN if open_n else Palette.RED
            self.topo.create_line(cx, cy, x, y, fill="#b8c4d6", width=2)
            self._draw_node(x, y, color, host.get("ip", "?"), open_n)
        self.topo.create_text(cx, cy + 42,
                              text=f"{len(up)} host(s) up",
                              fill=Palette.MUTED, font=("Segoe UI", 9))

    def _draw_diamond(self, x, y, size, color):
        self.topo.create_polygon(x, y - size, x + size, y, x, y + size,
                                 x - size, y, outline="#0d2c5b", fill=color,
                                 width=2)
        self.topo.create_text(x, y, text="N", fill="white",
                              font=("Segoe UI", int(size * 0.66), "bold"))

    def _draw_node(self, x, y, color, ip, open_n):
        self.topo.create_oval(x - 11, y - 11, x + 11, y + 11,
                              fill=color, outline="#ffffff", width=2)
        self.topo.create_oval(x - 4, y - 4, x + 4, y + 4, fill="white")
        self.topo.create_text(x, y + 24, text=ip, fill="#333333",
                              font=("Segoe UI", 8, "bold"))
        if open_n:
            self.topo.create_text(x, y + 36, text=f"{open_n} open",
                                  fill=color, font=("Segoe UI", 7))

    def _topo_click(self, event):
        best = None
        best_d = 40
        for ip, (x, y) in self.topology_nodes.items():
            d = ((event.x - x) ** 2 + (event.y - y) ** 2) ** 0.5
            if d < best_d:
                best, best_d = ip, d
        if best:
            self.show_host_details(best)

    # ------------------------------------------------------------------
    # History tab
    # ------------------------------------------------------------------
    def _refresh_history(self):
        self.hist_list.delete(0, "end")
        for e in self.history:
            self.hist_list.insert("end", f"{e['when']} â€” {e['target']}")

    def load_history(self):
        sel = self.hist_list.curselection()
        if not sel:
            return
        e = self.history[sel[0]]
        self._last_data = e.get("data")
        self.current_json = e.get("json", "")
        self._reset_output()
        self._out_text_append(e.get("text", ""), "ws")
        self.render_ports_tree(e.get("data"))
        self.render_topology()
        self.status(f"Loaded scan from {e['when']}")

    def delete_history(self):
        sel = self.hist_list.curselection()
        if not sel:
            return
        self.history.pop(sel[0])
        self._refresh_history()

    # ------------------------------------------------------------------
    # Save / misc
    # ------------------------------------------------------------------
    def save_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._dump_output())
            self.status(f"Output saved to {path}.")

    def save_all(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")])
        if not path:
            return
        docs = [{"meta": self._record_meta, "output": self._dump_output(),
                 "data": getattr(self, "_last_data", None)}]
        for e in self.history:
            docs.append({"scan": e["when"], "command": e["command"],
                         "data": e["data"]})
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(docs, f, ensure_ascii=False, indent=2)
        self.status(f"Saved all scan data to {path}.")

    def show_about(self):
        messagebox.showinfo(
            APP_NAME,
            f"{APP_NAME} {VERSION}\n\n"
            "A Nmap-style network scanner with:\n"
            "  * Rust scanning engine (TCP connect / SYN / UDP / ping,\n"
            "    service + OS detection)\n"
            "  * Python Tkinter GUI (Zenmap style)\n\n"
            f"Backend: {self.backend}")

    def status(self, msg):
        self.status_var.set(msg)

    def on_close(self):
        if self.scan_process is not None and self.scan_process.poll() is None:
            try:
                if sys.platform.startswith("win"):
                    subprocess.run(
                        ["taskkill", "/PID", str(self.scan_process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW)
                else:
                    self.scan_process.kill()
            except Exception:
                pass
        for e in self.history:
            try:
                os.unlink(e["json"])
            except OSError:
                pass
        if self.current_json and self.scan_process is None:
            try:
                os.unlink(self.current_json)
            except OSError:
                pass
        self.destroy()


def main():
    app = FakeNmapApp()
    app.mainloop()


if __name__ == "__main__":
    main()