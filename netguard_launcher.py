#!/usr/bin/env python3
"""
NetGuard Launcher
"""

import customtkinter as ctk
import tkinter as tk
import subprocess, threading, webbrowser, os, sys, time, math

# ─────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────
PROJECT_DIR   = os.path.expanduser("~/")
VENV_PYTHON   = os.path.expanduser("~/venv/bin/python3")
MAIN_SCRIPT   = os.path.expanduser("~/main.py")
APP_SCRIPT    = os.path.expanduser("~/app.py")
DASHBOARD_URL = "http://127.0.0.1:5000"

# ─────────────────────────────────────────────────────────────
#  COLOURS
# ─────────────────────────────────────────────────────────────
BG      = "#080d14"
SURFACE = "#0d1520"
CARD    = "#111c2b"
BORDER  = "#1a2d45"
TEXT    = "#cdd9e8"
DIM     = "#5a7a9a"
BLUE    = "#3d9dff"
CYAN    = "#00d2c8"
GREEN   = "#00e07a"
YELLOW  = "#ffc642"
ORANGE  = "#ff7b35"
RED     = "#ff3d57"
PURPLE  = "#b06cff"

# Disabled text colors — visible but clearly muted
DIS_BLUE   = "#2e5a8a"   # readable blue-grey
DIS_RED    = "#7a2535"   # readable muted red
DIS_GREEN  = "#1e6040"   # readable muted green

# Base window size fonts are designed for
BASE_W =800

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ─────────────────────────────────────────────────────────────
#  FONT SPEC  helper  (family, size, weight)
# ─────────────────────────────────────────────────────────────
class FS:
    """Immutable font spec — keeps base size for scaling."""
    def __init__(self, family, size, weight="normal"):
        self.family = family
        self.size   = size
        self.weight = weight

    def scaled(self, factor):
        s = max(9, int(self.size * factor))
        return (self.family, s, self.weight)

    def tuple(self):
        return (self.family, self.size, self.weight)


# Font specs (base sizes — will scale with window)
F_TITLE    = FS("Courier", 40, "bold")
F_SUBTITLE = FS("Courier", 16,"bold")
F_STATUS   = FS("Courier", 18, "bold")
F_DETAIL   = FS("Courier", 14)
F_BTN1     = FS("Courier", 16, "bold")   # row-1 buttons
F_BTN2     = FS("Courier", 15, "bold")   # row-2 buttons
F_STAT_LBL = FS("Courier",  11)
F_STAT_VAL = FS("Courier", 15, "bold")
F_LOG_HDR  = FS("Courier", 13, "bold")
F_LOG      = FS("Courier",  10)


class _StatProxy:
    """Thread-safe proxy — updates a CTkLabel via after()."""
    def __init__(self, launcher, key):
        self._l = launcher
        self._k = key

    def set(self, v):
        def _do():
            lbl = self._l._stat_vals.get(self._k)
            if lbl:
                lbl.configure(text=str(v))
        self._l.after(0, _do)

    def get(self):
        lbl = self._l._stat_vals.get(self._k)
        return lbl.cget("text") if lbl else "\u2014"


class NetGuardLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetGuard Launcher")
        self.geometry("660x860")
        self.minsize(480, 640)
        self.resizable(True, True)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"660x860+{(sw-660)//2}+{(sh-860)//2}")

        # State
        self.process      = None
        self.running      = False
        self._start_t     = None
        self._dot_anim_id = None
        self._pulse_phase = 0.0
        self._dot_color   = DIM
        self._stat_vals   = {}

        # Font scaling registry:  [(widget, font_spec), ...]
        self._scalable   = []
        self._resize_job = None

        self._build_ui()

        # Stat proxies
        self.sv_flask   = _StatProxy(self, "flask")
        self.sv_configs = _StatProxy(self, "configs")
        self.sv_uptime  = _StatProxy(self, "uptime")
        self.sv_port    = _StatProxy(self, "port")

        # Bind resize
        self.bind("<Configure>", self._on_resize_debounce)

        self._log("NetGuard Launcher ready.", DIM)
        self._log("Click  \u25b6 Start NetGuard  to begin.", DIM)
        self._tick()
        self._start_activity_watcher()

    # ══════════════════════════════════════════════════════════
    #  RESPONSIVE FONT SCALING
    # ══════════════════════════════════════════════════════════
    def _reg(self, widget, font_spec):
        """Register a widget for font scaling and set initial font."""
        widget.configure(font=font_spec.tuple())
        self._scalable.append((widget, font_spec))
        return widget

    def _on_resize_debounce(self, event):
        if event.widget is not self:
            return
        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(60, self._apply_scale)

    def _apply_scale(self):
        w = self.winfo_width()
        # Scale factor: 0.88 min (small window) → 2.0 max (very large)
        factor = max(0.88, min(w / BASE_W, 2.0))
        for widget, fs in self._scalable:
            try:
                widget.configure(font=fs.scaled(factor))
            except Exception:
                pass
        # Also scale the log text widget font
        try:
            new_log = max(8, int(9 * factor))
            self.log.configure(font=("Courier", new_log))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════
    #  BUILD UI
    # ══════════════════════════════════════════════════════════
    def _build_ui(self):

        # ── HEADER ────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=0, height=108)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        inner = ctk.CTkFrame(hdr, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        # Hex icon
        hex_c = tk.Canvas(inner, width=58, height=64,
                          bg=SURFACE, highlightthickness=0)
        hex_c.pack(side="left", padx=(0, 18))
        cx, cy = 29, 32
        pts_outer = []
        for i in range(6):
            a = math.radians(60 * i - 30)
            pts_outer += [cx + 25 * math.cos(a), cy + 25 * math.sin(a)]
        hex_c.create_polygon(pts_outer, outline=BLUE, fill="", width=2)
        pts_inner = []
        for i in range(6):
            a = math.radians(60 * i - 30)
            pts_inner += [cx + 15 * math.cos(a), cy + 15 * math.sin(a)]
        hex_c.create_polygon(pts_inner, outline=BLUE, fill=SURFACE, width=1)

        ttl = ctk.CTkFrame(inner, fg_color="transparent")
        ttl.pack(side="left")

        lbl_title = ctk.CTkLabel(ttl, text="NETGUARD", text_color="#ffffff")
        self._reg(lbl_title, F_TITLE)
        lbl_title.pack(anchor="w")

        lbl_sub1 = ctk.CTkLabel(ttl,
                     text="AI-Driven Automated Network Configuration, Topology Mapping",
                     text_color=DIM)
        self._reg(lbl_sub1, F_SUBTITLE)
        lbl_sub1.pack(anchor="w")

        lbl_sub2 = ctk.CTkLabel(ttl,
                     text="Topology Mapping & Security Assessment System",
                     text_color=DIM)
        self._reg(lbl_sub2, F_SUBTITLE)
        lbl_sub2.pack(anchor="w")

        # Separator
        ctk.CTkFrame(self, fg_color="#1a3a5c", height=1,
                     corner_radius=0).pack(fill="x")
        ctk.CTkFrame(self, fg_color=BORDER, height=1,
                     corner_radius=0).pack(fill="x")

        # ── STATUS CARD ───────────────────────────────────────
        sc = ctk.CTkFrame(self, fg_color=CARD, corner_radius=10,
                           border_width=1, border_color=BORDER)
        sc.pack(fill="x", padx=16, pady=12)

        sc_in = ctk.CTkFrame(sc, fg_color="transparent")
        sc_in.pack(fill="x", padx=18, pady=14)

        dot_row = ctk.CTkFrame(sc_in, fg_color="transparent")
        dot_row.pack(fill="x")

        self._dot_canvas = tk.Canvas(dot_row, width=22, height=22,
                                      bg=CARD, highlightthickness=0)
        self._dot_canvas.pack(side="left")
        self._glow_oval = self._dot_canvas.create_oval(
            1, 1, 21, 21, fill="", outline=DIM, width=1)
        self._dot_oval = self._dot_canvas.create_oval(
            6, 6, 16, 16, fill=DIM, outline="")

        self._stat_lbl = ctk.CTkLabel(dot_row, text="OFFLINE",
                                       text_color=DIM)
        self._reg(self._stat_lbl, F_STATUS)
        self._stat_lbl.pack(side="left", padx=(10, 0))

        self._stat_det = ctk.CTkLabel(sc_in, text="System not started",
                                       text_color=DIM)
        self._reg(self._stat_det, F_DETAIL)
        self._stat_det.pack(anchor="w", pady=(5, 0))

        # ── BUTTONS ROW 1 ─────────────────────────────────────
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", padx=16, pady=(0, 6))

        self.btn_start = ctk.CTkButton(
            r1, text="\u25b6   Start NetGuard",
            fg_color="#0d3d6e", hover_color="#1a5a9e",
            text_color=BLUE,   text_color_disabled=DIS_BLUE,
            border_color=BLUE, border_width=1,
            corner_radius=8, font=F_BTN1.tuple(),
            height=44, command=self.start_system)
        self.btn_start.pack(side="left", padx=(0, 6), fill="x", expand=True)
        self._scalable.append((self.btn_start, F_BTN1))

        self.btn_stop = ctk.CTkButton(
            r1, text="\u25a0   Stop",
            fg_color="#3a0a12", hover_color="#5c1522",
            text_color=RED,    text_color_disabled=DIS_RED,
            border_color=RED,  border_width=1,
            corner_radius=8, font=F_BTN1.tuple(),
            height=44, width=110, command=self.stop_system,
            state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 6))
        self._scalable.append((self.btn_stop, F_BTN1))

        self.btn_dash = ctk.CTkButton(
            r1, text="\u2b21   Dashboard",
            fg_color="#0b2e1a", hover_color="#0f3d24",
            text_color=GREEN,  text_color_disabled=DIS_GREEN,
            border_color=GREEN, border_width=1,
            corner_radius=8, font=F_BTN1.tuple(),
            height=44, width=142, command=self.open_dashboard,
            state="disabled")
        self.btn_dash.pack(side="left")
        self._scalable.append((self.btn_dash, F_BTN1))

        # ── BUTTONS ROW 2 ─────────────────────────────────────
        r2 = ctk.CTkFrame(self, fg_color="transparent")
        r2.pack(fill="x", padx=16, pady=(0, 10))

        btn_cfg = ctk.CTkButton(
            r2, text="\U0001f4c2   Open Configs",
            fg_color="#0d1a10", hover_color="#14250e",
            text_color=GREEN, border_color="#1a3d20", border_width=1,
            corner_radius=8, font=F_BTN2.tuple(),
            height=38, command=self.open_configs)
        btn_cfg.pack(side="left", padx=(0, 6), fill="x", expand=True)
        self._scalable.append((btn_cfg, F_BTN2))

        btn_clr = ctk.CTkButton(
            r2, text="\u27f3   Clear Log",
            fg_color=SURFACE, hover_color=CARD,
            text_color=DIM, border_color=BORDER, border_width=1,
            corner_radius=8, font=F_BTN2.tuple(),
            height=38, width=132, command=self.clear_log)
        btn_clr.pack(side="left", padx=(0, 6))
        self._scalable.append((btn_clr, F_BTN2))

        btn_exit = ctk.CTkButton(
            r2, text="\u2715   Exit",
            fg_color=SURFACE, hover_color="#1e0a04",
            text_color=ORANGE, border_color=BORDER, border_width=1,
            corner_radius=8, font=F_BTN2.tuple(),
            height=38, width=108, command=self.on_close)
        btn_exit.pack(side="left")
        self._scalable.append((btn_exit, F_BTN2))

        # ── STATS BAR ─────────────────────────────────────────
        sb = ctk.CTkFrame(self, fg_color=CARD, corner_radius=10,
                           border_width=1, border_color=BORDER)
        sb.pack(fill="x", padx=16, pady=(0, 10))

        stats_row = ctk.CTkFrame(sb, fg_color="transparent")
        stats_row.pack(fill="x", padx=6, pady=14)

        for idx, (key, label, color) in enumerate([
            ("flask",   "FLASK",   BLUE),
            ("configs", "CONFIGS", GREEN),
            ("uptime",  "UPTIME",  CYAN),
            ("port",    "PORT",    GREEN),
        ]):
            cell = ctk.CTkFrame(stats_row, fg_color="transparent")
            cell.pack(side="left", expand=True, fill="both")

            if idx > 0:
                tk.Frame(cell, bg=BORDER, width=1).pack(
                    side="left", fill="y", padx=(0, 10))

            col_frame = ctk.CTkFrame(cell, fg_color="transparent")
            col_frame.pack(expand=True)

            lbl_k = ctk.CTkLabel(col_frame, text=label, text_color=DIM)
            self._reg(lbl_k, F_STAT_LBL)
            lbl_k.pack()

            val_lbl = ctk.CTkLabel(col_frame, text="\u2014",
                                    text_color=color)
            self._reg(val_lbl, F_STAT_VAL)
            val_lbl.pack()
            self._stat_vals[key] = val_lbl

        # ── LOG ───────────────────────────────────────────────
        log_hdr = ctk.CTkFrame(self, fg_color=SURFACE,
                                corner_radius=0, height=34)
        log_hdr.pack(fill="x")
        log_hdr.pack_propagate(False)

        lbl_loghdr = ctk.CTkLabel(log_hdr, text="\u25b8  SYSTEM LOG",
                                   text_color=DIM)
        self._reg(lbl_loghdr, F_LOG_HDR)
        lbl_loghdr.pack(side="left", padx=18, pady=7)

        log_outer = ctk.CTkFrame(self, fg_color=BORDER, corner_radius=8)
        log_outer.pack(fill="both", expand=True, padx=16, pady=(2, 14))

        log_inner = tk.Frame(log_outer, bg="#030608")
        log_inner.pack(fill="both", expand=True, padx=1, pady=1)

        self.log = tk.Text(
            log_inner, bg="#030608", fg=CYAN,
            font=F_LOG.tuple(), state="disabled", wrap="word",
            relief="flat", padx=12, pady=8,
            insertbackground=BLUE, selectbackground=BORDER,
        )
        self.log.pack(side="left", fill="both", expand=True)

        sb2 = tk.Scrollbar(log_inner, command=self.log.yview,
                           bg=SURFACE, troughcolor=BG,
                           activebackground=BORDER)
        sb2.pack(side="right", fill="y")
        self.log.config(yscrollcommand=sb2.set)

        for tag, col in [
            ("g", GREEN), ("r", RED), ("y", YELLOW), ("b", BLUE),
            ("d", DIM), ("p", PURPLE), ("o", ORANGE), ("c", CYAN), ("w", TEXT),
        ]:
            self.log.tag_configure(tag, foreground=col)

    # ══════════════════════════════════════════════════════════
    #  COLOR UTILS
    # ══════════════════════════════════════════════════════════
    def _blend(self, c1, c2, t):
        r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
        r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
        return (f"#{int(r1+(r2-r1)*t):02x}"
                f"{int(g1+(g2-g1)*t):02x}"
                f"{int(b1+(b2-b1)*t):02x}")

    # ══════════════════════════════════════════════════════════
    #  STATUS DOT  (heartbeat pulse when ONLINE)
    # ══════════════════════════════════════════════════════════
    def _status(self, text, color, detail=""):
        self._dot_color = color
        self.after(0, lambda: self._status_ui(text, color, detail))

    def _status_ui(self, text, color, detail):
        if self._dot_anim_id:
            try:
                self.after_cancel(self._dot_anim_id)
            except Exception:
                pass
            self._dot_anim_id = None

        self._stat_lbl.configure(text=text, text_color=color)
        self._stat_det.configure(text=detail)

        if color == GREEN:
            self._pulse_phase = 0.0
            self._pulse_dot()
        else:
            try:
                self._dot_canvas.itemconfig(self._dot_oval, fill=color)
                self._dot_canvas.itemconfig(
                    self._glow_oval,
                    outline=self._blend(CARD, color, 0.4))
            except tk.TclError:
                pass

    def _pulse_dot(self):
        self._pulse_phase = (self._pulse_phase + 0.13) % (2 * math.pi)
        t = 0.5 + 0.5 * math.sin(self._pulse_phase)
        try:
            self._dot_canvas.itemconfig(self._dot_oval,
                                         fill=self._blend(DIM, GREEN, t))
            self._dot_canvas.itemconfig(self._glow_oval,
                                         outline=self._blend(CARD, GREEN, t * 0.45))
        except tk.TclError:
            return
        self._dot_anim_id = self.after(45, self._pulse_dot)

    # ══════════════════════════════════════════════════════════
    #  BUTTON ENABLE / DISABLE
    # ══════════════════════════════════════════════════════════
    def _enable(self, btn):
        self.after(0, lambda: btn.configure(state="normal"))

    def _disable(self, btn):
        self.after(0, lambda: btn.configure(state="disabled"))

    # ══════════════════════════════════════════════════════════
    #  LOGGING
    # ══════════════════════════════════════════════════════════
    def _log(self, msg, color=DIM):
        tag = {
            GREEN:"g", RED:"r", YELLOW:"y", BLUE:"b",
            DIM:"d", PURPLE:"p", ORANGE:"o", CYAN:"c", TEXT:"w"
        }.get(color, "w")

        def _do():
            ts = time.strftime("%H:%M:%S")
            self.log.configure(state="normal")
            self.log.insert("end", f"[{ts}] ", "d")
            self.log.insert("end", msg + "\n", tag)
            self.log.configure(state="disabled")
            self.log.see("end")
        self.after(0, _do)

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self._log("Log cleared.", DIM)

    # ══════════════════════════════════════════════════════════
    #  ACTIVITY WATCHER
    # ══════════════════════════════════════════════════════════
    def _start_activity_watcher(self):
        import threading as _thr, time as _time
        log_path = os.path.expanduser('~/netguard_activity.log')

        def _watch():
            last_pos = 0
            while True:
                try:
                    if os.path.exists(log_path):
                        sz = os.path.getsize(log_path)
                        if sz > last_pos:
                            with open(log_path, 'r') as fp:
                                fp.seek(last_pos)
                                new_lines = fp.read()
                            last_pos = sz
                            for raw in new_lines.splitlines():
                                raw = raw.strip()
                                if not raw:
                                    continue
                                if '||' in raw:
                                    msg_part, tag_part = raw.rsplit('||', 1)
                                else:
                                    msg_part, tag_part = raw, 'info'
                                col_map = {
                                    'green': GREEN, 'red': RED, 'orange': ORANGE,
                                    'blue': BLUE, 'yellow': YELLOW, 'cyan': CYAN,
                                    'dim': DIM, 'info': TEXT, 'done': GREEN,
                                }
                                self._log(f"[WEB] {msg_part}",
                                          col_map.get(tag_part, DIM))
                    else:
                        last_pos = 0
                except Exception:
                    pass
                _time.sleep(0.5)

        _thr.Thread(target=_watch, daemon=True).start()

    def _tick(self):
        if self._start_t and self.running:
            e = int(time.time() - self._start_t)
            h, r = divmod(e, 3600)
            m, s = divmod(r, 60)
            self.sv_uptime.set(f"{h:02d}:{m:02d}:{s:02d}")
        self.after(1000, self._tick)

    # ══════════════════════════════════════════════════════════
    #  ACTIONS  (logic 100% unchanged)
    # ══════════════════════════════════════════════════════════
    def start_system(self):
        if self.running:
            return
        threading.Thread(target=self._start_bg, daemon=True).start()

    def _start_bg(self):
        self._status("STARTING\u2026", YELLOW, "Please wait\u2026")
        self._log("\u2550" * 30, BLUE)
        self._log("  Starting NetGuard System    ", BLUE)
        self._log("\u2550" * 30, BLUE)
        self._disable(self.btn_start)

        configs_dir = os.path.expanduser("~/network_configs")
        if os.path.exists(configs_dir):
            count = len([f for f in os.listdir(configs_dir) if f.endswith(".txt")])
            self.sv_configs.set(str(count))
        else:
            self.sv_configs.set("0")

        if not os.path.exists(VENV_PYTHON):
            self._log(f"\u2717 Python not found: {VENV_PYTHON}", RED)
            self._log("  Run: python3 -m venv ~/venv && pip install -r requirements.txt", YELLOW)
            self._status("ERROR", RED, "venv not found")
            self._enable(self.btn_start)
            return

        script = MAIN_SCRIPT if os.path.exists(MAIN_SCRIPT) else APP_SCRIPT
        name   = os.path.basename(script)
        self._log(f"Starting {name}\u2026", DIM)

        try:
            self.process = subprocess.Popen(
                [VENV_PYTHON, script],
                cwd=PROJECT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as ex:
            self._log(f"\u2717 Could not start: {ex}", RED)
            self._status("ERROR", RED, str(ex))
            self._enable(self.btn_start)
            return

        self._log("Waiting for Flask server\u2026", DIM)
        ready = False
        for _ in range(30):
            if self.process.poll() is not None:
                self._log("\u2717 Process exited unexpectedly!", RED)
                self._status("ERROR", RED, "Check the log")
                self._enable(self.btn_start)
                return
            try:
                import urllib.request
                urllib.request.urlopen(DASHBOARD_URL, timeout=1)
                ready = True
                break
            except Exception:
                time.sleep(1)

        if not ready:
            self._log("\u26a0  Flask may still be loading\u2026", YELLOW)

        self.running  = True
        self._start_t = time.time()
        self.sv_flask.set("ON")
        self.sv_port.set("5000")

        self._status("ONLINE  \u2713", GREEN, f"Running \u2192 {DASHBOARD_URL}")
        self._log(f"\u2713 {name} is running!", GREEN)
        self._log(f"\u2713 Dashboard \u2192 {DASHBOARD_URL}", GREEN)

        self._enable(self.btn_stop)
        self._enable(self.btn_dash)

        time.sleep(1)
        self._log("Opening browser\u2026", DIM)
        webbrowser.open(DASHBOARD_URL)
        self._log("\u2713 Browser opened automatically.", GREEN)
        self._log("\u2550" * 30, BLUE)
        self._log("  System fully started \u2713      ", GREEN)
        self._log("\u2550" * 30, BLUE)

        threading.Thread(target=self._stream, daemon=True).start()

    def _stream(self):
        if not self.process:
            return
        for line in self.process.stdout:
            line = line.strip()
            if not line:
                continue
            if "ERROR" in line or "Error" in line:
                self._log(line, RED)
            elif "WARNING" in line:
                self._log(line, YELLOW)
            elif "Running on" in line or "Training" in line:
                self._log(line, GREEN)
            elif "GET /" in line or "POST /" in line:
                self._log(line, CYAN)
                self._refresh_config_count()
            elif "accuracy" in line.lower() or "model" in line.lower():
                self._log(line, PURPLE)
            else:
                self._log(line, DIM)

    def _refresh_config_count(self):
        configs_dir = os.path.expanduser("~/network_configs")
        if os.path.exists(configs_dir):
            count = len([f for f in os.listdir(configs_dir) if f.endswith(".txt")])
            self.sv_configs.set(str(count))

    def stop_system(self):
        threading.Thread(target=self._stop_bg, daemon=True).start()

    def _stop_bg(self):
        self._status("STOPPING\u2026", YELLOW, "Shutting down\u2026")
        self._log("Stopping NetGuard\u2026", ORANGE)
        self._disable(self.btn_stop)
        self._disable(self.btn_dash)

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None

        self.running  = False
        self._start_t = None
        self.sv_flask.set("\u2014")
        self.sv_port.set("\u2014")
        self.sv_uptime.set("\u2014")

        self._status("OFFLINE", DIM, "System stopped")
        self._log("\u2713 System stopped.", GREEN)
        self._log("Click \u25b6 Start NetGuard to run again.", DIM)
        self._enable(self.btn_start)

    def open_dashboard(self):
        if self.running:
            webbrowser.open(DASHBOARD_URL)
            self._log("Opening dashboard\u2026", BLUE)
        else:
            self._log("\u26a0  System not running. Start it first.", YELLOW)

    def open_configs(self):
        configs_dir = os.path.expanduser("~/network_configs")
        if not os.path.exists(configs_dir):
            self._log("\u26a0  No configs yet \u2014 run harvest first.", YELLOW)
            return
        count = len([f for f in os.listdir(configs_dir) if f.endswith(".txt")])
        self._log(f"Opening configs folder ({count} files)\u2026", GREEN)
        try:
            subprocess.Popen(["xdg-open", configs_dir],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            self.sv_configs.set(str(count))
        except Exception as e:
            self._log(f"\u2717 Could not open folder: {e}", RED)

    def on_close(self):
        if self.running:
            threading.Thread(target=self._shutdown_and_exit, daemon=True).start()
        else:
            self.destroy()
            sys.exit(0)

    def _shutdown_and_exit(self):
        self._stop_bg()
        time.sleep(1.5)
        self.after(0, self.destroy)
        self.after(200, lambda: sys.exit(0))


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = NetGuardLauncher()
    app.mainloop()
