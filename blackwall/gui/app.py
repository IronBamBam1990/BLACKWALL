"""
BLACKWALL v4.0 - Desktop Security Control Center
Professional GUI built with customtkinter for the BLACKWALL security suite.
"""

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Color palette
C_BG_DARK = "#0a0a12"
C_BG_SIDEBAR = "#0d0d18"
C_BG_CARD = "#12121e"
C_BG_INPUT = "#1a1a2e"
C_CYAN = "#00d4ff"
C_CYAN_DIM = "#0088aa"
C_RED = "#ff2244"
C_ORANGE = "#ff6644"
C_YELLOW = "#ffaa22"
C_GREEN = "#00ff41"
C_GREEN_DIM = "#00aa2a"
C_TEXT = "#e0e0e0"
C_TEXT_DIM = "#777790"
C_BORDER = "#2a2a3e"

SEVERITY_COLORS = {
    "CRITICAL": C_RED,
    "HIGH": C_ORANGE,
    "MEDIUM": C_YELLOW,
    "LOW": "#44aa44",
}

MONO_FONT = ("Consolas", 12)
MONO_FONT_SMALL = ("Consolas", 11)
HEADING_FONT = ("Segoe UI", 18, "bold")
SUBHEADING_FONT = ("Segoe UI", 14, "bold")
LABEL_FONT = ("Segoe UI", 12)
LABEL_FONT_SMALL = ("Segoe UI", 11)
BADGE_FONT = ("Segoe UI", 10, "bold")


def _format_bytes(n: int) -> str:
    """Format byte count into human-readable string."""
    if n < 0:
        n = 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def _format_time(iso_str: str) -> str:
    """Extract HH:MM:SS from an ISO timestamp or return as-is."""
    if not iso_str:
        return "--:--:--"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return iso_str[:8] if len(iso_str) >= 8 else iso_str


def _now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ===================================================================
# Main Application
# ===================================================================
class BlackwallGUI:
    """BLACKWALL v4.0 Desktop Security Control Center."""

    PAGES = ("dashboard", "honeypots", "network", "threats", "supply_chain", "settings")

    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("BLACKWALL v4.0")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        self.root.configure(fg_color=C_BG_DARK)

        # Backend references (set via set_backend)
        self._b: dict[str, Any] = {}
        self._config_path: Optional[Path] = None

        # Current page
        self._current_page = "dashboard"

        # Widget caches for updates
        self._stat_cards: dict[str, ctk.CTkLabel] = {}
        self._feed_box: Optional[ctk.CTkTextbox] = None
        self._quick_stats_labels: dict[str, ctk.CTkLabel] = {}
        self._recent_bans_frame: Optional[ctk.CTkFrame] = None
        self._honeypot_rows: list[dict] = []
        self._net_connections_frame: Optional[ctk.CTkScrollableFrame] = None
        self._net_search_var: Optional[ctk.StringVar] = None
        self._banned_frame: Optional[ctk.CTkScrollableFrame] = None
        self._whitelist_frame: Optional[ctk.CTkScrollableFrame] = None
        self._threats_frame: Optional[ctk.CTkScrollableFrame] = None
        self._ids_log_box: Optional[ctk.CTkTextbox] = None
        self._supply_frame: Optional[ctk.CTkScrollableFrame] = None
        self._supply_status_labels: dict[str, ctk.CTkLabel] = {}

        # Settings entry vars
        self._settings_vars: dict[str, Any] = {}

        # Track feed lines to avoid duplicates
        self._feed_event_count = 0

        # Build UI
        self._build_sidebar()
        self._build_pages()
        self._show_page("dashboard")

    # ------------------------------------------------------------------
    # Backend integration
    # ------------------------------------------------------------------
    def set_backend(self, backend_dict: dict):
        """Receive references to all backend modules."""
        self._b = backend_dict

    def set_config_path(self, path: str | Path):
        self._config_path = Path(path)

    def _get(self, key: str):
        """Safely get a backend module."""
        return self._b.get(key)

    # ------------------------------------------------------------------
    # Sidebar
    # ------------------------------------------------------------------
    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self.root, width=200, fg_color=C_BG_SIDEBAR, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo
        logo = ctk.CTkLabel(
            sidebar, text="BLACKWALL", font=("Consolas", 22, "bold"),
            text_color=C_CYAN, anchor="center",
        )
        logo.pack(pady=(24, 2), padx=10)
        ctk.CTkLabel(
            sidebar, text="v4.0  Security Suite", font=LABEL_FONT_SMALL,
            text_color=C_TEXT_DIM, anchor="center",
        ).pack(pady=(0, 20), padx=10)

        sep = ctk.CTkFrame(sidebar, height=1, fg_color=C_BORDER)
        sep.pack(fill="x", padx=16, pady=(0, 12))

        # Nav buttons
        nav_items = [
            ("dashboard", "Dashboard"),
            ("honeypots", "Honeypots"),
            ("network", "Network"),
            ("threats", "Threats"),
            ("supply_chain", "Supply Chain"),
            ("settings", "Settings"),
        ]
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        for page_key, label in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=f"  {label}", anchor="w",
                font=LABEL_FONT, height=38,
                fg_color="transparent", hover_color="#1a1a30",
                text_color=C_TEXT_DIM, corner_radius=6,
                command=lambda p=page_key: self._show_page(p),
            )
            btn.pack(fill="x", padx=12, pady=2)
            self._nav_buttons[page_key] = btn

        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(fill="both", expand=True)

        # Status indicator
        status_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        status_frame.pack(pady=(0, 18), padx=16, fill="x")
        self._status_dot = ctk.CTkLabel(
            status_frame, text="\u25cf", font=("Segoe UI", 16),
            text_color=C_GREEN, width=20,
        )
        self._status_dot.pack(side="left")
        self._status_label = ctk.CTkLabel(
            status_frame, text="ACTIVE", font=LABEL_FONT_SMALL,
            text_color=C_GREEN,
        )
        self._status_label.pack(side="left", padx=(4, 0))

    # ------------------------------------------------------------------
    # Page container
    # ------------------------------------------------------------------
    def _build_pages(self):
        self._page_container = ctk.CTkFrame(self.root, fg_color=C_BG_DARK, corner_radius=0)
        self._page_container.pack(side="right", fill="both", expand=True)

        self._pages: dict[str, ctk.CTkFrame] = {}
        builders = {
            "dashboard": self._build_dashboard,
            "honeypots": self._build_honeypots,
            "network": self._build_network,
            "threats": self._build_threats,
            "supply_chain": self._build_supply_chain,
            "settings": self._build_settings,
        }
        for name, builder in builders.items():
            frame = ctk.CTkFrame(self._page_container, fg_color=C_BG_DARK, corner_radius=0)
            self._pages[name] = frame
            builder(frame)

    def _show_page(self, page_name: str):
        for f in self._pages.values():
            f.pack_forget()
        self._pages[page_name].pack(fill="both", expand=True, padx=0, pady=0)
        self._current_page = page_name
        # Highlight active nav button
        for key, btn in self._nav_buttons.items():
            if key == page_name:
                btn.configure(fg_color="#1a1a30", text_color=C_CYAN)
            else:
                btn.configure(fg_color="transparent", text_color=C_TEXT_DIM)
        # Immediate data refresh for the newly shown page
        self._refresh_current_page()

    # ------------------------------------------------------------------
    # Dashboard Page
    # ------------------------------------------------------------------
    def _build_dashboard(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_rowconfigure(2, weight=0)

        # -- Stat Cards Row --
        cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        cards_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        card_defs = [
            ("total_events", "Total Events", "0", C_CYAN),
            ("banned_ips", "Banned IPs", "0", C_RED),
            ("active_honeypots", "Active Honeypots", "0", C_GREEN),
            ("threat_level", "Threat Level", "LOW", C_YELLOW),
        ]
        for col, (key, title, default, accent) in enumerate(card_defs):
            card = ctk.CTkFrame(cards_frame, fg_color=C_BG_CARD, corner_radius=10, height=90)
            card.grid(row=0, column=col, sticky="ew", padx=6, pady=4)
            card.grid_propagate(False)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                card, text=title, font=LABEL_FONT_SMALL,
                text_color=C_TEXT_DIM, anchor="w",
            ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 0))
            val_label = ctk.CTkLabel(
                card, text=default, font=("Consolas", 26, "bold"),
                text_color=accent, anchor="w",
            )
            val_label.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))
            self._stat_cards[key] = val_label

        # -- Live Attack Feed --
        feed_label = ctk.CTkLabel(
            parent, text="Live Attack Feed", font=SUBHEADING_FONT,
            text_color=C_TEXT, anchor="w",
        )
        feed_label.grid(row=1, column=0, sticky="nw", padx=22, pady=(8, 0))

        self._feed_box = ctk.CTkTextbox(
            parent, font=MONO_FONT, fg_color=C_BG_CARD,
            text_color=C_TEXT, corner_radius=8, wrap="none",
            activate_scrollbars=True, state="disabled",
        )
        self._feed_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(32, 8))

        # Configure severity tags
        self._feed_box.tag_config("CRITICAL", foreground=C_RED)
        self._feed_box.tag_config("HIGH", foreground=C_ORANGE)
        self._feed_box.tag_config("MEDIUM", foreground=C_YELLOW)
        self._feed_box.tag_config("LOW", foreground="#44aa44")
        self._feed_box.tag_config("timestamp", foreground=C_CYAN_DIM)

        # -- Bottom Row --
        bottom = ctk.CTkFrame(parent, fg_color="transparent", height=160)
        bottom.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        bottom.grid_columnconfigure((0, 1), weight=1)

        # Quick Stats panel
        qs_card = ctk.CTkFrame(bottom, fg_color=C_BG_CARD, corner_radius=10)
        qs_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)
        ctk.CTkLabel(qs_card, text="Quick Stats", font=SUBHEADING_FONT, text_color=C_TEXT).pack(
            anchor="w", padx=14, pady=(10, 6)
        )
        qs_items = [
            ("qs_connections", "Active Connections"),
            ("qs_listeners", "Listeners"),
            ("qs_bytes_in", "Bytes In"),
            ("qs_bytes_out", "Bytes Out"),
        ]
        for key, label in qs_items:
            row_f = ctk.CTkFrame(qs_card, fg_color="transparent")
            row_f.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(row_f, text=label, font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM).pack(
                side="left"
            )
            v = ctk.CTkLabel(row_f, text="--", font=MONO_FONT_SMALL, text_color=C_CYAN)
            v.pack(side="right")
            self._quick_stats_labels[key] = v

        # Recent Bans panel
        rb_card = ctk.CTkFrame(bottom, fg_color=C_BG_CARD, corner_radius=10)
        rb_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=4)
        ctk.CTkLabel(rb_card, text="Recent Bans", font=SUBHEADING_FONT, text_color=C_TEXT).pack(
            anchor="w", padx=14, pady=(10, 6)
        )
        self._recent_bans_frame = ctk.CTkFrame(rb_card, fg_color="transparent")
        self._recent_bans_frame.pack(fill="both", expand=True, padx=14, pady=(0, 10))

    # ------------------------------------------------------------------
    # Honeypots Page
    # ------------------------------------------------------------------
    def _build_honeypots(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Header / controls
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        ctk.CTkLabel(hdr, text="Honeypot Management", font=HEADING_FONT, text_color=C_TEXT).pack(
            side="left"
        )
        ctk.CTkButton(
            hdr, text="Stop All", font=LABEL_FONT, width=100,
            fg_color="#441122", hover_color="#662233", text_color=C_RED,
            command=self._honeypot_stop_all,
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            hdr, text="Start All", font=LABEL_FONT, width=100,
            fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
            command=self._honeypot_start_all,
        ).pack(side="right")

        # Table
        table_frame = ctk.CTkScrollableFrame(
            parent, fg_color=C_BG_CARD, corner_radius=10,
            scrollbar_button_color=C_BG_INPUT,
        )
        table_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        table_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        # Column headers
        headers = ["Name", "Port", "Status", "Hits", "Last Hit"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                table_frame, text=h, font=SUBHEADING_FONT,
                text_color=C_CYAN_DIM, anchor="w",
            ).grid(row=0, column=col, sticky="w", padx=12, pady=(8, 12))

        # Honeypot definitions from config
        hp_defs = [
            ("SSH", 2222), ("HTTP", 8080), ("FTP", 2121),
            ("RDP", 3390), ("SMB", 4450), ("Telnet", 2323),
            ("MySQL", 3307), ("SMTP", 2525), ("DNS", 5354),
            ("Catch-All", 0),
        ]
        self._honeypot_rows = []
        for row_idx, (name, default_port) in enumerate(hp_defs, start=1):
            row_data: dict[str, Any] = {"name": name}

            # Name
            ctk.CTkLabel(
                table_frame, text=name, font=MONO_FONT,
                text_color=C_TEXT, anchor="w",
            ).grid(row=row_idx, column=0, sticky="w", padx=12, pady=4)

            # Port (editable entry)
            port_var = ctk.StringVar(value=str(default_port) if default_port else "multi")
            port_entry = ctk.CTkEntry(
                table_frame, textvariable=port_var, font=MONO_FONT_SMALL,
                width=80, fg_color=C_BG_INPUT, text_color=C_TEXT,
                border_color=C_BORDER,
            )
            port_entry.grid(row=row_idx, column=1, sticky="w", padx=12, pady=4)
            row_data["port_var"] = port_var

            # Status toggle
            switch_var = ctk.BooleanVar(value=True)
            switch = ctk.CTkSwitch(
                table_frame, text="", variable=switch_var,
                onvalue=True, offvalue=False,
                progress_color=C_GREEN, button_color=C_CYAN,
                button_hover_color=C_CYAN_DIM,
                command=lambda n=name, v=switch_var: self._honeypot_toggle(n, v.get()),
            )
            switch.grid(row=row_idx, column=2, sticky="w", padx=12, pady=4)
            row_data["switch_var"] = switch_var

            # Hits
            hits_label = ctk.CTkLabel(
                table_frame, text="0", font=MONO_FONT,
                text_color=C_TEXT, anchor="w",
            )
            hits_label.grid(row=row_idx, column=3, sticky="w", padx=12, pady=4)
            row_data["hits_label"] = hits_label

            # Last hit
            last_label = ctk.CTkLabel(
                table_frame, text="--:--:--", font=MONO_FONT_SMALL,
                text_color=C_TEXT_DIM, anchor="w",
            )
            last_label.grid(row=row_idx, column=4, sticky="w", padx=12, pady=4)
            row_data["last_label"] = last_label

            self._honeypot_rows.append(row_data)

    def _honeypot_toggle(self, name: str, enabled: bool):
        """Toggle a single honeypot on/off via backend."""
        mgr = self._get("honeypot_manager")
        if not mgr:
            return
        # Run in thread so we don't freeze the GUI
        threading.Thread(
            target=self._honeypot_toggle_worker, args=(mgr, name, enabled),
            daemon=True,
        ).start()

    def _honeypot_toggle_worker(self, mgr, name: str, enabled: bool):
        try:
            key = name.lower().replace("-", "").replace(" ", "")
            for hp in mgr.honeypots:
                hp_type = getattr(hp, "name", "") or type(hp).__name__.lower()
                if key in hp_type.lower():
                    if not enabled:
                        import asyncio
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                        loop.run_until_complete(hp.stop())
                    break
        except Exception:
            pass

    def _honeypot_start_all(self):
        mgr = self._get("honeypot_manager")
        if not mgr:
            return
        for row in self._honeypot_rows:
            row["switch_var"].set(True)
        threading.Thread(target=self._start_all_worker, args=(mgr,), daemon=True).start()

    def _start_all_worker(self, mgr):
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            loop.run_until_complete(mgr.start_all())
        except Exception:
            pass

    def _honeypot_stop_all(self):
        mgr = self._get("honeypot_manager")
        if not mgr:
            return
        for row in self._honeypot_rows:
            row["switch_var"].set(False)
        threading.Thread(target=self._stop_all_worker, args=(mgr,), daemon=True).start()

    def _stop_all_worker(self, mgr):
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            loop.run_until_complete(mgr.stop_all())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Network Page
    # ------------------------------------------------------------------
    def _build_network(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_rowconfigure(3, weight=1)

        # Header + search
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        ctk.CTkLabel(hdr, text="Network Monitor", font=HEADING_FONT, text_color=C_TEXT).pack(
            side="left"
        )
        self._net_search_var = ctk.StringVar()
        ctk.CTkEntry(
            hdr, textvariable=self._net_search_var, placeholder_text="Filter IP / process...",
            font=LABEL_FONT, width=220, fg_color=C_BG_INPUT, text_color=C_TEXT,
            border_color=C_BORDER,
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            hdr, text="Refresh", font=LABEL_FONT, width=80,
            fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
            command=self._refresh_network,
        ).pack(side="right")

        # Active connections table
        self._net_connections_frame = ctk.CTkScrollableFrame(
            parent, fg_color=C_BG_CARD, corner_radius=10,
            label_text="Active Connections", label_font=SUBHEADING_FONT,
            label_text_color=C_CYAN_DIM,
            scrollbar_button_color=C_BG_INPUT,
        )
        self._net_connections_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        for c in range(6):
            self._net_connections_frame.grid_columnconfigure(c, weight=1)

        # Section label
        ctk.CTkLabel(
            parent, text="Banned IPs / Whitelist", font=SUBHEADING_FONT,
            text_color=C_TEXT, anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=22, pady=(4, 0))

        bottom = ctk.CTkFrame(parent, fg_color="transparent")
        bottom.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 16))
        bottom.grid_columnconfigure((0, 1), weight=1)
        bottom.grid_rowconfigure(0, weight=1)

        # Banned IPs list
        self._banned_frame = ctk.CTkScrollableFrame(
            bottom, fg_color=C_BG_CARD, corner_radius=10,
            label_text="Banned IPs", label_font=LABEL_FONT,
            label_text_color=C_RED,
            scrollbar_button_color=C_BG_INPUT,
        )
        self._banned_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)
        self._banned_frame.grid_columnconfigure(0, weight=1)

        # Whitelist management
        wl_frame = ctk.CTkFrame(bottom, fg_color=C_BG_CARD, corner_radius=10)
        wl_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=4)
        wl_frame.grid_columnconfigure(0, weight=1)
        wl_frame.grid_rowconfigure(1, weight=1)

        wl_hdr = ctk.CTkFrame(wl_frame, fg_color="transparent")
        wl_hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        ctk.CTkLabel(wl_hdr, text="Whitelist", font=LABEL_FONT, text_color=C_GREEN).pack(
            side="left"
        )
        self._wl_entry_var = ctk.StringVar()
        ctk.CTkEntry(
            wl_hdr, textvariable=self._wl_entry_var, placeholder_text="IP or CIDR",
            font=MONO_FONT_SMALL, width=150, fg_color=C_BG_INPUT,
            text_color=C_TEXT, border_color=C_BORDER,
        ).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            wl_hdr, text="+", font=LABEL_FONT, width=32,
            fg_color="#113322", hover_color="#225533", text_color=C_GREEN,
            command=self._whitelist_add,
        ).pack(side="right")

        self._whitelist_frame = ctk.CTkScrollableFrame(
            wl_frame, fg_color="transparent",
            scrollbar_button_color=C_BG_INPUT,
        )
        self._whitelist_frame.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 8))
        self._whitelist_frame.grid_columnconfigure(0, weight=1)

    def _refresh_network(self):
        self._update_network_page()

    def _ban_ip_action(self, ip: str):
        ab = self._get("auto_ban")
        if not ab:
            return
        threading.Thread(
            target=lambda: ab.ban_ip(ip, reason="Manual ban from GUI", severity="HIGH"),
            daemon=True,
        ).start()
        self.root.after(500, self._update_network_page)

    def _unban_ip_action(self, ip: str):
        ab = self._get("auto_ban")
        if not ab:
            return
        threading.Thread(target=lambda: ab.unban_ip(ip), daemon=True).start()
        self.root.after(500, self._update_network_page)

    def _whitelist_add(self):
        ip = self._wl_entry_var.get().strip()
        if not ip:
            return
        ab = self._get("auto_ban")
        if ab:
            import ipaddress
            try:
                net = ipaddress.ip_network(ip, strict=False)
                ab.whitelist.append(net)
            except ValueError:
                try:
                    addr = ipaddress.ip_address(ip)
                    ab.whitelist.append(addr)
                except ValueError:
                    return
        self._wl_entry_var.set("")
        self._update_whitelist_display()

    def _whitelist_remove(self, entry):
        ab = self._get("auto_ban")
        if ab and entry in ab.whitelist:
            ab.whitelist.remove(entry)
        self._update_whitelist_display()

    # ------------------------------------------------------------------
    # Threats Page
    # ------------------------------------------------------------------
    def _build_threats(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        parent.grid_rowconfigure(3, weight=1)

        # Header
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        ctk.CTkLabel(hdr, text="Threat Intelligence", font=HEADING_FONT, text_color=C_TEXT).pack(
            side="left"
        )
        ctk.CTkButton(
            hdr, text="Scan Network", font=LABEL_FONT, width=120,
            fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
            command=self._trigger_network_scan,
        ).pack(side="right")

        # Threat score table
        self._threats_frame = ctk.CTkScrollableFrame(
            parent, fg_color=C_BG_CARD, corner_radius=10,
            label_text="Threat Scores", label_font=SUBHEADING_FONT,
            label_text_color=C_RED,
            scrollbar_button_color=C_BG_INPUT,
        )
        self._threats_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))
        for c in range(6):
            self._threats_frame.grid_columnconfigure(c, weight=1)

        # IDS Attack Log header
        ctk.CTkLabel(
            parent, text="IDS Attack Log", font=SUBHEADING_FONT,
            text_color=C_TEXT, anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=22, pady=(4, 0))

        self._ids_log_box = ctk.CTkTextbox(
            parent, font=MONO_FONT_SMALL, fg_color=C_BG_CARD,
            text_color=C_TEXT, corner_radius=8, wrap="none",
            activate_scrollbars=True, state="disabled", height=180,
        )
        self._ids_log_box.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self._ids_log_box.tag_config("CRITICAL", foreground=C_RED)
        self._ids_log_box.tag_config("HIGH", foreground=C_ORANGE)
        self._ids_log_box.tag_config("MEDIUM", foreground=C_YELLOW)
        self._ids_log_box.tag_config("LOW", foreground="#44aa44")

    def _trigger_network_scan(self):
        """Trigger a manual network scan in a background thread."""
        nm = self._get("network_monitor")
        if not nm:
            return

        def _scan():
            try:
                conns = nm.get_active_connections()
                nm.check_port_scan(conns)
                nm.check_suspicious_connections(conns)
                nm.check_new_listeners()
            except Exception:
                pass

        threading.Thread(target=_scan, daemon=True).start()

    # ------------------------------------------------------------------
    # Supply Chain Page
    # ------------------------------------------------------------------
    def _build_supply_chain(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Header
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        ctk.CTkLabel(
            hdr, text="Supply Chain Security", font=HEADING_FONT, text_color=C_TEXT,
        ).pack(side="left")
        ctk.CTkButton(
            hdr, text="Run Full Scan", font=LABEL_FONT, width=120,
            fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
            command=self._trigger_supply_scan,
        ).pack(side="right")

        # Status row
        status_row = ctk.CTkFrame(parent, fg_color="transparent")
        status_row.grid(row=0, column=0, sticky="e", padx=160, pady=(16, 8))
        for key, label in [
            ("cred_status", "Credential Monitor"),
            ("container_status", "Container Security"),
        ]:
            sf = ctk.CTkFrame(status_row, fg_color=C_BG_CARD, corner_radius=6)
            sf.pack(side="left", padx=4)
            ctk.CTkLabel(sf, text=label, font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM).pack(
                side="left", padx=(8, 4), pady=4
            )
            sl = ctk.CTkLabel(sf, text="--", font=BADGE_FONT, text_color=C_GREEN)
            sl.pack(side="left", padx=(0, 8), pady=4)
            self._supply_status_labels[key] = sl

        # Results table
        self._supply_frame = ctk.CTkScrollableFrame(
            parent, fg_color=C_BG_CARD, corner_radius=10,
            label_text="Package Scan Results", label_font=SUBHEADING_FONT,
            label_text_color=C_CYAN_DIM,
            scrollbar_button_color=C_BG_INPUT,
        )
        self._supply_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        for c in range(4):
            self._supply_frame.grid_columnconfigure(c, weight=1)

    def _trigger_supply_scan(self):
        da = self._get("dependency_auditor")
        if not da:
            return

        def _scan():
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                loop.run_until_complete(da.full_audit())
            except Exception:
                pass

        threading.Thread(target=_scan, daemon=True).start()

    # ------------------------------------------------------------------
    # Settings Page
    # ------------------------------------------------------------------
    def _build_settings(self, parent: ctk.CTkFrame):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(
            parent, fg_color=C_BG_DARK, corner_radius=0,
            scrollbar_button_color=C_BG_INPUT,
        )
        scroll.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(scroll, text="Settings", font=HEADING_FONT, text_color=C_TEXT).grid(
            row=0, column=0, sticky="w", padx=8, pady=(0, 16)
        )

        sections = [
            ("Honeypot Ports", [
                ("hp_ssh_port", "SSH Port", "2222"),
                ("hp_http_port", "HTTP Port", "8080"),
                ("hp_ftp_port", "FTP Port", "2121"),
                ("hp_rdp_port", "RDP Port", "3390"),
                ("hp_smb_port", "SMB Port", "4450"),
                ("hp_telnet_port", "Telnet Port", "2323"),
                ("hp_mysql_port", "MySQL Port", "3307"),
                ("hp_smtp_port", "SMTP Port", "2525"),
                ("hp_dns_port", "DNS Port", "5354"),
            ]),
            ("Alert Settings", [
                ("alert_sound", "Sound Alerts", "toggle"),
                ("alert_toast", "Toast Notifications", "toggle"),
            ]),
            ("Auto-Ban", [
                ("autoban_enabled", "Auto-Ban Enabled", "toggle"),
                ("autoban_threshold", "Ban Threshold (hits)", "3"),
            ]),
            ("Supply Chain", [
                ("supply_interval", "Scan Interval (sec)", "3600"),
            ]),
        ]

        current_row = 1
        for section_title, fields in sections:
            ctk.CTkLabel(
                scroll, text=section_title, font=SUBHEADING_FONT, text_color=C_CYAN,
            ).grid(row=current_row, column=0, sticky="w", padx=8, pady=(16, 8))
            current_row += 1

            for key, label, default in fields:
                row_frame = ctk.CTkFrame(scroll, fg_color=C_BG_CARD, corner_radius=8)
                row_frame.grid(row=current_row, column=0, sticky="ew", padx=8, pady=3)
                row_frame.grid_columnconfigure(1, weight=1)
                current_row += 1

                ctk.CTkLabel(
                    row_frame, text=label, font=LABEL_FONT, text_color=C_TEXT,
                ).grid(row=0, column=0, sticky="w", padx=12, pady=8)

                if default == "toggle":
                    var = ctk.BooleanVar(value=False)
                    self._settings_vars[key] = var
                    ctk.CTkSwitch(
                        row_frame, text="", variable=var,
                        progress_color=C_GREEN, button_color=C_CYAN,
                        button_hover_color=C_CYAN_DIM,
                    ).grid(row=0, column=1, sticky="e", padx=12, pady=8)
                else:
                    var = ctk.StringVar(value=default)
                    self._settings_vars[key] = var
                    ctk.CTkEntry(
                        row_frame, textvariable=var, font=MONO_FONT_SMALL,
                        width=120, fg_color=C_BG_INPUT, text_color=C_TEXT,
                        border_color=C_BORDER,
                    ).grid(row=0, column=1, sticky="e", padx=12, pady=8)

        # Whitelist CIDR section
        ctk.CTkLabel(
            scroll, text="Whitelist (CIDR Ranges)", font=SUBHEADING_FONT, text_color=C_CYAN,
        ).grid(row=current_row, column=0, sticky="w", padx=8, pady=(16, 8))
        current_row += 1

        wl_row = ctk.CTkFrame(scroll, fg_color=C_BG_CARD, corner_radius=8)
        wl_row.grid(row=current_row, column=0, sticky="ew", padx=8, pady=3)
        wl_row.grid_columnconfigure(0, weight=1)
        current_row += 1

        self._settings_wl_var = ctk.StringVar(
            value="127.0.0.1, 192.168.0.0/24, 192.168.1.0/24, 10.0.0.0/8"
        )
        ctk.CTkEntry(
            wl_row, textvariable=self._settings_wl_var, font=MONO_FONT_SMALL,
            fg_color=C_BG_INPUT, text_color=C_TEXT, border_color=C_BORDER,
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=8)

        # Save button
        current_row += 1
        ctk.CTkButton(
            scroll, text="Save Configuration", font=SUBHEADING_FONT, height=44,
            fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
            command=self._save_settings,
        ).grid(row=current_row, column=0, sticky="ew", padx=8, pady=(20, 8))

        # Load current config values
        self._load_settings_from_config()

    def _load_settings_from_config(self):
        """Load current config values into settings widgets."""
        if not self._config_path:
            self._config_path = Path(__file__).parent.parent.parent / "config" / "config.json"
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            return

        hp = cfg.get("honeypots", {})
        port_map = {
            "hp_ssh_port": ("ssh", "port"),
            "hp_http_port": ("http", "port"),
            "hp_ftp_port": ("ftp", "port"),
            "hp_rdp_port": ("rdp", "port"),
            "hp_smb_port": ("smb", "port"),
            "hp_telnet_port": ("telnet", "port"),
            "hp_mysql_port": ("mysql", "port"),
            "hp_smtp_port": ("smtp", "port"),
            "hp_dns_port": ("dns", "port"),
        }
        for key, (hp_name, field) in port_map.items():
            v = self._settings_vars.get(key)
            if v:
                v.set(str(hp.get(hp_name, {}).get(field, "")))

        alerts = cfg.get("alerts", {})
        sv = self._settings_vars.get("alert_sound")
        if sv:
            sv.set(alerts.get("sound_enabled", False))
        tv = self._settings_vars.get("alert_toast")
        if tv:
            tv.set(alerts.get("toast_enabled", False))

        mon = cfg.get("monitor", {})
        ab = self._settings_vars.get("autoban_enabled")
        if ab:
            ab.set(mon.get("auto_ban_enabled", True))
        at = self._settings_vars.get("autoban_threshold")
        if at:
            at.set(str(mon.get("brute_force_threshold", 3)))

        wl = cfg.get("whitelist", [])
        self._settings_wl_var.set(", ".join(wl))

    def _save_settings(self):
        """Save settings to config/config.json."""
        if not self._config_path:
            self._config_path = Path(__file__).parent.parent.parent / "config" / "config.json"
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

        # Update honeypot ports
        hp = cfg.setdefault("honeypots", {})
        port_map = {
            "hp_ssh_port": "ssh", "hp_http_port": "http", "hp_ftp_port": "ftp",
            "hp_rdp_port": "rdp", "hp_smb_port": "smb", "hp_telnet_port": "telnet",
            "hp_mysql_port": "mysql", "hp_smtp_port": "smtp", "hp_dns_port": "dns",
        }
        for key, hp_name in port_map.items():
            v = self._settings_vars.get(key)
            if v:
                try:
                    port_val = int(v.get())
                    hp.setdefault(hp_name, {})["port"] = port_val
                except ValueError:
                    pass

        # Alerts
        alerts = cfg.setdefault("alerts", {})
        sv = self._settings_vars.get("alert_sound")
        if sv:
            alerts["sound_enabled"] = sv.get()
        tv = self._settings_vars.get("alert_toast")
        if tv:
            alerts["toast_enabled"] = tv.get()

        # Auto-ban
        mon = cfg.setdefault("monitor", {})
        ab = self._settings_vars.get("autoban_enabled")
        if ab:
            mon["auto_ban_enabled"] = ab.get()
        at = self._settings_vars.get("autoban_threshold")
        if at:
            try:
                mon["brute_force_threshold"] = int(at.get())
            except ValueError:
                pass

        # Whitelist
        wl_str = self._settings_wl_var.get().strip()
        if wl_str:
            cfg["whitelist"] = [s.strip() for s in wl_str.split(",") if s.strip()]

        # Apply alert settings to live backend
        am = self._get("alert_manager")
        if am:
            am.sound_enabled = alerts.get("sound_enabled", False)
            am.toast_enabled = alerts.get("toast_enabled", False)

        # Apply auto-ban threshold to live backend
        ab_mod = self._get("auto_ban")
        if ab_mod:
            try:
                ab_mod.ban_threshold_honeypot = int(
                    self._settings_vars.get("autoban_threshold", ctk.StringVar(value="3")).get()
                )
            except ValueError:
                pass

        # Write file
        try:
            tmp = self._config_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            tmp.replace(self._config_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Update loop
    # ------------------------------------------------------------------
    def _update_loop(self):
        """Periodic update cycle. Runs every 2 seconds."""
        try:
            self._refresh_current_page()
        except Exception:
            pass
        self.root.after(2000, self._update_loop)

    def _refresh_current_page(self):
        """Refresh data for the currently visible page only."""
        page = self._current_page
        if page == "dashboard":
            self._update_dashboard()
        elif page == "honeypots":
            self._update_honeypots()
        elif page == "network":
            self._update_network_page()
        elif page == "threats":
            self._update_threats()
        elif page == "supply_chain":
            self._update_supply_chain()
        # settings page doesn't need periodic refresh

    # ------------------------------------------------------------------
    # Dashboard updates
    # ------------------------------------------------------------------
    def _update_dashboard(self):
        # Stat cards
        mgr = self._get("honeypot_manager")
        ab = self._get("auto_ban")
        ts = self._get("threat_scorer")

        total_events = 0
        banned_count = 0
        active_hp = 0
        threat_level = "LOW"

        if mgr:
            try:
                stats = mgr.get_stats()
                total_events = stats.get("total_events", 0)
                active_hp = len(mgr.honeypots)
            except Exception:
                pass

        if ab:
            try:
                banned_count = len(ab.banned_ips)
            except Exception:
                pass

        if ts:
            try:
                ts_stats = ts.get_stats()
                if ts_stats.get("critical_count", 0) > 0:
                    threat_level = "CRITICAL"
                elif ts_stats.get("high_count", 0) > 0:
                    threat_level = "HIGH"
                elif ts_stats.get("tracked_ips", 0) > 5:
                    threat_level = "MEDIUM"
            except Exception:
                pass

        self._stat_cards["total_events"].configure(text=str(total_events))
        self._stat_cards["banned_ips"].configure(text=str(banned_count))
        self._stat_cards["active_honeypots"].configure(text=str(active_hp))

        tl_color = SEVERITY_COLORS.get(threat_level, C_TEXT)
        self._stat_cards["threat_level"].configure(text=threat_level, text_color=tl_color)

        # Quick stats
        nm = self._get("network_monitor")
        if nm:
            try:
                net_stats = nm.get_network_stats()
                conns = nm.get_active_connections()
                established = [c for c in conns if c.get("status") == "ESTABLISHED"]
                listeners = [c for c in conns if c.get("status") == "LISTEN"]
                self._quick_stats_labels["qs_connections"].configure(
                    text=str(len(established))
                )
                self._quick_stats_labels["qs_listeners"].configure(
                    text=str(len(listeners))
                )
                self._quick_stats_labels["qs_bytes_in"].configure(
                    text=_format_bytes(net_stats.get("bytes_recv", 0))
                )
                self._quick_stats_labels["qs_bytes_out"].configure(
                    text=_format_bytes(net_stats.get("bytes_sent", 0))
                )
            except Exception:
                pass

        # Live attack feed - append new events from honeypot manager alerts and IDS
        self._update_attack_feed()

        # Recent bans
        self._update_recent_bans()

    def _update_attack_feed(self):
        """Populate attack feed with data from honeypot manager and network monitor."""
        if not self._feed_box:
            return

        mgr = self._get("honeypot_manager")
        nm = self._get("network_monitor")
        ids_mod = self._get("intrusion_detector")

        new_lines: list[tuple[str, str]] = []  # (text, severity)

        # Honeypot events via manager stats
        if mgr:
            try:
                stats = mgr.get_stats()
                current_count = stats.get("total_events", 0)
                if current_count > self._feed_event_count:
                    last_event = stats.get("last_event")
                    if last_event:
                        ts_str = _format_time(last_event.get("timestamp", ""))
                        hp_type = last_event.get("honeypot", "???").upper()
                        src_ip = last_event.get("source_ip", "?.?.?.?")
                        details = last_event.get("details", {})
                        action = details.get("action", "connection")
                        desc = details.get("description", action)

                        # Determine severity from details
                        severity = "MEDIUM"
                        if details.get("threat_match"):
                            severity = "CRITICAL"
                        elif "brute" in desc.lower() or "exploit" in desc.lower():
                            severity = "HIGH"
                        elif "login" in desc.lower():
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                        line = (
                            f"[{ts_str}] {severity:<9} {src_ip:<18} -> "
                            f"{hp_type:<7} {desc}"
                        )
                        new_lines.append((line, severity))
                    self._feed_event_count = current_count
            except Exception:
                pass

        # Network monitor alerts
        if nm:
            try:
                recent = nm.get_recent_alerts(5)
                for alert in recent:
                    ts_str = _format_time(alert.get("timestamp", ""))
                    sev = alert.get("severity", "LOW")
                    src = alert.get("source_ip", alert.get("address", ""))
                    atype = alert.get("type", "UNKNOWN")
                    proc = alert.get("process", "")
                    desc = atype
                    if proc:
                        desc += f" ({proc})"
                    line = f"[{ts_str}] {sev:<9} {src:<18} -> {'NET':<7} {desc}"
                    new_lines.append((line, sev))
            except Exception:
                pass

        if new_lines:
            self._feed_box.configure(state="normal")
            for line_text, sev in new_lines[-10:]:
                self._feed_box.insert("end", line_text + "\n", sev)
            self._feed_box.see("end")
            # Keep max 500 lines
            content = self._feed_box.get("1.0", "end")
            lines = content.split("\n")
            if len(lines) > 500:
                self._feed_box.delete("1.0", f"{len(lines)-500}.0")
            self._feed_box.configure(state="disabled")

    def _update_recent_bans(self):
        if not self._recent_bans_frame:
            return
        ab = self._get("auto_ban")
        if not ab:
            return

        # Clear existing
        for w in self._recent_bans_frame.winfo_children():
            w.destroy()

        try:
            bans = ab.get_ban_list()
            # Sort by banned_at descending, take last 5
            sorted_bans = sorted(
                bans.items(),
                key=lambda x: x[1].get("banned_at", ""),
                reverse=True,
            )[:5]

            if not sorted_bans:
                ctk.CTkLabel(
                    self._recent_bans_frame, text="No bans yet",
                    font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
                ).pack(anchor="w")
                return

            for ip, info in sorted_bans:
                row = ctk.CTkFrame(self._recent_bans_frame, fg_color="transparent")
                row.pack(fill="x", pady=1)
                reasons = info.get("reasons", [])
                reason_str = reasons[-1] if reasons else "unknown"
                sev = info.get("severity", "HIGH")
                color = SEVERITY_COLORS.get(sev, C_TEXT)
                ctk.CTkLabel(
                    row, text=f"{ip}", font=MONO_FONT_SMALL, text_color=color,
                ).pack(side="left")
                ctk.CTkLabel(
                    row, text=f"  {reason_str[:40]}", font=LABEL_FONT_SMALL,
                    text_color=C_TEXT_DIM,
                ).pack(side="left")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Honeypots updates
    # ------------------------------------------------------------------
    def _update_honeypots(self):
        mgr = self._get("honeypot_manager")
        if not mgr:
            return
        try:
            stats = mgr.get_stats()
            by_type = stats.get("by_type", {})
            last_event = stats.get("last_event")
            last_hp = last_event.get("honeypot", "").upper() if last_event else ""
            last_time = _format_time(last_event.get("timestamp", "")) if last_event else "--:--:--"

            for row in self._honeypot_rows:
                name = row["name"]
                key = name.lower().replace("-", "").replace(" ", "")
                hits = 0
                for type_key, count in by_type.items():
                    if key in type_key.lower().replace("_", ""):
                        hits += count
                row["hits_label"].configure(text=str(hits))
                if last_hp and key in last_hp.lower().replace("_", ""):
                    row["last_label"].configure(text=last_time, text_color=C_CYAN)
                elif hits > 0:
                    row["last_label"].configure(text_color=C_TEXT_DIM)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Network updates
    # ------------------------------------------------------------------
    def _update_network_page(self):
        nm = self._get("network_monitor")
        if not self._net_connections_frame:
            return

        # Clear table
        for w in self._net_connections_frame.winfo_children():
            w.destroy()

        # Headers
        headers = ["Local Port", "Remote IP", "Remote Port", "Status", "Process", "Action"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                self._net_connections_frame, text=h, font=LABEL_FONT,
                text_color=C_CYAN_DIM, anchor="w",
            ).grid(row=0, column=col, sticky="w", padx=8, pady=(4, 8))

        connections = []
        if nm:
            try:
                connections = nm.get_active_connections()
            except Exception:
                pass

        # Apply filter
        filter_text = self._net_search_var.get().strip().lower() if self._net_search_var else ""
        if filter_text:
            connections = [
                c for c in connections
                if filter_text in c.get("local_addr", "").lower()
                or filter_text in c.get("remote_addr", "").lower()
                or filter_text in c.get("process", "").lower()
            ]

        for row_idx, conn in enumerate(connections[:100], start=1):
            local = conn.get("local_addr", "")
            remote = conn.get("remote_addr", "")
            status = conn.get("status", "")
            proc = conn.get("process", "")

            local_port = local.rsplit(":", 1)[-1] if ":" in local else local
            remote_ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
            remote_port = remote.rsplit(":", 1)[-1] if ":" in remote else ""

            status_color = C_GREEN if status == "ESTABLISHED" else C_YELLOW

            ctk.CTkLabel(
                self._net_connections_frame, text=local_port,
                font=MONO_FONT_SMALL, text_color=C_TEXT,
            ).grid(row=row_idx, column=0, sticky="w", padx=8, pady=2)

            ctk.CTkLabel(
                self._net_connections_frame, text=remote_ip,
                font=MONO_FONT_SMALL, text_color=C_TEXT,
            ).grid(row=row_idx, column=1, sticky="w", padx=8, pady=2)

            ctk.CTkLabel(
                self._net_connections_frame, text=remote_port,
                font=MONO_FONT_SMALL, text_color=C_TEXT,
            ).grid(row=row_idx, column=2, sticky="w", padx=8, pady=2)

            ctk.CTkLabel(
                self._net_connections_frame, text=status,
                font=MONO_FONT_SMALL, text_color=status_color,
            ).grid(row=row_idx, column=3, sticky="w", padx=8, pady=2)

            ctk.CTkLabel(
                self._net_connections_frame, text=proc,
                font=MONO_FONT_SMALL, text_color=C_TEXT_DIM,
            ).grid(row=row_idx, column=4, sticky="w", padx=8, pady=2)

            # Ban button (only for non-empty remote IPs that are not local)
            if remote_ip and not remote_ip.startswith("127.") and not remote_ip.startswith("0."):
                ctk.CTkButton(
                    self._net_connections_frame, text="Ban", font=BADGE_FONT,
                    width=50, height=24,
                    fg_color="#441122", hover_color="#662233", text_color=C_RED,
                    command=lambda ip=remote_ip: self._ban_ip_action(ip),
                ).grid(row=row_idx, column=5, padx=8, pady=2)

        # Update banned IPs list
        self._update_banned_display()
        self._update_whitelist_display()

    def _update_banned_display(self):
        if not self._banned_frame:
            return
        for w in self._banned_frame.winfo_children():
            w.destroy()

        ab = self._get("auto_ban")
        if not ab:
            return

        try:
            bans = ab.get_ban_list()
            if not bans:
                ctk.CTkLabel(
                    self._banned_frame, text="No banned IPs",
                    font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
                ).grid(row=0, column=0, padx=8, pady=4)
                return

            for idx, (ip, info) in enumerate(bans.items()):
                row = ctk.CTkFrame(self._banned_frame, fg_color="transparent")
                row.grid(row=idx, column=0, sticky="ew", padx=4, pady=2)
                row.grid_columnconfigure(0, weight=1)

                sev = info.get("severity", "HIGH")
                color = SEVERITY_COLORS.get(sev, C_TEXT)
                ctk.CTkLabel(
                    row, text=ip, font=MONO_FONT_SMALL, text_color=color,
                ).pack(side="left", padx=(4, 8))

                reasons = info.get("reasons", [])
                reason_short = reasons[-1][:30] if reasons else ""
                ctk.CTkLabel(
                    row, text=reason_short, font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
                ).pack(side="left", fill="x", expand=True)

                ctk.CTkButton(
                    row, text="Unban", font=BADGE_FONT, width=52, height=22,
                    fg_color="#112244", hover_color="#223366", text_color=C_CYAN,
                    command=lambda i=ip: self._unban_ip_action(i),
                ).pack(side="right", padx=4)
        except Exception:
            pass

    def _update_whitelist_display(self):
        if not self._whitelist_frame:
            return
        for w in self._whitelist_frame.winfo_children():
            w.destroy()

        ab = self._get("auto_ban")
        if not ab:
            return

        try:
            for idx, entry in enumerate(ab.whitelist):
                row = ctk.CTkFrame(self._whitelist_frame, fg_color="transparent")
                row.grid(row=idx, column=0, sticky="ew", padx=4, pady=1)
                row.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(
                    row, text=str(entry), font=MONO_FONT_SMALL, text_color=C_GREEN,
                ).pack(side="left", padx=4)

                ctk.CTkButton(
                    row, text="X", font=BADGE_FONT, width=28, height=22,
                    fg_color="#441122", hover_color="#662233", text_color=C_RED,
                    command=lambda e=entry: self._whitelist_remove(e),
                ).pack(side="right", padx=4)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Threats updates
    # ------------------------------------------------------------------
    def _update_threats(self):
        ts = self._get("threat_scorer")
        if not self._threats_frame:
            return

        # Clear table
        for w in self._threats_frame.winfo_children():
            w.destroy()

        # Headers
        headers = ["IP Address", "Score", "Severity", "Country", "Events", "Actions"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                self._threats_frame, text=h, font=LABEL_FONT,
                text_color=C_CYAN_DIM, anchor="w",
            ).grid(row=0, column=col, sticky="w", padx=8, pady=(4, 8))

        if not ts:
            return

        try:
            threats = ts.get_top_threats(30)
            for row_idx, t in enumerate(threats, start=1):
                ip = t.get("ip", "")
                score = t.get("score", 0)
                severity = t.get("severity", "LOW")
                country = t.get("country", "--")
                events = t.get("event_count", 0)
                sev_color = SEVERITY_COLORS.get(severity, C_TEXT)

                ctk.CTkLabel(
                    self._threats_frame, text=ip,
                    font=MONO_FONT_SMALL, text_color=C_TEXT,
                ).grid(row=row_idx, column=0, sticky="w", padx=8, pady=2)

                # Score with progress bar
                score_frame = ctk.CTkFrame(self._threats_frame, fg_color="transparent")
                score_frame.grid(row=row_idx, column=1, sticky="w", padx=8, pady=2)
                ctk.CTkProgressBar(
                    score_frame, width=80, height=12,
                    progress_color=sev_color, fg_color=C_BG_INPUT,
                ).pack(side="left", padx=(0, 4))
                # Set progress bar value (0-1 range, max 999)
                pb = score_frame.winfo_children()[0]
                pb.set(min(score / 999, 1.0))
                ctk.CTkLabel(
                    score_frame, text=str(score), font=MONO_FONT_SMALL,
                    text_color=sev_color,
                ).pack(side="left")

                # Severity badge
                badge = ctk.CTkLabel(
                    self._threats_frame, text=f" {severity} ",
                    font=BADGE_FONT, text_color=sev_color,
                    fg_color=C_BG_INPUT, corner_radius=4,
                )
                badge.grid(row=row_idx, column=2, sticky="w", padx=8, pady=2)

                ctk.CTkLabel(
                    self._threats_frame, text=country,
                    font=MONO_FONT_SMALL, text_color=C_TEXT_DIM,
                ).grid(row=row_idx, column=3, sticky="w", padx=8, pady=2)

                ctk.CTkLabel(
                    self._threats_frame, text=str(events),
                    font=MONO_FONT_SMALL, text_color=C_TEXT,
                ).grid(row=row_idx, column=4, sticky="w", padx=8, pady=2)

                # Action buttons
                act_frame = ctk.CTkFrame(self._threats_frame, fg_color="transparent")
                act_frame.grid(row=row_idx, column=5, sticky="w", padx=8, pady=2)
                ctk.CTkButton(
                    act_frame, text="Ban", font=BADGE_FONT, width=42, height=22,
                    fg_color="#441122", hover_color="#662233", text_color=C_RED,
                    command=lambda i=ip: self._ban_ip_action(i),
                ).pack(side="left", padx=(0, 4))
                ctk.CTkButton(
                    act_frame, text="WL", font=BADGE_FONT, width=36, height=22,
                    fg_color="#113322", hover_color="#225533", text_color=C_GREEN,
                    command=lambda i=ip: self._whitelist_ip_from_threats(i),
                ).pack(side="left")
        except Exception:
            pass

        # IDS attack log
        self._update_ids_log()

    def _whitelist_ip_from_threats(self, ip: str):
        """Add an IP to the whitelist directly from the threats page."""
        ab = self._get("auto_ban")
        if not ab:
            return
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            ab.whitelist.append(addr)
            # Also unban if currently banned
            if ip in ab.banned_ips:
                threading.Thread(target=lambda: ab.unban_ip(ip), daemon=True).start()
        except ValueError:
            pass

    def _update_ids_log(self):
        if not self._ids_log_box:
            return

        ids_mod = self._get("intrusion_detector")
        nm = self._get("network_monitor")

        lines: list[tuple[str, str]] = []

        # Get alerts from IDS
        if ids_mod:
            try:
                attacks = getattr(ids_mod, "recent_attacks", [])
                if callable(attacks):
                    attacks = attacks()
                elif hasattr(ids_mod, "get_recent_attacks"):
                    attacks = ids_mod.get_recent_attacks()
                for atk in attacks[-20:]:
                    ts_str = _format_time(atk.get("timestamp", ""))
                    sev = atk.get("severity", "LOW")
                    src = atk.get("source_ip", "")
                    atype = atk.get("type", "UNKNOWN")
                    desc = atk.get("description", atype)
                    line = f"[{ts_str}] {sev:<9} {src:<18} {desc}"
                    lines.append((line, sev))
            except Exception:
                pass

        # Also show network monitor alerts
        if nm:
            try:
                alerts = nm.get_recent_alerts(20)
                for alert in alerts:
                    ts_str = _format_time(alert.get("timestamp", ""))
                    sev = alert.get("severity", "LOW")
                    src = alert.get("source_ip", alert.get("address", ""))
                    atype = alert.get("type", "UNKNOWN")
                    line = f"[{ts_str}] {sev:<9} {src:<18} {atype}"
                    lines.append((line, sev))
            except Exception:
                pass

        if lines:
            self._ids_log_box.configure(state="normal")
            self._ids_log_box.delete("1.0", "end")
            for line_text, sev in lines[-40:]:
                self._ids_log_box.insert("end", line_text + "\n", sev)
            self._ids_log_box.see("end")
            self._ids_log_box.configure(state="disabled")

    # ------------------------------------------------------------------
    # Supply Chain updates
    # ------------------------------------------------------------------
    def _update_supply_chain(self):
        da = self._get("dependency_auditor")
        cm = self._get("credential_monitor")
        cont = self._get("container_monitor")

        # Update status labels
        if cm:
            try:
                running = getattr(cm, "_running", False)
                status = "ACTIVE" if running else "IDLE"
                color = C_GREEN if running else C_YELLOW
                self._supply_status_labels["cred_status"].configure(text=status, text_color=color)
            except Exception:
                pass

        if cont:
            try:
                running = getattr(cont, "_running", False)
                status = "ACTIVE" if running else "IDLE"
                color = C_GREEN if running else C_YELLOW
                self._supply_status_labels["container_status"].configure(
                    text=status, text_color=color
                )
            except Exception:
                pass

        if not self._supply_frame:
            return

        # Clear table
        for w in self._supply_frame.winfo_children():
            w.destroy()

        # Headers
        headers = ["Package", "Version", "Status", "Issue"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                self._supply_frame, text=h, font=LABEL_FONT,
                text_color=C_CYAN_DIM, anchor="w",
            ).grid(row=0, column=col, sticky="w", padx=8, pady=(4, 8))

        if not da:
            ctk.CTkLabel(
                self._supply_frame, text="Dependency auditor not loaded",
                font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
            ).grid(row=1, column=0, columnspan=4, padx=8, pady=4)
            return

        try:
            # Try to get results from auditor
            results = getattr(da, "results", [])
            if callable(results):
                results = results()
            elif hasattr(da, "get_results"):
                results = da.get_results()
            elif hasattr(da, "findings"):
                findings = da.findings
                results = findings if isinstance(findings, list) else []

            if not results:
                # Try to get quick local scan data
                if hasattr(da, "local_packages"):
                    pkgs = da.local_packages
                    if callable(pkgs):
                        pkgs = pkgs()
                    if isinstance(pkgs, dict):
                        results = [
                            {"package": k, "version": v, "status": "OK", "issue": ""}
                            for k, v in list(pkgs.items())[:50]
                        ]

            if not results:
                ctk.CTkLabel(
                    self._supply_frame,
                    text="No scan results yet. Click 'Run Full Scan' to start.",
                    font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
                ).grid(row=1, column=0, columnspan=4, padx=8, pady=4)
                return

            for row_idx, r in enumerate(results[:100], start=1):
                pkg = r.get("package", r.get("name", ""))
                ver = r.get("version", "")
                status = r.get("status", r.get("severity", "OK"))
                issue = r.get("issue", r.get("description", ""))

                # Status color
                if status in ("CRITICAL", "critical"):
                    s_color = C_RED
                    s_text = "CRITICAL"
                elif status in ("WARN", "WARNING", "HIGH", "high"):
                    s_color = C_ORANGE
                    s_text = "WARN"
                elif status in ("MEDIUM", "medium"):
                    s_color = C_YELLOW
                    s_text = "WARN"
                else:
                    s_color = C_GREEN
                    s_text = "OK"

                ctk.CTkLabel(
                    self._supply_frame, text=pkg,
                    font=MONO_FONT_SMALL, text_color=C_TEXT,
                ).grid(row=row_idx, column=0, sticky="w", padx=8, pady=2)

                ctk.CTkLabel(
                    self._supply_frame, text=ver,
                    font=MONO_FONT_SMALL, text_color=C_TEXT_DIM,
                ).grid(row=row_idx, column=1, sticky="w", padx=8, pady=2)

                ctk.CTkLabel(
                    self._supply_frame, text=f" {s_text} ",
                    font=BADGE_FONT, text_color=s_color,
                    fg_color=C_BG_INPUT, corner_radius=4,
                ).grid(row=row_idx, column=2, sticky="w", padx=8, pady=2)

                ctk.CTkLabel(
                    self._supply_frame, text=issue[:60] if issue else "",
                    font=LABEL_FONT_SMALL, text_color=C_TEXT_DIM,
                ).grid(row=row_idx, column=3, sticky="w", padx=8, pady=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self):
        """Start the GUI application. Blocks until window is closed."""
        self.root.after(2000, self._update_loop)
        self.root.mainloop()

    def stop(self):
        """Gracefully stop the GUI."""
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
