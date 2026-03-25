"""
BLACKWALL Dashboard v4.0 - Cyberpunk-themed zero-flicker security dashboard.
Uses ANSI escape codes for cursor repositioning instead of cls.
Renders only changed parts of the screen.
"""

import asyncio
import sys
import os
from datetime import datetime, timezone
from io import StringIO

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("Install: pip install rich")
    sys.exit(1)

import psutil

SEVERITY_STYLES = {
    "CRITICAL": "bold red reverse",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "dim green",
}

# Cyberpunk color palette
CY = "bold cyan"
MG = "bold magenta"
RD = "bold red"
GN = "bold green"
YL = "bold yellow"
DM = "dim"


class BlackwallDashboard:
    def __init__(self, honeypot_manager=None, network_monitor=None,
                 intrusion_detector=None, auto_ban=None,
                 geoip=None, threat_intel=None, arp_monitor=None,
                 process_monitor=None, file_integrity=None, alert_manager=None,
                 threat_scorer=None, canary_tokens=None, usb_monitor=None,
                 eventlog_monitor=None, bandwidth_monitor=None,
                 outbound_analyzer=None, registry_monitor=None,
                 supply_chain=None, credential_monitor=None,
                 dependency_auditor=None, container_monitor=None):
        self.honeypot_mgr = honeypot_manager
        self.net_monitor = network_monitor
        self.ids = intrusion_detector
        self.auto_ban = auto_ban
        self.geoip = geoip
        self.threat_intel = threat_intel
        self.arp_monitor = arp_monitor
        self.proc_monitor = process_monitor
        self.fim = file_integrity
        self.alert_mgr = alert_manager
        self.threat_scorer = threat_scorer
        self.canary = canary_tokens
        self.usb_mon = usb_monitor
        self.eventlog = eventlog_monitor
        self.bw_mon = bandwidth_monitor
        self.outbound = outbound_analyzer
        self.reg_mon = registry_monitor
        self.supply_chain = supply_chain
        self.credential_monitor = credential_monitor
        self.dependency_auditor = dependency_auditor
        self.container_monitor = container_monitor
        self.console = Console()
        self._running = False
        self._page = 0
        self._page_count = 5
        self._page_timer = 0
        self._page_interval = 15
        self._last_frame = ""
        self._first_render = True
        self._buffer_console = Console(
            file=StringIO(), width=120,
            force_terminal=True, color_system="truecolor",
        )

    # ================================================================
    #                           HEADER
    # ================================================================
    def _header(self) -> Panel:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        pages = ["OVERVIEW", "THREAT INTEL", "INTEGRITY", "DEFENSE", "SUPPLY CHAIN"]
        h = Text()
        h.append("  \u25c8 BLACKWALL v4.0 \u25c8", style="bold cyan on black")
        h.append("  \u2502  ", style="dim magenta")
        h.append(now, style="bold cyan")
        h.append("  \u2502  ", style="dim magenta")
        h.append("BARRIER ACTIVE", style="bold green on black")
        h.append("  \u2502  ", style="dim magenta")
        h.append(pages[self._page], style="bold magenta")
        if self.threat_intel:
            s = self.threat_intel.get_stats()
            h.append(f"  \u2502  TI:{s.get('total_bad_ips', 0)}", style="yellow")
        return Panel(h, style="bold magenta", box=box.DOUBLE)

    # ================================================================
    #                     PAGE 1: OVERVIEW
    # ================================================================
    def _honeypot_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("HP", style="cyan", width=7)
        t.add_column("Port", style="yellow", width=5)
        t.add_column("Hits", style="red", justify="right", width=5)
        t.add_column("", width=3)
        if self.honeypot_mgr:
            stats = self.honeypot_mgr.get_stats()
            bt = stats.get("by_type", {})
            for hp in self.honeypot_mgr.honeypots:
                hits = bt.get(hp.name, 0)
                hs = "bold red" if hits > 10 else "red" if hits > 0 else "green"
                t.add_row(
                    hp.name.upper(), str(hp.port),
                    Text(str(hits), style=hs),
                    Text("ON", style="bold green"),
                )
        return Panel(t, title="[cyan]\u25c8 HONEYPOTS[/]", border_style="cyan", box=box.DOUBLE)

    def _alerts_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Time", style="dim", width=8)
        t.add_column("Sev", width=4)
        t.add_column("Type", style="yellow", width=15)
        t.add_column("IP", style="red", width=15)
        t.add_column("Info", width=28)
        alerts = []
        if self.net_monitor:
            alerts.extend(self.net_monitor.get_recent_alerts(6))
        if self.ids:
            alerts.extend(self.ids.detected_attacks[-6:])
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        for a in alerts[:8]:
            ts = a.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
            except Exception:
                ts = ts[:8]
            sev = a.get("severity", "LOW")
            t.add_row(
                ts,
                Text(sev[:4], style=SEVERITY_STYLES.get(sev, "dim")),
                a.get("type", "")[:15],
                a.get("source_ip", a.get("ip", ""))[:15],
                (a.get("description", "") or "")[:28],
            )
        if not alerts:
            t.add_row("", "", "System clean", "", "")
        return Panel(t, title="[red]\u25c8 ALERTS[/]", border_style="red", box=box.DOUBLE)

    def _banned_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("IP", style="red", width=15)
        t.add_column("Reason", width=25)
        t.add_column("Sev", width=4)
        t.add_column("FW", width=2)
        if self.auto_ban:
            bans = self.auto_ban.get_ban_list()
            for ip, info in list(bans.items())[-6:]:
                rs = info.get("reasons", [])
                r = rs[-1][:25] if rs else "?"
                fw = Text("Y", style="green") if info.get("firewall_rule_added") else Text("N", style="red")
                t.add_row(ip, r, Text(info.get("severity", "")[:4], style="bold red"), fw)
            if not bans:
                t.add_row("", "None", "", "")
        return Panel(t, title="[magenta]\u25c8 BANNED[/]", border_style="magenta", box=box.DOUBLE)

    def _network_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=13)
        t.add_column("", style="yellow", justify="right", width=13)
        if self.net_monitor:
            s = self.net_monitor.get_network_stats()
            c = self.net_monitor.get_active_connections()

            def fmt(b):
                for u in ["B", "KB", "MB", "GB"]:
                    if b < 1024:
                        return f"{b:.1f}{u}"
                    b /= 1024
                return f"{b:.1f}TB"

            est = sum(1 for x in c if x["status"] == "ESTABLISHED")
            lis = sum(1 for x in c if x["status"] == "LISTEN")
            t.add_row("Established", str(est))
            t.add_row("Listeners", str(lis))
            t.add_row("Bytes Sent", fmt(s.get("bytes_sent", 0)))
            t.add_row("Bytes Recv", fmt(s.get("bytes_recv", 0)))
            t.add_row("Errors", str(s.get("errors_in", 0) + s.get("errors_out", 0)))
        return Panel(t, title="[yellow]\u25c8 NETWORK[/]", border_style="yellow", box=box.DOUBLE)

    # ================================================================
    #                    PAGE 2: THREAT INTEL
    # ================================================================
    def _geo_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("CC", width=3)
        t.add_column("Country", style="cyan", width=14)
        t.add_column("Hits", style="red", justify="right", width=6)
        if self.honeypot_mgr:
            bc = self.honeypot_mgr.get_stats().get("by_country", {})
            for cc, cnt in sorted(bc.items(), key=lambda x: x[1], reverse=True)[:10]:
                nm = cc
                if self.geoip:
                    for d in self.geoip._cache.values():
                        if d.get("country") == cc:
                            nm = d.get("country_name", cc)[:14]
                            break
                t.add_row(cc, nm, str(cnt))
        if not t.rows:
            t.add_row("--", "No data", "0")
        return Panel(t, title="[cyan]\u25c8 COUNTRIES[/]", border_style="cyan", box=box.DOUBLE)

    def _feeds_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Feed", style="yellow", width=18)
        t.add_column("IPs", style="red", justify="right", width=7)
        t.add_column("Updated", style="dim", width=9)
        if self.threat_intel:
            for n, fi in self.threat_intel.get_stats().get("feeds", {}).items():
                u = fi.get("last_update", "?")
                try:
                    u = datetime.fromisoformat(u).strftime("%H:%M:%S")
                except Exception:
                    pass
                t.add_row(fi.get("description", n)[:18], str(fi.get("count", 0)), u)
            if not self.threat_intel.feed_stats:
                t.add_row("Loading...", "", "")
        else:
            t.add_row("Disabled", "", "")
        return Panel(t, title="[yellow]\u25c8 THREAT FEEDS[/]", border_style="yellow", box=box.DOUBLE)

    def _attackers_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("IP", style="red", width=15)
        t.add_column("Hits", justify="right", width=5)
        t.add_column("CC", width=3)
        t.add_column("TI", width=3)
        if self.honeypot_mgr:
            top = sorted(
                self.honeypot_mgr.get_stats().get("by_ip", {}).items(),
                key=lambda x: x[1], reverse=True,
            )[:10]
            for ip, cnt in top:
                cc = ""
                ti = Text("---", style="dim")
                if self.geoip:
                    cc = self.geoip.get_cached(ip).get("country", "")
                if self.threat_intel and self.threat_intel.check_ip(ip):
                    ti = Text("HIT", style="bold red")
                t.add_row(ip, str(cnt), cc, ti)
        if not t.rows:
            t.add_row("", "0", "", "")
        return Panel(t, title="[red]\u25c8 TOP ATTACKERS[/]", border_style="red", box=box.DOUBLE)

    def _sys_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=10)
        t.add_column("", width=22)
        try:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("C:\\")

            def bar(p, w=14):
                f = int(p / 100 * w)
                c = "green" if p < 60 else "yellow" if p < 85 else "red"
                return Text(f"{'#' * f}{'.' * (w - f)} {p:.0f}%", style=c)

            t.add_row("CPU", bar(cpu))
            t.add_row("RAM", bar(mem.percent))
            t.add_row("Disk C:", bar(disk.percent))
            t.add_row("RAM MB", f"{mem.used // (1024 ** 2)}/{mem.total // (1024 ** 2)}")
        except Exception:
            t.add_row("N/A", "")
        return Panel(t, title="[magenta]\u25c8 SYSTEM[/]", border_style="magenta", box=box.DOUBLE)

    # ================================================================
    #                  PAGE 3: SYSTEM INTEGRITY
    # ================================================================
    def _arp_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=14)
        t.add_column("", style="yellow", width=18)
        if self.arp_monitor:
            s = self.arp_monitor.get_stats()
            ac = s.get("alerts", 0)
            t.add_row("Gateway IP", s.get("gateway_ip") or "N/A")
            t.add_row("Gateway MAC", s.get("gateway_mac") or "N/A")
            t.add_row("ARP Entries", str(s.get("entries", 0)))
            t.add_row("Alerts", Text(str(ac), style="bold red" if ac > 0 else "green"))
        else:
            t.add_row("Status", "Off")
        return Panel(t, title="[cyan]\u25c8 ARP GUARD[/]", border_style="cyan", box=box.DOUBLE)

    def _proc_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Time", style="dim", width=8)
        t.add_column("Process", style="yellow", width=14)
        t.add_column("Parent", style="dim", width=10)
        t.add_column("Sev", width=4)
        if self.proc_monitor:
            for p in self.proc_monitor.get_recent_processes(6)[-6:]:
                ts = p.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = ts[:8]
                sev = p.get("severity", "LOW")
                t.add_row(
                    ts, p.get("name", "?")[:14],
                    p.get("parent_name", "?")[:10],
                    Text(sev[:4], style=SEVERITY_STYLES.get(sev, "dim")),
                )
            if not self.proc_monitor.new_process_log:
                t.add_row("", "Clean", "", "")
            s = self.proc_monitor.get_stats()
            t.add_row("", f"PIDs: {s['tracked_pids']}", "", "")
        else:
            t.add_row("", "Off", "", "")
        return Panel(t, title="[yellow]\u25c8 PROCESSES[/]", border_style="yellow", box=box.DOUBLE)

    def _fim_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=16)
        t.add_column("", style="yellow", width=14)
        if self.fim:
            s = self.fim.get_stats()
            ch = s.get("changes_detected", 0)
            t.add_row("Monitored", str(s.get("monitored_files", 0)))
            t.add_row("Baseline", str(s.get("baseline_files", 0)))
            t.add_row("Changes", Text(str(ch), style="bold red" if ch > 0 else "green"))
            t.add_row("Alerts", str(s.get("alerts", 0)))
        else:
            t.add_row("Status", "Off")
        return Panel(t, title="[green]\u25c8 FILE INTEGRITY[/]", border_style="green", box=box.DOUBLE)

    # ================================================================
    #                      PAGE 4: DEFENSE
    # ================================================================
    def _scores_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("IP", style="red", width=15)
        t.add_column("Score", justify="right", width=5)
        t.add_column("Sev", width=4)
        t.add_column("CC", width=3)
        t.add_column("HPs", width=3)
        if self.threat_scorer:
            for th in self.threat_scorer.get_top_threats(8):
                sev = th["severity"]
                sc = th["score"]
                sc_style = "bold red" if sc >= 100 else "red" if sc >= 60 else "yellow" if sc >= 30 else "dim"
                t.add_row(
                    th["ip"][:15],
                    Text(str(sc), style=sc_style),
                    Text(sev[:4], style=SEVERITY_STYLES.get(sev, "dim")),
                    th.get("country", ""),
                    str(th.get("honeypots_hit", 0)),
                )
        if not t.rows:
            t.add_row("", "0", "", "", "")
        return Panel(t, title="[red]\u25c8 THREAT SCORES[/]", border_style="red", box=box.DOUBLE)

    def _canary_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=14)
        t.add_column("", style="yellow", width=16)
        if self.canary:
            s = self.canary.get_stats()
            al = s.get("alerts", 0)
            t.add_row("Deployed", str(s.get("deployed", 0)))
            t.add_row("Triggered", Text(str(al), style="bold red" if al > 0 else "green"))
            t.add_row("Locations", str(len(s.get("locations", []))))
        else:
            t.add_row("Status", "Off")
        if self.usb_mon:
            s2 = self.usb_mon.get_stats()
            t.add_row("", "")
            t.add_row("USB Devices", str(s2.get("known_devices", 0)))
            ua = s2.get("alerts", 0)
            t.add_row("USB Alerts", Text(str(ua), style="bold red" if ua > 0 else "green"))
        return Panel(t, title="[cyan]\u25c8 CANARY & USB[/]", border_style="cyan", box=box.DOUBLE)

    def _eventlog_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("Time", style="dim", width=8)
        t.add_column("Event", style="yellow", width=20)
        t.add_column("Sev", width=4)
        if self.eventlog:
            for a in self.eventlog.alerts[-6:]:
                ts = a.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = ts[:8]
                sev = a.get("severity", "LOW")
                t.add_row(
                    ts, a.get("type", "")[:20],
                    Text(sev[:4], style=SEVERITY_STYLES.get(sev, "dim")),
                )
            if not self.eventlog.alerts:
                t.add_row("", "No events", "")
            s = self.eventlog.get_stats()
            t.add_row("", f"Monitoring {s.get('monitored_event_ids', 0)} IDs", "")
        else:
            t.add_row("", "Off", "")
        return Panel(t, title="[yellow]\u25c8 WIN EVENT LOG[/]", border_style="yellow", box=box.DOUBLE)

    def _bw_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=12)
        t.add_column("", style="yellow", width=16)
        if self.bw_mon:
            s = self.bw_mon.get_stats()
            t.add_row("Upload", s.get("send_rate", "N/A"))
            t.add_row("Download", s.get("recv_rate", "N/A"))
            t.add_row("Samples", str(s.get("samples", 0)))
            ba = s.get("alerts", 0)
            t.add_row("BW Alerts", Text(str(ba), style="bold red" if ba > 0 else "green"))
        else:
            t.add_row("Status", "Off")
        if self.outbound:
            so = self.outbound.get_stats()
            oa = so.get("alerts", 0)
            t.add_row("", "")
            t.add_row("Outbound Trk", str(so.get("tracked_connections", 0)))
            t.add_row("OB Alerts", Text(str(oa), style="bold red" if oa > 0 else "green"))
        if self.reg_mon:
            sr = self.reg_mon.get_stats()
            t.add_row("", "")
            t.add_row("Services", str(sr.get("services", 0)))
            t.add_row("Sched Tasks", str(sr.get("scheduled_tasks", 0)))
            ra = sr.get("alerts", 0)
            t.add_row("Reg Alerts", Text(str(ra), style="bold red" if ra > 0 else "green"))
        return Panel(t, title="[magenta]\u25c8 BW & REGISTRY[/]", border_style="magenta", box=box.DOUBLE)

    # ================================================================
    #                  PAGE 5: SUPPLY CHAIN
    # ================================================================
    def _supply_chain_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=18)
        t.add_column("", style="yellow", width=14)
        if self.supply_chain:
            try:
                s = self.supply_chain.get_stats() if hasattr(self.supply_chain, "get_stats") else {}
                comp = s.get("compromised_packages", 0)
                pth = s.get("pth_files_detected", 0)
                setup = s.get("suspicious_setup", 0)
                typo = s.get("typosquatting_alerts", 0)
                pip_mon = s.get("pip_monitoring", False)
                t.add_row("Compromised Pkgs", Text(
                    str(comp), style="bold red" if comp > 0 else "green"))
                t.add_row(".pth Detected", Text(
                    str(pth), style="bold red" if pth > 0 else "green"))
                t.add_row("Suspicious setup", Text(
                    str(setup), style="yellow" if setup > 0 else "green"))
                t.add_row("Typosquat Alerts", Text(
                    str(typo), style="bold red" if typo > 0 else "green"))
                t.add_row("Pip Monitoring", Text(
                    "Active" if pip_mon else "Inactive",
                    style="green" if pip_mon else "dim"))
            except Exception:
                t.add_row("Status", Text("Error", style="bold red"))
        else:
            t.add_row("Status", Text("Offline", style="dim"))
            t.add_row("Module", "Not loaded")
        return Panel(
            t, title="[cyan]\u25c8 SUPPLY CHAIN GUARDIAN[/]",
            border_style="cyan", box=box.DOUBLE,
        )

    def _credential_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=18)
        t.add_column("", style="yellow", width=14)
        if self.credential_monitor:
            try:
                s = self.credential_monitor.get_stats() if hasattr(self.credential_monitor, "get_stats") else {}
                files = s.get("monitored_files", 0)
                baseline = s.get("baseline_status", "Unknown")
                access = s.get("recent_access_alerts", 0)
                exfil = s.get("exfiltration_attempts", 0)
                t.add_row("Monitored Files", str(files))
                t.add_row("Baseline", Text(
                    str(baseline),
                    style="green" if baseline in ("OK", "Valid", True) else "yellow"))
                t.add_row("Access Alerts", Text(
                    str(access), style="bold red" if access > 0 else "green"))
                t.add_row("Exfil Attempts", Text(
                    str(exfil), style="bold red" if exfil > 0 else "green"))
            except Exception:
                t.add_row("Status", Text("Error", style="bold red"))
        else:
            t.add_row("Status", Text("Offline", style="dim"))
            t.add_row("Module", "Not loaded")
        return Panel(
            t, title="[magenta]\u25c8 CREDENTIAL VAULT[/]",
            border_style="magenta", box=box.DOUBLE,
        )

    def _dependency_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=18)
        t.add_column("", style="yellow", width=14)
        if self.dependency_auditor:
            try:
                s = self.dependency_auditor.get_stats() if hasattr(self.dependency_auditor, "get_stats") else {}
                total = s.get("total_packages", 0)
                direct = s.get("direct_deps", 0)
                trans = s.get("transitive_deps", 0)
                abandoned = s.get("abandoned_packages", 0)
                integrity = s.get("integrity_failures", 0)
                typo = s.get("typosquats_detected", 0)
                t.add_row("Total Packages", str(total))
                t.add_row("Direct Deps", str(direct))
                t.add_row("Transitive Deps", str(trans))
                t.add_row("Abandoned", Text(
                    str(abandoned), style="yellow" if abandoned > 0 else "green"))
                t.add_row("Integrity Fail", Text(
                    str(integrity), style="bold red" if integrity > 0 else "green"))
                t.add_row("Typosquats", Text(
                    str(typo), style="bold red" if typo > 0 else "green"))
            except Exception:
                t.add_row("Status", Text("Error", style="bold red"))
        else:
            t.add_row("Status", Text("Offline", style="dim"))
            t.add_row("Module", "Not loaded")
        return Panel(
            t, title="[yellow]\u25c8 DEPENDENCY AUDIT[/]",
            border_style="yellow", box=box.DOUBLE,
        )

    def _container_panel(self) -> Panel:
        t = Table(box=None, expand=True, show_edge=False, pad_edge=False)
        t.add_column("", style="cyan", width=18)
        t.add_column("", style="yellow", width=14)
        if self.container_monitor:
            try:
                s = self.container_monitor.get_stats() if hasattr(self.container_monitor, "get_stats") else {}
                docker = s.get("docker_status", "Unknown")
                running = s.get("running_containers", 0)
                priv = s.get("privileged_containers", 0)
                suspicious = s.get("suspicious_images", 0)
                miners = s.get("crypto_miners", 0)
                t.add_row("Docker Status", Text(
                    str(docker),
                    style="green" if docker in ("Running", "Active", "OK") else "yellow"))
                t.add_row("Running", str(running))
                t.add_row("Privileged", Text(
                    str(priv), style="bold red" if priv > 0 else "green"))
                t.add_row("Suspicious Img", Text(
                    str(suspicious), style="bold red" if suspicious > 0 else "green"))
                t.add_row("Crypto Miners", Text(
                    str(miners), style="bold red" if miners > 0 else "green"))
            except Exception:
                t.add_row("Status", Text("Error", style="bold red"))
        else:
            t.add_row("Status", Text("Offline", style="dim"))
            t.add_row("Module", "Not loaded")
        return Panel(
            t, title="[red]\u25c8 CONTAINER SECURITY[/]",
            border_style="red", box=box.DOUBLE,
        )

    # ================================================================
    #                          LAYOUT
    # ================================================================
    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["header"].update(self._header())

        layout["body"].split_row(Layout(name="L"), Layout(name="R"))
        layout["L"].split_column(Layout(name="a"), Layout(name="b"))
        layout["R"].split_column(Layout(name="c"), Layout(name="d"))

        if self._page == 0:
            layout["a"].update(self._honeypot_panel())
            layout["b"].update(self._banned_panel())
            layout["c"].update(self._alerts_panel())
            layout["d"].update(self._network_panel())
        elif self._page == 1:
            layout["a"].update(self._geo_panel())
            layout["b"].update(self._feeds_panel())
            layout["c"].update(self._attackers_panel())
            layout["d"].update(self._sys_panel())
        elif self._page == 2:
            layout["a"].update(self._arp_panel())
            layout["b"].update(self._fim_panel())
            layout["c"].update(self._proc_panel())
            layout["d"].update(self._sys_panel())
        elif self._page == 3:
            layout["a"].update(self._scores_panel())
            layout["b"].update(self._canary_panel())
            layout["c"].update(self._eventlog_panel())
            layout["d"].update(self._bw_panel())
        else:
            layout["a"].update(self._supply_chain_panel())
            layout["b"].update(self._credential_panel())
            layout["c"].update(self._dependency_panel())
            layout["d"].update(self._container_panel())

        # Footer
        tb = len(self.auto_ban.get_ban_list()) if self.auto_ban else 0
        ta = len(self.net_monitor.alerts) if self.net_monitor else 0
        te = self.honeypot_mgr._event_count if self.honeypot_mgr else 0
        f = Text()
        f.append("  \u25c8 ", style="bold cyan")
        f.append(f"Ev:{te}", style="cyan")
        f.append(" \u2502 ", style="dim magenta")
        f.append(f"Ban:{tb}", style="red")
        f.append(" \u2502 ", style="dim magenta")
        f.append(f"Alert:{ta}", style="yellow")
        f.append(" \u2502 ", style="dim magenta")
        pn = ["1:Over", "2:Intel", "3:Integ", "4:Def", "5:Chain"]
        for i, n in enumerate(pn):
            f.append(
                f"[{n}]" if i == self._page else f" {n} ",
                style="bold cyan" if i == self._page else "dim",
            )
        f.append(" \u2502 ", style="dim magenta")
        f.append("The Wall Holds.", style="bold magenta")
        f.append(" \u2502 Keys:1-5 \u2502 Ctrl+C", style="dim")
        layout["footer"].update(Panel(f, style="dim magenta", box=box.DOUBLE))
        return layout

    def _enable_vt_processing(self):
        """Enable VT100 escape codes in Windows Console."""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    def _start_keyboard_thread(self):
        """Start keyboard listener in a daemon thread."""
        import threading

        def _kb_loop():
            try:
                import msvcrt
            except ImportError:
                return
            while self._running:
                try:
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        if ch in (b"1", b"2", b"3", b"4", b"5"):
                            self._page = int(ch) - 1
                            self._page_timer = 0
                except Exception:
                    pass
                import time
                time.sleep(0.1)

        t = threading.Thread(target=_kb_loop, daemon=True)
        t.start()

    async def run(self, refresh_interval: float = 3.0):
        self._running = True
        self._enable_vt_processing()

        # Clear screen once at start (no repeated cls!)
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

        # Keyboard input in background thread (non-blocking)
        self._start_keyboard_thread()

        while self._running:
            try:
                # Adapt to terminal size
                try:
                    cols, rows = os.get_terminal_size()
                except OSError:
                    cols, rows = 120, 35
                self._buffer_console = Console(
                    file=StringIO(), width=cols,
                    force_terminal=True, color_system="truecolor",
                )

                # Render layout to buffer
                self._buffer_console.print(self._build_layout(), height=rows - 1)
                frame = self._buffer_console.file.getvalue()

                # Trim to terminal size
                lines = frame.split("\n")
                if len(lines) > rows:
                    lines = lines[:rows]
                frame = "\n".join(lines)

                # Move cursor home + overwrite (no cls flicker!)
                sys.stdout.write("\033[H" + frame)
                sys.stdout.flush()

                self._page_timer += refresh_interval
                if self._page_timer >= self._page_interval:
                    self._page = (self._page + 1) % self._page_count
                    self._page_timer = 0
            except Exception:
                pass
            await asyncio.sleep(refresh_interval)

    def stop(self):
        self._running = False
