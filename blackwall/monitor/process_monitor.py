"""
Process Integrity Monitor - Wykrywa nowe/podejrzane procesy.
Monitoruje spawning procesow, flagi podejrzane parent-child relacje.
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


# Procesy ktore sa zawsze bezpieczne (nie generuja alertow)
DEFAULT_SAFE_PROCESSES = {
    # Windows core
    "svchost.exe", "system", "system idle process", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "rundll32.exe", "runtimebroker.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
    "shellexperiencehost.exe", "applicationframehost.exe", "systemsettings.exe",
    "lockapp.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "spoolsv.exe", "dashost.exe", "smartscreen.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "wmiprvse.exe",
    "msiexec.exe", "musnotification.exe", "settingsynchost.exe",
    "useroobebroker.exe", "backgroundtaskhost.exe", "compattelrunner.exe",
    "audiodg.exe", "wsappx.exe",
    # Drivers / hardware
    "nvinspector.exe", "nvcontainer.exe", "nvdisplay.container.exe",
    "igfxem.exe", "igfxhk.exe", "igfxtray.exe",
    "lghub.exe", "lghub_agent.exe", "lghub_updater.exe", "lghub_system_tray.exe",
    "raikiservice.exe", "nzxt cam.exe",
    # Common apps
    "chrome.exe", "firefox.exe", "msedge.exe", "msedgewebview2.exe",
    "code.exe", "discord.exe", "steam.exe", "steamwebhelper.exe",
    "slack.exe", "teams.exe", "spotify.exe", "onedrive.exe",
    "onedrive.sync.service.exe",
    # Security
    "nortonsvc.exe", "nortonbrowserupdater.exe", "navapsvc.exe",
    "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe",
    # Python (nasza suite)
    "python.exe", "python3.exe", "pythonw.exe",
    # Networking / system services
    "wlanext.exe", "jhi_service.exe", "iscsiagent.exe",
    "sdxhelper.exe", "phoneexperiencehost.exe", "widgets.exe",
    "widgetservice.exe", "gameinputsvc.exe", "gamebarftserver.exe",
}

# Podejrzane relacje parent -> child
SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("iexplore.exe", "cmd.exe"),
    ("svchost.exe", "cmd.exe"),   # jesli nie SYSTEM
}


class ProcessMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 3)
        extra_safe = set(p.lower() for p in config.get("whitelist_processes", []))
        self.safe_processes = DEFAULT_SAFE_PROCESSES | extra_safe

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.known_pids = {}  # pid -> {"name", "exe", "create_time"}
        self.alert_callbacks = []
        self.alerts = []
        self.new_process_log = []
        self._running = False
        self._first_scan = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("ProcessMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "process_monitor.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _fire_alert(self, alert: dict):
        self.alerts.append(alert)
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-250:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _get_process_info(self, proc: psutil.Process) -> dict | None:
        try:
            info = proc.as_dict(attrs=[
                "pid", "name", "exe", "cmdline", "username",
                "create_time", "ppid", "status",
            ])
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _get_parent_name(self, ppid: int) -> str:
        try:
            return psutil.Process(ppid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def scan(self) -> list:
        """Skanuje procesy, wykrywa nowe/podejrzane."""
        alerts = []
        current_pids = {}

        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or "unknown"
                current_pids[pid] = {
                    "name": name,
                    "create_time": proc.info["create_time"],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if self._first_scan:
            self.known_pids = current_pids.copy()
            self._first_scan = False
            self.logger.info(f"Process baseline: {len(current_pids)} processes")
            return alerts

        # Znajdz nowe procesy
        for pid, info in current_pids.items():
            if pid in self.known_pids:
                continue

            name = info["name"]
            name_lower = name.lower()

            # Ignoruj znane bezpieczne
            if name_lower in self.safe_processes:
                continue

            # Pobierz pelne info
            try:
                proc = psutil.Process(pid)
                full_info = self._get_process_info(proc)
                if not full_info:
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            ppid = full_info.get("ppid", 0)
            parent_name = self._get_parent_name(ppid)
            username = full_info.get("username", "unknown")
            exe = full_info.get("exe", "unknown")
            cmdline = full_info.get("cmdline", [])
            cmdline_str = " ".join(cmdline)[:500] if cmdline else ""

            # Okresl severity
            severity = "LOW"

            # Podejrzane parent-child
            pair = (parent_name.lower(), name_lower)
            if pair in SUSPICIOUS_PARENT_CHILD:
                severity = "CRITICAL"

            # Cmd/powershell spawned by nieoczekiwany parent
            if name_lower in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                if parent_name.lower() not in (
                    "explorer.exe", "code.exe", "windowsterminal.exe",
                    "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe",
                    "conhost.exe", "svchost.exe", "services.exe",
                ):
                    severity = "HIGH"

            # SYSTEM user z podejrzanym procesem
            SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if username and "SYSTEM" in username.upper() and name_lower not in self.safe_processes:
                if SEV_ORDER.get(severity, 0) < SEV_ORDER.get("MEDIUM", 1):
                    severity = "MEDIUM"

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "NEW_PROCESS",
                "pid": pid,
                "name": name,
                "exe": exe or "N/A",
                "cmdline": cmdline_str,
                "username": username or "N/A",
                "parent_pid": ppid,
                "parent_name": parent_name,
                "severity": severity,
                "description": f"New: {name} (PID {pid}) by {parent_name}",
            }

            self.new_process_log.append(entry)
            if len(self.new_process_log) > 200:
                self.new_process_log = self.new_process_log[-100:]

            # Alert tylko dla HIGH i CRITICAL
            if severity in ("HIGH", "CRITICAL"):
                alerts.append(entry)
                self.logger.warning(
                    f"[{severity}] New process: {name} (PID {pid}) "
                    f"Parent: {parent_name} User: {username} CMD: {cmdline_str[:100]}"
                )
                self._fire_alert(entry)

        self.known_pids = current_pids
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return

        self._running = True
        self.logger.info("Process Monitor started")

        while self._running:
            try:
                self.scan()
            except Exception as e:
                self.logger.error(f"Process scan error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    def get_recent_processes(self, count: int = 20) -> list:
        return self.new_process_log[-count:]

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "tracked_pids": len(self.known_pids),
            "new_processes_logged": len(self.new_process_log),
            "alerts": len(self.alerts),
        }
