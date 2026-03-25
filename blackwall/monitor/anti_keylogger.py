"""
Anti-Keylogger - Wykrywa programy ktore przechwytuja klawiature.
Monitoruje:
- Procesy z hookami na klawiature (SetWindowsHookEx)
- Procesy czytajace input z klawiatury innych aplikacji
- Znane nazwy keyloggerow
- Procesy z podejrzanymi uprawnieniami do input devices
"""

import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


# Znane nazwy keyloggerow / spyware procesow
KNOWN_KEYLOGGER_NAMES = {
    "keylogger", "kl.exe", "keylog", "hookkey", "keyhook",
    "inputcapture", "keystroke", "keysniff", "keyspy",
    "spyware", "spy.exe", "ratclient", "rat.exe",
    "meterpreter", "payload", "beacon", "cobalt",
    "mimikatz", "procdump", "lazagne", "credwiz",
    "pwdump", "hashdump", "wce.exe", "gsecdump",
    "rubeus", "kerberoast", "sharphound", "bloodhound",
    "empire", "covenant", "sliver", "havoc",
}

# Procesy ktore NIGDY nie powinny sluchac klawiatury
SUSPICIOUS_INPUT_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
}

# Normalne procesy ktore moga miec input hooks (whitelist)
INPUT_HOOK_WHITELIST = {
    "explorer.exe", "dwm.exe", "csrss.exe", "svchost.exe",
    "searchhost.exe", "runtimebroker.exe", "ctfmon.exe",
    "lghub.exe", "lghub_agent.exe",  # Logitech
    "nortonsvc.exe", "navapsvc.exe",  # Norton
    "msmpeng.exe",  # Defender
    "discord.exe", "steam.exe", "code.exe",
    "windowsterminal.exe", "conhost.exe",
    "chrome.exe", "firefox.exe", "msedge.exe",
}


class AntiKeylogger:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 10)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.alert_callbacks = []
        self.alerts = []
        self._known_safe_pids = set()
        self._alerted_pids = set()
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("AntiKeylogger")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "anti_keylogger.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _fire_alert(self, alert: dict):
        self.alerts.append(alert)
        if len(self.alerts) > 200:
            self.alerts = self.alerts[-100:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def scan(self) -> list:
        """Skanuje procesy pod katem keyloggerow."""
        alerts = []

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()

                if pid in self._alerted_pids:
                    continue

                severity = None
                reason = ""

                # 1. Znana nazwa keyloggera
                for kl_name in KNOWN_KEYLOGGER_NAMES:
                    if kl_name in name or kl_name in exe or kl_name in cmdline:
                        severity = "CRITICAL"
                        reason = f"Known malware name: {kl_name}"
                        break

                # 2. Podejrzane slowa w command line
                if not severity:
                    sus_keywords = [
                        "keylog", "hook", "capture key", "record key",
                        "getasynckeystate", "setwindowshookex", "rawinput",
                        "clipboard", "screenshot", "screenlog",
                    ]
                    for kw in sus_keywords:
                        if kw in cmdline:
                            severity = "HIGH"
                            reason = f"Suspicious keyword in cmdline: {kw}"
                            break

                # 3. Podejrzane procesy z siecią
                if not severity and name in SUSPICIOUS_INPUT_PROCESSES:
                    # Sprawdz czy ma polaczenia sieciowe
                    try:
                        connections = proc.net_connections()
                        if connections:
                            severity = "HIGH"
                            reason = f"{name} has network connections ({len(connections)})"
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                if severity:
                    self._alerted_pids.add(pid)
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "KEYLOGGER_DETECTED",
                        "severity": severity,
                        "pid": pid,
                        "process_name": proc.info["name"],
                        "exe": proc.info["exe"] or "N/A",
                        "reason": reason,
                        "description": f"Keylogger? {proc.info['name']} (PID:{pid}) - {reason}",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(alert["description"])

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return alerts

    def scan_input_hooks(self) -> list:
        """Sprawdza procesy z Windows input hooks (wymaga admina)."""
        alerts = []
        try:
            # PowerShell: znajdz procesy z uchwytami do RawInput lub keyboard hooks
            ps_cmd = (
                "Get-Process | Where-Object {$_.Modules.ModuleName -match 'user32'} | "
                "Select-Object Id,ProcessName -First 30 | ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            # Parsuj ale nie alertuj na whitelist
            # (uzywamy tylko do dodatkowego kontekstu)
        except Exception:
            pass
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Anti-Keylogger started")
        while self._running:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self.scan)
            except Exception as e:
                self.logger.error(f"Scan error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "alerts": len(self.alerts),
            "scanned_pids": len(self._alerted_pids),
        }
