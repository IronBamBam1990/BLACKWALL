"""
Registry & Startup Monitor - Wykrywa persistence mechanisms.
Monitoruje klucze rejestru uzywane przez malware do autostartu,
nowe uslugi systemowe i zaplanowane zadania.
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


# Klucze rejestru uzywane do persistence
AUTORUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]

# Startup folders
STARTUP_PATHS = [
    Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
]


class RegistryMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 30)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.baseline_autorun = {}   # key_path -> {value_name: value_data}
        self.baseline_services = {}  # service_name -> display_name
        self.baseline_tasks = set()  # task names
        self.baseline_startup_files = {}  # path -> mtime
        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._first_scan = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("RegistryMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "registry_monitor.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
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

    def _query_reg_key(self, key_path: str) -> dict:
        """Odpytuje klucz rejestru i zwraca wartosci."""
        values = {}
        try:
            result = subprocess.run(
                ["reg", "query", key_path],
                capture_output=True, timeout=10, encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("HK") or line.startswith("End"):
                        continue
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        name, reg_type, data = parts[0], parts[1], parts[2]
                        values[name] = {"type": reg_type, "data": data[:500]}
        except Exception:
            pass
        return values

    def _get_services(self) -> dict:
        """Pobiera liste uslug systemowych."""
        services = {}
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress"],
                capture_output=True, timeout=8, encoding="utf-8", errors="replace",
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for svc in data:
                    name = svc.get("Name", "")
                    if name:
                        services[name] = {
                            "display": svc.get("DisplayName", ""),
                            "status": str(svc.get("Status", "")),
                            "start_type": str(svc.get("StartType", "")),
                        }
        except Exception as e:
            self.logger.error(f"Get services error: {e}")
        return services

    def _get_scheduled_tasks(self) -> set:
        """Pobiera liste zaplanowanych zadan."""
        tasks = set()
        try:
            result = subprocess.run(
                ["schtasks", "/Query", "/FO", "CSV", "/NH"],
                capture_output=True, timeout=8, encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip().strip('"')
                    if line and not line.startswith("INFO"):
                        name = line.split('","')[0].strip('"') if '","' in line else line.split(",")[0].strip('"')
                        if name and name != "TaskName":
                            tasks.add(name)
        except Exception as e:
            self.logger.error(f"Get tasks error: {e}")
        return tasks

    def _get_startup_files(self) -> dict:
        """Pobiera pliki z folderow Startup."""
        files = {}
        for folder in STARTUP_PATHS:
            if folder.exists():
                try:
                    for f in folder.iterdir():
                        if f.is_file():
                            files[str(f)] = f.stat().st_mtime
                except PermissionError:
                    pass
        return files

    def scan(self) -> list:
        """Skanuje pod katem zmian w persistence."""
        alerts = []

        # === AUTORUN REGISTRY ===
        current_autorun = {}
        for key in AUTORUN_KEYS[:6]:  # Pomijamy Services (za duzy)
            values = self._query_reg_key(key)
            if values:
                current_autorun[key] = values

        if self._first_scan:
            self.baseline_autorun = current_autorun
        else:
            for key, values in current_autorun.items():
                baseline_values = self.baseline_autorun.get(key, {})
                for name, info in values.items():
                    if name not in baseline_values:
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "NEW_AUTORUN_ENTRY",
                            "registry_key": key,
                            "value_name": name,
                            "value_data": info.get("data", "")[:200],
                            "severity": "CRITICAL",
                            "description": f"New autorun: {name} = {info.get('data', '')[:60]}",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self.logger.warning(f"NEW AUTORUN: {key}\\{name} = {info.get('data', '')[:100]}")
                    elif info.get("data") != baseline_values[name].get("data"):
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "AUTORUN_MODIFIED",
                            "registry_key": key,
                            "value_name": name,
                            "old_data": baseline_values[name].get("data", "")[:200],
                            "new_data": info.get("data", "")[:200],
                            "severity": "CRITICAL",
                            "description": f"Modified autorun: {name}",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)

            # Sprawdz usuniete (tez podejrzane - moze ukrywanie)
            for key, values in self.baseline_autorun.items():
                current_values = current_autorun.get(key, {})
                for name in values:
                    if name not in current_values:
                        self.logger.info(f"Autorun removed: {key}\\{name}")

        self.baseline_autorun = current_autorun

        # === SERVICES ===
        current_services = self._get_services()
        if self._first_scan:
            self.baseline_services = current_services
        else:
            for name, info in current_services.items():
                if name not in self.baseline_services:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "NEW_SERVICE",
                        "service_name": name,
                        "display_name": info.get("display", ""),
                        "start_type": info.get("start_type", ""),
                        "severity": "HIGH",
                        "description": f"New service: {info.get('display', name)}",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(f"NEW SERVICE: {name} ({info.get('display', '')})")
        self.baseline_services = current_services

        # === SCHEDULED TASKS ===
        current_tasks = self._get_scheduled_tasks()
        if self._first_scan:
            self.baseline_tasks = current_tasks
        else:
            new_tasks = current_tasks - self.baseline_tasks
            for task in new_tasks:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "NEW_SCHEDULED_TASK",
                    "task_name": task,
                    "severity": "HIGH",
                    "description": f"New scheduled task: {task[:60]}",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(f"NEW TASK: {task}")
        self.baseline_tasks = current_tasks

        # === STARTUP FILES ===
        current_startup = self._get_startup_files()
        if self._first_scan:
            self.baseline_startup_files = current_startup
        else:
            for path, mtime in current_startup.items():
                if path not in self.baseline_startup_files:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "NEW_STARTUP_FILE",
                        "file_path": path,
                        "severity": "CRITICAL",
                        "description": f"New startup file: {Path(path).name}",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(f"NEW STARTUP FILE: {path}")
        self.baseline_startup_files = current_startup

        self._first_scan = False
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Registry & Startup Monitor started")
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
            "autorun_keys": sum(len(v) for v in self.baseline_autorun.values()),
            "services": len(self.baseline_services),
            "scheduled_tasks": len(self.baseline_tasks),
            "startup_files": len(self.baseline_startup_files),
            "alerts": len(self.alerts),
        }
