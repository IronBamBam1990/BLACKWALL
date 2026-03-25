"""
File Integrity Monitor (FIM) - Monitoruje zmiany w krytycznych plikach systemowych.
Wykrywa modyfikacje, usuniecia, zmiany uprawnien.
"""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


# Domyslne pliki do monitorowania
DEFAULT_WATCHED_PATHS = [
    # System krytyczne
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\taskhost.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\services.exe",
    # Boot
    r"C:\Windows\System32\bootmgr",
    r"C:\bootmgr",
    # Security
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SECURITY",
    r"C:\Windows\System32\config\SYSTEM",
]


class FileIntegrityMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 30)
        self.watched_paths = config.get("watched_paths", DEFAULT_WATCHED_PATHS)
        self.baseline_file = Path(config.get("baseline_file", "config/file_integrity_baseline.json"))

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.baseline = {}
        self.alert_callbacks = []
        self.alerts = []
        self.changes_detected = 0
        self._running = False
        self._setup_logger()

        # Dodaj pliki suite do monitorowania
        suite_dir = Path(__file__).parent.parent
        for f in ["security_suite.py", "config/config.json"]:
            p = str(suite_dir / f)
            if p not in self.watched_paths:
                self.watched_paths.append(p)

    def _setup_logger(self):
        self.logger = logging.getLogger("FileIntegrity")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "file_integrity.log",
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

    def _hash_file(self, filepath: str) -> str | None:
        """Oblicza SHA-256 hash pliku."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def _get_file_info(self, filepath: str) -> dict | None:
        """Pobiera info o pliku."""
        try:
            stat = os.stat(filepath)
            file_hash = self._hash_file(filepath)
            return {
                "path": filepath,
                "hash": file_hash,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "mtime_str": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            }
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def build_baseline(self):
        """Buduje baseline hashow."""
        self.baseline = {}
        for path in self.watched_paths:
            info = self._get_file_info(path)
            if info:
                self.baseline[path] = info

        # Zapisz baseline
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(self.baseline, f, indent=2)

        self.logger.info(f"Baseline built: {len(self.baseline)} files")

    def load_baseline(self) -> bool:
        """Laduje baseline z pliku."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    self.baseline = json.load(f)
                self.logger.info(f"Baseline loaded: {len(self.baseline)} files")
                return True
            except (json.JSONDecodeError, IOError):
                pass
        return False

    def check(self) -> list:
        """Sprawdza pliki pod katem zmian."""
        alerts = []

        for path in self.watched_paths:
            baseline_info = self.baseline.get(path)
            current_info = self._get_file_info(path)

            # Plik usuniety
            if baseline_info and not current_info:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "FILE_DELETED",
                    "path": path,
                    "severity": "CRITICAL",
                    "description": f"Plik usuniety: {path}",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(alert["description"])
                continue

            # Plik nowy (nie byl w baseline)
            if not baseline_info and current_info:
                self.baseline[path] = current_info
                continue

            if not baseline_info or not current_info:
                continue

            # Hash zmieniony
            if current_info["hash"] and baseline_info.get("hash") and \
               current_info["hash"] != baseline_info["hash"]:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "FILE_MODIFIED",
                    "path": path,
                    "old_hash": baseline_info["hash"][:16] + "...",
                    "new_hash": current_info["hash"][:16] + "...",
                    "old_size": baseline_info.get("size", 0),
                    "new_size": current_info["size"],
                    "severity": "CRITICAL" if "System32" in path else "HIGH",
                    "description": f"Plik zmodyfikowany: {Path(path).name}",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(
                    f"FILE MODIFIED: {path} | "
                    f"Hash: {baseline_info['hash'][:16]}... -> {current_info['hash'][:16]}..."
                )
                self.changes_detected += 1

            # Rozmiar zmieniony (nawet bez zmiany hasha - dziwne)
            elif current_info["size"] != baseline_info.get("size", 0):
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "FILE_SIZE_CHANGE",
                    "path": path,
                    "old_size": baseline_info.get("size", 0),
                    "new_size": current_info["size"],
                    "severity": "HIGH",
                    "description": f"Rozmiar zmieniony: {Path(path).name}",
                }
                alerts.append(alert)
                self._fire_alert(alert)

        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return

        self._running = True

        # Zaladuj lub zbuduj baseline
        if not self.load_baseline():
            self.build_baseline()

        self.logger.info("File Integrity Monitor started")

        while self._running:
            try:
                self.check()
            except Exception as e:
                self.logger.error(f"FIM check error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "monitored_files": len(self.watched_paths),
            "baseline_files": len(self.baseline),
            "changes_detected": self.changes_detected,
            "alerts": len(self.alerts),
        }
