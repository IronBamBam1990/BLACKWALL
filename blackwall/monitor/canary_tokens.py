"""
Canary Tokens - Pliki/klucze pulapki na systemie.
Gdy ktos je otwiera/czyta - natychmiastowy alert CRITICAL.
Wykrywa lateral movement, insider threats, malware szukajacy credentials.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


# Canary files - pliki ktore wygladaja na cenne ale sa pulapka
CANARY_FILE_TEMPLATES = {
    "passwords.txt": (
        "# Internal credentials - CONFIDENTIAL\n"
        "# Updated: 2024-03-15\n\n"
        "VPN Gateway: admin / Vpn_G4t3w4y_2024!\n"
        "SSH root: ssh_r00t_k3y_2024\n"
        "Database: db_admin / Db_M4st3r_P@ss!\n"
        "AWS Console: ops@company.com / 4ws_C0ns0l3!\n"
    ),
    "id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIA\n"
        "CANARY_TOKEN_DO_NOT_USE_THIS_KEY\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "backup_credentials.xlsx.lnk": "",  # Pusty plik - sam fakt dostepu jest alertem
    ".env.backup": (
        "DB_PASSWORD=Pr0d_DB_2024_s3cret!\n"
        "API_KEY=sk-fake-canary-token-do-not-use\n"
        "AWS_SECRET_ACCESS_KEY=CANARY/FAKE/KEY/DO/NOT/USE\n"
        "STRIPE_SECRET=sk_live_CANARY_FAKE_DO_NOT_USE\n"
    ),
    "wallet.dat": (
        "# Bitcoin wallet backup\n"
        "# CANARY TOKEN - THIS IS NOT A REAL WALLET\n"
    ),
    "vpn_config.ovpn": (
        "client\n"
        "dev tun\n"
        "remote vpn.internal.company.com 1194\n"
        "auth-user-pass credentials.txt\n"
        "# CANARY TOKEN\n"
    ),
}

# Lokalizacje canary plikow
CANARY_LOCATIONS = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
    Path.home() / ".ssh",
]


class CanaryTokens:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 5)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.canary_files = {}  # path -> {hash, mtime, atime}
        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._deployed = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("CanaryTokens")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "canary_tokens.log",
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
        if len(self.alerts) > 200:
            self.alerts = self.alerts[-100:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def deploy(self):
        """Tworzy canary files w strategicznych lokalizacjach."""
        deployed = 0
        for location in CANARY_LOCATIONS:
            if not location.exists():
                try:
                    location.mkdir(parents=True, exist_ok=True)
                except OSError:
                    continue

            for filename, content in CANARY_FILE_TEMPLATES.items():
                filepath = location / filename
                if filepath.exists():
                    continue  # Nie nadpisuj istniejacych plikow

                try:
                    filepath.write_text(content, encoding="utf-8")
                    # Ustaw atime na teraz (baseline)
                    stat = filepath.stat()
                    self.canary_files[str(filepath)] = {
                        "mtime": stat.st_mtime,
                        "atime": stat.st_atime,
                        "size": stat.st_size,
                        "hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                    }
                    deployed += 1
                except (OSError, PermissionError):
                    pass

        self._deployed = True
        self.logger.info(f"Deployed {deployed} canary files in {len(CANARY_LOCATIONS)} locations")
        return deployed

    def check(self) -> list:
        """Sprawdza czy canary files zostaly odczytane/zmodyfikowane."""
        alerts = []

        for filepath_str, baseline in list(self.canary_files.items()):
            filepath = Path(filepath_str)
            if not filepath.exists():
                # PLIK USUNIETY - ktos go skasowal!
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "CANARY_DELETED",
                    "path": filepath_str,
                    "filename": filepath.name,
                    "severity": "CRITICAL",
                    "description": f"Canary DELETED: {filepath.name} in {filepath.parent}",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(alert["description"])
                del self.canary_files[filepath_str]
                continue

            try:
                stat = filepath.stat()
            except OSError:
                continue

            # ACCESS TIME CHANGED - ktos czyta plik!
            if stat.st_atime > baseline["atime"] + 1:  # +1s tolerancja
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "CANARY_ACCESSED",
                    "path": filepath_str,
                    "filename": filepath.name,
                    "severity": "CRITICAL",
                    "description": f"Canary READ: {filepath.name} - ktos czyta pulapke!",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(alert["description"])
                # Aktualizuj baseline zeby nie alertowac ponownie
                baseline["atime"] = stat.st_atime

            # MODIFICATION TIME CHANGED - ktos edytuje plik!
            if stat.st_mtime > baseline["mtime"] + 1:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "CANARY_MODIFIED",
                    "path": filepath_str,
                    "filename": filepath.name,
                    "severity": "CRITICAL",
                    "description": f"Canary MODIFIED: {filepath.name} - intruz edytuje pulapke!",
                }
                alerts.append(alert)
                self._fire_alert(alert)
                self.logger.warning(alert["description"])
                baseline["mtime"] = stat.st_mtime

        return alerts

    def cleanup(self):
        """Usuwa canary files (przy zamykaniu suite)."""
        removed = 0
        for filepath_str in list(self.canary_files.keys()):
            try:
                Path(filepath_str).unlink()
                removed += 1
            except OSError:
                pass
        self.canary_files.clear()
        self.logger.info(f"Cleaned up {removed} canary files")

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True

        # Deploy canary files
        count = self.deploy()
        self.logger.info(f"Canary Tokens monitor started ({count} files deployed)")

        while self._running:
            try:
                self.check()
            except Exception as e:
                self.logger.error(f"Check error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False
        self.cleanup()

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "deployed": len(self.canary_files),
            "alerts": len(self.alerts),
            "locations": [str(p) for p in CANARY_LOCATIONS if p.exists()],
        }
