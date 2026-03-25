"""
USB Device Monitor - Wykrywa nowe urzadzenia USB.
Chroni przed Rubber Ducky, BadUSB, nieznanymi pendrive.
"""

import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


class USBMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 5)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.known_devices = set()  # (device_id, description) tuples
        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._first_scan = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("USBMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "usb_monitor.log",
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

    def _get_usb_devices(self) -> set:
        """Pobiera liste USB urzadzen przez PowerShell."""
        devices = set()
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-PnpDevice -Class USB,HIDClass,DiskDrive,Keyboard,Mouse -Status OK -ErrorAction SilentlyContinue | "
                 "Select-Object InstanceId,FriendlyName,Class | ConvertTo-Json -Compress"],
                capture_output=True, timeout=8,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for dev in data:
                    dev_id = dev.get("InstanceId", "")
                    name = dev.get("FriendlyName", "Unknown")
                    dev_class = dev.get("Class", "")
                    if dev_id:
                        devices.add((dev_id, name, dev_class))
        except Exception as e:
            self.logger.error(f"USB scan error: {e}")
        return devices

    def scan(self) -> list:
        """Skanuje USB urzadzenia."""
        alerts = []
        current = self._get_usb_devices()

        if self._first_scan:
            self.known_devices = current
            self._first_scan = False
            self.logger.info(f"USB baseline: {len(current)} devices")
            return alerts

        # Nowe urzadzenia
        new_devices = current - self.known_devices
        for dev_id, name, dev_class in new_devices:
            # Okresl severity na podstawie typu
            severity = "MEDIUM"
            if dev_class in ("Keyboard", "HIDClass"):
                # Keyboard = potencjalny Rubber Ducky!
                severity = "CRITICAL"
            elif dev_class == "DiskDrive":
                severity = "HIGH"

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "NEW_USB_DEVICE",
                "device_id": dev_id[:100],
                "device_name": name[:100],
                "device_class": dev_class,
                "severity": severity,
                "description": f"New USB: {name} ({dev_class})",
            }
            alerts.append(alert)
            self._fire_alert(alert)
            self.logger.warning(f"NEW USB: {name} | Class: {dev_class} | ID: {dev_id[:60]}")

        # Usuniete urzadzenia
        removed = self.known_devices - current
        for dev_id, name, dev_class in removed:
            self.logger.info(f"USB removed: {name}")

        self.known_devices = current
        return alerts

    async def monitor_loop(self):
        """Uzywane tylko jesli nie przez safe_monitor_loop."""
        if not self.enabled:
            return
        self._running = True
        # Baseline SYNCHRONICZNIE przed petla
        self.scan()
        self.logger.info(f"USB Monitor started ({len(self.known_devices)} baseline devices)")
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
            "known_devices": len(self.known_devices),
            "alerts": len(self.alerts),
        }
