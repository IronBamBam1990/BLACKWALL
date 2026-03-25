"""
ARP Spoof Detection - Monitoruje tablice ARP.
Wykrywa ARP poisoning, zmiany MAC adresow, spoofing gateway.
"""

import asyncio
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


class ARPMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 5)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.arp_baseline = {}  # ip -> mac
        self.mac_to_ips = {}    # mac -> set of IPs
        self.gateway_ip = None
        self.gateway_mac = None
        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._first_scan = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("ARPMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "arp_monitor.log",
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

    def _get_arp_table(self) -> dict:
        """Parsuje ARP table z 'arp -a'."""
        arp_table = {}
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, timeout=10, encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                # Format Windows: 192.168.1.1  00-aa-bb-cc-dd-ee  dynamic
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(\w+)",
                        line,
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).lower().replace("-", ":")
                        entry_type = match.group(3)
                        if entry_type == "dynamic":
                            arp_table[ip] = mac
        except Exception as e:
            self.logger.error(f"Cannot read ARP table: {e}")
        return arp_table

    def _get_gateway(self) -> str | None:
        """Pobiera IP bramy domyslnej."""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                capture_output=True, timeout=10, encoding="utf-8", errors="replace",
            )
            if result.returncode == 0:
                gw = result.stdout.strip()
                if re.match(r"\d+\.\d+\.\d+\.\d+", gw):
                    return gw
        except Exception:
            pass

        # Fallback: ipconfig
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True, timeout=10, encoding="utf-8", errors="replace",
            )
            for line in result.stdout.splitlines():
                if "Default Gateway" in line or "Brama domyslna" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return None

    def scan(self) -> list:
        """Wykonuje skan ARP i zwraca wykryte anomalie."""
        alerts = []
        current_arp = self._get_arp_table()

        if not current_arp:
            return alerts

        # Pierwszy skan - ustaw baseline
        if self._first_scan:
            self.arp_baseline = current_arp.copy()
            self.gateway_ip = self._get_gateway()
            if self.gateway_ip and self.gateway_ip in current_arp:
                self.gateway_mac = current_arp[self.gateway_ip]
                self.logger.info(
                    f"Gateway: {self.gateway_ip} -> {self.gateway_mac}"
                )
            self._first_scan = False
            self.logger.info(f"ARP baseline set: {len(current_arp)} entries")
            return alerts

        # Sprawdz zmiany MAC
        for ip, mac in current_arp.items():
            old_mac = self.arp_baseline.get(ip)
            if old_mac and old_mac != mac:
                is_gateway = ip == self.gateway_ip
                severity = "CRITICAL" if is_gateway else "HIGH"

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "ARP_SPOOF_DETECTED" if is_gateway else "ARP_MAC_CHANGE",
                    "ip": ip,
                    "old_mac": old_mac,
                    "new_mac": mac,
                    "is_gateway": is_gateway,
                    "severity": severity,
                    "description": (
                        f"GATEWAY ARP SPOOF! {ip}: {old_mac} -> {mac}"
                        if is_gateway
                        else f"MAC zmiana: {ip}: {old_mac} -> {mac}"
                    ),
                }
                alerts.append(alert)
                self.logger.warning(alert["description"])
                self._fire_alert(alert)

        # Sprawdz duplikaty MAC (wiele IP na jednym MAC = potencjalny spoof)
        mac_to_ips = {}
        for ip, mac in current_arp.items():
            if mac not in mac_to_ips:
                mac_to_ips[ip] = set()
            mac_to_ips.setdefault(mac, set()).add(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 3:  # Wiecej niz 3 IP na jednym MAC
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "ARP_DUPLICATE_MAC",
                    "mac": mac,
                    "ips": sorted(ips),
                    "count": len(ips),
                    "severity": "HIGH",
                    "description": f"MAC {mac} ma {len(ips)} IP: {', '.join(sorted(ips)[:5])}",
                }
                alerts.append(alert)
                self.logger.warning(alert["description"])
                self._fire_alert(alert)

        # Aktualizuj baseline
        self.arp_baseline.update(current_arp)
        self.mac_to_ips = mac_to_ips

        return alerts

    async def monitor_loop(self):
        """Glowna petla monitorowania ARP."""
        if not self.enabled:
            return

        self._running = True
        self.logger.info("ARP Monitor started")

        while self._running:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self.scan)
            except Exception as e:
                self.logger.error(f"ARP scan error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False
        self.logger.info("ARP Monitor stopped")

    def get_arp_table(self) -> dict:
        return self.arp_baseline.copy()

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "entries": len(self.arp_baseline),
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "alerts": len(self.alerts),
        }
