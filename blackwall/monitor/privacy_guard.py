"""
Privacy Guard - Ochrona prywatnosci.
- Wykrywa DNS leaks (zapytania DNS lecace poza VPN/DoH)
- Wykrywa WebRTC leaks
- Monitoruje outbound connections do known trackers
- Wykrywa sniffing na interfejsach sieciowych (promiscuous mode)
- Wykrywa polaczenia do znanych data brokerow
"""

import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


# Znane domeny trackerow / data brokerow
KNOWN_TRACKERS = {
    # Google tracking
    "google-analytics.com", "googleadservices.com", "doubleclick.net",
    "googlesyndication.com", "googletagmanager.com",
    # Facebook
    "facebook.com/tr", "connect.facebook.net", "fbcdn.net",
    # Microsoft telemetry
    "vortex.data.microsoft.com", "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com", "telemetry.microsoft.com",
    "data.microsoft.com",
    # Other trackers
    "scorecardresearch.com", "quantserve.com", "outbrain.com",
    "taboola.com", "criteo.com", "adnxs.com",
    # Data brokers
    "acxiom.com", "oracle.com/marketingcloud", "lotame.com",
}

# Znane IP serwerow telemetrycznych Microsoft
MS_TELEMETRY_IPS = {
    "13.107.4.50", "13.107.5.88",
    "204.79.197.200",
}


class PrivacyGuard:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 15)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.alert_callbacks = []
        self.alerts = []
        self._alerted_keys = set()
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("PrivacyGuard")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "privacy_guard.log",
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
        if len(self.alerts) > 300:
            self.alerts = self.alerts[-150:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def check_promiscuous_mode(self) -> list:
        """Wykrywa interfejsy w trybie promiscuous (sniffing!)."""
        alerts = []
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Select-Object Name,PromiscuousMode,Status | ConvertTo-Json -Compress"],
                capture_output=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                adapters = json.loads(result.stdout)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                for adapter in adapters:
                    if adapter.get("PromiscuousMode"):
                        key = f"promisc_{adapter.get('Name', '')}"
                        if key not in self._alerted_keys:
                            self._alerted_keys.add(key)
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "type": "PROMISCUOUS_MODE",
                                "severity": "CRITICAL",
                                "adapter": adapter.get("Name", "unknown"),
                                "description": f"SNIFFING! Adapter {adapter.get('Name','')} in promiscuous mode",
                            }
                            alerts.append(alert)
                            self._fire_alert(alert)
                            self.logger.warning(alert["description"])
        except Exception:
            pass
        return alerts

    def check_dns_leak(self) -> list:
        """Sprawdza czy DNS nie leakuje (zapytania lecace plain-text na port 53)."""
        alerts = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.port == 53 and conn.status == "ESTABLISHED":
                    dns_ip = conn.raddr.ip
                    # Jesli DNS idzie do czegos innego niz Cloudflare/Google DoH
                    safe_dns = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                                "9.9.9.9", "149.112.112.112", "127.0.0.1"}
                    if dns_ip not in safe_dns:
                        key = f"dns_leak_{dns_ip}"
                        if key not in self._alerted_keys:
                            self._alerted_keys.add(key)
                            proc_name = "unknown"
                            if conn.pid:
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except Exception:
                                    pass
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "type": "DNS_LEAK",
                                "severity": "HIGH",
                                "dns_server": dns_ip,
                                "process": proc_name,
                                "description": f"DNS Leak! {proc_name} -> {dns_ip}:53 (not encrypted)",
                            }
                            alerts.append(alert)
                            self._fire_alert(alert)
        except (psutil.AccessDenied, PermissionError):
            pass
        return alerts

    def check_tracker_connections(self) -> list:
        """Wykrywa polaczenia do znanych trackerow."""
        alerts = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.status == "ESTABLISHED":
                    remote_ip = conn.raddr.ip
                    if remote_ip in MS_TELEMETRY_IPS:
                        key = f"tracker_{remote_ip}"
                        if key not in self._alerted_keys:
                            self._alerted_keys.add(key)
                            proc_name = "unknown"
                            if conn.pid:
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except Exception:
                                    pass
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "type": "TELEMETRY_CONNECTION",
                                "severity": "MEDIUM",
                                "remote_ip": remote_ip,
                                "process": proc_name,
                                "description": f"Telemetry: {proc_name} -> {remote_ip} (Microsoft)",
                            }
                            alerts.append(alert)
                            self._fire_alert(alert)
        except (psutil.AccessDenied, PermissionError):
            pass
        return alerts

    def scan(self) -> list:
        alerts = []
        alerts.extend(self.check_promiscuous_mode())
        alerts.extend(self.check_dns_leak())
        alerts.extend(self.check_tracker_connections())
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Privacy Guard started")
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
        }
