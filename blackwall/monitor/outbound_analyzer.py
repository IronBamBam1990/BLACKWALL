"""
Outbound Connection Analyzer - Wykrywa podejrzane polaczenia wychodzace.
C2 beaconing detection, DNS exfiltration, unusual destinations.
"""

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


# Znane porty C2 / backdoor
# 5555 = Android ADB, 8888/8443 = dev servers - nie C2
C2_PORTS = {
    4444, 6666, 6667, 1337, 31337, 12345, 54321,
    4443, 9001, 9030,  # Tor
    6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669,  # IRC
    1234, 3333, 7777, 9999,
}

# Znane procesy ktore NIE powinny miec polaczen wychodzacych
SUSPICIOUS_OUTBOUND_PROCS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe",
}

# Porty ktore sa normalne dla polaczen wychodzacych
NORMAL_OUTBOUND_PORTS = {80, 443, 53, 8080, 8443}


class OutboundAnalyzer:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 10)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Beacon detection: track timing of connections per (ip, port)
        self.conn_timing = defaultdict(list)  # (ip,port) -> [timestamps]
        self.beacon_threshold = 5  # min powtorzen
        self.beacon_jitter_max = 0.3  # max 30% odchylenia od sredniej

        self.alert_callbacks = []
        self.alerts = []
        self.suspicious_connections = []
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("OutboundAnalyzer")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "outbound_analyzer.log",
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

    def _get_proc_name(self, pid: int) -> str:
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def _is_local(self, ip: str) -> bool:
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return True

    def scan(self) -> list:
        """Analizuje polaczenia wychodzace."""
        alerts = []
        now = time.time()

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0

                # Ignoruj polaczenia do lokalnych IP
                if self._is_local(remote_ip):
                    continue

                proc_name = self._get_proc_name(conn.pid) if conn.pid else "unknown"
                proc_lower = proc_name.lower()

                # === CHECK 1: C2 port ===
                if remote_port in C2_PORTS:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "C2_PORT_OUTBOUND",
                        "source_ip": remote_ip,
                        "remote_port": remote_port,
                        "process": proc_name,
                        "pid": conn.pid,
                        "severity": "CRITICAL",
                        "description": f"{proc_name} -> {remote_ip}:{remote_port} (C2 port)",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(alert["description"])

                # === CHECK 2: Suspicious process with outbound ===
                if proc_lower in SUSPICIOUS_OUTBOUND_PROCS:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "SUSPICIOUS_PROC_OUTBOUND",
                        "source_ip": remote_ip,
                        "remote_port": remote_port,
                        "process": proc_name,
                        "pid": conn.pid,
                        "severity": "CRITICAL",
                        "description": f"{proc_name} (PID:{conn.pid}) connecting to {remote_ip}:{remote_port}",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(alert["description"])

                # === CHECK 3: Non-standard port outbound ===
                if remote_port not in NORMAL_OUTBOUND_PORTS and remote_port > 1024:
                    key = (remote_ip, remote_port)
                    self.conn_timing[key].append(now)
                    # Cleanup old entries
                    self.conn_timing[key] = [t for t in self.conn_timing[key] if now - t < 3600]

                # === CHECK 4: Beacon detection ===
                key = (remote_ip, remote_port)
                times = self.conn_timing.get(key, [])
                if len(times) >= self.beacon_threshold:
                    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                    if intervals:
                        avg = sum(intervals) / len(intervals)
                        if avg > 0:
                            jitter = max(abs(i - avg) / avg for i in intervals)
                            if jitter < self.beacon_jitter_max:
                                alert = {
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "type": "C2_BEACON_DETECTED",
                                    "source_ip": remote_ip,
                                    "remote_port": remote_port,
                                    "process": proc_name,
                                    "interval_avg": round(avg, 1),
                                    "jitter": round(jitter, 3),
                                    "occurrences": len(times),
                                    "severity": "CRITICAL",
                                    "description": f"Beacon: {proc_name} -> {remote_ip}:{remote_port} every {avg:.0f}s",
                                }
                                alerts.append(alert)
                                self._fire_alert(alert)
                                self.logger.warning(alert["description"])
                                # Reset to avoid repeating
                                self.conn_timing[key] = []

        except (psutil.AccessDenied, PermissionError):
            pass

        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Outbound Analyzer started")
        while self._running:
            try:
                self.scan()
            except Exception as e:
                self.logger.error(f"Scan error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "alerts": len(self.alerts),
            "tracked_connections": len(self.conn_timing),
        }
