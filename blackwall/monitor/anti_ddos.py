"""
Anti-DDoS Monitor - Wykrywa i blokuje ataki DDoS/flood.
Monitoruje incoming connections per second, SYN floods, UDP floods.
Automatycznie blokuje flooding IP w firewallu.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


class AntiDDoS:
    def __init__(self, config: dict = None, log_dir: str = "logs", auto_ban=None):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 3)

        # Progi DDoS
        self.conn_per_sec_threshold = config.get("connections_per_second_alert", 50)
        self.conn_per_ip_threshold = config.get("connections_per_ip_alert", 20)
        self.packets_spike_multiplier = config.get("packets_spike_multiplier", 10)

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.auto_ban = auto_ban

        # Tracking
        self._last_counters = None
        self._last_time = None
        self._conn_history = deque(maxlen=60)  # (timestamp, total_conn_count)
        self._ip_conn_count = defaultdict(int)
        self._baseline_pps = deque(maxlen=30)  # packets per second baseline
        self._ddos_active = False
        self._blocked_flood_ips = set()

        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("AntiDDoS")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "anti_ddos.log",
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

    def scan(self) -> list:
        alerts = []
        now = time.time()

        # === PACKET RATE ANALYSIS ===
        try:
            counters = psutil.net_io_counters()
        except Exception:
            return alerts

        if self._last_counters and self._last_time:
            dt = now - self._last_time
            if dt > 0:
                pps_in = (counters.packets_recv - self._last_counters.packets_recv) / dt
                pps_out = (counters.packets_sent - self._last_counters.packets_sent) / dt
                bps_in = (counters.bytes_recv - self._last_counters.bytes_recv) / dt

                self._baseline_pps.append(pps_in)

                # Baseline z ostatnich 30 probek
                if len(self._baseline_pps) >= 10:
                    baseline_list = list(self._baseline_pps)[:-1]
                    avg_pps = sum(baseline_list) / len(baseline_list) if baseline_list else 0
                    if avg_pps > 0 and pps_in > avg_pps * self.packets_spike_multiplier:
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "DDOS_PACKET_FLOOD",
                            "severity": "CRITICAL",
                            "current_pps": int(pps_in),
                            "baseline_pps": int(avg_pps),
                            "multiplier": round(pps_in / avg_pps, 1),
                            "bps_in": int(bps_in),
                            "description": f"DDoS! {int(pps_in)} pkt/s ({pps_in/avg_pps:.1f}x normal)",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self._ddos_active = True
                        self.logger.warning(alert["description"])
                    elif self._ddos_active and pps_in < avg_pps * 2:
                        self._ddos_active = False
                        self.logger.info("DDoS attack appears to have stopped")

        self._last_counters = counters
        self._last_time = now

        # === PER-IP CONNECTION FLOODING ===
        try:
            ip_counts = defaultdict(int)
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.status in ("ESTABLISHED", "SYN_RECV", "SYN_SENT"):
                    ip_counts[conn.raddr.ip] += 1

                # SYN_RECV flood detection (half-open connections)
                if conn.status == "SYN_RECV" and conn.raddr:
                    ip_counts[conn.raddr.ip] += 5  # Wazniejsze

            for ip, count in ip_counts.items():
                if count >= self.conn_per_ip_threshold:
                    if ip not in self._blocked_flood_ips:
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "DDOS_IP_FLOOD",
                            "source_ip": ip,
                            "severity": "CRITICAL",
                            "connections": count,
                            "description": f"IP flood: {ip} with {count} connections",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self._blocked_flood_ips.add(ip)
                        self.logger.warning(alert["description"])

                        # Auto-ban
                        if self.auto_ban:
                            self.auto_ban.ban_ip(ip, reason=f"DDoS: {count} connections", severity="CRITICAL")

            # Total connections
            total_conns = sum(ip_counts.values())
            self._conn_history.append((now, total_conns))

        except (psutil.AccessDenied, PermissionError):
            pass

        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Anti-DDoS Monitor started")
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
            "ddos_active": self._ddos_active,
            "blocked_ips": len(self._blocked_flood_ips),
            "alerts": len(self.alerts),
            "current_pps": int(self._baseline_pps[-1]) if self._baseline_pps else 0,
        }
