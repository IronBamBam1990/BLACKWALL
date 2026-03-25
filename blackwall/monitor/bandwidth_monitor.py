"""
Bandwidth Anomaly Detection - Wykrywa nietypowe skoki ruchu sieciowego.
Bazuje na rolling average, alertuje gdy ruch przekracza N-krotnosc normy.
Wykrywa data exfiltration, DDoS, crypto mining.
"""

import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


class BandwidthMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 10)
        self.anomaly_multiplier = config.get("anomaly_multiplier", 5.0)  # 5x normy = alert
        self.window_size = config.get("window_samples", 60)  # 60 probek baseline

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Rolling windows
        self.sent_history = deque(maxlen=self.window_size)
        self.recv_history = deque(maxlen=self.window_size)
        self.last_counters = None
        self.last_time = None

        self.alert_callbacks = []
        self.alerts = []
        self.current_rates = {"send_rate": 0, "recv_rate": 0}
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("BandwidthMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "bandwidth_monitor.log",
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

    def _fmt_rate(self, bps: float) -> str:
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if bps < 1024:
                return f"{bps:.1f} {unit}"
            bps /= 1024
        return f"{bps:.1f} TB/s"

    def sample(self) -> list:
        """Pobiera probe ruchu i sprawdza anomalie."""
        alerts = []
        now = time.time()

        try:
            counters = psutil.net_io_counters()
        except Exception:
            return alerts

        if self.last_counters is None:
            self.last_counters = counters
            self.last_time = now
            return alerts

        dt = now - self.last_time
        if dt <= 0:
            return alerts

        # Oblicz rate (bytes/sec)
        send_rate = (counters.bytes_sent - self.last_counters.bytes_sent) / dt
        recv_rate = (counters.bytes_recv - self.last_counters.bytes_recv) / dt

        self.current_rates = {"send_rate": send_rate, "recv_rate": recv_rate}

        self.last_counters = counters
        self.last_time = now

        # Dodaj do historii
        self.sent_history.append(send_rate)
        self.recv_history.append(recv_rate)

        # Potrzebujemy min 10 probek do baseline
        if len(self.sent_history) < 10:
            return alerts

        # Oblicz srednie (bez aktualnej probki)
        avg_send = sum(list(self.sent_history)[:-1]) / (len(self.sent_history) - 1)
        avg_recv = sum(list(self.recv_history)[:-1]) / (len(self.recv_history) - 1)

        # Minimalne progi (nie alertuj na malym ruchu)
        min_threshold = 1024 * 100  # 100 KB/s

        # === Upload anomaly (data exfiltration) ===
        if avg_send > 0 and send_rate > max(avg_send * self.anomaly_multiplier, min_threshold):
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "UPLOAD_SPIKE",
                "current_rate": self._fmt_rate(send_rate),
                "average_rate": self._fmt_rate(avg_send),
                "multiplier": round(send_rate / avg_send, 1) if avg_send > 0 else 0,
                "severity": "HIGH",
                "description": f"Upload spike: {self._fmt_rate(send_rate)} ({send_rate/avg_send:.1f}x normal)",
            }
            alerts.append(alert)
            self._fire_alert(alert)
            self.logger.warning(alert["description"])

        # === Download anomaly (DDoS, unwanted downloads) ===
        if avg_recv > 0 and recv_rate > max(avg_recv * self.anomaly_multiplier, min_threshold):
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "DOWNLOAD_SPIKE",
                "current_rate": self._fmt_rate(recv_rate),
                "average_rate": self._fmt_rate(avg_recv),
                "multiplier": round(recv_rate / avg_recv, 1) if avg_recv > 0 else 0,
                "severity": "HIGH",
                "description": f"Download spike: {self._fmt_rate(recv_rate)} ({recv_rate/avg_recv:.1f}x normal)",
            }
            alerts.append(alert)
            self._fire_alert(alert)
            self.logger.warning(alert["description"])

        # === Sustained high upload (crypto mining, data leak) ===
        recent_sent = list(self.sent_history)[-5:] if len(self.sent_history) >= 5 else []
        if recent_sent and all(r > 1024 * 1024 for r in recent_sent):  # >1MB/s sustained
            avg_recent = sum(recent_sent) / len(recent_sent)
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "SUSTAINED_HIGH_UPLOAD",
                "average_rate": self._fmt_rate(avg_recent),
                "duration_samples": len(recent_sent),
                "severity": "CRITICAL",
                "description": f"Sustained upload: {self._fmt_rate(avg_recent)} for {len(recent_sent)} samples",
            }
            alerts.append(alert)
            self._fire_alert(alert)

        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Bandwidth Monitor started")
        while self._running:
            try:
                self.sample()
            except Exception as e:
                self.logger.error(f"Sample error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "send_rate": self._fmt_rate(self.current_rates.get("send_rate", 0)),
            "recv_rate": self._fmt_rate(self.current_rates.get("recv_rate", 0)),
            "samples": len(self.sent_history),
            "alerts": len(self.alerts),
        }
