"""
Honeypot Manager v2 - Uruchamia i zarzadza wszystkimi honeypotami.
Integracja z GeoIP i Threat Intel.
"""

import asyncio
import json
import logging
import os
import sys
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

sys.path.insert(0, str(Path(__file__).parent.parent))

from honeypots.ssh_honeypot import SSHHoneypot
from honeypots.http_honeypot import HTTPHoneypot
from honeypots.ftp_honeypot import FTPHoneypot
from honeypots.rdp_honeypot import RDPHoneypot
from honeypots.smb_honeypot import SMBHoneypot
from honeypots.telnet_honeypot import TelnetHoneypot
from honeypots.mysql_honeypot import MySQLHoneypot
from honeypots.smtp_honeypot import SMTPHoneypot
from honeypots.dns_honeypot import DNSHoneypot
from honeypots.catchall_honeypot import CatchAllHoneypot


class HoneypotManager:
    def __init__(self, config: dict, log_dir: str = "logs", geoip=None, threat_intel=None):
        self.config = config
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.honeypots = []
        self.event_log = self.log_dir / "honeypot_events.jsonl"
        self.alert_callbacks = []
        self.geoip = geoip
        self.threat_intel = threat_intel
        self._event_count = 0
        self._write_lock = threading.Lock()
        # Cached stats - aktualizowane inkrementalnie, nie z pliku
        self._stats_by_type = defaultdict(int)
        self._stats_by_ip = defaultdict(int)
        self._stats_by_country = defaultdict(int)
        self._last_event = None
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("HoneypotManager")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "honeypot_manager.log",
            maxBytes=100 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

    def on_alert(self, callback):
        self.alert_callbacks.append(callback)

    def _fire_alert(self, event: dict):
        for cb in self.alert_callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def log_event(self, honeypot_type: str, source_ip: str, source_port: int, details: dict):
        """Loguje zdarzenie z honeypota do JSONL z GeoIP i threat intel."""
        self._event_count += 1

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "honeypot": honeypot_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "details": details,
        }

        # GeoIP enrichment
        if self.geoip:
            geo = self.geoip.lookup_sync(source_ip)
            if geo:
                event["geo"] = {k: v for k, v in geo.items() if not k.startswith("_")}

        # Threat intel check
        if self.threat_intel:
            threat = self.threat_intel.check_ip(source_ip)
            if threat:
                event["threat_intel"] = threat
                details["threat_match"] = True

        # Thread-safe file write
        with self._write_lock:
            with open(self.event_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

        # Aktualizuj cached stats inkrementalnie (O(1) zamiast O(n))
        self._stats_by_type[honeypot_type] += 1
        self._stats_by_ip[source_ip] += 1
        geo = event.get("geo", {})
        cc = geo.get("country", "")
        if cc:
            self._stats_by_country[cc] += 1
        self._last_event = event

        self.logger.info(
            f"[{honeypot_type}] {source_ip}:{source_port} - {details.get('action', 'unknown')}"
        )
        self._fire_alert(event)
        return event

    def get_stats(self) -> dict:
        """Zwraca cached stats - O(1) zamiast czytania calego pliku."""
        return {
            "total_events": self._event_count,
            "by_type": dict(self._stats_by_type),
            "by_ip": dict(self._stats_by_ip),
            "by_country": dict(self._stats_by_country),
            "last_event": self._last_event,
        }

    async def start_all(self):
        hp_config = self.config.get("honeypots", {})
        honeypot_classes = {
            "ssh": SSHHoneypot,
            "http": HTTPHoneypot,
            "ftp": FTPHoneypot,
            "rdp": RDPHoneypot,
            "smb": SMBHoneypot,
            "telnet": TelnetHoneypot,
            "mysql": MySQLHoneypot,
            "smtp": SMTPHoneypot,
            "dns": DNSHoneypot,
        }

        tasks = []
        used_ports = set()
        for name, cls in honeypot_classes.items():
            cfg = hp_config.get(name, {})
            if cfg.get("enabled", False):
                port = cfg.get("port", 0)
                hp = cls(port=port, manager=self)
                self.honeypots.append(hp)
                used_ports.add(port)
                self.logger.info(f"Starting {name} honeypot on port {port}")
                tasks.append(asyncio.create_task(hp.start()))

        # Catch-All: nasluch na WSZYSTKICH popularnych portach
        catchall_cfg = hp_config.get("catchall", {})
        if catchall_cfg.get("enabled", True):
            catchall = CatchAllHoneypot(manager=self, exclude_ports=used_ports)
            self.honeypots.append(catchall)
            self.logger.info(f"Starting catch-all honeypot on {len(catchall.ports)} ports")
            tasks.append(asyncio.create_task(catchall.start()))

        if tasks:
            self.logger.info(f"Started {len(tasks)} honeypots ({len(used_ports)} dedicated + catch-all)")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_all(self):
        for hp in self.honeypots:
            try:
                await hp.stop()
            except Exception as e:
                self.logger.error(f"Error stopping honeypot: {e}")
        self.honeypots.clear()
