"""
Network Monitor - Monitoruje ruch sieciowy, wykrywa skany portow,
IP spoofing, ARP poisoning, podejrzane polaczenia.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


class NetworkMonitor:
    def __init__(self, config: dict, log_dir: str = "logs"):
        self.config = config.get("monitor", {})
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.event_log = self.log_dir / "network_events.jsonl"

        # Progi detekcji
        self.port_scan_threshold = self.config.get("port_scan_threshold", 5)
        self.port_scan_window = self.config.get("port_scan_window_seconds", 10)
        self.brute_force_threshold = self.config.get("brute_force_threshold", 3)
        self.brute_force_window = self.config.get("brute_force_window_seconds", 60)

        # Tracking
        self.connection_history = defaultdict(list)  # ip -> [(timestamp, port), ...]
        self.known_connections = set()
        self.alerts = []
        self.alert_callbacks = []

        self._running = False
        self._alerted_suspicious = {}  # (ip, port) -> timestamp - deduplikacja
        self._scan_count = 0
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("NetworkMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "network_monitor.log",
            maxBytes=100 * 1024 * 1024,
            backupCount=5,
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
        # Trzymaj max 1000 alertow w pamieci
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-500:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def log_event(self, event_type: str, source_ip: str, details: dict):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "source_ip": source_ip,
            "details": details,
        }
        with open(self.event_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        self.logger.info(f"[{event_type}] {source_ip}: {json.dumps(details)}")
        return event

    def get_recent_alerts(self, count: int = 50) -> list:
        return self.alerts[-count:]

    def get_active_connections(self) -> list:
        """Zwraca aktywne polaczenia sieciowe."""
        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" or conn.status == "LISTEN":
                    entry = {
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                    # Dodaj nazwe procesu
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            entry["process"] = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            entry["process"] = "unknown"
                    connections.append(entry)
        except (psutil.AccessDenied, PermissionError):
            self.logger.warning("Brak uprawnien do odczytu polaczen sieciowych")
        return connections

    # IP ktore sa ignorowane w detekcji port scan (localhost, lokalne)
    LOCAL_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::", "localhost"}

    def _is_local_ip(self, ip: str) -> bool:
        """Sprawdza czy IP jest lokalne (nie powinno triggerowac alertow)."""
        if ip in self.LOCAL_IPS:
            return True
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return True
        return False

    def check_port_scan(self, connections: list):
        """Wykrywa skanowanie portow - wiele polaczen z jednego IP na rozne porty."""
        now = time.time()
        remote_ips = defaultdict(set)

        for conn in connections:
            if conn.get("remote_addr") and conn["status"] == "ESTABLISHED":
                parts = conn["remote_addr"].rsplit(":", 1)
                if len(parts) != 2:
                    continue
                ip = parts[0]
                try:
                    port = int(parts[1])
                except (ValueError, IndexError):
                    continue
                # Ignoruj lokalne IP
                if self._is_local_ip(ip):
                    continue
                remote_ips[ip].add(port)
                self.connection_history[ip].append((now, port))

        # Sprawdz history dla kazdego IP
        for ip, timestamps in self.connection_history.items():
            # Usun stare wpisy
            recent = [(t, p) for t, p in timestamps if now - t < self.port_scan_window]
            self.connection_history[ip] = recent

            unique_ports = len(set(p for _, p in recent))
            if unique_ports >= self.port_scan_threshold:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "PORT_SCAN_DETECTED",
                    "source_ip": ip,
                    "unique_ports": unique_ports,
                    "ports": sorted(set(p for _, p in recent)),
                    "severity": "HIGH",
                }
                self.log_event("PORT_SCAN", ip, alert)
                self._fire_alert(alert)
                return ip
        return None

    def check_suspicious_connections(self, connections: list) -> list:
        """Wykrywa podejrzane polaczenia (z deduplikacja)."""
        suspicious = []
        now = time.time()
        bad_ports = {4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321}

        for conn in connections:
            if not conn.get("remote_addr"):
                continue

            parts = conn["remote_addr"].rsplit(":", 1)
            if len(parts) != 2:
                continue

            remote_ip = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                continue

            if port in bad_ports:
                key = (remote_ip, port)
                # Deduplikacja - nie alertuj tego samego (ip,port) w ciagu 5 min
                last_alert = self._alerted_suspicious.get(key, 0)
                if now - last_alert < 300:
                    continue
                self._alerted_suspicious[key] = now

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "SUSPICIOUS_PORT",
                    "source_ip": remote_ip,
                    "port": port,
                    "process": conn.get("process", "unknown"),
                    "severity": "MEDIUM",
                }
                suspicious.append(alert)
                self.log_event("SUSPICIOUS_PORT", remote_ip, alert)
                self._fire_alert(alert)

        # Cleanup starych dedup kluczy co 20 cykli
        self._scan_count += 1
        if self._scan_count % 20 == 0:
            cutoff = now - 600
            self._alerted_suspicious = {k: t for k, t in self._alerted_suspicious.items() if t > cutoff}
            # Cleanup connection_history - usun IP bez recent activity
            stale = [ip for ip, entries in self.connection_history.items() if not entries]
            for ip in stale:
                del self.connection_history[ip]

        return suspicious

    # Znane bezpieczne procesy systemowe (nie generuja alertow NEW_LISTENER)
    KNOWN_SAFE_PROCESSES = {
        "svchost.exe", "system", "lsass.exe", "services.exe", "wininit.exe",
        "spoolsv.exe", "nortonsvc.exe", "lghub_agent.exe", "lghub_updater.exe",
        "steam.exe", "discord.exe", "code.exe", "onedrive.sync.service.exe",
        "jhi_service.exe", "iscsiagent.exe", "python.exe", "python3.exe",
        "warp-svc.exe",
    }

    def check_new_listeners(self) -> list:
        """Wykrywa nowe procesy nasluchujace na portach."""
        new_listeners = []
        current = set()

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    key = (conn.laddr.ip, conn.laddr.port, conn.pid)
                    current.add(key)

                    if key not in self.known_connections:
                        proc_name = "unknown"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        # Ignoruj znane bezpieczne procesy na localhost
                        is_local = self._is_local_ip(conn.laddr.ip)
                        is_safe = proc_name.lower() in self.KNOWN_SAFE_PROCESSES

                        # Alert tylko dla nieznanych procesow lub procesow na 0.0.0.0 (publicznych)
                        if is_local and is_safe:
                            continue

                        severity = "LOW" if is_local else "HIGH"

                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "NEW_LISTENER",
                            "address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "pid": conn.pid,
                            "process": proc_name,
                            "severity": severity,
                        }
                        new_listeners.append(alert)
                        self.log_event("NEW_LISTENER", conn.laddr.ip, alert)
                        self._fire_alert(alert)
        except (psutil.AccessDenied, PermissionError):
            pass

        self.known_connections = current
        return new_listeners

    def get_network_stats(self) -> dict:
        """Zwraca statystyki sieciowe."""
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errors_in": io.errin,
                "errors_out": io.errout,
                "drops_in": io.dropin,
                "drops_out": io.dropout,
            }
        except Exception:
            return {}

    async def monitor_loop(self):
        """Glowna petla monitorowania."""
        self._running = True
        self.logger.info("Network Monitor started")

        # Inicjalizuj znane polaczenia
        self.check_new_listeners()

        while self._running:
            try:
                connections = self.get_active_connections()
                self.check_port_scan(connections)
                self.check_suspicious_connections(connections)
                self.check_new_listeners()
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")

            await asyncio.sleep(5)

    async def stop(self):
        self._running = False
        self.logger.info("Network Monitor stopped")
