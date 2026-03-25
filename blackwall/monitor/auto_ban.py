"""
Auto-Ban System - Automatycznie blokuje IP atakujacych.
Integracja z Windows Firewall przez PowerShell.
"""

import asyncio
import ipaddress
import json
import logging
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


class AutoBan:
    def __init__(self, config: dict, log_dir: str = "logs"):
        self.config = config
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.ban_file = self.log_dir / "banned_ips.json"
        self.whitelist = self._parse_whitelist(config.get("whitelist", []))
        self.banned_ips = self._load_bans()

        # Tracking honeypot hits
        self.honeypot_hits = defaultdict(int)  # ip -> count
        self.ban_threshold_honeypot = 3

        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("AutoBan")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "auto_ban.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

    def _parse_whitelist(self, whitelist: list) -> list:
        """Parsuje whiteliste IP/CIDR."""
        parsed = []
        for entry in whitelist:
            try:
                parsed.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                try:
                    parsed.append(ipaddress.ip_address(entry))
                except ValueError:
                    pass
        return parsed

    def _is_whitelisted(self, ip: str) -> bool:
        """Sprawdza czy IP jest na whiteliscie."""
        try:
            addr = ipaddress.ip_address(ip)
            for entry in self.whitelist:
                if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if addr in entry:
                        return True
                elif addr == entry:
                    return True
        except ValueError:
            pass
        return False

    def _load_bans(self) -> dict:
        """Laduje zbanowane IP z pliku."""
        if self.ban_file.exists():
            try:
                with open(self.ban_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_bans(self):
        """Zapisuje zbanowane IP do pliku (atomicznie)."""
        tmp = self.ban_file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.banned_ips, f, indent=2, ensure_ascii=False)
        tmp.replace(self.ban_file)

    def is_banned(self, ip: str) -> bool:
        return ip in self.banned_ips

    def ban_ip(self, ip: str, reason: str, severity: str = "HIGH") -> bool:
        """Banuje IP - dodaje do listy i tworzy regule firewall."""
        # Walidacja IP - zapobiega command injection w PowerShell
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.logger.warning(f"Invalid IP format, rejecting ban: {ip!r}")
            return False

        if self._is_whitelisted(ip):
            self.logger.info(f"IP {ip} jest na whiteliscie - nie banuję")
            return False

        if ip in self.banned_ips:
            # Aktualizuj reason
            self.banned_ips[ip]["reasons"].append(reason)
            self.banned_ips[ip]["hit_count"] += 1
            self._save_bans()
            return True

        self.banned_ips[ip] = {
            "banned_at": datetime.now(timezone.utc).isoformat(),
            "reasons": [reason],
            "severity": severity,
            "hit_count": 1,
            "firewall_rule_added": False,
        }

        # Dodaj regule firewall
        success = self._add_firewall_rule(ip)
        self.banned_ips[ip]["firewall_rule_added"] = success

        self._save_bans()
        self.logger.info(f"BANNED IP: {ip} | Reason: {reason} | Firewall: {success}")
        return True

    def unban_ip(self, ip: str) -> bool:
        """Odbanowuje IP."""
        if ip not in self.banned_ips:
            return False

        self._remove_firewall_rule(ip)
        del self.banned_ips[ip]
        self._save_bans()
        self.logger.info(f"UNBANNED IP: {ip}")
        return True

    def _add_firewall_rule(self, ip: str) -> bool:
        """Dodaje regule blokujaca w Windows Firewall."""
        rule_name = f"SecuritySuite_Block_{ip.replace('.', '_').replace(':', '_')}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" '
            f'-Direction Inbound -Action Block '
            f'-RemoteAddress {ip} '
            f'-Profile Any -Enabled True'
        )
        try:
            result = subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                self.logger.info(f"Firewall rule added for {ip}")
                return True
            else:
                self.logger.error(f"Firewall rule failed for {ip}: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"Cannot add firewall rule: {e}")
            return False

    def _remove_firewall_rule(self, ip: str) -> bool:
        """Usuwa regule firewall."""
        rule_name = f"SecuritySuite_Block_{ip.replace('.', '_').replace(':', '_')}"
        cmd = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
        try:
            subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True, text=True, timeout=30,
            )
            return True
        except Exception:
            return False

    def process_honeypot_event(self, event: dict):
        """Przetwarza zdarzenie z honeypota - automatycznie banuje po progu."""
        source_ip = event.get("source_ip", "")
        if not source_ip or self._is_whitelisted(source_ip):
            return

        self.honeypot_hits[source_ip] += 1
        honeypot_type = event.get("honeypot", "unknown")

        if self.honeypot_hits[source_ip] >= self.ban_threshold_honeypot:
            self.ban_ip(
                source_ip,
                reason=f"Honeypot trigger: {self.honeypot_hits[source_ip]} hits (last: {honeypot_type})",
                severity="HIGH",
            )

    def process_attack(self, attack: dict):
        """Przetwarza wykryty atak - natychmiastowy ban dla CRITICAL."""
        source_ip = attack.get("source_ip", "")
        if not source_ip or self._is_whitelisted(source_ip):
            return

        severity = attack.get("severity", "LOW")
        if severity == "CRITICAL":
            self.ban_ip(
                source_ip,
                reason=f"Attack: {attack.get('type', 'unknown')} - {attack.get('description', '')}",
                severity="CRITICAL",
            )

    def process_port_scan(self, source_ip: str):
        """Banuje IP za skanowanie portow."""
        if source_ip and not self._is_whitelisted(source_ip):
            self.ban_ip(source_ip, reason="Port scanning detected", severity="HIGH")

    def get_ban_list(self) -> dict:
        return self.banned_ips.copy()

    def get_stats(self) -> dict:
        return {
            "total_banned": len(self.banned_ips),
            "with_firewall_rules": sum(
                1 for b in self.banned_ips.values() if b.get("firewall_rule_added")
            ),
            "by_severity": {
                "CRITICAL": sum(1 for b in self.banned_ips.values() if b.get("severity") == "CRITICAL"),
                "HIGH": sum(1 for b in self.banned_ips.values() if b.get("severity") == "HIGH"),
                "MEDIUM": sum(1 for b in self.banned_ips.values() if b.get("severity") == "MEDIUM"),
            },
        }
