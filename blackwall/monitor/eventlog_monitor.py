"""
Windows Event Log Monitor - Monitoruje logi bezpieczenstwa Windows.
Wykrywa failed logons, privilege escalation, audit policy changes,
account lockouts, nowe konta, RDP logowania.
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from logging.handlers import RotatingFileHandler


# Event IDs ktore sa istotne dla bezpieczenstwa
CRITICAL_EVENTS = {
    # Account Logon
    4625: {"name": "FAILED_LOGON", "severity": "MEDIUM", "desc": "Failed login attempt"},
    4624: {"name": "SUCCESSFUL_LOGON", "severity": "LOW", "desc": "Successful login"},
    4648: {"name": "EXPLICIT_LOGON", "severity": "HIGH", "desc": "Login with explicit credentials"},

    # Account Management
    4720: {"name": "ACCOUNT_CREATED", "severity": "HIGH", "desc": "New user account created"},
    4722: {"name": "ACCOUNT_ENABLED", "severity": "MEDIUM", "desc": "User account enabled"},
    4724: {"name": "PASSWORD_RESET", "severity": "HIGH", "desc": "Password reset attempt"},
    4728: {"name": "GROUP_MEMBER_ADDED", "severity": "HIGH", "desc": "Member added to security group"},
    4732: {"name": "LOCAL_GROUP_MEMBER_ADDED", "severity": "HIGH", "desc": "Member added to local group"},
    4740: {"name": "ACCOUNT_LOCKOUT", "severity": "HIGH", "desc": "Account locked out"},

    # Privilege Use
    4672: {"name": "SPECIAL_PRIVILEGES", "severity": "MEDIUM", "desc": "Special privileges assigned"},
    4673: {"name": "PRIVILEGE_USE", "severity": "MEDIUM", "desc": "Privileged service called"},

    # Policy Change
    4719: {"name": "AUDIT_POLICY_CHANGED", "severity": "CRITICAL", "desc": "Audit policy was changed"},
    4739: {"name": "DOMAIN_POLICY_CHANGED", "severity": "CRITICAL", "desc": "Domain policy changed"},

    # System
    1102: {"name": "AUDIT_LOG_CLEARED", "severity": "CRITICAL", "desc": "Security log was cleared"},
    4697: {"name": "SERVICE_INSTALLED", "severity": "HIGH", "desc": "New service installed"},
    7045: {"name": "NEW_SERVICE", "severity": "HIGH", "desc": "New service installed (System log)"},

    # Logon with RDP
    4778: {"name": "RDP_SESSION_RECONNECT", "severity": "MEDIUM", "desc": "RDP session reconnected"},
    4779: {"name": "RDP_SESSION_DISCONNECT", "severity": "LOW", "desc": "RDP session disconnected"},

    # PowerShell
    4104: {"name": "POWERSHELL_SCRIPT", "severity": "MEDIUM", "desc": "PowerShell script block logged"},

    # Firewall
    2003: {"name": "FIREWALL_RULE_CHANGED", "severity": "HIGH", "desc": "Firewall rule modified"},
    2004: {"name": "FIREWALL_RULE_ADDED", "severity": "MEDIUM", "desc": "Firewall rule added"},
    2006: {"name": "FIREWALL_RULE_DELETED", "severity": "HIGH", "desc": "Firewall rule deleted"},
}

# Event IDs ktore sa zawsze CRITICAL - nawet jedno wystapienie
ALWAYS_CRITICAL = {1102, 4719, 4739, 4720, 4697, 7045}


class EventLogMonitor:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 15)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Track last check time
        self._last_check = datetime.now(timezone.utc) - timedelta(minutes=5)
        self._failed_logon_count = {}  # ip/user -> count in window
        self.alert_callbacks = []
        self.alerts = []
        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("EventLogMonitor")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "eventlog_monitor.log",
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
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-250:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def scan(self) -> list:
        """Skanuje Windows Event Logi od ostatniego checku."""
        alerts = []
        now = datetime.now(timezone.utc)

        # Buduj zapytanie PowerShell
        since_ms = int((now - self._last_check).total_seconds() * 1000) + 1000
        event_ids = ",".join(str(eid) for eid in CRITICAL_EVENTS.keys())

        # Query Security log
        ps_cmd = (
            f"Get-WinEvent -FilterHashtable @{{"
            f"LogName='Security','System';"
            f"Id={event_ids};"
            f"StartTime=(Get-Date).AddMilliseconds(-{since_ms})"
            f"}} -MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"Select-Object Id,TimeCreated,Message,LevelDisplayName | "
            f"ConvertTo-Json -Compress"
        )

        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, timeout=10,
                encoding="utf-8", errors="replace",
            )

            if result.returncode == 0 and result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]

                for event in events:
                    event_id = event.get("Id", 0)
                    info = CRITICAL_EVENTS.get(event_id)
                    if not info:
                        continue

                    message = str(event.get("Message", "")).encode("ascii", errors="replace").decode("ascii")[:500]
                    severity = info["severity"]

                    # Eskaluj do CRITICAL jesli na liscie
                    if event_id in ALWAYS_CRITICAL:
                        severity = "CRITICAL"

                    alert = {
                        "timestamp": now.isoformat(),
                        "type": f"WINLOG_{info['name']}",
                        "event_id": event_id,
                        "severity": severity,
                        "description": f"[EventID:{event_id}] {info['desc']}",
                        "message_preview": message[:200],
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.info(f"[{event_id}] {info['name']}: {message[:100]}")

        except subprocess.TimeoutExpired:
            self.logger.warning("Event log query timed out")
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.error(f"Event log scan error: {e}")

        self._last_check = now
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("Windows Event Log Monitor started")
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
            "last_check": self._last_check.isoformat(),
            "monitored_event_ids": len(CRITICAL_EVENTS),
        }
