"""
Alert Manager - Dzwiekowe alerty, Windows Toast notyfikacje, Webhook.
"""

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import winsound
    HAS_WINSOUND = True
except ImportError:
    HAS_WINSOUND = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Dzwiekowe profile per severity
SOUND_PROFILES = {
    "CRITICAL": [(2500, 150), (2500, 150), (2500, 150)],  # 3x szybki wysoki beep
    "HIGH": [(1800, 200), (1800, 200)],                    # 2x sredni beep
    "MEDIUM": [(1200, 200)],                                # 1x krotki beep
    "LOW": [],                                              # cisza
}


class AlertManager:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.sound_enabled = config.get("sound_enabled", True)
        self.toast_enabled = config.get("toast_enabled", False)
        self.webhook_url = config.get("webhook_url", "")
        self.min_severity_sound = config.get("min_severity_sound", "HIGH")
        self.min_severity_toast = config.get("min_severity_toast", "MEDIUM")
        self.cooldown_seconds = config.get("cooldown_seconds", 10)

        self.log_dir = Path(log_dir)
        self._last_sound = 0
        self._last_toast = 0
        self._ip_cooldown = {}  # ip -> last_alert_time
        self._alert_count = 0
        self._logger = logging.getLogger("AlertManager")

    def _severity_meets(self, severity: str, minimum: str) -> bool:
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)

    def _is_on_cooldown(self, source_ip: str = "") -> bool:
        now = time.time()
        if source_ip and source_ip in self._ip_cooldown:
            if now - self._ip_cooldown[source_ip] < 300:  # 5 min per IP
                return True
        return False

    def handle_alert(self, alert: dict):
        """Glowny handler - wywolywany przez inne komponenty."""
        severity = alert.get("severity", "LOW")
        source_ip = alert.get("source_ip", alert.get("ip", ""))
        now = time.time()

        self._alert_count += 1

        # Cooldown per IP
        if self._is_on_cooldown(source_ip):
            return

        if source_ip:
            self._ip_cooldown[source_ip] = now

        # Cleanup stare cooldowny co 100 alertow
        if self._alert_count % 100 == 0:
            cutoff = now - 600  # 10 min
            self._ip_cooldown = {ip: t for ip, t in self._ip_cooldown.items() if t > cutoff}

        # Sound
        if self.sound_enabled and HAS_WINSOUND:
            if self._severity_meets(severity, self.min_severity_sound):
                if now - self._last_sound >= self.cooldown_seconds:
                    self._play_sound(severity)
                    self._last_sound = now

        # Toast
        if self.toast_enabled:
            if self._severity_meets(severity, self.min_severity_toast):
                if now - self._last_toast >= 30:
                    self._show_toast(alert)
                    self._last_toast = now

        # Webhook (async - przechowaj task zeby nie byl garbage collected)
        if self.webhook_url and HAS_AIOHTTP:
            if self._severity_meets(severity, "HIGH"):
                try:
                    task = asyncio.create_task(self._send_webhook(alert))
                    task.add_done_callback(lambda t: t.exception() if not t.cancelled() and t.exception() else None)
                except RuntimeError:
                    pass  # No event loop

    def _play_sound(self, severity: str):
        """Gra dzwiek alertu w osobnym watku (nie blokuje event loop)."""
        if not HAS_WINSOUND:
            return
        profile = SOUND_PROFILES.get(severity, [])
        if not profile:
            return
        def _beep():
            for freq, duration in profile:
                try:
                    winsound.Beep(freq, duration)
                except Exception:
                    pass
        threading.Thread(target=_beep, daemon=True).start()

    def _show_toast(self, alert: dict):
        """Pokazuje Windows Toast notification."""
        try:
            # Proba z win10toast (lekka biblioteka)
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            title = f"SECURITY ALERT [{alert.get('severity', 'UNKNOWN')}]"
            msg = alert.get("description", str(alert.get("type", "Unknown alert")))
            ip = alert.get("source_ip", alert.get("ip", ""))
            if ip:
                msg += f"\nIP: {ip}"
            toaster.show_toast(title, msg, duration=5, threaded=True)
        except ImportError:
            pass
        except Exception:
            pass

    async def _send_webhook(self, alert: dict):
        """Wysyla alert na webhook (Discord/Slack format)."""
        if not self.webhook_url:
            return
        try:
            severity = alert.get("severity", "LOW")
            color_map = {"CRITICAL": 0xFF0000, "HIGH": 0xFF6600, "MEDIUM": 0xFFCC00, "LOW": 0x00FF00}

            # Discord webhook format
            payload = {
                "embeds": [{
                    "title": f"Security Alert: {alert.get('type', 'Unknown')}",
                    "description": alert.get("description", "No details"),
                    "color": color_map.get(severity, 0xFFFFFF),
                    "fields": [
                        {"name": "Severity", "value": severity, "inline": True},
                        {"name": "IP", "value": alert.get("source_ip", alert.get("ip", "N/A")), "inline": True},
                        {"name": "Time", "value": alert.get("timestamp", "N/A"), "inline": True},
                    ],
                    "footer": {"text": "Security Suite Alert System"},
                }],
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 204):
                        self._logger.warning(f"Webhook failed: HTTP {resp.status}")
        except Exception as e:
            self._logger.error(f"Webhook error: {e}")

    def get_stats(self) -> dict:
        return {
            "total_alerts": self._alert_count,
            "sound_enabled": self.sound_enabled,
            "toast_enabled": self.toast_enabled,
            "webhook_configured": bool(self.webhook_url),
        }
