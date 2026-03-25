"""
Threat Intelligence - Sprawdza IP atakujacych w znanych bazach zagrozen.
Pobiera listy z darmowych zrodel: Emerging Threats, Feodo Tracker, Tor Exit Nodes.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# Darmowe feedy z zlosliwymi IP
DEFAULT_FEEDS = {
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "description": "Emerging Threats Compromised IPs",
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "Feodo Tracker C2 Botnet IPs",
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "description": "Tor Exit Nodes",
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "description": "Blocklist.de Attackers",
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "description": "CINS Army Threat List",
    },
}


class ThreatIntelChecker:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.refresh_hours = config.get("refresh_hours", 6)
        self.feeds = config.get("feeds", DEFAULT_FEEDS)
        self.abuseipdb_key = config.get("abuseipdb_api_key", "")

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # IP sets per feed
        self.bad_ips = {}  # feed_name -> set of IPs
        self.all_bad_ips = set()  # union of all feeds
        self.last_refresh = 0
        self.feed_stats = {}

        self._running = False
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("ThreatIntel")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "threat_intel.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

    async def refresh_feeds(self):
        """Pobiera wszystkie feedy zagrozen."""
        if not HAS_AIOHTTP:
            self.logger.error("aiohttp not installed - cannot fetch threat feeds")
            return

        self.logger.info("Refreshing threat intelligence feeds...")
        total = 0

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            for name, feed in self.feeds.items():
                url = feed if isinstance(feed, str) else feed.get("url", "")
                desc = feed.get("description", name) if isinstance(feed, dict) else name
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            ips = set()
                            for line in text.splitlines():
                                line = line.strip()
                                # Ignoruj komentarze i puste linie
                                if not line or line.startswith("#") or line.startswith(";"):
                                    continue
                                # Wyciagnij IP (moze byc IP:port lub sam IP)
                                ip = line.split(":")[0].split("/")[0].split(" ")[0].strip()
                                # Walidacja bazowa
                                parts = ip.split(".")
                                if len(parts) == 4 and all(
                                    p.isdigit() and 0 <= int(p) <= 255 for p in parts
                                ):
                                    ips.add(ip)

                            self.bad_ips[name] = ips
                            self.feed_stats[name] = {
                                "description": desc,
                                "count": len(ips),
                                "last_update": datetime.now(timezone.utc).isoformat(),
                            }
                            total += len(ips)
                            self.logger.info(f"  [{name}] {len(ips)} IPs loaded")
                        else:
                            self.logger.warning(f"  [{name}] HTTP {resp.status}")
                except Exception as e:
                    self.logger.error(f"  [{name}] Error: {e}")

        # Zbuduj union
        self.all_bad_ips = set()
        for ips in self.bad_ips.values():
            self.all_bad_ips.update(ips)

        self.last_refresh = time.time()
        self.logger.info(
            f"Threat intel refreshed: {total} total IPs from {len(self.bad_ips)} feeds, "
            f"{len(self.all_bad_ips)} unique"
        )

    def check_ip(self, ip: str) -> dict | None:
        """Sprawdza IP w zaladowanych feedach. Zwraca info lub None."""
        if not self.enabled or ip not in self.all_bad_ips:
            return None

        # Znajdz w ktorych feedach jest to IP
        sources = []
        for name, ips in self.bad_ips.items():
            if ip in ips:
                desc = self.feed_stats.get(name, {}).get("description", name)
                sources.append({"feed": name, "description": desc})

        return {
            "ip": ip,
            "threat": True,
            "sources": sources,
            "source_count": len(sources),
            "severity": "CRITICAL" if len(sources) >= 2 else "HIGH",
        }

    async def check_abuseipdb(self, ip: str) -> dict | None:
        """Sprawdza IP w AbuseIPDB (wymaga API key)."""
        if not self.abuseipdb_key or not HAS_AIOHTTP:
            return None

        try:
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json",
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        d = data.get("data", {})
                        score = d.get("abuseConfidenceScore", 0)
                        return {
                            "ip": ip,
                            "abuse_score": score,
                            "country": d.get("countryCode", ""),
                            "isp": d.get("isp", ""),
                            "domain": d.get("domain", ""),
                            "total_reports": d.get("totalReports", 0),
                            "is_tor": d.get("isTor", False),
                            "threat": score >= 50,
                            "severity": "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM",
                        }
        except Exception as e:
            self.logger.error(f"AbuseIPDB check failed for {ip}: {e}")

        return None

    async def refresh_loop(self):
        """Petla odswie zania feedow."""
        self._running = True
        # Pierwsze pobranie
        await self.refresh_feeds()

        while self._running:
            await asyncio.sleep(self.refresh_hours * 3600)
            if self._running:
                await self.refresh_feeds()

    async def stop(self):
        self._running = False

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "total_bad_ips": len(self.all_bad_ips),
            "feeds": self.feed_stats,
            "last_refresh": datetime.fromtimestamp(
                self.last_refresh, tz=timezone.utc
            ).isoformat() if self.last_refresh else "never",
        }
