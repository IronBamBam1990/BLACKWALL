"""
GeoIP Lookup - Lokalizacja geograficzna atakujacych IP.
Uzywa darmowego API ip-api.com jako fallback (bez potrzeby bazy danych).
Opcjonalnie MaxMind GeoLite2 jesli dostepna.
"""

import asyncio
import json
import ipaddress
import time
from functools import lru_cache
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


class GeoIPLookup:
    def __init__(self, config: dict = None):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.db_path = config.get("database_path", "")
        self._reader = None
        self._cache = {}
        self._cache_ttl = 3600  # 1h
        self._rate_limit_remaining = 45
        self._rate_limit_reset = 0

        if HAS_GEOIP2 and self.db_path and Path(self.db_path).exists():
            try:
                self._reader = geoip2.database.Reader(self.db_path)
            except Exception:
                pass

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    def lookup_sync(self, ip: str) -> dict:
        """Synchroniczny lookup - z cache."""
        if not self.enabled or self._is_private(ip):
            return {}

        # Cache
        cached = self._cache.get(ip)
        if cached and time.time() - cached["_time"] < self._cache_ttl:
            return cached

        # GeoIP2 local database
        if self._reader:
            try:
                resp = self._reader.city(ip)
                result = {
                    "country": resp.country.iso_code or "??",
                    "country_name": resp.country.name or "Unknown",
                    "city": resp.city.name or "",
                    "latitude": resp.location.latitude,
                    "longitude": resp.location.longitude,
                    "_time": time.time(),
                }
                self._cache[ip] = result
                return result
            except Exception:
                pass

        return {}

    async def lookup(self, ip: str) -> dict:
        """Async lookup - uzywa API jesli brak lokalnej bazy."""
        if not self.enabled or self._is_private(ip):
            return {}

        # Cache
        cached = self._cache.get(ip)
        if cached and time.time() - cached["_time"] < self._cache_ttl:
            return cached

        # Local db first
        if self._reader:
            return self.lookup_sync(ip)

        # Fallback: ip-api.com (darmowe, 45 req/min)
        if not aiohttp:
            return {}

        now = time.time()
        if self._rate_limit_remaining <= 0 and now < self._rate_limit_reset:
            return {}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    self._rate_limit_remaining = int(resp.headers.get("X-Rl", 45))
                    ttl = int(resp.headers.get("X-Ttl", 60))
                    self._rate_limit_reset = now + ttl

                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            result = {
                                "country": data.get("countryCode", "??"),
                                "country_name": data.get("country", "Unknown"),
                                "city": data.get("city", ""),
                                "latitude": data.get("lat"),
                                "longitude": data.get("lon"),
                                "isp": data.get("isp", ""),
                                "org": data.get("org", ""),
                                "asn": data.get("as", ""),
                                "_time": time.time(),
                            }
                            self._cache[ip] = result
                            return result
        except Exception:
            pass

        return {}

    def get_cached(self, ip: str) -> dict:
        """Zwraca dane z cache bez nowego zapytania."""
        cached = self._cache.get(ip)
        if cached and time.time() - cached["_time"] < self._cache_ttl:
            return {k: v for k, v in cached.items() if not k.startswith("_")}
        return {}

    def get_country_stats(self) -> dict:
        """Statystyki krajow z cache."""
        countries = {}
        for ip, data in self._cache.items():
            cc = data.get("country", "??")
            name = data.get("country_name", "Unknown")
            if cc not in countries:
                countries[cc] = {"name": name, "count": 0, "ips": []}
            countries[cc]["count"] += 1
            countries[cc]["ips"].append(ip)
        return dict(sorted(countries.items(), key=lambda x: x[1]["count"], reverse=True))

    def close(self):
        if self._reader:
            self._reader.close()
