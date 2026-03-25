"""
Rate Limiter + Tarpit - Spowalnia atakujacych i limituje ich polaczenia.
Tarpit: celowo opoznia odpowiedzi zeby marnowac czas atakujacego.
"""

import asyncio
import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, config: dict = None):
        config = config or {}
        self.max_connections_per_ip = config.get("max_connections_per_ip", 10)
        self.window_seconds = config.get("window_seconds", 60)
        self.tarpit_enabled = config.get("tarpit_enabled", True)
        self.tarpit_delay_seconds = config.get("tarpit_delay_seconds", 5)
        self.tarpit_after_hits = config.get("tarpit_after_hits", 3)

        self._connections = defaultdict(list)  # ip -> [timestamps]
        self._tarpit_ips = set()

    def check(self, ip: str) -> dict:
        """Sprawdza rate limit. Zwraca {'allowed': bool, 'tarpit': bool, 'delay': float}."""
        if not ip:
            return {"allowed": True, "tarpit": False, "delay": 0}

        now = time.time()
        # Cleanup stare wpisy
        self._connections[ip] = [t for t in self._connections[ip] if now - t < self.window_seconds]
        self._connections[ip].append(now)

        count = len(self._connections[ip])

        # Blocked
        if count > self.max_connections_per_ip:
            return {"allowed": False, "tarpit": False, "delay": 0}

        # Tarpit
        if self.tarpit_enabled and count >= self.tarpit_after_hits:
            self._tarpit_ips.add(ip)
            # Delay rosnie z iloscia polaczen
            delay = self.tarpit_delay_seconds * (count - self.tarpit_after_hits + 1)
            delay = min(delay, 30)  # Max 30s
            return {"allowed": True, "tarpit": True, "delay": delay}

        return {"allowed": True, "tarpit": False, "delay": 0}

    def is_tarpitted(self, ip: str) -> bool:
        return ip in self._tarpit_ips

    def get_stats(self) -> dict:
        now = time.time()
        active = {ip: len([t for t in times if now - t < self.window_seconds])
                  for ip, times in self._connections.items()
                  if any(now - t < self.window_seconds for t in times)}
        return {
            "active_ips": len(active),
            "tarpitted_ips": len(self._tarpit_ips),
            "top_connectors": sorted(active.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def cleanup(self):
        """Okresowy cleanup."""
        now = time.time()
        stale = [ip for ip, times in self._connections.items()
                 if not any(now - t < self.window_seconds * 2 for t in times)]
        for ip in stale:
            del self._connections[ip]
            self._tarpit_ips.discard(ip)
