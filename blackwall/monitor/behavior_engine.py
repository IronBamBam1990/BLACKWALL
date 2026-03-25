"""
Behavioral Analysis Engine - Wykrywa zagrozenia na podstawie ZACHOWANIA, nie sygnatur.
Nieznane IP, nieznane ataki, zero-day - wszystko wykrywane przez anomalie w behavior.

Podejscie:
- Baseline normalnego ruchu -> wykryj odchylenia
- Timing analysis -> wykryj automatyczne narzedzia (za szybko/za regularnie)
- Session profiling -> wykryj reconnaissance vs exploitation vs exfiltration
- Connection pattern analysis -> wykryj C2 beaconing nawet na niestandardowych portach
- Protocol anomaly -> wykryj tunelowanie (DNS over HTTP, data in ICMP, etc.)
"""

import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone


class BehaviorProfile:
    """Profil behawioralny pojedynczego IP."""
    __slots__ = [
        "ip", "first_seen", "last_seen",
        "connection_times", "ports_touched", "honeypots_touched",
        "bytes_sent", "commands_issued", "login_attempts",
        "session_durations", "inter_arrival_times",
        "protocols_used", "flags",
    ]

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.connection_times = deque(maxlen=200)
        self.ports_touched = set()
        self.honeypots_touched = set()
        self.bytes_sent = 0
        self.commands_issued = 0
        self.login_attempts = 0
        self.session_durations = deque(maxlen=50)
        self.inter_arrival_times = deque(maxlen=100)
        self.protocols_used = set()
        self.flags = set()


# Behavioral indicators z wagami
BEHAVIOR_INDICATORS = {
    # === TIMING ANOMALIES ===
    "MACHINE_SPEED_INTERACTION": {
        "weight": 40,
        "description": "Interakcje szybsze niz mozliwe dla czlowieka (<100ms miedzy akcjami)",
    },
    "PERFECT_TIMING_REGULARITY": {
        "weight": 60,
        "description": "Idealnie regularne interwaly - bot/skrypt, nie czlowiek",
    },
    "RAPID_PORT_ENUMERATION": {
        "weight": 50,
        "description": "Szybkie skanowanie wielu portow w krotkim czasie",
    },

    # === SESSION ANOMALIES ===
    "MULTI_HONEYPOT_SWEEP": {
        "weight": 70,
        "description": "Atakuje wiele roznych honeypotow - reconnaissance sweep",
    },
    "CREDENTIAL_STUFFING": {
        "weight": 80,
        "description": "Wiele roznych credentials w krotkim czasie - lista haseł",
    },
    "DEEP_EXPLOITATION": {
        "weight": 90,
        "description": "Przeszedl od recon do exploitation (login -> commands -> exfil)",
    },
    "IMMEDIATE_COMMAND_EXECUTION": {
        "weight": 70,
        "description": "Natychmiast po loginie wykonuje komendy - automatyczny exploit",
    },

    # === CONNECTION PATTERN ANOMALIES ===
    "PERIODIC_BEACON": {
        "weight": 85,
        "description": "Regularne polaczenia w stalych odstepach - C2 beacon",
    },
    "CONNECTION_BURST": {
        "weight": 45,
        "description": "Nagle duzo polaczen po okresie ciszy",
    },
    "PROTOCOL_MISMATCH": {
        "weight": 60,
        "description": "Uzywa protokolu niezgodnego z portem (np. HTTP na porcie SSH)",
    },

    # === DATA ANOMALIES ===
    "HIGH_ENTROPY_PAYLOAD": {
        "weight": 55,
        "description": "Wysoka entropia danych - zaszyfrowane/zakodowane payloady",
    },
    "EXFILTRATION_PATTERN": {
        "weight": 90,
        "description": "Wzorzec exfiltracji: male requesty -> duze odpowiedzi",
    },

    # === EVASION DETECTION ===
    "SLOW_SCAN": {
        "weight": 65,
        "description": "Celowo wolne skanowanie zeby uniknac detekcji (1 port/min+)",
    },
    "ROTATING_SOURCE": {
        "weight": 50,
        "description": "Rozne porty zrodlowe z tego samego IP - proba ukrycia",
    },
}


class BehaviorEngine:
    def __init__(self, config: dict = None):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.profiles = {}  # ip -> BehaviorProfile
        self.alert_callbacks = []
        self.alerts = []
        self._credential_cache = defaultdict(list)  # ip -> [(time, user, pass)]

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

    def _get_profile(self, ip: str) -> BehaviorProfile:
        if ip not in self.profiles:
            self.profiles[ip] = BehaviorProfile(ip)
        return self.profiles[ip]

    def _calc_entropy(self, data: bytes) -> float:
        """Shannon entropy danych (0-8 dla bajtow)."""
        if not data:
            return 0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _calc_timing_regularity(self, times: list) -> float:
        """Oblicza jak regularne sa interwaly (0=chaotyczne, 1=idealnie regularne)."""
        if len(times) < 3:
            return 0
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            return 0
        avg = sum(intervals) / len(intervals)
        if avg == 0:
            return 1.0
        variance = sum((i - avg) ** 2 for i in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        # Coefficient of variation (niski = regularny)
        cv = std_dev / avg if avg > 0 else 0
        regularity = max(0, 1 - cv)
        return regularity

    def _is_local(self, ip: str) -> bool:
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except (ValueError, ImportError):
            return True

    def process_event(self, event: dict) -> list:
        """Analizuje event behawioralnie. Zwraca liste wykrytych anomalii."""
        if not self.enabled:
            return []

        ip = event.get("source_ip", "")
        if not ip or self._is_local(ip):
            return []

        profile = self._get_profile(ip)
        now = time.time()
        details = event.get("details", {})
        action = details.get("action", "")
        honeypot = event.get("honeypot", "")

        # Update profile
        if profile.connection_times:
            iat = now - profile.connection_times[-1]
            profile.inter_arrival_times.append(iat)
        profile.connection_times.append(now)
        profile.last_seen = now

        if honeypot:
            profile.honeypots_touched.add(honeypot)
        port = details.get("target_port", 0)
        if port:
            profile.ports_touched.add(port)
        if action == "login_attempt":
            profile.login_attempts += 1
        if action == "command_executed":
            profile.commands_issued += 1

        # === RUN DETECTORS ===
        detected = []

        # 1. MACHINE SPEED - interakcje szybsze niz 100ms
        if profile.inter_arrival_times and len(profile.inter_arrival_times) >= 3:
            recent_iats = list(profile.inter_arrival_times)[-10:]
            fast_count = sum(1 for t in recent_iats if t < 0.1)
            if fast_count >= 3:
                detected.append("MACHINE_SPEED_INTERACTION")

        # 2. PERFECT TIMING - regularne interwaly (bot)
        if len(profile.connection_times) >= 5:
            recent = list(profile.connection_times)[-20:]
            regularity = self._calc_timing_regularity(recent)
            if regularity > 0.85:
                detected.append("PERFECT_TIMING_REGULARITY")

        # 3. RAPID PORT ENUMERATION
        recent_60s = [t for t in profile.connection_times if now - t < 60]
        if len(profile.ports_touched) >= 5 and len(recent_60s) >= 5:
            detected.append("RAPID_PORT_ENUMERATION")

        # 4. MULTI-HONEYPOT SWEEP
        if len(profile.honeypots_touched) >= 3:
            detected.append("MULTI_HONEYPOT_SWEEP")

        # 5. CREDENTIAL STUFFING
        if action == "login_attempt":
            username = details.get("username", "")
            password = details.get("password", "")
            self._credential_cache[ip].append((now, username, password))
            # Cleanup old
            self._credential_cache[ip] = [
                (t, u, p) for t, u, p in self._credential_cache[ip]
                if now - t < 120
            ]
            unique_creds = len(set(
                (u, p) for t, u, p in self._credential_cache[ip]
            ))
            if unique_creds >= 5:
                detected.append("CREDENTIAL_STUFFING")

        # 6. DEEP EXPLOITATION (recon -> exploit chain)
        if (profile.login_attempts > 0 and profile.commands_issued > 0
                and len(profile.honeypots_touched) >= 2):
            detected.append("DEEP_EXPLOITATION")

        # 7. IMMEDIATE COMMAND after login
        if action == "command_executed" and profile.login_attempts > 0:
            login_time = None
            for t in reversed(list(profile.connection_times)):
                if now - t < 5:
                    login_time = t
                    break
            if login_time and now - login_time < 2:
                detected.append("IMMEDIATE_COMMAND_EXECUTION")

        # 8. PERIODIC BEACON
        if len(profile.inter_arrival_times) >= 8:
            recent_iats = list(profile.inter_arrival_times)[-15:]
            regularity = self._calc_timing_regularity(
                [sum(recent_iats[:i+1]) for i in range(len(recent_iats))]
            )
            avg_iat = sum(recent_iats) / len(recent_iats)
            if regularity > 0.8 and avg_iat > 5:
                detected.append("PERIODIC_BEACON")

        # 9. CONNECTION BURST
        last_5s = sum(1 for t in profile.connection_times if now - t < 5)
        last_60s = sum(1 for t in profile.connection_times if now - t < 60)
        if last_5s >= 5 and last_60s - last_5s < 3:
            detected.append("CONNECTION_BURST")

        # 10. SLOW SCAN (evasion)
        time_span = now - profile.first_seen
        if (time_span > 300 and len(profile.ports_touched) >= 5
                and len(profile.ports_touched) / (time_span / 60) < 2):
            detected.append("SLOW_SCAN")

        # 11. HIGH ENTROPY PAYLOAD
        raw_data = details.get("hex_preview", "")
        if raw_data and len(raw_data) >= 32:
            try:
                data_bytes = bytes.fromhex(raw_data)
                entropy = self._calc_entropy(data_bytes)
                if entropy > 6.5:  # Wysokie = zaszyfrowane/skompresowane
                    detected.append("HIGH_ENTROPY_PAYLOAD")
            except ValueError:
                pass

        # === GENERATE ALERTS ===
        alerts = []
        for indicator in detected:
            # Dedup - nie fire tego samego indicator dla tego IP w ciagu 120s
            dedup_key = f"{ip}:{indicator}"
            if not hasattr(self, "_dedup"):
                self._dedup = {}
            last_fire = self._dedup.get(dedup_key, 0)
            if now - last_fire < 120:
                continue
            self._dedup[dedup_key] = now

            info = BEHAVIOR_INDICATORS.get(indicator, {})
            weight = info.get("weight", 10)
            severity = "CRITICAL" if weight >= 70 else "HIGH" if weight >= 40 else "MEDIUM"

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": f"BEHAVIOR_{indicator}",
                "source_ip": ip,
                "severity": severity,
                "weight": weight,
                "description": info.get("description", indicator),
                "profile": {
                    "honeypots": len(profile.honeypots_touched),
                    "ports": len(profile.ports_touched),
                    "logins": profile.login_attempts,
                    "commands": profile.commands_issued,
                    "connections": len(profile.connection_times),
                },
            }
            alerts.append(alert)
            self._fire_alert(alert)

            # Add flag to profile
            profile.flags.add(indicator)

        return alerts

    def get_profile_summary(self, ip: str) -> dict:
        p = self.profiles.get(ip)
        if not p:
            return {}
        return {
            "ip": ip,
            "first_seen": datetime.fromtimestamp(p.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(p.last_seen, tz=timezone.utc).isoformat(),
            "honeypots": sorted(p.honeypots_touched),
            "ports": len(p.ports_touched),
            "login_attempts": p.login_attempts,
            "commands": p.commands_issued,
            "connections": len(p.connection_times),
            "flags": sorted(p.flags),
        }

    def get_suspicious_profiles(self, min_flags: int = 1) -> list:
        """Zwraca profile z flagami behawioralnymi."""
        result = []
        for ip, p in self.profiles.items():
            if len(p.flags) >= min_flags:
                total_weight = sum(
                    BEHAVIOR_INDICATORS.get(f, {}).get("weight", 0)
                    for f in p.flags
                )
                result.append({
                    "ip": ip,
                    "flags": sorted(p.flags),
                    "flag_count": len(p.flags),
                    "total_weight": total_weight,
                    "honeypots": len(p.honeypots_touched),
                    "connections": len(p.connection_times),
                })
        return sorted(result, key=lambda x: x["total_weight"], reverse=True)

    def get_stats(self) -> dict:
        flagged = sum(1 for p in self.profiles.values() if p.flags)
        return {
            "tracked_ips": len(self.profiles),
            "flagged_ips": flagged,
            "total_alerts": len(self.alerts),
            "indicators_active": len(set(
                f for p in self.profiles.values() for f in p.flags
            )),
        }

    def cleanup(self):
        """Usun stale profile (>1h bez aktywnosci)."""
        now = time.time()
        stale = [ip for ip, p in self.profiles.items() if now - p.last_seen > 3600]
        for ip in stale:
            del self.profiles[ip]
        # Cleanup dedup
        if hasattr(self, "_dedup"):
            self._dedup = {k: t for k, t in self._dedup.items() if now - t < 300}
        # Cleanup credential cache
        self._credential_cache = {
            ip: [(t, u, p) for t, u, p in creds if now - t < 300]
            for ip, creds in self._credential_cache.items()
            if any(now - t < 300 for t, _, _ in creds)
        }
