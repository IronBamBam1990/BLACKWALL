"""
Threat Scorer - Oblicza score zagrozenia dla kazdego IP.
Laczy dane z honeypotow, IDS, threat intel, GeoIP w jeden wynik.
"""

import ipaddress
from collections import defaultdict
from datetime import datetime, timezone


# Wagi per zdarzenie
SCORE_WEIGHTS = {
    # Honeypot hits
    "honeypot_hit": 10,
    "login_attempt": 15,
    "command_executed": 20,
    "mail_attempt": 10,
    "file_transfer_attempt": 15,

    # IDS detections
    "BRUTE_FORCE": 50,
    "DEFAULT_CREDENTIALS": 40,
    "EXPLOIT_ATTEMPT": 60,
    "MALICIOUS_COMMAND": 70,
    "DNS_TUNNELING": 80,
    "C2_PORT_CONNECTION": 60,

    # Network
    "PORT_SCAN_DETECTED": 30,
    "SUSPICIOUS_PORT": 20,
    "C2_PORT_OUTBOUND": 90,
    "C2_BEACON_DETECTED": 100,

    # Threat Intel
    "threat_intel_match": 50,
    "threat_intel_multi_feed": 80,

    # Multipliers
    "from_tor": 1.5,
    "from_known_bad_country": 1.2,
}

# Kraje z najczesciej zlosliwym ruchem (mnoznik)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "VN", "BR", "ID", "IN", "PK"}

# Progi
SCORE_THRESHOLDS = {
    "LOW": 0,
    "MEDIUM": 30,
    "HIGH": 60,
    "CRITICAL": 100,
}


class ThreatScorer:
    def __init__(self):
        self.ip_scores = defaultdict(lambda: {
            "score": 0,
            "events": [],
            "first_seen": None,
            "last_seen": None,
            "honeypots_hit": set(),
            "country": "",
            "threat_intel": False,
        })
        # Tylko IP ktore dotknely honeypoty sa scorowane
        self._honeypot_ips = set()

    def _is_local(self, ip: str) -> bool:
        """Ignoruj lokalne IP - to nie sa ataki."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return True

    def add_event(self, ip: str, event_type: str, details: dict = None):
        """Dodaje zdarzenie i aktualizuje score."""
        if not ip or self._is_local(ip):
            return

        entry = self.ip_scores[ip]
        now = datetime.now(timezone.utc).isoformat()

        if entry["first_seen"] is None:
            entry["first_seen"] = now
        entry["last_seen"] = now

        # Base score
        base = SCORE_WEIGHTS.get(event_type, 5)
        multiplier = 1.0

        # GeoIP multiplier
        country = (details or {}).get("country", entry.get("country", ""))
        if country:
            entry["country"] = country
            if country in HIGH_RISK_COUNTRIES:
                multiplier *= SCORE_WEIGHTS.get("from_known_bad_country", 1.2)

        # Threat intel multiplier
        if (details or {}).get("threat_intel"):
            entry["threat_intel"] = True
            base += SCORE_WEIGHTS.get("threat_intel_match", 50)

        # Honeypot tracking
        honeypot = (details or {}).get("honeypot", "")
        if honeypot:
            entry["honeypots_hit"].add(honeypot)
            # Multi-honeypot bonus (atakuje wiele uslug = bardziej niebezpieczny)
            if len(entry["honeypots_hit"]) >= 3:
                multiplier *= 1.3

        entry["score"] += int(base * multiplier)

        # Cap at 999
        if entry["score"] > 999:
            entry["score"] = 999

        entry["events"].append({
            "type": event_type,
            "time": now,
            "score_added": int(base * multiplier),
        })

        # Keep max 50 events per IP
        if len(entry["events"]) > 50:
            entry["events"] = entry["events"][-30:]

    def get_score(self, ip: str) -> int:
        return self.ip_scores.get(ip, {}).get("score", 0)

    def get_severity(self, ip: str) -> str:
        score = self.get_score(ip)
        if score >= SCORE_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        if score >= SCORE_THRESHOLDS["HIGH"]:
            return "HIGH"
        if score >= SCORE_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    def get_top_threats(self, count: int = 20) -> list:
        """Top N IP po score."""
        ranked = sorted(
            self.ip_scores.items(),
            key=lambda x: x[1]["score"],
            reverse=True,
        )[:count]

        result = []
        for ip, data in ranked:
            result.append({
                "ip": ip,
                "score": data["score"],
                "severity": self.get_severity(ip),
                "country": data.get("country", ""),
                "honeypots_hit": len(data.get("honeypots_hit", set())),
                "threat_intel": data.get("threat_intel", False),
                "first_seen": data.get("first_seen", ""),
                "last_seen": data.get("last_seen", ""),
                "event_count": len(data.get("events", [])),
            })
        return result

    def get_stats(self) -> dict:
        scores = [d["score"] for d in self.ip_scores.values()]
        return {
            "tracked_ips": len(self.ip_scores),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "critical_count": sum(1 for s in scores if s >= SCORE_THRESHOLDS["CRITICAL"]),
            "high_count": sum(1 for s in scores if SCORE_THRESHOLDS["HIGH"] <= s < SCORE_THRESHOLDS["CRITICAL"]),
        }

    def process_honeypot_event(self, event: dict):
        """Przetwarza event z honeypota - TYLKO tu IP wchodzi do scorera."""
        ip = event.get("source_ip", "")
        if not ip or self._is_local(ip):
            return
        self._honeypot_ips.add(ip)  # Oznacz jako honeypot-touching IP

        details = event.get("details", {})
        action = details.get("action", "honeypot_hit")
        geo = event.get("geo", {})
        ti = event.get("threat_intel", {})

        self.add_event(ip, action, {
            "honeypot": event.get("honeypot", ""),
            "country": geo.get("country", ""),
            "threat_intel": ti.get("threat", False),
        })

    def process_attack(self, attack: dict):
        """Przetwarza atak - tylko jesli IP juz dotknelo honeypot."""
        ip = attack.get("source_ip", "")
        if not ip or self._is_local(ip):
            return
        # Scoruj ataki tylko od IP ktore wczesniej trafily na honeypot
        if ip in self._honeypot_ips:
            self.add_event(ip, attack.get("type", "unknown"))

    def process_network_alert(self, alert: dict):
        """Przetwarza alert sieciowy - tylko honeypot-touching IP."""
        ip = alert.get("source_ip", alert.get("ip", ""))
        if not ip or self._is_local(ip):
            return
        if ip in self._honeypot_ips:
            self.add_event(ip, alert.get("type", "unknown"))
