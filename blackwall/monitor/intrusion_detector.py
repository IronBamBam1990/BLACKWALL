"""
Intrusion Detection System (IDS) - Analizuje zdarzenia z honeypotow i monitora.
Wykrywa wzorce atakow, brute force, i znane exploity.
"""

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# Znane wzorce atakow w HTTP requestach
KNOWN_EXPLOIT_PATTERNS = [
    # Web shells
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
    "eval(", "exec(", "system(", "passthru(",
    # Directory traversal
    "../../../", "..\\..\\",
    # SQL Injection
    "' or 1=1", "union select", "drop table", "' or ''='",
    "1=1--", "' and 1=1", "or 1=1#", "admin'--",
    # XSS
    "<script>", "javascript:", "onerror=", "onload=",
    # Common scanners
    "nikto", "nmap", "masscan", "sqlmap", "burp", "dirbuster",
    "gobuster", "wfuzz", "ffuf", "nuclei", "acunetix",
    # Common exploit paths
    "/wp-admin", "/phpmyadmin", "/.env", "/config.php",
    "/shell.php", "/c99.php", "/r57.php", "/b374k.php",
    "/cgi-bin/", "/manager/html", "/solr/",
    "/.git/config", "/.svn/entries", "/.DS_Store",
    "/wp-config.php", "/xmlrpc.php", "/wp-json/wp/v2/users",
    "/actuator", "/api/v1", "/graphql", "/swagger",
    "/debug", "/trace", "/metrics", "/health",
    "/server-status", "/server-info",
    # Log4Shell
    "${jndi:", "${jndi:ldap",
    # Spring4Shell
    "class.module.classloader",
    # SSRF
    "http://169.254.169.254", "http://metadata.google",
    "http://100.100.100.200",
    # Command injection
    ";id", "|id", "$(id)", "`id`", ";cat /etc/passwd",
    "&&whoami", "||whoami",
    # Cookie/Session attacks
    "document.cookie", "set-cookie:", "cookie:", ".cookie",
    "session_id=", "phpsessid=", "jsessionid=",
    "steal", "exfil", "c2", "callback",
    # Cookie injection / XSS cookie theft
    "img src=x onerror", "svg onload", "body onload",
    "fetch(", "xmlhttprequest", "navigator.sendbeacon",
    "btoa(document.cookie)", "encodeuri(document.cookie)",
    "window.location=", "document.location=",
    # Session fixation
    "set-cookie", "sessionid", "connect.sid",
    # CSRF
    "csrf", "xsrf",
    # File inclusion / path traversal for config stealing
    "/proc/self/environ", "/etc/environment",
    "web.config", "appsettings.json", "database.yml",
    "wp-config.php.bak", ".env.bak", ".env.local",
]

# Znane domyslne credentials (set dla O(1) lookup)
KNOWN_DEFAULT_CREDS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("admin", "admin123"), ("test", "test"), ("user", "user"),
    ("administrator", "administrator"), ("guest", "guest"),
    ("admin", ""), ("root", ""), ("pi", "raspberry"),
    ("admin", "1234"), ("admin", "12345"), ("admin", "pass"),
    ("root", "123456"), ("root", "admin"), ("user", "password"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("ftpuser", "ftpuser"), ("ftp", "ftp"), ("anonymous", ""),
    ("sa", ""), ("sa", "sa"), ("sa", "password"),
}


class IntrusionDetector:
    def __init__(self, config: dict, log_dir: str = "logs"):
        self.config = config.get("monitor", {})
        self.log_dir = Path(log_dir)
        self.brute_force_threshold = self.config.get("brute_force_threshold", 3)
        self.brute_force_window = self.config.get("brute_force_window_seconds", 60)

        # Tracking
        self.login_attempts = defaultdict(list)  # ip -> [(timestamp, user, pass), ...]
        self.detected_attacks = []
        self.attack_callbacks = []
        self._recent_alert_keys = set()  # Deduplikacja: (ip, type) -> nie alertuj ponownie w 60s
        self._alert_key_times = {}       # (ip, type) -> timestamp

    def on_attack(self, callback):
        self.attack_callbacks.append(callback)

    def _fire_attack(self, attack: dict):
        # Deduplikacja - nie fire tego samego (ip, type) w ciagu 60s
        now = time.time()
        key = (attack.get("source_ip", ""), attack.get("type", ""))
        last = self._alert_key_times.get(key, 0)
        if now - last < 60:
            # Cichutko dodaj do listy ale nie fire callbacks
            self.detected_attacks.append(attack)
            return
        self._alert_key_times[key] = now

        # Cleanup starych kluczy co 50 atakow
        if len(self._alert_key_times) > 200:
            cutoff = now - 120
            self._alert_key_times = {k: t for k, t in self._alert_key_times.items() if t > cutoff}

        self.detected_attacks.append(attack)
        if len(self.detected_attacks) > 1000:
            self.detected_attacks = self.detected_attacks[-500:]
        for cb in self.attack_callbacks:
            try:
                cb(attack)
            except Exception:
                pass

    def analyze_honeypot_event(self, event: dict) -> dict | None:
        """Analizuje zdarzenie z honeypota pod katem znanych atakow."""
        source_ip = event.get("source_ip", "unknown")
        details = event.get("details", {})
        action = details.get("action", "")

        # Sprawdz brute force
        if action == "login_attempt":
            return self._check_brute_force(source_ip, details)

        # Sprawdz exploit patterns w HTTP
        if action == "http_request":
            return self._check_exploit_patterns(source_ip, details)

        # Sprawdz podejrzane komendy w telnet
        if action == "command_executed":
            return self._check_malicious_commands(source_ip, details)

        # Sprawdz DNS tunneling
        if action == "dns_query":
            return self._check_dns_tunneling(source_ip, details)

        # Catch-all - polaczenie na C2 port (tylko z publicznych IP)
        if action == "connection_attempt":
            target_port = details.get("target_port", 0)
            # 5555 = Android ADB (normalny), usuniety z listy
            c2_ports = {4444, 6666, 1337, 31337, 12345, 54321}
            try:
                import ipaddress
                addr = ipaddress.ip_address(source_ip)
                if addr.is_private or addr.is_loopback:
                    return None  # Lokalne IP - nie flaguj
            except ValueError:
                pass
            if target_port in c2_ports:
                attack = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "C2_PORT_CONNECTION",
                    "source_ip": source_ip,
                    "port": target_port,
                    "severity": "HIGH",
                    "description": f"Connection to C2 port {target_port}",
                }
                self._fire_attack(attack)
                return attack

        return None

    def _check_dns_tunneling(self, source_ip: str, details: dict) -> dict | None:
        """Wykrywa DNS tunneling (bardzo dlugie domeny)."""
        domain = details.get("domain", "")
        if not domain:
            return None
        labels = domain.split(".")
        max_label = max((len(l) for l in labels), default=0)
        if max_label > 40 or len(domain) > 120:
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "DNS_TUNNELING",
                "source_ip": source_ip,
                "domain": domain[:253],
                "max_label_len": max_label,
                "severity": "CRITICAL",
                "description": f"DNS tunnel: {domain[:60]}... (label {max_label} chars)",
            }
            self._fire_attack(attack)
            return attack
        return None

    def _check_brute_force(self, source_ip: str, details: dict) -> dict | None:
        """Wykrywa brute force - wiele prob logowania z jednego IP."""
        now = time.time()
        username = details.get("username", "")
        password = details.get("password", "")

        self.login_attempts[source_ip].append((now, username, password))

        # Usun stare wpisy
        recent = [
            (t, u, p) for t, u, p in self.login_attempts[source_ip]
            if now - t < self.brute_force_window
        ]
        self.login_attempts[source_ip] = recent

        # Sprawdz default credentials
        if (username, password) in KNOWN_DEFAULT_CREDS:
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "DEFAULT_CREDENTIALS",
                "source_ip": source_ip,
                "username": username,
                "severity": "HIGH",
                "description": f"Proba logowania domyslnymi credentials: {username}/{password}",
            }
            self._fire_attack(attack)
            return attack

        # Sprawdz brute force
        if len(recent) >= self.brute_force_threshold:
            creds = [(u, p) for _, u, p in recent]
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "BRUTE_FORCE",
                "source_ip": source_ip,
                "attempts": len(recent),
                "credentials_tried": [{"user": u, "pass": p} for u, p in creds[-10:]],
                "severity": "CRITICAL",
                "description": f"Brute force: {len(recent)} prob w {self.brute_force_window}s",
            }
            self._fire_attack(attack)
            return attack

        return None

    def _check_exploit_patterns(self, source_ip: str, details: dict) -> dict | None:
        """Wykrywa znane wzorce exploitow w HTTP requestach."""
        request_line = details.get("request_line", "")
        body = details.get("body_preview", "")
        user_agent = details.get("user_agent", "")
        full_text = f"{request_line} {body} {user_agent}".lower()

        found_patterns = []
        for pattern in KNOWN_EXPLOIT_PATTERNS:
            if pattern.lower() in full_text:
                found_patterns.append(pattern)

        if found_patterns:
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "EXPLOIT_ATTEMPT",
                "source_ip": source_ip,
                "patterns_matched": found_patterns,
                "request": request_line[:300],
                "user_agent": user_agent[:200],
                "severity": "CRITICAL",
                "description": f"Exploit patterns: {', '.join(found_patterns[:5])}",
            }
            self._fire_attack(attack)
            return attack

        return None

    def _check_malicious_commands(self, source_ip: str, details: dict) -> dict | None:
        """Wykrywa zlosliwe komendy w honeypot shell."""
        cmd = details.get("command", "").lower()

        malicious_indicators = [
            "wget", "curl", "nc ", "ncat", "netcat",
            "/dev/tcp", "bash -i", "python -c", "perl -e",
            "chmod +x", "rm -rf", "dd if=", "mkfs",
            "iptables -F", "ufw disable",
            "cat /etc/shadow", "cat /etc/passwd",
            "ssh-keygen", "authorized_keys",
            "crontab", "base64 -d", "base64 --decode",
            "reverse", "shell", "bind",
            # Exfiltration
            "scp ", "sftp ", "rsync ", "ftp ", "tftp ",
            # Privilege escalation
            "sudo su", "su root", "pkexec", "doas ",
            # Persistence
            "/etc/cron", ".bashrc", ".profile", "systemctl enable",
            # Enumeration
            "find / -perm", "find / -writable", "linpeas", "linenum",
            "uname -a", "cat /proc/version", "dpkg -l",
            # Crypto mining
            "xmrig", "minerd", "cpuminer", "stratum+tcp",
        ]

        found = [ind for ind in malicious_indicators if ind in cmd]
        if found:
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "MALICIOUS_COMMAND",
                "source_ip": source_ip,
                "command": details.get("command", "")[:500],
                "indicators": found,
                "severity": "CRITICAL",
                "description": f"Zlosliwa komenda: {cmd[:100]}",
            }
            self._fire_attack(attack)
            return attack

        return None

    def get_attack_stats(self) -> dict:
        """Statystyki wykrytych atakow."""
        stats = {
            "total_attacks": len(self.detected_attacks),
            "by_type": defaultdict(int),
            "by_ip": defaultdict(int),
            "by_severity": defaultdict(int),
            "recent": self.detected_attacks[-10:],
        }
        for a in self.detected_attacks:
            stats["by_type"][a.get("type", "unknown")] += 1
            stats["by_ip"][a.get("source_ip", "unknown")] += 1
            stats["by_severity"][a.get("severity", "unknown")] += 1

        # Convert defaultdicts to regular dicts for JSON serialization
        stats["by_type"] = dict(stats["by_type"])
        stats["by_ip"] = dict(stats["by_ip"])
        stats["by_severity"] = dict(stats["by_severity"])
        return stats
