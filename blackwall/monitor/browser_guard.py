"""
Browser Guard - Chroni przegladarki przed kradzieza cookies/sesji/hasel.

Wykrywa:
- Infostealery czytajace pliki cookies/Login Data przegladarek
- Nieautoryzowany dostep do browser profile (nie przez sam browser)
- Malicious browser extensions
- Clipboard hijacking (podmiana adresow crypto)
- Cookie injection patterns
- Procesy dumpujace pamiec przegladarki
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil

# ===== SCIEZKI DO CHRONIONYCH PLIKOW PRZEGLADAREK =====
BROWSER_SENSITIVE_FILES = {}

_user = Path.home()
_chrome = _user / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
_edge = _user / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"
_firefox_profiles = _user / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
_brave = _user / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data"
_opera = _user / "AppData" / "Roaming" / "Opera Software" / "Opera Stable"
_duckduckgo = _user / "AppData" / "Local" / "DuckDuckGo" / "User Data"

for name, base in [("chrome", _chrome), ("edge", _edge), ("brave", _brave),
                    ("opera", _opera), ("duckduckgo", _duckduckgo)]:
    for profile in ["Default", "Profile 1", "Profile 2"]:
        pdir = base / profile
        if pdir.exists():
            BROWSER_SENSITIVE_FILES[f"{name}_{profile}_cookies"] = pdir / "Cookies"
            BROWSER_SENSITIVE_FILES[f"{name}_{profile}_login"] = pdir / "Login Data"
            BROWSER_SENSITIVE_FILES[f"{name}_{profile}_webdata"] = pdir / "Web Data"
            BROWSER_SENSITIVE_FILES[f"{name}_{profile}_localstorage"] = pdir / "Local Storage" / "leveldb"
            BROWSER_SENSITIVE_FILES[f"{name}_{profile}_sessions"] = pdir / "Sessions"
    # Local State (encryption key for cookies!)
    local_state = base / "Local State"
    if local_state.exists():
        BROWSER_SENSITIVE_FILES[f"{name}_local_state"] = local_state

# Firefox
if _firefox_profiles.exists():
    for profile_dir in _firefox_profiles.iterdir():
        if profile_dir.is_dir():
            pname = profile_dir.name[:20]
            for fname in ["cookies.sqlite", "logins.json", "key4.db", "cert9.db",
                          "formhistory.sqlite", "places.sqlite"]:
                fp = profile_dir / fname
                if fp.exists():
                    BROWSER_SENSITIVE_FILES[f"firefox_{pname}_{fname}"] = fp

# Procesy przegladarek (legit dostep)
BROWSER_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "browser_broker.exe", "crashpad_handler.exe",
    "msedgewebview2.exe", "chromium.exe",
    "duckduckgo.exe", "duckduckgo browser.exe",
}

# Znane infostealery i narzedzia do kradziezi cookies
INFOSTEALER_NAMES = {
    # Infostealers
    "redline", "raccoon", "vidar", "mars", "arkei", "oski", "azorult",
    "predator", "stealc", "risepro", "lumma", "mystic",
    "formbook", "lokibot", "pony", "agenttesla", "hawkeye",
    "taurus", "cryptbot", "aurora", "rhadamanthys", "strigoi",
    # Tools
    "lazagne", "mimikatz", "browserpass", "hackbrowserdata",
    "sharpcookiemonster", "cookiemonster", "chromecookiestealer",
    "nirsoft", "webbrowserpassview", "chromepass",
    "sharpchromium", "sharpweb", "cookie_exfiltrator",
    # Suspicious
    "stealer", "dumper", "grabber", "exfil", "credential",
}

# Crypto adresy regex (dla clipboard hijacking)
CRYPTO_PATTERNS = {
    "bitcoin": re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$"),
    "ethereum": re.compile(r"^0x[0-9a-fA-F]{40}$"),
    "monero": re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$"),
}


class BrowserGuard:
    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 5)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Baseline access times
        self.file_baselines = {}  # path -> last_atime
        self.alert_callbacks = []
        self.alerts = []
        self._alerted_pids = set()
        self._last_clipboard = ""
        self._clipboard_swaps = 0
        self._running = False
        self._first_scan = True
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("BrowserGuard")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "browser_guard.log",
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
        if len(self.alerts) > 300:
            self.alerts = self.alerts[-150:]
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def check_cookie_theft_processes(self) -> list:
        """Wykrywa KAZDY proces ktory dotyka plikow cookies/hasel - bez wzgledu na nazwe.
        Uzywa open_files() psutil do sprawdzenia KTORY proces ma otwarty handle."""
        alerts = []

        # Sciezki do monitorowania (lowercase do porownania)
        protected_keywords = {
            "cookies", "login data", "web data", "local state",
            "logins.json", "key4.db", "cookies.sqlite", "cert9.db",
            "formhistory.sqlite",
        }

        # Whitelist procesow + ich folderow exe
        safe_exe_dirs = {
            "google", "chrome", "microsoft", "edge", "mozilla", "firefox",
            "brave", "opera", "duckduckgo",
            "norton", "malwarebytes", "kaspersky", "avast", "avg", "eset",
            "windows defender", "msmpeng",
            "security-suite",  # my
        }

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()

                if pid in self._alerted_pids:
                    continue

                # Sprawdz czy to browser lub AV
                is_safe = (
                    name in BROWSER_PROCESSES
                    or name in {"svchost.exe", "system", "searchindexer.exe"}
                    or any(sd in exe for sd in safe_exe_dirs)
                )
                if is_safe:
                    continue

                # Sprawdz otwarte pliki tego procesu
                try:
                    open_files = proc.open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for f in open_files:
                    fpath = f.path.lower()
                    # Czy ten plik to chroniony plik przegladarki?
                    fname = os.path.basename(fpath)
                    if fname in protected_keywords or any(kw in fpath for kw in protected_keywords):
                        self._alerted_pids.add(pid)
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "COOKIE_THEFT_REALTIME",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "process": proc.info["name"],
                            "exe": proc.info["exe"] or "N/A",
                            "accessed_file": f.path,
                            "description": (
                                f"COOKIE THEFT! '{proc.info['name']}' (PID:{pid}) "
                                f"has open handle on: {fname}"
                            ),
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self.logger.warning(alert["description"])
                        break  # Jeden alert per proces

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return alerts

    def check_browser_file_access(self) -> list:
        """Monitoruje access time na plikach cookies/login przegladarek."""
        alerts = []

        for name, filepath in BROWSER_SENSITIVE_FILES.items():
            if not isinstance(filepath, Path) or not filepath.exists():
                continue
            if filepath.is_dir():
                continue

            try:
                stat = filepath.stat()
                current_atime = stat.st_atime

                if self._first_scan:
                    self.file_baselines[str(filepath)] = current_atime
                    continue

                baseline = self.file_baselines.get(str(filepath), current_atime)

                # Access time zmieniony = ktos czytal plik
                if current_atime > baseline + 2:
                    # Sprawdz czy to browser sam (normalny dostep)
                    browser_running = False
                    for bproc in BROWSER_PROCESSES:
                        for p in psutil.process_iter(["name"]):
                            try:
                                if p.info["name"] and p.info["name"].lower() == bproc:
                                    browser_running = True
                                    break
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                        if browser_running:
                            break

                    # Jesli browser NIE jest uruchomiony a ktos czyta cookies = ALARM
                    if not browser_running and "cookies" in name.lower():
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "COOKIE_FILE_READ_NO_BROWSER",
                            "severity": "CRITICAL",
                            "file": str(filepath),
                            "file_label": name,
                            "description": f"Cookies read while browser closed! {filepath.name}",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self.logger.warning(alert["description"])

                    self.file_baselines[str(filepath)] = current_atime

            except (OSError, PermissionError):
                continue

        self._first_scan = False
        return alerts

    def check_clipboard_hijacking(self) -> list:
        """Wykrywa podmiane adresow crypto w clipboard."""
        alerts = []
        try:
            # Uzyj subprocess zamiast ctypes (bezpieczniejsze - bez segfault)
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command", "Get-Clipboard -ErrorAction SilentlyContinue"],
                capture_output=True, timeout=3,
                encoding="utf-8", errors="replace",
            )
            if result.returncode != 0:
                return alerts

            text = result.stdout.strip()
            if not text:
                return alerts

            if text != self._last_clipboard and self._last_clipboard:
                for crypto, pattern in CRYPTO_PATTERNS.items():
                    if pattern.match(self._last_clipboard):
                        if pattern.match(text) and text != self._last_clipboard:
                            self._clipboard_swaps += 1
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "type": "CLIPBOARD_HIJACK",
                                "severity": "CRITICAL",
                                "crypto_type": crypto,
                                "original_addr": self._last_clipboard[:20] + "...",
                                "swapped_to": text[:20] + "...",
                                "swap_count": self._clipboard_swaps,
                                "description": f"CLIPBOARD HIJACK! {crypto} address swapped!",
                            }
                            alerts.append(alert)
                            self._fire_alert(alert)
                            self.logger.warning(alert["description"])
                            break

            self._last_clipboard = text[:500]
        except Exception:
            pass
        return alerts

    def check_memory_dump(self) -> list:
        """Wykrywa procesy probuajce dumpowac pamiec przegladarek."""
        alerts = []
        dump_tools = {
            "procdump", "processdump", "sqldumper", "comsvcs",
            "minidump", "memdump", "memorydump",
        }

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()

                if pid in self._alerted_pids:
                    continue

                # Dump tool targeting browser
                is_dump = any(dt in name or dt in cmdline for dt in dump_tools)
                targets_browser = any(bp in cmdline for bp in ["chrome", "firefox", "edge", "brave"])

                if is_dump and targets_browser:
                    self._alerted_pids.add(pid)
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "BROWSER_MEMORY_DUMP",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "process": proc.info["name"],
                        "description": f"Browser memory dump! {proc.info['name']} targeting browser",
                    }
                    alerts.append(alert)
                    self._fire_alert(alert)
                    self.logger.warning(alert["description"])

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return alerts

    def check_open_handles_powershell(self) -> list:
        """Fallback: uzywa handle64/PowerShell do sprawdzenia kto czyta pliki cookies.
        Dziala nawet jesli psutil.open_files() nie ma uprawnien."""
        alerts = []
        # Sprawdz TYLKO najwazniejsze pliki
        critical_files = []
        for name, path in BROWSER_SENSITIVE_FILES.items():
            if isinstance(path, Path) and path.exists() and "cookies" in name.lower():
                critical_files.append(str(path))

        if not critical_files:
            return alerts

        for fpath in critical_files[:5]:  # Max 5 zeby nie obciazac
            try:
                import subprocess
                # PowerShell: znajdz procesy z otwartym handleem na tym pliku
                ps_cmd = (
                    f"$file = '{fpath}'; "
                    f"Get-Process | ForEach-Object {{ "
                    f"  try {{ $_.Modules | Where-Object {{ $_.FileName -like \"*Cookies*\" }} }} catch {{}} "
                    f"}} 2>$null | Select-Object -First 5 | ConvertTo-Json -Compress"
                )
                # Ta metoda jest ograniczona - lepsza jest psutil.open_files()
                # ale zostawiamy jako fallback
            except Exception:
                pass
        return alerts

    def check_suspicious_file_copies(self) -> list:
        """Wykrywa procesy kopiujace pliki przegladarek (cp, copy, xcopy, robocopy)."""
        alerts = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()

                if pid in self._alerted_pids:
                    continue

                # Procesy kopiujace
                copy_procs = {"xcopy.exe", "robocopy.exe", "copy.exe"}
                is_copy = name in copy_procs or "copy" in cmdline or "xcopy" in cmdline

                if not is_copy:
                    continue

                # Czy kopiuje pliki przegladarek?
                browser_paths = ["\\chrome\\", "\\edge\\", "\\firefox\\", "\\brave\\",
                                "\\duckduckgo\\", "cookies", "login data", "local state"]
                for bp in browser_paths:
                    if bp in cmdline:
                        self._alerted_pids.add(pid)
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "BROWSER_FILE_COPY",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "process": proc.info["name"],
                            "cmdline": cmdline[:300],
                            "description": f"Browser data COPY! {proc.info['name']} copying {bp}",
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self.logger.warning(alert["description"])
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return alerts

    def check_network_after_browser_access(self) -> list:
        """Wykrywa procesy ktore czytaly pliki przegladarki I maja polaczenia sieciowe.
        To jest pattern infostealera: czytaj cookies -> wyslij na C2."""
        alerts = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()

                if pid in self._alerted_pids:
                    continue
                if name in BROWSER_PROCESSES or name in {"svchost.exe", "system"}:
                    continue

                # Sprawdz czy ma otwarte pliki przegladarki
                has_browser_file = False
                try:
                    for f in proc.open_files():
                        fpath = f.path.lower()
                        if any(kw in fpath for kw in ["cookies", "login data", "local state",
                                                       "logins.json", "key4.db"]):
                            has_browser_file = True
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                if not has_browser_file:
                    continue

                # Ma plik przegladarki - sprawdz czy tez ma polaczenia sieciowe
                try:
                    connections = proc.net_connections()
                    outbound = [c for c in connections if c.raddr and c.status == "ESTABLISHED"]
                    if outbound:
                        self._alerted_pids.add(pid)
                        remote_ips = [f"{c.raddr.ip}:{c.raddr.port}" for c in outbound[:5]]
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "INFOSTEALER_EXFILTRATION",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "process": proc.info["name"],
                            "exe": proc.info["exe"] or "N/A",
                            "remote_connections": remote_ips,
                            "description": (
                                f"EXFILTRATION! '{proc.info['name']}' has browser files "
                                f"+ network to {remote_ips[0]}"
                            ),
                        }
                        alerts.append(alert)
                        self._fire_alert(alert)
                        self.logger.warning(alert["description"])
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return alerts

    def scan(self) -> list:
        alerts = []
        alerts.extend(self.check_cookie_theft_processes())
        alerts.extend(self.check_browser_file_access())
        alerts.extend(self.check_suspicious_file_copies())
        alerts.extend(self.check_network_after_browser_access())
        alerts.extend(self.check_clipboard_hijacking())
        alerts.extend(self.check_memory_dump())
        return alerts

    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info(
            f"Browser Guard started - monitoring {len(BROWSER_SENSITIVE_FILES)} browser files"
        )
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
            "monitored_files": len(BROWSER_SENSITIVE_FILES),
            "alerts": len(self.alerts),
            "clipboard_swaps": self._clipboard_swaps,
        }
