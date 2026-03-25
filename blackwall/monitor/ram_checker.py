"""
RAM / Memory Security Scanner - Detects credential harvesting from process memory.

Inspired by the TeamPCP/Trivy/LiteLLM supply-chain attack that injected
malicious code into pip packages to harvest API keys, tokens, and secrets
from environment variables and memory at runtime.

Detects:
- Processes exposing secrets in environment variables
- Executables running from temp directories (dropper pattern)
- Base64-obfuscated command lines (python/node)
- Processes spawned by pip/npm install (supply-chain vector)
- PowerShell encoded commands
- Shell spawned by scripting runtimes (python->cmd, node->powershell)
- Access to credential files (.env, .aws/credentials, .ssh/id_rsa, wallet.dat)
- Known malware process names (miners, reverse shells, cred dumpers)
- RAM pressure spikes and per-process memory growth anomalies
"""

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

import psutil


# ---------------------------------------------------------------------------
# Environment variable patterns that indicate exposed credentials
# ---------------------------------------------------------------------------
EXACT_SECRET_ENV_VARS = {
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT",
    "NPM_TOKEN", "NPM_AUTH_TOKEN",
    "SLACK_TOKEN", "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN", "DISCORD_BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "AZURE_CLIENT_SECRET", "AZURE_STORAGE_KEY",
    "GCP_SERVICE_ACCOUNT_KEY",
    "DOCKER_PASSWORD", "DOCKER_AUTH_TOKEN",
    "HEROKU_API_KEY",
    "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN",
    "VAULT_TOKEN",
}

# Wildcard patterns: *_SECRET*, *_PASSWORD*, *_TOKEN*, *_KEY*
_WILDCARD_RE = re.compile(
    r"_(SECRET|PASSWORD|PASSWD|TOKEN|KEY|APIKEY|API_KEY|PRIVATE_KEY)",
    re.IGNORECASE,
)

# DATABASE_URL containing inline password
_DB_URL_PASSWORD_RE = re.compile(
    r"(mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@]{4,}@",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Known malware / attacker-tool process names (lowercase)
# ---------------------------------------------------------------------------
KNOWN_MALWARE_NAMES = {
    # Crypto miners
    "xmrig", "xmrig.exe", "minerd", "minerd.exe",
    "cpuminer", "cpuminer.exe", "cgminer", "cgminer.exe",
    "bfgminer", "bfgminer.exe", "ethminer", "ethminer.exe",
    "nbminer", "nbminer.exe", "t-rex", "t-rex.exe",
    "phoenixminer", "phoenixminer.exe",
    # Credential dumpers
    "mimikatz", "mimikatz.exe",
    "lazagne", "lazagne.exe",
    "rubeus", "rubeus.exe",
    "sharpdump", "sharpdump.exe",
    "procdump", "procdump.exe",
    "secretsdump", "secretsdump.exe",
    # Reverse shells / netcat
    "nc.exe", "ncat.exe", "netcat.exe",
    # Misc
    "cobaltstrike", "beacon.exe",
}

# Temp directory fragments (lowercase) for suspicious-path detection
_TEMP_FRAGMENTS = None  # built lazily in __init__


class RAMChecker:
    """Memory / RAM security scanner.

    Scans running processes for credential exposure, suspicious behaviour,
    known-malware names, and abnormal memory-pressure patterns.
    """

    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("interval", 10)
        self.whitelist_processes = {
            n.lower() for n in config.get("whitelist_processes", [])
        }

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.alert_callbacks = []
        self.alerts: list[dict] = []
        self._running = False

        # Per-process RSS tracking for growth-rate detection
        # {pid: (timestamp, rss_bytes)}
        self._rss_history: dict[int, tuple[float, int]] = {}
        self._last_total_ram_pct: float = 0.0

        # Stats counters
        self._processes_scanned = 0
        self._suspicious_found = 0
        self._credential_exposures = 0
        self._alerts_count = 0
        self._last_scan: str = ""

        # Build temp-dir fragments for this machine
        self._temp_fragments = self._build_temp_fragments()

        self._setup_logger()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def _setup_logger(self):
        self.logger = logging.getLogger("RAMChecker")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            self.log_dir / "ram_checker.log",
            maxBytes=50 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Alert plumbing (matches project pattern)
    # ------------------------------------------------------------------
    def on_alert(self, callback):
        """Register an alert callback."""
        self.alert_callbacks.append(callback)

    def _fire_alert(self, alert: dict):
        self.alerts.append(alert)
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-250:]
        self._alerts_count += 1
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_temp_fragments() -> list[str]:
        frags = []
        for var in ("TEMP", "TMP"):
            val = os.environ.get(var)
            if val:
                frags.append(val.lower().replace("\\", "/"))
        frags.append("appdata/local/temp")
        frags.append("appdata\\local\\temp")
        # De-duplicate while preserving order
        seen = set()
        unique = []
        for f in frags:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return unique

    @staticmethod
    def _safe_cmdline_str(proc_info: dict) -> str:
        parts = proc_info.get("cmdline") or []
        return " ".join(parts)[:2000]

    def _make_alert(self, alert_type: str, severity: str, description: str,
                    pid: int = 0, process: str = "", **extra) -> dict:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": alert_type,
            "severity": severity,
            "pid": pid,
            "process": process,
            "description": description,
            **extra,
        }
        return alert

    # ------------------------------------------------------------------
    # 1. Environment variable credential scanning
    # ------------------------------------------------------------------
    def _check_env_credentials(self, proc: psutil.Process,
                               info: dict) -> list[dict]:
        alerts = []
        try:
            env = proc.environ()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return alerts

        name = info.get("name") or "unknown"
        pid = info.get("pid", 0)
        flagged_vars = []

        for key, value in env.items():
            if not value:
                continue

            # Exact match on known secret var names
            if key.upper() in EXACT_SECRET_ENV_VARS:
                flagged_vars.append(key)
                continue

            # DATABASE_URL with inline password
            if key.upper() == "DATABASE_URL" and _DB_URL_PASSWORD_RE.search(value):
                flagged_vars.append(key)
                continue

            # Wildcard pattern with minimum value length
            if _WILDCARD_RE.search(key) and len(value) > 20:
                flagged_vars.append(key)

        if flagged_vars:
            self._credential_exposures += 1
            desc = (
                f"Process '{name}' (PID:{pid}) exposes secrets in env: "
                f"{', '.join(flagged_vars[:5])}"
            )
            alert = self._make_alert(
                "CREDENTIAL_IN_ENV", "HIGH", desc,
                pid=pid, process=name,
                exposed_vars=flagged_vars[:10],
            )
            alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    # 2. Suspicious process detection
    # ------------------------------------------------------------------
    def _check_suspicious_process(self, info: dict) -> list[dict]:
        alerts = []
        name = (info.get("name") or "unknown").lower()
        exe = (info.get("exe") or "").replace("\\", "/").lower()
        pid = info.get("pid", 0)
        cmdline_str = self._safe_cmdline_str(info).lower()
        ppid = info.get("ppid", 0)

        # --- Running from temp directory ---
        if exe:
            for frag in self._temp_fragments:
                if frag in exe:
                    alert = self._make_alert(
                        "TEMP_DIR_EXECUTABLE", "HIGH",
                        f"Process '{name}' (PID:{pid}) runs from temp dir: {exe[:120]}",
                        pid=pid, process=name, exe=exe[:200],
                    )
                    alerts.append(alert)
                    break

        # --- Base64-obfuscated command line (python/node) ---
        if name in ("python.exe", "python3.exe", "pythonw.exe",
                     "node.exe", "node"):
            # Look for long base64 blobs in the command line
            b64_match = re.search(r"[A-Za-z0-9+/=]{80,}", cmdline_str)
            if b64_match:
                alert = self._make_alert(
                    "OBFUSCATED_CMDLINE", "HIGH",
                    f"Process '{name}' (PID:{pid}) has base64 blob in cmdline",
                    pid=pid, process=name,
                )
                alerts.append(alert)

        # --- PowerShell encoded command ---
        if name in ("powershell.exe", "pwsh.exe"):
            if re.search(r"\s-e(nc|ncodedcommand)?\s", cmdline_str):
                alert = self._make_alert(
                    "POWERSHELL_ENCODED", "CRITICAL",
                    f"PowerShell (PID:{pid}) running encoded command",
                    pid=pid, process=name,
                )
                alerts.append(alert)

        # --- Shell spawned by scripting runtime ---
        if name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            try:
                parent_name = psutil.Process(ppid).name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                parent_name = ""
            if parent_name in ("python.exe", "python3.exe", "pythonw.exe",
                               "node.exe"):
                alert = self._make_alert(
                    "SHELL_FROM_SCRIPT_RUNTIME", "MEDIUM",
                    f"'{name}' (PID:{pid}) spawned by '{parent_name}'",
                    pid=pid, process=name, parent=parent_name,
                )
                alerts.append(alert)

        # --- Child of pip / npm install (supply-chain attack vector) ---
        try:
            parent = psutil.Process(ppid)
            parent_cmdline = " ".join(parent.cmdline() or []).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            parent_cmdline = ""
        if ("pip install" in parent_cmdline or "pip3 install" in parent_cmdline
                or "npm install" in parent_cmdline
                or "npm i " in parent_cmdline):
            alert = self._make_alert(
                "SPAWNED_BY_PACKAGE_INSTALL", "HIGH",
                f"Process '{name}' (PID:{pid}) spawned during package install",
                pid=pid, process=name, parent_cmdline=parent_cmdline[:200],
            )
            alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # 3. Credential file access (command-line heuristic)
    # ------------------------------------------------------------------
    _SENSITIVE_FILE_PATTERNS = (
        ".env", ".aws/credentials", ".aws\\credentials",
        ".ssh/id_rsa", ".ssh\\id_rsa",
        ".ssh/id_ed25519", ".ssh\\id_ed25519",
        "wallet.dat", "credentials.json",
        ".npmrc", ".pypirc",
        ".docker/config.json", ".docker\\config.json",
        ".kube/config", ".kube\\config",
    )

    def _check_credential_file_access(self, info: dict) -> list[dict]:
        alerts = []
        cmdline_str = self._safe_cmdline_str(info).lower()
        if not cmdline_str:
            return alerts

        name = (info.get("name") or "unknown").lower()
        pid = info.get("pid", 0)
        hits = [p for p in self._SENSITIVE_FILE_PATTERNS if p in cmdline_str]

        if len(hits) >= 2:
            self._credential_exposures += 1
            alert = self._make_alert(
                "CREDENTIAL_FILE_ACCESS", "CRITICAL",
                f"Process '{name}' (PID:{pid}) references multiple "
                f"credential files: {', '.join(hits[:5])}",
                pid=pid, process=name, files=hits[:10],
            )
            alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    # 4. Known malware process names
    # ------------------------------------------------------------------
    def _check_known_malware(self, info: dict) -> list[dict]:
        alerts = []
        name = (info.get("name") or "").lower()
        pid = info.get("pid", 0)
        cmdline_str = self._safe_cmdline_str(info).lower()

        if name in KNOWN_MALWARE_NAMES:
            alert = self._make_alert(
                "KNOWN_MALWARE", "CRITICAL",
                f"Known malware/tool detected: '{name}' (PID:{pid})",
                pid=pid, process=name,
            )
            alerts.append(alert)
            return alerts

        # nc/ncat with -e (reverse shell)
        if name in ("nc.exe", "ncat.exe", "netcat.exe"):
            if " -e " in cmdline_str or " -e\t" in cmdline_str:
                alert = self._make_alert(
                    "REVERSE_SHELL", "CRITICAL",
                    f"Reverse shell: '{name}' (PID:{pid}) with -e flag",
                    pid=pid, process=name,
                )
                alerts.append(alert)

        # bitsadmin /transfer (download stager)
        if name == "bitsadmin.exe" and "/transfer" in cmdline_str:
            alert = self._make_alert(
                "DOWNLOAD_STAGER", "HIGH",
                f"Download stager: bitsadmin /transfer (PID:{pid})",
                pid=pid, process=name,
            )
            alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # 5. Memory pressure detection
    # ------------------------------------------------------------------
    def _check_memory_pressure(self) -> list[dict]:
        alerts = []
        mem = psutil.virtual_memory()
        current_pct = mem.percent

        # Sudden spike above 90%
        if current_pct > 90.0 and self._last_total_ram_pct > 0:
            delta = current_pct - self._last_total_ram_pct
            if delta > 15.0:
                alert = self._make_alert(
                    "RAM_PRESSURE_SPIKE", "HIGH",
                    f"RAM usage spiked {self._last_total_ram_pct:.1f}% -> "
                    f"{current_pct:.1f}% (+{delta:.1f}%)",
                    ram_percent=current_pct,
                )
                alerts.append(alert)
        self._last_total_ram_pct = current_pct

        # Per-process RSS growth rate
        now = time.monotonic()
        current_rss: dict[int, tuple[float, int]] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                rss = proc.memory_info().rss
                current_rss[pid] = (now, rss)

                prev = self._rss_history.get(pid)
                if prev is not None:
                    prev_time, prev_rss = prev
                    elapsed_min = (now - prev_time) / 60.0
                    if elapsed_min > 0:
                        growth_mb = (rss - prev_rss) / (1024 * 1024)
                        rate_mb_min = growth_mb / elapsed_min
                        if rate_mb_min > 100.0:
                            pname = proc.info["name"] or "unknown"
                            alert = self._make_alert(
                                "RAPID_MEMORY_GROWTH", "MEDIUM",
                                f"'{pname}' (PID:{pid}) growing "
                                f"{rate_mb_min:.0f} MB/min "
                                f"(RSS: {rss // (1024*1024)} MB)",
                                pid=pid, process=pname,
                                growth_rate_mb_min=round(rate_mb_min, 1),
                            )
                            alerts.append(alert)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        self._rss_history = current_rss
        return alerts

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------
    def scan(self) -> list[dict]:
        """Run a full scan cycle. Returns list of alerts generated."""
        if not self.enabled:
            return []

        scan_alerts: list[dict] = []
        scanned = 0

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "ppid"]
        ):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()

                # Skip whitelisted
                if name in self.whitelist_processes:
                    continue

                scanned += 1

                # 1. Env-var credential scan
                scan_alerts.extend(self._check_env_credentials(proc, info))

                # 2. Suspicious process behaviour
                scan_alerts.extend(self._check_suspicious_process(info))

                # 3. Credential file references in cmdline
                scan_alerts.extend(self._check_credential_file_access(info))

                # 4. Known malware names
                scan_alerts.extend(self._check_known_malware(info))

            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        # 5. Memory pressure (system-wide + per-process growth)
        try:
            scan_alerts.extend(self._check_memory_pressure())
        except Exception as exc:
            self.logger.error(f"Memory pressure check error: {exc}")

        # Update stats
        self._processes_scanned = scanned
        self._suspicious_found += len(scan_alerts)
        self._last_scan = datetime.now(timezone.utc).isoformat()

        # Fire alerts and log
        for alert in scan_alerts:
            self._fire_alert(alert)
            sev = alert.get("severity", "INFO")
            if sev == "CRITICAL":
                self.logger.critical(alert["description"])
            elif sev == "HIGH":
                self.logger.warning(alert["description"])
            else:
                self.logger.info(alert["description"])

        if scan_alerts:
            self.logger.info(
                f"Scan complete: {scanned} procs, {len(scan_alerts)} alerts"
            )

        return scan_alerts

    # ------------------------------------------------------------------
    # Async loop (matches project pattern)
    # ------------------------------------------------------------------
    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("RAM Checker started")
        while self._running:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self.scan)
            except Exception as e:
                self.logger.error(f"Scan error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "processes_scanned": self._processes_scanned,
            "suspicious_found": self._suspicious_found,
            "credential_exposures": self._credential_exposures,
            "alerts": self._alerts_count,
            "last_scan": self._last_scan,
        }
