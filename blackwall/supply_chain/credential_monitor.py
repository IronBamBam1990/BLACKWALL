"""
Credential Vault Monitor - Wykrywa nieautoryzowany dostep do plikow z poswiadczeniami.

Monitoruje pliki SSH, AWS, Kubernetes, Docker, GCloud, klucze API, portfele crypto,
tokeny rejestrow pakietow, dane logowania Git i magazyny hasel przegladarek.
Inspirowane atakami supply-chain kradnacymi klucze API, SSH i portfele kryptowalut.
"""

import asyncio
import ctypes
import ctypes.wintypes
import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

import psutil


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
SEVERITY_LOW = "LOW"            # Known process accessing credential files
SEVERITY_MEDIUM = "MEDIUM"      # New/unknown process accessing credentials
SEVERITY_HIGH = "HIGH"          # Credential file modified (hash changed)
SEVERITY_CRITICAL = "CRITICAL"  # Multiple credential files accessed by unknown process


# ---------------------------------------------------------------------------
# Default credential locations (Windows-centric)
# ---------------------------------------------------------------------------
_HOME = Path.home()
_APPDATA = Path(os.environ.get("APPDATA", _HOME / "AppData" / "Roaming"))
_LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", _HOME / "AppData" / "Local"))

# Individual files
DEFAULT_CREDENTIAL_FILES: List[str] = [
    # SSH
    str(_HOME / ".ssh" / "id_rsa"),
    str(_HOME / ".ssh" / "id_rsa.pub"),
    str(_HOME / ".ssh" / "id_ed25519"),
    str(_HOME / ".ssh" / "id_ed25519.pub"),
    str(_HOME / ".ssh" / "known_hosts"),
    str(_HOME / ".ssh" / "authorized_keys"),
    str(_HOME / ".ssh" / "config"),
    # AWS
    str(_HOME / ".aws" / "credentials"),
    str(_HOME / ".aws" / "config"),
    # Kubernetes
    str(_HOME / ".kube" / "config"),
    # Docker
    str(_HOME / ".docker" / "config.json"),
    # Package registries
    str(_HOME / ".npmrc"),
    str(_HOME / ".pypirc"),
    # Git credentials
    str(_HOME / ".git-credentials"),
    str(_HOME / ".gitconfig"),
    # Crypto wallets
    str(_APPDATA / "Bitcoin" / "wallet.dat"),
    str(_APPDATA / "Ethereum" / "keystore"),
    str(_APPDATA / "Electrum" / "wallets"),
]

# Directories to scan recursively for .env files
DEFAULT_ENV_SCAN_DIRS: List[str] = [
    str(_HOME / "Desktop"),
    str(_HOME / "Documents"),
    str(_HOME / "Projects"),
    str(_HOME / "repos"),
    str(_HOME / "dev"),
    str(_HOME / "src"),
]

# Google Cloud config directory
GCLOUD_DIR = str(_APPDATA / "gcloud")

# Browser password stores (Windows)
BROWSER_CREDENTIAL_PATHS: List[str] = [
    # Chrome
    str(_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"),
    str(_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Web Data"),
    str(_LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Local State"),
    # Edge
    str(_LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data"),
    str(_LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Default" / "Web Data"),
    str(_LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Local State"),
    # Firefox (profiles are dynamic, use directory scanning)
    str(_APPDATA / "Mozilla" / "Firefox" / "Profiles"),
]

# Processes that are expected to access credential files
DEFAULT_KNOWN_PROCESSES: Set[str] = {
    "ssh.exe", "ssh-agent.exe", "ssh-add.exe", "sshd.exe",
    "git.exe", "git-remote-https.exe", "git-credential-manager.exe",
    "git-credential-manager-core.exe",
    "aws.exe", "aws-cli.exe",
    "kubectl.exe", "helm.exe",
    "docker.exe", "dockerd.exe", "docker-compose.exe",
    "gcloud.exe", "gsutil.exe",
    "node.exe", "npm.cmd", "npm.exe", "npx.exe", "yarn.exe", "pnpm.exe",
    "pip.exe", "pip3.exe", "python.exe", "python3.exe", "pythonw.exe",
    "code.exe", "devenv.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "explorer.exe", "notepad.exe", "notepad++.exe",
    "gpg.exe", "gpg-agent.exe",
    "keepass.exe", "keepassxc.exe", "1password.exe",
    "searchindexer.exe", "searchprotocolhost.exe",
    "msmpeng.exe", "mpcmdrun.exe",
    "svchost.exe", "system",
}


# ---------------------------------------------------------------------------
# Windows file-handle sniffing via NtQuerySystemInformation (optional)
# ---------------------------------------------------------------------------
def _try_get_open_files_for_pid(pid: int) -> List[str]:
    """Best-effort list of file paths that *pid* currently has open.

    NOTE: psutil.Process.open_files() causes access violation (segfault) on
    Python 3.14 + Windows due to NtQuerySystemInformation thread safety bug.
    Disabled for now - returns empty list. File access monitoring uses
    mtime/hash-based detection instead.
    """
    # DISABLED: psutil.open_files() segfaults on Python 3.14 Windows
    # See: https://github.com/giampaolo/psutil/issues/2366
    return []


# ---------------------------------------------------------------------------
# CredentialVaultMonitor
# ---------------------------------------------------------------------------
class CredentialVaultMonitor:
    """Monitors credential files for unauthorized access and modification.

    Parameters
    ----------
    config : dict, optional
        Configuration overrides.  Recognised keys:
        - ``enabled`` (bool, default True)
        - ``scan_interval_seconds`` (int, default 60)
        - ``burst_threshold`` (int, default 5) – accesses within the burst
          window that trigger a CRITICAL alert.
        - ``burst_window_seconds`` (int, default 10)
        - ``extra_credential_files`` (list[str]) – additional files to watch.
        - ``extra_known_processes`` (list[str]) – additional safe processes.
        - ``env_scan_dirs`` (list[str]) – dirs to scan for .env files.
        - ``monitor_browsers`` (bool, default True)
    alert_callback : callable, optional
        Async or sync callback ``(alert_dict) -> ...`` invoked on every alert.
    log_dir : str
        Directory for log files.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        alert_callback: Optional[Callable] = None,
        log_dir: str = "logs",
    ):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 60)
        self.burst_threshold = config.get("burst_threshold", 5)
        self.burst_window = config.get("burst_window_seconds", 10)
        self.monitor_browsers = config.get("monitor_browsers", True)

        # Merge extra files / processes with defaults
        self.credential_files: List[str] = list(DEFAULT_CREDENTIAL_FILES)
        self.credential_files.extend(config.get("extra_credential_files", []))

        self.known_processes: Set[str] = set(DEFAULT_KNOWN_PROCESSES)
        self.known_processes.update(
            p.lower() for p in config.get("extra_known_processes", [])
        )

        self.env_scan_dirs: List[str] = config.get(
            "env_scan_dirs", DEFAULT_ENV_SCAN_DIRS
        )

        # Alert callback
        self.alert_callback = alert_callback

        # Logging
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_logger()

        # Internal state
        self._hash_baseline: Dict[str, str] = {}   # path -> sha256
        self._stat_baseline: Dict[str, float] = {}  # path -> last mtime
        self._process_access_history: Dict[int, List[str]] = defaultdict(list)  # pid -> [paths]
        self._access_timestamps: List[float] = []   # for burst detection
        self._seen_process_keys: Set[str] = set()    # "pid:name" already alerted
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Stats
        self.alerts: List[Dict[str, Any]] = []
        self.total_scans = 0
        self.total_alerts = 0

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def _setup_logger(self) -> None:
        self.logger = logging.getLogger("CredentialVaultMonitor")
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            fh = RotatingFileHandler(
                self.log_dir / "credential_monitor.log",
                maxBytes=50 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            fh.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(fh)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the credential vault monitor loop."""
        if not self.enabled:
            self.logger.info("Credential Vault Monitor is disabled in config.")
            return
        if self._running:
            self.logger.warning("Monitor already running.")
            return

        self._running = True
        self.logger.info("=== Credential Vault Monitor starting ===")

        # Discover all credential files (including dynamic .env scan)
        self._discover_credential_files()

        # Build initial hash baseline
        self._build_hash_baseline()

        self.logger.info(
            "Monitoring %d credential file paths.  Scan interval: %ds",
            len(self.credential_files),
            self.scan_interval,
        )

        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Gracefully stop the monitor."""
        if not self._running:
            return
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.logger.info(
            "=== Credential Vault Monitor stopped.  "
            "Total scans: %d | Total alerts: %d ===",
            self.total_scans,
            self.total_alerts,
        )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _discover_credential_files(self) -> None:
        """Expand dynamic credential file locations."""
        discovered: Set[str] = set(self.credential_files)

        # Scan for .env files
        for scan_dir in self.env_scan_dirs:
            scan_path = Path(scan_dir)
            if not scan_path.is_dir():
                continue
            try:
                for env_file in scan_path.rglob(".env"):
                    discovered.add(str(env_file))
                for env_file in scan_path.rglob(".env.*"):
                    discovered.add(str(env_file))
            except (PermissionError, OSError):
                continue

        # Google Cloud directory
        gcloud_path = Path(GCLOUD_DIR)
        if gcloud_path.is_dir():
            for name in (
                "credentials.db",
                "access_tokens.db",
                "application_default_credentials.json",
                "properties",
            ):
                discovered.add(str(gcloud_path / name))

        # Firefox profiles (dynamic profile names)
        ff_profiles = Path(_APPDATA / "Mozilla" / "Firefox" / "Profiles")
        if ff_profiles.is_dir():
            try:
                for profile_dir in ff_profiles.iterdir():
                    if profile_dir.is_dir():
                        for cred_file in ("logins.json", "key4.db", "cert9.db"):
                            discovered.add(str(profile_dir / cred_file))
            except (PermissionError, OSError):
                pass

        # Browser credential paths
        if self.monitor_browsers:
            discovered.update(BROWSER_CREDENTIAL_PATHS)

        self.credential_files = sorted(discovered)

    # ------------------------------------------------------------------
    # Hash baseline
    # ------------------------------------------------------------------
    def _sha256(self, filepath: str) -> Optional[str]:
        """Return hex SHA-256 of *filepath*, or None on failure."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _build_hash_baseline(self) -> None:
        """Hash every existing credential file to establish a baseline."""
        for fpath in self.credential_files:
            if os.path.isfile(fpath):
                digest = self._sha256(fpath)
                if digest:
                    self._hash_baseline[fpath] = digest
                try:
                    self._stat_baseline[fpath] = os.path.getmtime(fpath)
                except OSError:
                    pass
        self.logger.info(
            "Hash baseline built for %d existing files.", len(self._hash_baseline)
        )

    # ------------------------------------------------------------------
    # Core scan loop
    # ------------------------------------------------------------------
    async def _monitor_loop(self) -> None:
        """Periodic scan loop."""
        while self._running:
            try:
                await self._run_scan()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.error("Scan error: %s", exc, exc_info=True)
            try:
                await asyncio.sleep(self.scan_interval)
            except asyncio.CancelledError:
                raise

    async def _run_scan(self) -> None:
        """Execute one full scan cycle."""
        self.total_scans += 1
        self.logger.debug("Scan #%d starting", self.total_scans)

        # 1. Check for hash / modification changes
        await self._check_file_modifications()

        # 2. Check which processes currently have credential files open
        await self._check_process_access()

        # 3. Burst detection (prune old timestamps)
        self._prune_access_timestamps()

        self.logger.debug("Scan #%d complete", self.total_scans)

    # ------------------------------------------------------------------
    # File modification detection
    # ------------------------------------------------------------------
    async def _check_file_modifications(self) -> None:
        """Detect new, modified, or deleted credential files."""
        for fpath in self.credential_files:
            if not os.path.isfile(fpath):
                # If it was in baseline and is now gone, that is also notable
                if fpath in self._hash_baseline:
                    await self._emit_alert(
                        severity=SEVERITY_HIGH,
                        category="credential_file_deleted",
                        message=f"Credential file was deleted: {fpath}",
                        details={"path": fpath},
                    )
                    del self._hash_baseline[fpath]
                    self._stat_baseline.pop(fpath, None)
                continue

            try:
                current_mtime = os.path.getmtime(fpath)
            except OSError:
                continue

            previous_mtime = self._stat_baseline.get(fpath)

            # Quick mtime check to avoid hashing unchanged files
            if previous_mtime is not None and current_mtime == previous_mtime:
                continue

            # mtime changed – verify via hash
            current_hash = self._sha256(fpath)
            if current_hash is None:
                continue

            old_hash = self._hash_baseline.get(fpath)

            if old_hash is None:
                # New credential file appeared
                self._hash_baseline[fpath] = current_hash
                self._stat_baseline[fpath] = current_mtime
                self.logger.info("New credential file indexed: %s", fpath)
                continue

            if current_hash != old_hash:
                await self._emit_alert(
                    severity=SEVERITY_HIGH,
                    category="credential_file_modified",
                    message=f"Credential file was modified: {fpath}",
                    details={
                        "path": fpath,
                        "old_hash": old_hash,
                        "new_hash": current_hash,
                    },
                )
                self._hash_baseline[fpath] = current_hash

            self._stat_baseline[fpath] = current_mtime

    # ------------------------------------------------------------------
    # Process-level access detection
    # ------------------------------------------------------------------
    async def _check_process_access(self) -> None:
        """Iterate running processes and find ones that have credential files open."""
        credential_set = set(self.credential_files)
        # Normalise to lower-case for Windows path comparison
        credential_lower: Dict[str, str] = {
            p.lower(): p for p in credential_set if os.path.isfile(p)
        }

        if not credential_lower:
            return

        # NOTE: Process file-handle sniffing disabled on Python 3.14 Windows
        # due to psutil.open_files() segfault.  Hash/mtime monitoring is active.
        pid_files_map: Dict[int, List[str]] = {}

        now = time.monotonic()

        for pid, matched_paths in pid_files_map.items():
            try:
                proc = psutil.Process(pid)
                pname = proc.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"

            proc_key = f"{pid}:{pname}"
            is_known = pname in self.known_processes

            # Track per-process access
            for mpath in matched_paths:
                if mpath not in self._process_access_history[pid]:
                    self._process_access_history[pid].append(mpath)
                self._access_timestamps.append(now)

            unique_accessed = self._process_access_history[pid]

            # --- Severity decision ---
            if not is_known and len(unique_accessed) >= 3:
                # CRITICAL: unknown process reading multiple credential files
                await self._emit_alert(
                    severity=SEVERITY_CRITICAL,
                    category="multi_credential_exfiltration",
                    message=(
                        f"CRITICAL: Process '{pname}' (PID {pid}) accessed "
                        f"{len(unique_accessed)} credential files — possible exfiltration"
                    ),
                    details={
                        "pid": pid,
                        "process": pname,
                        "files_accessed": list(unique_accessed),
                    },
                )
            elif not is_known and proc_key not in self._seen_process_keys:
                # MEDIUM: first time seeing this unknown process on creds
                await self._emit_alert(
                    severity=SEVERITY_MEDIUM,
                    category="unknown_process_credential_access",
                    message=(
                        f"Unknown process '{pname}' (PID {pid}) accessing "
                        f"credential file(s): {matched_paths}"
                    ),
                    details={
                        "pid": pid,
                        "process": pname,
                        "files_accessed": matched_paths,
                    },
                )
            elif is_known and proc_key not in self._seen_process_keys:
                # LOW: known process, first sighting this cycle
                self.logger.debug(
                    "Known process '%s' (PID %d) accessing credential files: %s",
                    pname,
                    pid,
                    matched_paths,
                )
                await self._emit_alert(
                    severity=SEVERITY_LOW,
                    category="known_process_credential_access",
                    message=(
                        f"Known process '{pname}' (PID {pid}) accessing "
                        f"credential file(s)"
                    ),
                    details={
                        "pid": pid,
                        "process": pname,
                        "files_accessed": matched_paths,
                    },
                )

            self._seen_process_keys.add(proc_key)

        # Burst detection
        await self._check_burst(now)

    def _gather_process_file_handles(
        self, credential_lower: Dict[str, str]
    ) -> Dict[int, List[str]]:
        """Iterate all processes and return {pid: [matched credential paths]}.

        Runs in a thread-pool executor to avoid blocking async loop.
        """
        result: Dict[int, List[str]] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if pid == 0:
                    continue
                open_files = _try_get_open_files_for_pid(pid)
                matched = []
                for fpath in open_files:
                    norm = fpath.lower()
                    if norm in credential_lower:
                        matched.append(credential_lower[norm])
                if matched:
                    result[pid] = matched
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        return result

    # ------------------------------------------------------------------
    # Burst / rate detection
    # ------------------------------------------------------------------
    def _prune_access_timestamps(self) -> None:
        cutoff = time.monotonic() - self.burst_window
        self._access_timestamps = [
            t for t in self._access_timestamps if t >= cutoff
        ]

    async def _check_burst(self, now: float) -> None:
        recent = [
            t for t in self._access_timestamps
            if t >= now - self.burst_window
        ]
        if len(recent) >= self.burst_threshold:
            await self._emit_alert(
                severity=SEVERITY_CRITICAL,
                category="credential_access_burst",
                message=(
                    f"Burst of {len(recent)} credential file accesses within "
                    f"{self.burst_window}s — possible automated exfiltration"
                ),
                details={
                    "access_count": len(recent),
                    "window_seconds": self.burst_window,
                    "threshold": self.burst_threshold,
                },
            )
            # Reset so we don't fire every scan
            self._access_timestamps.clear()

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------
    async def _emit_alert(
        self,
        severity: str,
        category: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "CredentialVaultMonitor",
            "severity": severity,
            "category": category,
            "message": message,
            "details": details or {},
        }

        self.alerts.append(alert)
        self.total_alerts += 1

        # Log at appropriate level
        log_level = {
            SEVERITY_LOW: logging.DEBUG,
            SEVERITY_MEDIUM: logging.WARNING,
            SEVERITY_HIGH: logging.ERROR,
            SEVERITY_CRITICAL: logging.CRITICAL,
        }.get(severity, logging.WARNING)
        self.logger.log(log_level, "[%s] %s", severity, message)

        # Invoke callback
        if self.alert_callback is not None:
            try:
                ret = self.alert_callback(alert)
                if asyncio.iscoroutine(ret) or asyncio.isfuture(ret):
                    await ret
            except Exception as exc:
                self.logger.error("Alert callback error: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        """Return a summary dict of current monitor state."""
        return {
            "running": self._running,
            "enabled": self.enabled,
            "total_scans": self.total_scans,
            "total_alerts": self.total_alerts,
            "monitored_files": len(self.credential_files),
            "credential_paths": len(self.credential_files),
            "baselined_files": len(self._hash_baseline),
            "baseline_status": "OK" if self._hash_baseline else "Unknown",
            "scan_interval_seconds": self.scan_interval,
            "recent_access_alerts": self.total_alerts,
            "exfiltration_attempts": 0,
            "recent_alerts": self.alerts[-20:],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Alias for get_status() - used by web dashboard."""
        return self.get_status()

    def get_baseline(self) -> Dict[str, str]:
        """Return current hash baseline (path -> sha256)."""
        return dict(self._hash_baseline)

    def reset_baseline(self) -> None:
        """Force a full re-baseline of all credential files."""
        self._hash_baseline.clear()
        self._stat_baseline.clear()
        self._build_hash_baseline()
        self.logger.info("Baseline manually reset.")

    def add_credential_path(self, path: str) -> None:
        """Add a new path to the watch list at runtime."""
        norm = str(Path(path).resolve())
        if norm not in self.credential_files:
            self.credential_files.append(norm)
            if os.path.isfile(norm):
                digest = self._sha256(norm)
                if digest:
                    self._hash_baseline[norm] = digest
                try:
                    self._stat_baseline[norm] = os.path.getmtime(norm)
                except OSError:
                    pass
            self.logger.info("Added credential path: %s", norm)

    def add_known_process(self, process_name: str) -> None:
        """Whitelist a process name at runtime."""
        self.known_processes.add(process_name.lower())
        self.logger.info("Added known process: %s", process_name.lower())
