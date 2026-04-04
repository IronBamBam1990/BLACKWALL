"""
Supply Chain Guardian - Wykrywa ataki na lancuch dostaw pakietow Python/npm.

Inspirowane prawdziwymi atakami: LiteLLM/Trivy (.pth injection), event-stream,
ua-parser-js, colors/faker. Monitoruje site-packages, pip install procesy,
dependency tree, typosquatting, zlosliwe skrypty instalacyjne.
"""

import asyncio
import json
import logging
import os
import re
import site
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import psutil

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# ---------------------------------------------------------------------------
# Known compromised packages
# ---------------------------------------------------------------------------
KNOWN_COMPROMISED: Dict[str, Dict[str, Any]] = {
    # Python
    "litellm": {
        "compromised_versions": ["4.97.9", "4.97.8"],
        "reason": ".pth file injection stealing API keys via background HTTP POST",
        "severity": SEVERITY_CRITICAL,
        "cve": "CVE-2025-LITELLM",
    },
    "jeIlyfish": {
        "compromised_versions": ["*"],
        "reason": "Typosquat of jellyfish - steals SSH keys",
        "severity": SEVERITY_CRITICAL,
    },
    "python3-dateutil": {
        "compromised_versions": ["*"],
        "reason": "Typosquat of python-dateutil - steals SSH keys and crypto wallets",
        "severity": SEVERITY_CRITICAL,
    },
    "colourama": {
        "compromised_versions": ["*"],
        "reason": "Typosquat of colorama - cryptocurrency stealer",
        "severity": SEVERITY_CRITICAL,
    },
    "pypistats": {
        "compromised_versions": ["*"],
        "reason": "Typosquat of pypistats-io - data exfiltration",
        "severity": SEVERITY_HIGH,
    },
    # npm
    "event-stream": {
        "compromised_versions": ["3.3.6"],
        "reason": "Malicious flatmap-stream dependency stealing Bitcoin wallets",
        "severity": SEVERITY_CRITICAL,
        "cve": "CVE-2018-16492",
    },
    "ua-parser-js": {
        "compromised_versions": ["0.7.29", "0.8.0", "1.0.0"],
        "reason": "Cryptominer and password stealer injected by hijacked maintainer",
        "severity": SEVERITY_CRITICAL,
        "cve": "CVE-2021-23424",
    },
    "coa": {
        "compromised_versions": ["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1",
                                  "3.1.3"],
        "reason": "Compromised maintainer account - spawns reverse shell",
        "severity": SEVERITY_CRITICAL,
    },
    "rc": {
        "compromised_versions": ["1.2.9", "1.3.9", "2.3.9"],
        "reason": "Compromised maintainer account - exfiltrates env variables",
        "severity": SEVERITY_CRITICAL,
    },
    "colors": {
        "compromised_versions": ["1.4.1", "1.4.2"],
        "reason": "Maintainer protest - infinite loop DoS (LIBERTY LIBERTY LIBERTY)",
        "severity": SEVERITY_HIGH,
    },
    "faker": {
        "compromised_versions": ["6.6.6"],
        "reason": "Maintainer protest - prints ENDGAME message and exits",
        "severity": SEVERITY_HIGH,
    },
    "peacenotwar": {
        "compromised_versions": ["*"],
        "reason": "Protestware - overwrites files with anti-war messages",
        "severity": SEVERITY_CRITICAL,
    },
    "node-ipc": {
        "compromised_versions": ["10.1.1", "10.1.2", "10.1.3"],
        "reason": "Peacenotwar dependency - geo-targeted file destruction",
        "severity": SEVERITY_CRITICAL,
    },
    "es5-ext": {
        "compromised_versions": ["0.10.53", "0.10.54"],
        "reason": "Protestware - anti-war postinstall message + telemetry",
        "severity": SEVERITY_MEDIUM,
    },
    "ctx": {
        "compromised_versions": ["*"],
        "reason": "PyPI hijack - steals environment variables via webhook",
        "severity": SEVERITY_CRITICAL,
    },
    "phpass": {
        "compromised_versions": ["*"],
        "reason": "PyPI hijack - credential stealer",
        "severity": SEVERITY_CRITICAL,
    },
    "lottie-player": {
        "compromised_versions": ["2.0.4", "2.0.5", "2.0.6", "2.0.7", "2.0.8"],
        "reason": "npm hijack - injects crypto wallet drainer into web pages",
        "severity": SEVERITY_CRITICAL,
    },
    # Axios supply chain attack - March 30, 2026 (North Korea / UNC1069 / Sapphire Sleet)
    "axios": {
        "compromised_versions": ["1.7.1", "1.7.2"],
        "reason": "Compromised maintainer account - postinstall hook drops cross-platform RAT via plain-crypto-js from sfrclak[.]com:8000",
        "severity": SEVERITY_CRITICAL,
        "cve": "CVE-2026-AXIOS",
    },
    "plain-crypto-js": {
        "compromised_versions": ["*"],
        "reason": "Malicious package from axios supply chain attack - stage-2 RAT loader for Windows/macOS/Linux",
        "severity": SEVERITY_CRITICAL,
    },
}

# Popular packages to detect typosquatting against
# Known safe .pth files (not malware, standard Python ecosystem)
SAFE_PTH_FILES = {
    "distutils-precedence.pth",  # setuptools - overrides distutils
    "easy-install.pth",          # setuptools legacy
    "setuptools.pth",            # setuptools
    "virtualenv_path_extensions.pth",  # virtualenv
    "poetry.pth",                # poetry
    "site-packages.pth",         # standard
    "README.txt",                # not actually .pth but sometimes present
    "no-global-site-packages.txt",
}

# Known safe package pairs that trigger false-positive typosquatting
# Format: frozenset({installed_name, popular_name})
SAFE_TYPOSQUAT_PAIRS = {
    frozenset({"scapy", "scipy"}),       # both legitimate, different domains
    frozenset({"click", "black"}),       # both popular, not related
    frozenset({"flask", "black"}),       # both popular, not related
    frozenset({"pip", "six"}),           # both core packages
    frozenset({"six", "pip"}),           # reverse
    frozenset({"rich", "ruff"}),         # both popular tools
    frozenset({"attrs", "attr"}),        # same project, different names
    frozenset({"pillow", "pyllow"}),     # pillow is legitimate
    frozenset({"boto3", "boto"}),        # both AWS SDK versions
    frozenset({"pytz", "pytest"}),       # both well-known
    frozenset({"idna", "idnx"}),         # idna is legitimate
    frozenset({"jinja2", "ninja2"}),     # jinja2 is legitimate
}

POPULAR_PACKAGES = {
    # Python top 100+
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "wheel", "cryptography", "pyyaml", "pillow",
    "scipy", "matplotlib", "sqlalchemy", "jinja2", "click", "colorama",
    "attrs", "packaging", "certifi", "charset-normalizer", "idna",
    "typing-extensions", "aiohttp", "pydantic", "fastapi", "uvicorn",
    "pytest", "tox", "coverage", "black", "ruff", "mypy", "pylint",
    "celery", "redis", "psutil", "paramiko", "fabric", "ansible",
    "scrapy", "beautifulsoup4", "selenium", "httpx", "httpcore",
    "python-dateutil", "pytz", "six", "decorator", "jsonschema",
    "jellyfish", "tensorflow", "torch", "transformers", "openai",
    "langchain", "litellm", "tiktoken", "tokenizers", "scikit-learn",
    # npm top
    "express", "react", "vue", "angular", "lodash", "axios", "moment",
    "webpack", "babel", "eslint", "prettier", "typescript", "next",
    "gatsby", "electron", "socket.io", "commander", "chalk", "inquirer",
    "yargs", "glob", "rimraf", "mkdirp", "dotenv", "uuid", "cors",
}

# Suspicious patterns in setup.py / __init__.py
SETUP_PY_DANGEROUS_PATTERNS = [
    (re.compile(r"__import__\s*\("), "Dynamic __import__() call"),
    (re.compile(r"subprocess\.(call|run|Popen|check_output|check_call)"),
     "subprocess execution"),
    (re.compile(r"os\.system\s*\("), "os.system() call"),
    (re.compile(r"os\.popen\s*\("), "os.popen() call"),
    (re.compile(r"\bexec\s*\("), "exec() call"),
    (re.compile(r"\beval\s*\("), "eval() call"),
    (re.compile(r"ctypes\.(cdll|windll|CDLL|WinDLL)"), "ctypes DLL loading"),
    (re.compile(r"socket\.connect\s*\("), "Network socket connection"),
    (re.compile(r"urlopen\s*\("), "URL fetch during install"),
    (re.compile(r"requests\.(get|post|put|delete)\s*\("), "HTTP request during install"),
    (re.compile(r"httpx\.(get|post|put|delete|Client)\s*\("), "httpx request during install"),
    (re.compile(r"base64\.(b64decode|decodebytes)\s*\("), "base64 decoding (obfuscation)"),
    (re.compile(r"codecs\.decode\s*\(.*rot"), "ROT13/codec obfuscation"),
    (re.compile(r"compile\s*\(.*exec"), "Compile + exec (obfuscated execution)"),
    (re.compile(r"marshal\.loads\s*\("), "marshal.loads (bytecode injection)"),
    (re.compile(r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}"),
     "Heavy hex-encoded strings (obfuscation)"),
]

INIT_PY_NETWORK_PATTERNS = [
    (re.compile(r"import\s+socket"), "socket import"),
    (re.compile(r"from\s+socket\s+import"), "socket import"),
    (re.compile(r"import\s+urllib"), "urllib import"),
    (re.compile(r"from\s+urllib"), "urllib import"),
    (re.compile(r"import\s+requests"), "requests import"),
    (re.compile(r"import\s+httpx"), "httpx import"),
    (re.compile(r"import\s+aiohttp"), "aiohttp import"),
    (re.compile(r"\.connect\s*\("), "connect() call"),
    (re.compile(r"\.send\s*\("), "send() call"),
    (re.compile(r"urlopen\s*\("), "urlopen() call"),
]

INIT_PY_DANGEROUS_IMPORTS = [
    (re.compile(r"^import\s+os\b", re.MULTILINE), "os module import"),
    (re.compile(r"^from\s+os\s+import", re.MULTILINE), "os module import"),
    (re.compile(r"^import\s+subprocess\b", re.MULTILINE), "subprocess import"),
    (re.compile(r"^from\s+subprocess\s+import", re.MULTILINE), "subprocess import"),
    (re.compile(r"^import\s+ctypes\b", re.MULTILINE), "ctypes import"),
    (re.compile(r"^from\s+ctypes\s+import", re.MULTILINE), "ctypes import"),
]

# Packages that legitimately use os/subprocess in __init__.py (reduce noise)
INIT_IMPORT_WHITELIST = {
    "psutil", "setuptools", "pip", "virtualenv", "tox", "nox",
    "fabric", "invoke", "paramiko", "ansible", "salt",
    "pytest", "coverage", "pylint", "mypy", "black", "ruff",
    "pathlib", "shutil", "tempfile", "platform", "distutils",
}


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,        # insert
                prev_row[j + 1] + 1,    # delete
                prev_row[j] + cost,     # replace
            ))
        prev_row = curr_row
    return prev_row[-1]


class ThreatEvent:
    """A single supply chain threat detection."""

    __slots__ = ("timestamp", "severity", "package", "description", "evidence",
                 "category", "action_taken")

    def __init__(
        self,
        severity: str,
        package: str,
        description: str,
        evidence: str = "",
        category: str = "supply_chain",
        action_taken: str = "none",
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.severity = severity
        self.package = package
        self.description = description
        self.evidence = evidence
        self.category = category
        self.action_taken = action_taken

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "package": self.package,
            "description": self.description,
            "evidence": self.evidence,
            "category": self.category,
            "action_taken": self.action_taken,
        }

    def __repr__(self) -> str:
        return (f"ThreatEvent(severity={self.severity!r}, package={self.package!r}, "
                f"description={self.description!r})")


class SupplyChainGuardian:
    """
    Monitors Python and npm supply chains for compromised packages,
    malicious install scripts, .pth injection, typosquatting, and more.

    Usage:
        guardian = SupplyChainGuardian(
            config={"scan_interval": 300},
            alert_callback=my_async_callback,
            log_dir="logs",
        )
        await guardian.start()
        ...
        await guardian.stop()
    """

    def __init__(
        self,
        config: Optional[dict] = None,
        alert_callback: Optional[Callable[[ThreatEvent], Coroutine]] = None,
        log_dir: str = "logs",
    ):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval", 300)
        self.pip_watch_interval = config.get("pip_watch_interval", 5)
        self.typosquat_threshold = config.get("typosquat_distance", 2)
        self.scan_npm = config.get("scan_npm", True)
        self.scan_pip = config.get("scan_pip", True)
        self.project_roots: List[str] = config.get("project_roots", ["."])
        self.extra_compromised: Dict[str, dict] = config.get(
            "extra_compromised_packages", {}
        )

        self.alert_callback = alert_callback
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._running = False
        self._tasks: List[asyncio.Task] = []
        self.threats: List[ThreatEvent] = []
        self._known_pip_pids: Set[int] = set()
        self._scanned_pth: Set[str] = set()
        self._scanned_packages: Set[str] = set()

        # Merge user-supplied compromised list
        self.compromised_db = {**KNOWN_COMPROMISED, **self.extra_compromised}

        self._setup_logger()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _setup_logger(self) -> None:
        self.logger = logging.getLogger("SupplyChainGuardian")
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.log_dir / "supply_chain.log",
                maxBytes=50 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all monitoring loops."""
        if not self.enabled:
            self.logger.info("Supply Chain Guardian disabled via config")
            return

        self._running = True
        self.logger.info("========================================")
        self.logger.info("SUPPLY CHAIN GUARDIAN ONLINE")
        self.logger.info("Scan interval: %ds | npm: %s | pip: %s",
                         self.scan_interval, self.scan_npm, self.scan_pip)
        self.logger.info("Known compromised packages: %d",
                         len(self.compromised_db))
        self.logger.info("========================================")

        self._tasks = [
            asyncio.create_task(self._periodic_scan_loop(), name="scg-periodic"),
            asyncio.create_task(self._pip_watch_loop(), name="scg-pip-watch"),
        ]
        self.logger.info("Guardian tasks started (%d)", len(self._tasks))

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "total_threats": len(self.threats),
            "compromised_packages": sum(1 for t in self.threats if "compromised" in str(getattr(t, "category", "")).lower()),
            "pth_files_detected": sum(1 for t in self.threats if "pth" in str(getattr(t, "category", "")).lower()),
            "typosquatting_alerts": sum(1 for t in self.threats if "typo" in str(getattr(t, "category", "")).lower()),
            "pip_monitoring": self._running,
        }

    async def stop(self) -> None:
        """Gracefully stop all monitoring."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self.logger.info("Supply Chain Guardian stopped. Total threats found: %d",
                         len(self.threats))

    # ------------------------------------------------------------------
    # Alert dispatch
    # ------------------------------------------------------------------

    async def _emit_threat(self, event: ThreatEvent) -> None:
        self.threats.append(event)
        self.logger.warning(
            "THREAT [%s] pkg=%s | %s | evidence=%s",
            event.severity, event.package, event.description,
            event.evidence[:200] if event.evidence else "N/A",
        )
        if self.alert_callback:
            try:
                result = self.alert_callback(event)
                if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                    await result
            except Exception as exc:
                self.logger.error("Alert callback failed: %s", exc)

    # ------------------------------------------------------------------
    # Periodic full scan
    # ------------------------------------------------------------------

    async def _periodic_scan_loop(self) -> None:
        """Main loop: runs all scans every scan_interval seconds."""
        while self._running:
            try:
                self.logger.info("--- Starting periodic supply chain scan ---")
                t0 = time.monotonic()

                scan_coros = [
                    self._scan_known_compromised(),
                    self._scan_pth_files(),
                    self._scan_init_files(),
                    self._scan_setup_py_files(),
                    self._scan_dependency_trees(),
                    self._detect_typosquatting(),
                ]
                if self.scan_npm:
                    scan_coros.append(self._scan_npm_packages())

                results = await asyncio.gather(*scan_coros, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error("Scan task %d failed: %s", i, result)

                elapsed = time.monotonic() - t0
                self.logger.info(
                    "--- Scan complete in %.1fs | Total threats: %d ---",
                    elapsed, len(self.threats),
                )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("Periodic scan error: %s", exc, exc_info=True)

            try:
                await asyncio.sleep(self.scan_interval)
            except asyncio.CancelledError:
                break

    # ------------------------------------------------------------------
    # Pip process watcher
    # ------------------------------------------------------------------

    async def _pip_watch_loop(self) -> None:
        """Monitor for pip install subprocesses in real-time."""
        while self._running:
            try:
                await self._check_pip_processes()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.debug("Pip watch error: %s", exc)

            try:
                await asyncio.sleep(self.pip_watch_interval)
            except asyncio.CancelledError:
                break

    async def _check_pip_processes(self) -> None:
        """Detect running pip install processes and log what they're installing."""
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                cmdline = info.get("cmdline") or []
                name = (info.get("name") or "").lower()

                if pid in self._known_pip_pids:
                    continue

                # Detect pip install
                cmd_str = " ".join(cmdline).lower()
                is_pip_install = (
                    ("pip" in name and "install" in cmd_str)
                    or ("python" in name and "-m" in cmd_str
                        and "pip" in cmd_str and "install" in cmd_str)
                )
                if not is_pip_install:
                    continue

                self._known_pip_pids.add(pid)

                # Extract package name from cmdline
                packages = self._extract_pip_packages(cmdline)
                self.logger.info(
                    "PIP INSTALL detected: pid=%d packages=%s cmd=%s",
                    pid, packages, " ".join(cmdline[:10]),
                )

                for pkg in packages:
                    pkg_lower = pkg.lower().split("==")[0].split(">=")[0].split("<=")[0]
                    # Check against compromised db
                    if pkg_lower in self.compromised_db:
                        entry = self.compromised_db[pkg_lower]
                        await self._emit_threat(ThreatEvent(
                            severity=entry.get("severity", SEVERITY_CRITICAL),
                            package=pkg_lower,
                            description=(
                                f"LIVE INSTALL of known compromised package: "
                                f"{entry.get('reason', 'Unknown')}"
                            ),
                            evidence=f"pip install command: {' '.join(cmdline[:8])}",
                            category="supply_chain.live_install",
                        ))

                    # Typosquat check on live installs
                    typo_match = self._check_typosquat(pkg_lower)
                    if typo_match:
                        await self._emit_threat(ThreatEvent(
                            severity=SEVERITY_HIGH,
                            package=pkg_lower,
                            description=(
                                f"Possible typosquat being installed! "
                                f"Similar to popular package '{typo_match}'"
                            ),
                            evidence=f"Levenshtein distance <= {self.typosquat_threshold}",
                            category="supply_chain.typosquat_install",
                        ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    @staticmethod
    def _extract_pip_packages(cmdline: list) -> List[str]:
        """Extract package names from a pip install command line."""
        packages = []
        found_install = False
        skip_next = False

        for arg in cmdline:
            if skip_next:
                skip_next = False
                continue
            arg_lower = arg.lower()
            if arg_lower == "install":
                found_install = True
                continue
            if not found_install:
                continue
            # Skip flags
            if arg.startswith("-"):
                if arg in ("-r", "--requirement", "-e", "--editable",
                           "-t", "--target", "--prefix", "-i", "--index-url",
                           "--extra-index-url", "-f", "--find-links"):
                    skip_next = True
                continue
            if arg.startswith(".") or arg.startswith("/") or arg.startswith("\\"):
                continue
            packages.append(arg)
        return packages

    # ------------------------------------------------------------------
    # Scan: known compromised packages
    # ------------------------------------------------------------------

    async def _scan_known_compromised(self) -> None:
        """Check installed pip packages against the compromised database."""
        installed = await self._get_installed_pip_packages()

        for pkg_name, pkg_version in installed.items():
            pkg_lower = pkg_name.lower()
            if pkg_lower not in self.compromised_db:
                continue

            entry = self.compromised_db[pkg_lower]
            comp_versions = entry.get("compromised_versions", [])

            if "*" in comp_versions or pkg_version in comp_versions:
                await self._emit_threat(ThreatEvent(
                    severity=entry.get("severity", SEVERITY_CRITICAL),
                    package=pkg_lower,
                    description=(
                        f"COMPROMISED PACKAGE INSTALLED: {pkg_lower}=={pkg_version} | "
                        f"{entry.get('reason', 'Known malicious')}"
                    ),
                    evidence=(
                        f"Version {pkg_version} in compromised list: {comp_versions}. "
                        f"CVE: {entry.get('cve', 'N/A')}"
                    ),
                    category="supply_chain.compromised",
                    action_taken="alert",
                ))

    async def _get_installed_pip_packages(self) -> Dict[str, str]:
        """Get dict of installed pip packages {name: version}."""
        packages = {}
        try:
            result = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pip", "list", "--format=json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=30)
            result = type("R", (), {"returncode": result.returncode, "stdout": stdout.decode("utf-8", errors="replace")})()
            if result.returncode == 0 and result.stdout.strip():
                for entry in json.loads(result.stdout):
                    packages[entry["name"].lower()] = entry.get("version", "unknown")
        except Exception as exc:
            self.logger.error("Failed to list pip packages: %s", exc)
        return packages

    # ------------------------------------------------------------------
    # Scan: .pth files (LiteLLM attack vector)
    # ------------------------------------------------------------------

    async def _scan_pth_files(self) -> None:
        """
        Scan all site-packages for .pth files that execute code.
        This is the exact vector used in the LiteLLM attack: a .pth file
        with 'import' on a line causes Python to exec it on every startup.
        """
        site_dirs = self._get_site_packages_dirs()

        for sp_dir in site_dirs:
            sp_path = Path(sp_dir)
            if not sp_path.exists():
                continue

            try:
                pth_files = list(sp_path.glob("*.pth"))
            except PermissionError:
                continue

            for pth_file in pth_files:
                pth_str = str(pth_file)
                if pth_str in self._scanned_pth:
                    continue
                self._scanned_pth.add(pth_str)

                # Skip known safe .pth files
                if pth_file.name in SAFE_PTH_FILES:
                    continue

                try:
                    content = pth_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                dangerous_lines = []
                for lineno, line in enumerate(content.splitlines(), 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    # .pth lines starting with "import" are executed by site.py
                    if stripped.startswith("import "):
                        dangerous_lines.append((lineno, stripped))
                    # Also flag exec/eval/os/subprocess
                    for pat, desc in SETUP_PY_DANGEROUS_PATTERNS[:6]:
                        if pat.search(stripped):
                            dangerous_lines.append((lineno, f"{desc}: {stripped[:100]}"))
                            break

                if dangerous_lines:
                    evidence_text = "; ".join(
                        f"L{ln}: {txt[:80]}" for ln, txt in dangerous_lines[:5]
                    )
                    severity = SEVERITY_CRITICAL if any(
                        "import " in txt for _, txt in dangerous_lines
                    ) else SEVERITY_HIGH

                    await self._emit_threat(ThreatEvent(
                        severity=severity,
                        package=pth_file.stem,
                        description=(
                            f".pth file executes code on Python startup: "
                            f"{pth_file.name} ({len(dangerous_lines)} dangerous lines)"
                        ),
                        evidence=evidence_text,
                        category="supply_chain.pth_injection",
                    ))

    # ------------------------------------------------------------------
    # Scan: __init__.py files with network/system calls
    # ------------------------------------------------------------------

    async def _scan_init_files(self) -> None:
        """Scan __init__.py in site-packages for network calls and dangerous imports."""
        site_dirs = self._get_site_packages_dirs()

        for sp_dir in site_dirs:
            sp_path = Path(sp_dir)
            if not sp_path.exists():
                continue

            try:
                pkg_dirs = [d for d in sp_path.iterdir()
                            if d.is_dir() and not d.name.startswith(("_", "."))]
            except PermissionError:
                continue

            for pkg_dir in pkg_dirs:
                pkg_name = pkg_dir.name.lower().replace("-", "_")
                if pkg_name in INIT_IMPORT_WHITELIST:
                    continue
                if pkg_name in self._scanned_packages:
                    continue

                init_file = pkg_dir / "__init__.py"
                if not init_file.exists():
                    continue

                self._scanned_packages.add(pkg_name)

                try:
                    content = init_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                # Skip large files (likely legitimate)
                if len(content) > 500_000:
                    continue

                # Check for network patterns
                network_hits = []
                for pat, desc in INIT_PY_NETWORK_PATTERNS:
                    matches = pat.findall(content)
                    if matches:
                        network_hits.append(desc)

                # Only alert if there's both an import AND a call
                has_net_import = any("import" in h for h in network_hits)
                has_net_call = any(
                    kw in h for h in network_hits
                    for kw in ("connect", "send", "urlopen")
                )
                if has_net_import and has_net_call:
                    await self._emit_threat(ThreatEvent(
                        severity=SEVERITY_HIGH,
                        package=pkg_name,
                        description=(
                            f"__init__.py makes network calls: "
                            f"{', '.join(network_hits[:5])}"
                        ),
                        evidence=f"File: {init_file}",
                        category="supply_chain.init_network",
                    ))

                # Check for dangerous imports (os, subprocess, ctypes)
                danger_hits = []
                for pat, desc in INIT_PY_DANGEROUS_IMPORTS:
                    if pat.search(content):
                        danger_hits.append(desc)

                if danger_hits and pkg_name not in INIT_IMPORT_WHITELIST:
                    # Only flag if combined with suspicious patterns
                    suspicious_extra = []
                    for pat, desc in SETUP_PY_DANGEROUS_PATTERNS:
                        if pat.search(content):
                            suspicious_extra.append(desc)

                    if suspicious_extra:
                        await self._emit_threat(ThreatEvent(
                            severity=SEVERITY_MEDIUM,
                            package=pkg_name,
                            description=(
                                f"__init__.py has dangerous imports + suspicious patterns: "
                                f"{', '.join(danger_hits)} | {', '.join(suspicious_extra[:3])}"
                            ),
                            evidence=f"File: {init_file}",
                            category="supply_chain.init_danger",
                        ))

    # ------------------------------------------------------------------
    # Scan: setup.py files
    # ------------------------------------------------------------------

    async def _scan_setup_py_files(self) -> None:
        """Find and analyze setup.py files in site-packages for install-time code exec."""
        site_dirs = self._get_site_packages_dirs()

        for sp_dir in site_dirs:
            sp_path = Path(sp_dir)
            if not sp_path.exists():
                continue

            # Also check egg-info dirs for setup.py
            try:
                candidates = list(sp_path.glob("*/setup.py"))
                candidates += list(sp_path.glob("*.egg-info/setup.py"))
            except PermissionError:
                continue

            for setup_file in candidates:
                setup_str = str(setup_file)
                try:
                    content = setup_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                if len(content) > 200_000:
                    continue

                hits = []
                for pat, desc in SETUP_PY_DANGEROUS_PATTERNS:
                    if pat.search(content):
                        hits.append(desc)

                if hits:
                    pkg_name = setup_file.parent.name.split(".egg")[0].lower()
                    await self._emit_threat(ThreatEvent(
                        severity=SEVERITY_HIGH if len(hits) >= 2 else SEVERITY_MEDIUM,
                        package=pkg_name,
                        description=(
                            f"setup.py contains dangerous patterns: "
                            f"{', '.join(hits[:5])}"
                        ),
                        evidence=f"File: {setup_file} | {len(hits)} patterns matched",
                        category="supply_chain.setup_py",
                    ))

    # ------------------------------------------------------------------
    # Scan: dependency tree analysis
    # ------------------------------------------------------------------

    async def _scan_dependency_trees(self) -> None:
        """Parse requirements/config files and flag transitive dependency risks."""
        for root in self.project_roots:
            root_path = Path(root).resolve()
            if not root_path.exists():
                continue

            # requirements.txt
            for req_file in root_path.glob("requirements*.txt"):
                await self._analyze_requirements_txt(req_file)

            # pyproject.toml
            pyproject = root_path / "pyproject.toml"
            if pyproject.exists():
                await self._analyze_pyproject_toml(pyproject)

            # package.json
            if self.scan_npm:
                pkg_json = root_path / "package.json"
                if pkg_json.exists():
                    await self._analyze_package_json(pkg_json)

    async def _analyze_requirements_txt(self, filepath: Path) -> None:
        """Analyze a requirements.txt for compromised/suspicious deps."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Extract package name
            pkg_name = re.split(r"[>=<!\[\];@\s]", line)[0].lower()
            if not pkg_name:
                continue

            # Check compromised
            if pkg_name in self.compromised_db:
                entry = self.compromised_db[pkg_name]
                await self._emit_threat(ThreatEvent(
                    severity=entry.get("severity", SEVERITY_HIGH),
                    package=pkg_name,
                    description=(
                        f"Compromised package in {filepath.name}: "
                        f"{entry.get('reason', 'Known malicious')}"
                    ),
                    evidence=f"File: {filepath} | Line: {line}",
                    category="supply_chain.dependency",
                ))

            # Check typosquat
            typo = self._check_typosquat(pkg_name)
            if typo:
                await self._emit_threat(ThreatEvent(
                    severity=SEVERITY_MEDIUM,
                    package=pkg_name,
                    description=(
                        f"Possible typosquat in {filepath.name}: "
                        f"'{pkg_name}' similar to '{typo}'"
                    ),
                    evidence=f"Levenshtein distance <= {self.typosquat_threshold}",
                    category="supply_chain.typosquat",
                ))

    async def _analyze_pyproject_toml(self, filepath: Path) -> None:
        """Analyze pyproject.toml for dependency issues."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        # Simple TOML parsing for dependencies (no external dep required)
        dep_pattern = re.compile(r'"([a-zA-Z0-9_-]+)')
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if "dependencies" in stripped and "=" in stripped:
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("[") and "dependencies" not in stripped:
                    in_deps = False
                    continue
                match = dep_pattern.search(stripped)
                if match:
                    pkg_name = match.group(1).lower()
                    if pkg_name in self.compromised_db:
                        entry = self.compromised_db[pkg_name]
                        await self._emit_threat(ThreatEvent(
                            severity=entry.get("severity", SEVERITY_HIGH),
                            package=pkg_name,
                            description=(
                                f"Compromised package in pyproject.toml: "
                                f"{entry.get('reason', 'Known malicious')}"
                            ),
                            evidence=f"File: {filepath}",
                            category="supply_chain.dependency",
                        ))

    async def _analyze_package_json(self, filepath: Path) -> None:
        """Analyze package.json for compromised deps and transitive risk."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception as exc:
            self.logger.debug("Failed to parse %s: %s", filepath, exc)
            return

        all_deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies",
                     "optionalDependencies"):
            all_deps.update(data.get(key, {}))

        for pkg_name, version_spec in all_deps.items():
            pkg_lower = pkg_name.lower()
            if pkg_lower in self.compromised_db:
                entry = self.compromised_db[pkg_lower]
                await self._emit_threat(ThreatEvent(
                    severity=entry.get("severity", SEVERITY_HIGH),
                    package=pkg_lower,
                    description=(
                        f"Compromised npm package in package.json: "
                        f"{entry.get('reason', 'Known malicious')}"
                    ),
                    evidence=f"File: {filepath} | {pkg_name}: {version_spec}",
                    category="supply_chain.npm_dependency",
                ))

        # Transitive dependency warning (devDependencies are higher risk)
        dev_deps = data.get("devDependencies", {})
        if len(dev_deps) > 50:
            await self._emit_threat(ThreatEvent(
                severity=SEVERITY_LOW,
                package="(project)",
                description=(
                    f"Large devDependencies surface ({len(dev_deps)} packages) "
                    f"increases transitive dependency attack risk"
                ),
                evidence=f"File: {filepath}",
                category="supply_chain.transitive_risk",
            ))

    # ------------------------------------------------------------------
    # Typosquatting detection
    # ------------------------------------------------------------------

    def _check_typosquat(self, pkg_name: str) -> Optional[str]:
        """
        Check if a package name is suspiciously close to a popular package.
        Returns the popular package name if match found, else None.
        """
        if pkg_name in POPULAR_PACKAGES:
            return None  # It IS the popular package

        # Normalize: replace - and _ (pip considers them equivalent)
        normalized = pkg_name.replace("-", "").replace("_", "")

        # Check whitelist of known safe pairs
        def _is_safe_pair(name, popular):
            return frozenset({name, popular}) in SAFE_TYPOSQUAT_PAIRS

        for popular in POPULAR_PACKAGES:
            pop_normalized = popular.replace("-", "").replace("_", "")

            if normalized == pop_normalized:
                continue  # Same normalized name = pip equivalent, not a typosquat

            # Skip if the names are too different in length
            if abs(len(normalized) - len(pop_normalized)) > self.typosquat_threshold:
                continue

            dist = _levenshtein(normalized, pop_normalized)
            if 0 < dist <= self.typosquat_threshold:
                if _is_safe_pair(pkg_name, popular):
                    continue  # Known safe pair, skip
                return popular

        return None

    async def _detect_typosquatting(self) -> None:
        """Scan all installed packages for typosquatting."""
        installed = await self._get_installed_pip_packages()

        for pkg_name in installed:
            match = self._check_typosquat(pkg_name)
            if match:
                await self._emit_threat(ThreatEvent(
                    severity=SEVERITY_MEDIUM,
                    package=pkg_name,
                    description=(
                        f"Installed package '{pkg_name}' looks like typosquat "
                        f"of popular package '{match}'"
                    ),
                    evidence=(
                        f"Levenshtein distance <= {self.typosquat_threshold} "
                        f"from '{match}'"
                    ),
                    category="supply_chain.typosquat",
                ))

    # ------------------------------------------------------------------
    # npm monitoring
    # ------------------------------------------------------------------

    async def _scan_npm_packages(self) -> None:
        """Check node_modules for packages with suspicious install scripts."""
        for root in self.project_roots:
            nm_path = Path(root).resolve() / "node_modules"
            if not nm_path.exists():
                continue

            try:
                pkg_dirs = [d for d in nm_path.iterdir() if d.is_dir()]
            except PermissionError:
                continue

            for pkg_dir in pkg_dirs:
                # Handle scoped packages (@org/pkg)
                if pkg_dir.name.startswith("@"):
                    try:
                        scoped = [d for d in pkg_dir.iterdir() if d.is_dir()]
                    except PermissionError:
                        continue
                    for spkg in scoped:
                        await self._check_npm_package(spkg)
                else:
                    await self._check_npm_package(pkg_dir)

    async def _check_npm_package(self, pkg_dir: Path) -> None:
        """Analyze a single npm package for malicious install scripts."""
        pkg_json = pkg_dir / "package.json"
        if not pkg_json.exists():
            return

        try:
            content = pkg_json.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception:
            return

        pkg_name = data.get("name", pkg_dir.name).lower()
        scripts = data.get("scripts", {})

        # Check for install hooks
        install_hooks = {}
        for hook in ("preinstall", "postinstall", "install", "prepare"):
            if hook in scripts:
                install_hooks[hook] = scripts[hook]

        if not install_hooks:
            return

        # Analyze hook content for suspicious patterns
        suspicious = []
        for hook_name, cmd in install_hooks.items():
            cmd_lower = cmd.lower()

            # Network calls in install scripts
            net_patterns = [
                "curl ", "wget ", "fetch(", "http://", "https://",
                "net.request", "require('http", "require(\"http",
                "node -e", "node -p",
            ]
            for pat in net_patterns:
                if pat in cmd_lower:
                    suspicious.append(f"{hook_name}: network call ({pat.strip()})")
                    break

            # Shell execution
            shell_patterns = [
                "bash -c", "sh -c", "/bin/sh", "/bin/bash",
                "powershell", "cmd /c", "cmd.exe",
            ]
            for pat in shell_patterns:
                if pat in cmd_lower:
                    suspicious.append(f"{hook_name}: shell execution ({pat})")
                    break

            # Environment variable exfiltration
            if ("process.env" in cmd or "$(" in cmd or "env " in cmd_lower):
                suspicious.append(f"{hook_name}: accesses environment variables")

        if suspicious:
            # Check if this is a known compromised package too
            severity = SEVERITY_MEDIUM
            if pkg_name in self.compromised_db:
                severity = SEVERITY_CRITICAL
            elif any("network" in s for s in suspicious):
                severity = SEVERITY_HIGH

            await self._emit_threat(ThreatEvent(
                severity=severity,
                package=pkg_name,
                description=(
                    f"npm package has suspicious install scripts: "
                    f"{', '.join(suspicious[:4])}"
                ),
                evidence=(
                    f"Scripts: {json.dumps(install_hooks, indent=None)[:300]}"
                ),
                category="supply_chain.npm_install_script",
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_site_packages_dirs() -> List[str]:
        """Get all site-packages directories for the current Python."""
        dirs = []
        # site.getsitepackages() may not exist in virtualenvs
        try:
            dirs.extend(site.getsitepackages())
        except AttributeError:
            pass
        # User site-packages
        user_sp = site.getusersitepackages()
        if isinstance(user_sp, str):
            dirs.append(user_sp)
        elif isinstance(user_sp, list):
            dirs.extend(user_sp)
        # Also check sys.path for anything that looks like site-packages
        for p in sys.path:
            if "site-packages" in p and p not in dirs:
                dirs.append(p)
        return dirs

    def get_threat_summary(self) -> Dict[str, Any]:
        """Return a summary of all detected threats."""
        by_severity = {
            SEVERITY_CRITICAL: [],
            SEVERITY_HIGH: [],
            SEVERITY_MEDIUM: [],
            SEVERITY_LOW: [],
        }
        for t in self.threats:
            by_severity.get(t.severity, by_severity[SEVERITY_LOW]).append(t.to_dict())

        return {
            "total": len(self.threats),
            "critical": len(by_severity[SEVERITY_CRITICAL]),
            "high": len(by_severity[SEVERITY_HIGH]),
            "medium": len(by_severity[SEVERITY_MEDIUM]),
            "low": len(by_severity[SEVERITY_LOW]),
            "threats": by_severity,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    async def scan_now(self) -> Dict[str, Any]:
        """Run a one-shot scan and return results (for manual/API use)."""
        self.logger.info("Manual scan triggered")
        scan_coros = [
            self._scan_known_compromised(),
            self._scan_pth_files(),
            self._scan_init_files(),
            self._scan_setup_py_files(),
            self._scan_dependency_trees(),
            self._detect_typosquatting(),
        ]
        if self.scan_npm:
            scan_coros.append(self._scan_npm_packages())

        await asyncio.gather(*scan_coros, return_exceptions=True)
        return self.get_threat_summary()
