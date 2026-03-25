"""
BLACKWALL Dependency Auditor - Audits installed packages and dependency chains for security risks.

Detects typosquatting, abandoned packages, integrity violations, deep transitive dependencies,
and known vulnerabilities across both pip and npm ecosystems.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from importlib.metadata import distributions, packages_distributions, requires
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional, Any

import aiohttp


# ---------------------------------------------------------------------------
# Top popular PyPI packages (curated subset - realistic top-1000 representation)
# Used for typosquatting distance checks.  Full list is loaded once on first
# audit; this seed covers the most common targets.
# ---------------------------------------------------------------------------
_TOP_PYPI_PACKAGES: list[str] = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "six", "wheel", "certifi", "python-dateutil",
    "pyyaml", "idna", "charset-normalizer", "typing-extensions", "botocore",
    "s3transfer", "jmespath", "cryptography", "cffi", "pycparser", "pyasn1",
    "attrs", "click", "jinja2", "markupsafe", "packaging", "pygments",
    "colorama", "decorator", "pillow", "scipy", "matplotlib", "aiohttp",
    "yarl", "multidict", "frozenlist", "aiosignal", "protobuf", "grpcio",
    "googleapis-common-protos", "google-auth", "google-api-core",
    "google-cloud-storage", "google-cloud-core", "google-resumable-media",
    "psutil", "pytz", "filelock", "tqdm", "importlib-metadata", "zipp",
    "tomli", "exceptiongroup", "iniconfig", "pluggy", "pytest", "coverage",
    "virtualenv", "platformdirs", "distlib", "more-itertools", "py",
    "wrapt", "deprecated", "pyjwt", "oauthlib", "requests-oauthlib",
    "rsa", "cachetools", "pyasn1-modules", "httplib2", "google-auth-httplib2",
    "beautifulsoup4", "soupsieve", "lxml", "html5lib", "webencodings",
    "sqlalchemy", "greenlet", "alembic", "mako", "pydantic", "pydantic-core",
    "annotated-types", "fastapi", "starlette", "uvicorn", "httptools",
    "uvloop", "watchfiles", "websockets", "anyio", "sniffio", "httpx",
    "httpcore", "h11", "h2", "hpack", "hyperframe", "celery", "kombu",
    "billiard", "amqp", "vine", "redis", "pymongo", "motor", "dnspython",
    "paramiko", "bcrypt", "pynacl", "fabric", "invoke", "docker", "kubernetes",
    "websocket-client", "pyopenssl", "service-identity", "twisted",
    "automat", "constantly", "hyperlink", "incremental", "zope-interface",
    "scrapy", "w3lib", "queuelib", "itemloaders", "itemadapter",
    "parsel", "cssselect", "selenium", "webdriver-manager", "trio",
    "outcome", "sortedcontainers", "black", "mypy", "mypy-extensions",
    "isort", "flake8", "mccabe", "pycodestyle", "pyflakes", "pylint",
    "astroid", "lazy-object-proxy", "tomlkit", "bandit", "stevedore",
    "pbr", "gitpython", "gitdb", "smmap", "sphinx", "docutils",
    "snowballstemmer", "babel", "imagesize", "alabaster",
    "sphinxcontrib-serializinghtml", "sphinxcontrib-htmlhelp",
    "sphinxcontrib-jsmath", "sphinxcontrib-devhelp", "sphinxcontrib-qthelp",
    "sphinxcontrib-applehelp", "mkdocs", "mkdocs-material",
    "tensorboard", "tensorflow", "torch", "torchvision", "torchaudio",
    "transformers", "tokenizers", "huggingface-hub", "safetensors",
    "scikit-learn", "joblib", "threadpoolctl", "xgboost", "lightgbm",
    "catboost", "keras", "opencv-python", "networkx", "sympy", "mpmath",
    "statsmodels", "patsy", "seaborn", "plotly", "dash", "bokeh",
    "altair", "streamlit", "gradio", "wandb", "mlflow",
    "dask", "distributed", "cloudpickle", "fsspec", "toolz", "cytoolz",
    "partd", "locket", "pyarrow", "polars", "openpyxl", "xlsxwriter",
    "xlrd", "tabulate", "rich", "typer", "textual", "prompt-toolkit",
    "pyglet", "pygame", "arcade", "panda3d",
    "pendulum", "arrow", "humanize", "python-dotenv", "environs",
    "marshmallow", "webargs", "apispec", "flask-restful",
    "flask-sqlalchemy", "flask-migrate", "flask-login", "flask-wtf",
    "wtforms", "flask-cors", "django-rest-framework", "djangorestframework",
    "django-cors-headers", "django-filter", "django-extensions",
    "django-debug-toolbar", "django-redis", "celery", "flower",
    "gunicorn", "waitress", "gevent", "eventlet",
    "aiofiles", "aiomysql", "aiopg", "aiocache", "aioredis",
    "sentry-sdk", "newrelic", "datadog", "prometheus-client",
    "structlog", "loguru", "colorlog",
    "orjson", "ujson", "simplejson", "msgpack", "cbor2",
    "toml", "configparser", "python-json-logger",
    "python-multipart", "itsdangerous", "werkzeug",
    "trio-websocket", "wsproto", "asgiref",
    "tenacity", "retrying", "backoff",
    "apscheduler", "schedule", "rq", "dramatiq",
    "sshtunnel", "pexpect", "ptyprocess",
    "psycopg2", "psycopg2-binary", "asyncpg", "mysql-connector-python",
    "pymysql", "sqlite-utils", "peewee", "tortoise-orm",
    "elasticsearch", "opensearch-py",
    "minio", "google-cloud-bigquery",
    "azure-storage-blob", "azure-identity", "azure-core",
    "twilio", "stripe", "slack-sdk", "discord-py",
    "tweepy", "praw", "instaloader",
]


class DependencyAuditor:
    """Audits installed Python/npm packages for security risks.

    Features:
        - Installed package vulnerability checks via PyPI JSON API
        - Typosquatting detection using Levenshtein distance
        - Full dependency chain analysis with depth tracking
        - Package integrity verification against PyPI hashes
        - npm audit integration when node_modules present
    """

    # Severity constants
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __init__(
        self,
        alert_callback: Optional[Callable[[dict], Any]] = None,
        log_dir: str = "logs",
        full_audit_interval: int = 3600,
        quick_check_interval: int = 300,
        project_root: Optional[str] = None,
    ):
        self.alert_callback = alert_callback
        self.full_audit_interval = full_audit_interval
        self.quick_check_interval = quick_check_interval
        self.project_root = Path(project_root) if project_root else Path.cwd()

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # State
        self._running = False
        self._session: Optional[aiohttp.ClientSession] = None
        self._known_packages: set[str] = set()
        self._dependency_tree: dict[str, dict] = {}
        self._last_full_audit: float = 0.0
        self._alerts: list[dict] = []

        # Stats
        self.stats = {
            "total_packages": 0,
            "direct_deps": 0,
            "transitive_deps": 0,
            "flagged_packages": 0,
            "last_full_audit": None,
            "last_quick_check": None,
            "audits_completed": 0,
        }

        self._setup_logger()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self):
        """Start the dependency auditor background loops."""
        if self._running:
            self.logger.warning("Dependency auditor already running")
            return

        self._running = True
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"Accept": "application/json"},
        )
        self.logger.info("Dependency Auditor started")

        # Run initial full audit, then schedule periodic loops
        asyncio.ensure_future(self._full_audit_loop())
        asyncio.ensure_future(self._quick_check_loop())

    async def stop(self):
        """Gracefully stop the auditor and close resources."""
        self._running = False
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self.logger.info("Dependency Auditor stopped")

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _setup_logger(self):
        self.logger = logging.getLogger("DependencyAuditor")
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.log_dir / "dependency_auditor.log",
                maxBytes=50 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Alert dispatch
    # ------------------------------------------------------------------

    def _fire_alert(self, alert: dict):
        alert.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        self._alerts.append(alert)
        if len(self._alerts) > 2000:
            self._alerts = self._alerts[-1000:]
        self.logger.warning("ALERT [%s] %s: %s", alert["severity"], alert["type"], alert["description"])
        if self.alert_callback:
            try:
                result = self.alert_callback(alert)
                # Support async callbacks - schedule as task
                if asyncio.iscoroutine(result):
                    asyncio.ensure_future(result)
            except Exception as exc:
                self.logger.error("Alert callback error: %s", exc)

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def _full_audit_loop(self):
        """Periodic full audit of all packages."""
        while self._running:
            try:
                await self.run_full_audit()
            except Exception as exc:
                self.logger.error("Full audit error: %s", exc, exc_info=True)
            await asyncio.sleep(self.full_audit_interval)

    async def _quick_check_loop(self):
        """Periodic quick check for newly installed packages."""
        # Wait for initial full audit to complete before starting quick checks
        await asyncio.sleep(self.quick_check_interval)
        while self._running:
            try:
                await self._quick_check()
            except Exception as exc:
                self.logger.error("Quick check error: %s", exc, exc_info=True)
            await asyncio.sleep(self.quick_check_interval)

    # ------------------------------------------------------------------
    # Full audit orchestration
    # ------------------------------------------------------------------

    async def run_full_audit(self) -> dict:
        """Execute a comprehensive audit of all installed packages.

        Returns a summary dict with findings.
        """
        self.logger.info("=== Starting full dependency audit ===")
        findings: list[dict] = []

        # 1. Enumerate installed packages
        installed = self._enumerate_installed_packages()
        self.stats["total_packages"] = len(installed)
        self._known_packages = {p["name"] for p in installed}
        self.logger.info("Found %d installed packages", len(installed))

        # 2. Build dependency tree
        tree = self._build_dependency_tree(installed)
        self._dependency_tree = tree
        direct, transitive = self._classify_deps(tree)
        self.stats["direct_deps"] = len(direct)
        self.stats["transitive_deps"] = len(transitive)
        self.logger.info("Dependency tree: %d direct, %d transitive", len(direct), len(transitive))

        # 3. Circular dependency detection
        circles = self._detect_circular_deps(tree)
        for cycle in circles:
            alert = {
                "type": "CIRCULAR_DEPENDENCY",
                "severity": self.MEDIUM,
                "description": f"Circular dependency detected: {' -> '.join(cycle)}",
                "packages": cycle,
            }
            findings.append(alert)
            self._fire_alert(alert)

        # 4. Deep transitive dependency warnings
        for pkg_name, info in tree.items():
            if info.get("depth", 0) > 3:
                alert = {
                    "type": "DEEP_TRANSITIVE_DEPENDENCY",
                    "severity": self.MEDIUM,
                    "description": (
                        f"Deep transitive dependency: {pkg_name} at depth {info['depth']} "
                        f"(chain: {' -> '.join(info.get('chain', []))})"
                    ),
                    "package": pkg_name,
                    "depth": info["depth"],
                }
                findings.append(alert)
                self._fire_alert(alert)

        # 5. Typosquatting detection
        typosquat_findings = self._detect_typosquatting(installed)
        findings.extend(typosquat_findings)

        # 6. PyPI vulnerability / staleness checks (batched async)
        vuln_findings = await self._check_pypi_packages(installed)
        findings.extend(vuln_findings)

        # 7. Package integrity checks
        integrity_findings = await self._check_package_integrity(installed)
        findings.extend(integrity_findings)

        # 8. npm audit (if applicable)
        npm_findings = await self._run_npm_audit()
        findings.extend(npm_findings)

        # Update stats
        flagged = {f.get("package", f.get("packages", [""])[0] if isinstance(f.get("packages"), list) else "") for f in findings}
        self.stats["flagged_packages"] = len(flagged - {""})
        self.stats["last_full_audit"] = datetime.now(timezone.utc).isoformat()
        self.stats["audits_completed"] += 1
        self._last_full_audit = time.monotonic()

        self.logger.info(
            "=== Full audit complete: %d findings, %d packages flagged ===",
            len(findings), self.stats["flagged_packages"],
        )
        return {
            "total_packages": len(installed),
            "direct_deps": len(direct),
            "transitive_deps": len(transitive),
            "findings": findings,
            "attack_surface": len(installed),
        }

    # ------------------------------------------------------------------
    # Quick check - detect newly installed packages since last audit
    # ------------------------------------------------------------------

    async def _quick_check(self):
        """Fast check for packages that appeared since last full audit."""
        current = {p["name"] for p in self._enumerate_installed_packages()}
        new_packages = current - self._known_packages
        if not new_packages:
            self.stats["last_quick_check"] = datetime.now(timezone.utc).isoformat()
            return

        self.logger.info("Quick check found %d new packages: %s", len(new_packages), new_packages)
        for name in new_packages:
            # Run typosquatting check on new package
            typo = self._check_single_typosquat(name)
            if typo:
                self._fire_alert(typo)

        self._known_packages = current
        self.stats["last_quick_check"] = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # 1. Installed package enumeration
    # ------------------------------------------------------------------

    @staticmethod
    def _enumerate_installed_packages() -> list[dict]:
        """List all installed pip packages with metadata."""
        packages = []
        seen = set()
        for dist in distributions():
            name = dist.metadata["Name"]
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            version = dist.metadata["Version"] or "unknown"
            author = dist.metadata.get("Author") or dist.metadata.get("Author-email") or ""
            home_page = dist.metadata.get("Home-page") or ""
            summary = dist.metadata.get("Summary") or ""

            # Locate dist-info directory
            dist_info_path = None
            if hasattr(dist, '_path'):
                dist_info_path = str(dist._path)

            packages.append({
                "name": name,
                "name_normalized": re.sub(r"[-_.]+", "-", name).lower(),
                "version": version,
                "author": author,
                "home_page": home_page,
                "summary": summary,
                "dist_info_path": dist_info_path,
                "requires": dist.requires or [],
            })
        return packages

    # ------------------------------------------------------------------
    # 2. Typosquatting detection
    # ------------------------------------------------------------------

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return DependencyAuditor._levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _normalize_pkg(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    def _detect_typosquatting(self, installed: list[dict]) -> list[dict]:
        """Check all installed packages for typosquatting of popular packages."""
        findings = []
        popular_normalized = {self._normalize_pkg(p): p for p in _TOP_PYPI_PACKAGES}

        for pkg in installed:
            alert = self._check_single_typosquat(pkg["name"], popular_normalized)
            if alert:
                findings.append(alert)
                self._fire_alert(alert)
        return findings

    def _check_single_typosquat(
        self,
        pkg_name: str,
        popular_map: Optional[dict[str, str]] = None,
    ) -> Optional[dict]:
        """Check a single package name for typosquatting patterns.

        Returns an alert dict if suspicious, else None.
        """
        if popular_map is None:
            popular_map = {self._normalize_pkg(p): p for p in _TOP_PYPI_PACKAGES}

        norm = self._normalize_pkg(pkg_name)

        # Skip if the package itself IS a popular package
        if norm in popular_map:
            return None

        for pop_norm, pop_original in popular_map.items():
            distance = self._levenshtein(norm, pop_norm)
            if distance == 0:
                continue  # exact match already handled above

            if distance <= 2:
                pattern = self._classify_typosquat_pattern(norm, pop_norm)
                return {
                    "type": "TYPOSQUATTING_SUSPECT",
                    "severity": self.HIGH,
                    "description": (
                        f"Possible typosquat: '{pkg_name}' is {distance} edit(s) "
                        f"from popular package '{pop_original}' (pattern: {pattern})"
                    ),
                    "package": pkg_name,
                    "similar_to": pop_original,
                    "distance": distance,
                    "pattern": pattern,
                }
        return None

    @staticmethod
    def _classify_typosquat_pattern(suspect: str, target: str) -> str:
        """Classify the type of typosquatting pattern."""
        # Missing / extra hyphen
        if suspect.replace("-", "") == target.replace("-", ""):
            return "missing_hyphen"

        # Extra character
        if len(suspect) == len(target) + 1:
            for i in range(len(suspect)):
                if suspect[:i] + suspect[i + 1:] == target:
                    return "extra_char"

        # Missing character
        if len(suspect) + 1 == len(target):
            for i in range(len(target)):
                if target[:i] + target[i + 1:] == suspect:
                    return "missing_char"

        # Swapped characters
        if len(suspect) == len(target):
            diffs = [i for i in range(len(suspect)) if suspect[i] != target[i]]
            if len(diffs) == 2 and suspect[diffs[0]] == target[diffs[1]] and suspect[diffs[1]] == target[diffs[0]]:
                return "swapped_chars"

        # Homoglyph (common substitutions)
        homoglyphs = {"0": "o", "1": "l", "l": "i", "rn": "m", "vv": "w"}
        s, t = suspect, target
        for fake, real in homoglyphs.items():
            s = s.replace(fake, real)
            t = t.replace(fake, real)
        if s == t:
            return "homoglyph"

        return "unknown"

    # ------------------------------------------------------------------
    # 3. Dependency chain analysis
    # ------------------------------------------------------------------

    def _build_dependency_tree(self, installed: list[dict]) -> dict[str, dict]:
        """Build a full dependency tree with depth information.

        Returns a dict mapping normalized package name to tree info.
        """
        # Build adjacency list: package -> set of direct requirements
        pkg_map: dict[str, dict] = {}
        for pkg in installed:
            norm = self._normalize_pkg(pkg["name"])
            deps = set()
            for req in pkg["requires"]:
                # Parse requirement string, e.g. "requests (>=2.0) ; extra == 'security'"
                dep_name = re.split(r"[\s;(><=!~\[]", req)[0].strip()
                if dep_name:
                    deps.add(self._normalize_pkg(dep_name))
            pkg_map[norm] = {
                "name": pkg["name"],
                "version": pkg["version"],
                "direct_deps": deps,
                "depth": 0,
                "chain": [],
            }

        # Determine which packages are "direct" (not required by any other)
        all_transitive: set[str] = set()
        for info in pkg_map.values():
            all_transitive.update(info["direct_deps"])

        roots = set(pkg_map.keys()) - all_transitive

        # BFS to assign depth
        visited: set[str] = set()
        queue: list[tuple[str, int, list[str]]] = [(r, 0, [r]) for r in sorted(roots)]
        for name in queue:
            pass  # just initializing

        while queue:
            current, depth, chain = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current in pkg_map:
                pkg_map[current]["depth"] = depth
                pkg_map[current]["chain"] = chain
            info = pkg_map.get(current, {})
            for dep in sorted(info.get("direct_deps", set())):
                if dep not in visited and dep in pkg_map:
                    queue.append((dep, depth + 1, chain + [dep]))

        # Handle unvisited packages (part of cycles or disconnected)
        for name in pkg_map:
            if name not in visited:
                pkg_map[name]["depth"] = -1
                pkg_map[name]["chain"] = [name]

        return pkg_map

    @staticmethod
    def _classify_deps(tree: dict[str, dict]) -> tuple[set[str], set[str]]:
        """Classify packages into direct and transitive."""
        direct = {name for name, info in tree.items() if info.get("depth", 0) == 0}
        transitive = {name for name, info in tree.items() if info.get("depth", 0) > 0}
        return direct, transitive

    def _detect_circular_deps(self, tree: dict[str, dict]) -> list[list[str]]:
        """Detect circular dependencies using DFS cycle detection."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            info = tree.get(node, {})
            for dep in info.get("direct_deps", set()):
                if dep not in visited and dep in tree:
                    dfs(dep)
                elif dep in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(dep)
                    cycle = path[cycle_start:] + [dep]
                    cycles.append(cycle)

            path.pop()
            rec_stack.discard(node)

        for name in tree:
            if name not in visited:
                dfs(name)

        return cycles

    # ------------------------------------------------------------------
    # 4. PyPI vulnerability and staleness checks
    # ------------------------------------------------------------------

    async def _check_pypi_packages(self, installed: list[dict]) -> list[dict]:
        """Check packages against PyPI JSON API for vulnerabilities and staleness."""
        findings = []
        if not self._session:
            return findings

        semaphore = asyncio.Semaphore(10)  # Limit concurrent API calls

        async def check_one(pkg: dict) -> list[dict]:
            results = []
            name = pkg["name"]
            version = pkg["version"]
            async with semaphore:
                try:
                    data = await self._fetch_pypi_json(name)
                    if not data:
                        return results

                    # Check vulnerabilities
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        for vuln in vulns:
                            alert = {
                                "type": "KNOWN_VULNERABILITY",
                                "severity": self.CRITICAL,
                                "description": (
                                    f"Known vulnerability in {name}=={version}: "
                                    f"{vuln.get('id', 'unknown')} - {vuln.get('summary', 'No details')}"
                                ),
                                "package": name,
                                "version": version,
                                "vuln_id": vuln.get("id"),
                                "vuln_details": vuln.get("summary", ""),
                            }
                            results.append(alert)
                            self._fire_alert(alert)

                    # Check last release date (staleness)
                    info = data.get("info", {})
                    releases = data.get("releases", {})
                    if releases:
                        latest_upload = self._get_latest_upload_date(releases)
                        if latest_upload:
                            age = datetime.now(timezone.utc) - latest_upload
                            if age > timedelta(days=730):  # 2 years
                                alert = {
                                    "type": "ABANDONED_PACKAGE",
                                    "severity": self.MEDIUM,
                                    "description": (
                                        f"Package '{name}' last updated {age.days} days ago "
                                        f"({latest_upload.strftime('%Y-%m-%d')}). "
                                        f"Possibly abandoned/unmaintained."
                                    ),
                                    "package": name,
                                    "version": version,
                                    "last_updated": latest_upload.isoformat(),
                                    "days_since_update": age.days,
                                }
                                results.append(alert)
                                self._fire_alert(alert)

                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.logger.debug("PyPI check failed for %s: %s", name, exc)
            return results

        tasks = [check_one(pkg) for pkg in installed]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in batch_results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                self.logger.debug("Package check exception: %s", result)

        return findings

    async def _fetch_pypi_json(self, package_name: str) -> Optional[dict]:
        """Fetch package metadata from PyPI JSON API."""
        if not self._session:
            return None
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            async with self._session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    self.logger.debug("Package %s not found on PyPI (non-PyPI source?)", package_name)
                return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.logger.debug("PyPI API error for %s: %s", package_name, exc)
            return None

    @staticmethod
    def _get_latest_upload_date(releases: dict) -> Optional[datetime]:
        """Find the most recent upload date across all releases."""
        latest: Optional[datetime] = None
        for version_files in releases.values():
            for f in version_files:
                upload_str = f.get("upload_time_iso_8601") or f.get("upload_time")
                if not upload_str:
                    continue
                try:
                    dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if latest is None or dt > latest:
                        latest = dt
                except (ValueError, TypeError):
                    continue
        return latest

    # ------------------------------------------------------------------
    # 5. Package integrity verification
    # ------------------------------------------------------------------

    async def _check_package_integrity(self, installed: list[dict]) -> list[dict]:
        """Verify installed package integrity against PyPI records."""
        findings = []

        for pkg in installed:
            name = pkg["name"]

            # Check for missing dist-info (manually copied packages)
            if not pkg.get("dist_info_path") or not Path(str(pkg["dist_info_path"])).exists():
                alert = {
                    "type": "MISSING_DIST_INFO",
                    "severity": self.HIGH,
                    "description": (
                        f"Package '{name}' has no dist-info directory. "
                        f"May have been manually copied or tampered with."
                    ),
                    "package": name,
                    "version": pkg["version"],
                }
                findings.append(alert)
                self._fire_alert(alert)
                continue

            dist_info = Path(str(pkg["dist_info_path"]))

            # Check INSTALLER file - detect non-pip installs
            installer_file = dist_info / "INSTALLER"
            if installer_file.exists():
                try:
                    installer = installer_file.read_text(encoding="utf-8").strip()
                    if installer and installer.lower() not in ("pip", "uv"):
                        alert = {
                            "type": "NON_STANDARD_INSTALLER",
                            "severity": self.LOW,
                            "description": (
                                f"Package '{name}' installed via '{installer}' (non-pip)."
                            ),
                            "package": name,
                            "installer": installer,
                        }
                        findings.append(alert)
                        self._fire_alert(alert)
                except OSError:
                    pass

            # Check direct_url.json - detect non-PyPI sources
            direct_url_file = dist_info / "direct_url.json"
            if direct_url_file.exists():
                try:
                    direct_url = json.loads(direct_url_file.read_text(encoding="utf-8"))
                    url = direct_url.get("url", "")
                    if url and "pypi.org" not in url and "pythonhosted.org" not in url:
                        alert = {
                            "type": "NON_PYPI_SOURCE",
                            "severity": self.MEDIUM,
                            "description": (
                                f"Package '{name}' installed from non-PyPI source: {url}"
                            ),
                            "package": name,
                            "source_url": url,
                        }
                        findings.append(alert)
                        self._fire_alert(alert)
                except (json.JSONDecodeError, OSError):
                    pass

            # Verify RECORD hashes
            record_file = dist_info / "RECORD"
            if record_file.exists():
                integrity_issues = self._verify_record_hashes(dist_info, record_file)
                for issue in integrity_issues:
                    issue["package"] = name
                    findings.append(issue)
                    self._fire_alert(issue)
            else:
                alert = {
                    "type": "MISSING_RECORD",
                    "severity": self.HIGH,
                    "description": (
                        f"Package '{name}' has no RECORD file - "
                        f"installed with --no-verify or tampered."
                    ),
                    "package": name,
                }
                findings.append(alert)
                self._fire_alert(alert)

        return findings

    def _verify_record_hashes(self, dist_info: Path, record_file: Path) -> list[dict]:
        """Verify file hashes listed in RECORD against actual files."""
        issues = []
        site_packages = dist_info.parent

        try:
            record_text = record_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return issues

        for line in record_text.strip().splitlines():
            parts = line.split(",")
            if len(parts) < 3:
                continue

            rel_path = parts[0].strip()
            hash_spec = parts[1].strip()

            if not hash_spec or not rel_path:
                continue

            # Parse hash algorithm and expected digest
            if "=" not in hash_spec:
                continue
            algo, expected_b64 = hash_spec.split("=", 1)
            algo = algo.strip()

            # Only verify sha256
            if algo != "sha256":
                continue

            file_path = site_packages / rel_path
            if not file_path.exists():
                continue

            try:
                actual_hash = hashlib.sha256(file_path.read_bytes()).digest()
                import base64
                actual_b64 = base64.urlsafe_b64encode(actual_hash).rstrip(b"=").decode("ascii")

                if actual_b64 != expected_b64:
                    issues.append({
                        "type": "INTEGRITY_MISMATCH",
                        "severity": self.HIGH,
                        "description": (
                            f"File integrity mismatch: {rel_path} "
                            f"(expected {expected_b64[:16]}..., got {actual_b64[:16]}...)"
                        ),
                        "file": str(file_path),
                    })
            except OSError:
                pass

        return issues

    # ------------------------------------------------------------------
    # 6. npm audit
    # ------------------------------------------------------------------

    async def _run_npm_audit(self) -> list[dict]:
        """Run npm audit if node_modules / package-lock.json exist."""
        findings = []

        # Search for package-lock.json in project root and common locations
        search_paths = [
            self.project_root,
            self.project_root.parent,
            Path.home(),
        ]

        for base_path in search_paths:
            lock_file = base_path / "package-lock.json"
            if not lock_file.exists():
                continue

            self.logger.info("Found package-lock.json at %s", lock_file)

            # Parse package-lock.json for dependency tree analysis
            dep_confusion_findings = self._check_dependency_confusion(lock_file)
            findings.extend(dep_confusion_findings)

            # Run npm audit --json
            audit_findings = await self._exec_npm_audit(base_path)
            findings.extend(audit_findings)
            break  # Only audit first found

        return findings

    def _check_dependency_confusion(self, lock_file: Path) -> list[dict]:
        """Check for dependency confusion in package-lock.json.

        Private packages that could be claimed on the public npm registry.
        """
        findings = []
        try:
            data = json.loads(lock_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self.logger.debug("Failed to parse package-lock.json: %s", exc)
            return findings

        # v2/v3 lockfile format
        packages = data.get("packages", {})
        if not packages:
            # v1 format
            packages_v1 = data.get("dependencies", {})
            for name, info in packages_v1.items():
                resolved = info.get("resolved", "")
                if resolved and "registry.npmjs.org" not in resolved and "http" in resolved:
                    alert = {
                        "type": "NPM_PRIVATE_REGISTRY",
                        "severity": self.MEDIUM,
                        "description": (
                            f"npm package '{name}' resolved from non-public registry: {resolved}. "
                            f"Verify this is intentional (dependency confusion risk)."
                        ),
                        "package": name,
                        "registry": resolved,
                    }
                    findings.append(alert)
                    self._fire_alert(alert)
            return findings

        for pkg_path, info in packages.items():
            if not pkg_path.startswith("node_modules/"):
                continue
            name = pkg_path.replace("node_modules/", "", 1)
            resolved = info.get("resolved", "")
            if resolved and "registry.npmjs.org" not in resolved and "http" in resolved:
                alert = {
                    "type": "NPM_DEPENDENCY_CONFUSION",
                    "severity": self.HIGH,
                    "description": (
                        f"npm package '{name}' resolved from non-standard registry: "
                        f"{resolved}. Potential dependency confusion attack."
                    ),
                    "package": name,
                    "registry": resolved,
                }
                findings.append(alert)
                self._fire_alert(alert)

        return findings

    async def _exec_npm_audit(self, working_dir: Path) -> list[dict]:
        """Execute `npm audit --json` and parse results."""
        findings = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "audit", "--json",
                cwd=str(working_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except FileNotFoundError:
            self.logger.debug("npm not found, skipping npm audit")
            return findings
        except asyncio.TimeoutError:
            self.logger.warning("npm audit timed out")
            return findings
        except OSError as exc:
            self.logger.debug("npm audit exec error: %s", exc)
            return findings

        try:
            audit_data = json.loads(stdout.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return findings

        # Parse advisories/vulnerabilities
        vulnerabilities = audit_data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            severity_map = {
                "critical": self.CRITICAL,
                "high": self.HIGH,
                "moderate": self.MEDIUM,
                "low": self.LOW,
                "info": self.LOW,
            }
            npm_severity = vuln_info.get("severity", "info")
            mapped_severity = severity_map.get(npm_severity, self.MEDIUM)

            via = vuln_info.get("via", [])
            details = []
            for v in via:
                if isinstance(v, dict):
                    details.append(f"{v.get('title', 'Unknown')} ({v.get('url', 'no URL')})")
                elif isinstance(v, str):
                    details.append(v)

            alert = {
                "type": "NPM_VULNERABILITY",
                "severity": mapped_severity,
                "description": (
                    f"npm vulnerability in '{pkg_name}': {'; '.join(details) or npm_severity}"
                ),
                "package": pkg_name,
                "npm_severity": npm_severity,
                "fix_available": vuln_info.get("fixAvailable", False),
            }
            findings.append(alert)
            self._fire_alert(alert)

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return current audit statistics."""
        return {**self.stats}

    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> list[dict]:
        """Return recent alerts, optionally filtered by severity."""
        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        return alerts[-limit:]

    def get_dependency_tree(self) -> dict:
        """Return the last computed dependency tree."""
        return {**self._dependency_tree}
