"""
TeamPCP / Trivy / LiteLLM Supply Chain Attack Detector (March 2026).

Dedicated scanner for ALL known indicators of compromise from the TeamPCP
supply chain campaign that hit PyPI (litellm), Docker Hub (aquasec/trivy),
and npm (canisterworm). Checks persistence artifacts, exfil staging,
malicious .pth files, C2 DNS indicators, compromised packages, Kubernetes
pods, and Docker images - fully adapted for Windows.
"""

import ast
import asyncio
import csv
import io
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from logging.handlers import RotatingFileHandler

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ── Known C2 domains ──────────────────────────────────────────────────
C2_DOMAINS = [
    "models.litellm.cloud",
    "checkmarx.zone",
]
C2_DOMAIN_PATTERNS = [
    re.compile(r"[\w\-]+\.litellm\.cloud", re.IGNORECASE),
]

# ── Compromised package versions ──────────────────────────────────────
COMPROMISED_LITELLM = {"1.82.7", "1.82.8"}
COMPROMISED_TRIVY_TAGS = {"0.69.4", "0.69.5", "0.69.6"}

# ── Suspicious keywords inside .pth files ─────────────────────────────
PTH_SUSPICIOUS_KEYWORDS = [
    "subprocess", "os.system", "exec", "eval",
    "base64", "requests", "urllib", "socket",
]

# ── Known exfil staging filenames ─────────────────────────────────────
EXFIL_EXACT_NAMES = {"tpcp.tar.gz", "session.key", "payload.enc", "session.key.enc"}
EXFIL_GLOB_PATTERNS = ["*.tar.gz", "*.enc"]

# ── Large-file threshold for temp archives (bytes) ────────────────────
EXFIL_SIZE_THRESHOLD = 10 * 1024 * 1024  # 10 MB

SUBPROCESS_TIMEOUT = 10


class TeamPCPDetector:
    """Scans for every known indicator of the TeamPCP supply-chain attack."""

    def __init__(self, config: dict = None, log_dir: str = "logs"):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.interval = config.get("check_interval_seconds", 120)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.alert_callbacks = []
        self.alerts = []
        self.findings = []
        self._running = False
        self._last_scan = None

        # Counters
        self._persistence_found = 0
        self._exfil_staging_found = 0
        self._malicious_pth_found = 0
        self._c2_indicators = 0
        self._compromised_packages = 0
        self._k8s_indicators = 0
        self._artifacts_found = 0

        self._setup_logger()

    # ── Logger ────────────────────────────────────────────────────────
    def _setup_logger(self):
        self.logger = logging.getLogger("TeamPCPDetector")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.log_dir / "teampcp_detector.log",
                maxBytes=50 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(handler)

    # ── Alert plumbing ────────────────────────────────────────────────
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

    def _add_finding(self, severity: str, ftype: str, description: str, evidence: str = ""):
        finding = {
            "severity": severity,
            "type": ftype,
            "description": description,
            "evidence": evidence[:500],
        }
        self.findings.append(finding)
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "type": ftype,
            "description": description,
            "evidence": evidence[:500],
        }
        self._fire_alert(alert)
        lvl = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(severity, 20)
        self.logger.log(lvl, "[%s] %s | %s", severity, ftype, description)

    # ── Subprocess helper ─────────────────────────────────────────────
    @staticmethod
    def _run(cmd: list, timeout: int = SUBPROCESS_TIMEOUT) -> str:
        """Run *cmd* and return stdout. Returns '' on any failure."""
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return r.stdout if r.returncode == 0 else ""
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    # ══════════════════════════════════════════════════════════════════
    #  1. Persistence Artifacts
    # ══════════════════════════════════════════════════════════════════
    def _scan_persistence(self):
        home = Path.home()
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))

        # ── sysmon.py persistence scripts ─────────────────────────────
        suspect_paths = [
            home / ".config" / "sysmon" / "sysmon.py",
            appdata / "sysmon" / "sysmon.py",
            home / ".local" / "share" / "sysmon" / "sysmon.py",
            home / ".config" / "autostart" / "sysmon.py",
        ]
        for p in suspect_paths:
            if p.exists():
                self._persistence_found += 1
                self._add_finding(
                    "CRITICAL", "PERSISTENCE_SYSMON_PY",
                    f"TeamPCP persistence script found: {p}",
                    f"File exists at {p} (size {p.stat().st_size} bytes)",
                )

        # ── Scheduled tasks containing fake sysmon ────────────────────
        csv_out = self._run(["schtasks", "/Query", "/FO", "CSV", "/V", "/NH"])
        if csv_out:
            for row in csv.reader(io.StringIO(csv_out)):
                if len(row) < 9:
                    continue
                task_name = row[0].strip().lower()
                task_run = row[8].strip().lower() if len(row) > 8 else ""
                if "sysmon" in task_name and (".py" in task_run or "python" in task_run):
                    self._persistence_found += 1
                    self._add_finding(
                        "CRITICAL", "PERSISTENCE_SCHTASK",
                        f"Scheduled task masquerading as Sysmon runs Python: {row[0]}",
                        f"TaskToRun: {row[8][:200]}" if len(row) > 8 else "",
                    )

        # ── Services pretending to be Sysmon ──────────────────────────
        sc_out = self._run(["sc", "query", "type=", "service", "state=", "all"])
        if sc_out:
            current_svc = ""
            for line in sc_out.splitlines():
                line_s = line.strip()
                if line_s.upper().startswith("SERVICE_NAME"):
                    current_svc = line_s.split(":", 1)[-1].strip()
                if current_svc.lower() in ("sysmon", "sysmon64"):
                    # Real Sysmon has BINARY_PATH pointing to Sysmon*.exe
                    qc_out = self._run(["sc", "qc", current_svc])
                    if qc_out and "sysmon" in qc_out.lower():
                        if ".py" in qc_out.lower() or "python" in qc_out.lower():
                            self._persistence_found += 1
                            self._add_finding(
                                "CRITICAL", "PERSISTENCE_FAKE_SERVICE",
                                f"Service '{current_svc}' mimics Sysmon but runs Python",
                                qc_out[:300],
                            )

    # ══════════════════════════════════════════════════════════════════
    #  2. Exfiltration Staging Artifacts
    # ══════════════════════════════════════════════════════════════════
    def _scan_exfil(self):
        temp = Path(os.environ.get("TEMP", Path.home() / "AppData" / "Local" / "Temp"))
        if not temp.exists():
            return

        # ── Exact-name matches ────────────────────────────────────────
        for name in EXFIL_EXACT_NAMES:
            p = temp / name
            if p.exists():
                self._exfil_staging_found += 1
                self._add_finding(
                    "CRITICAL", "EXFIL_STAGING_EXACT",
                    f"Known TeamPCP exfil staging file: {p}",
                    f"Size: {p.stat().st_size} bytes, Modified: {datetime.fromtimestamp(p.stat().st_mtime).isoformat()}",
                )

        # ── Glob patterns (.tar.gz / .enc) ────────────────────────────
        try:
            for child in temp.iterdir():
                if not child.is_file():
                    continue
                name_lower = child.name.lower()
                if child.name in EXFIL_EXACT_NAMES:
                    continue  # already reported

                if name_lower.endswith(".tar.gz") or name_lower.endswith(".enc"):
                    severity = "MEDIUM"
                    ftype = "EXFIL_SUSPECT_ARCHIVE"
                    stat = child.stat()
                    if stat.st_size > EXFIL_SIZE_THRESHOLD:
                        severity = "HIGH"
                        ftype = "EXFIL_LARGE_ARCHIVE"
                    self._exfil_staging_found += 1
                    self._add_finding(
                        severity, ftype,
                        f"Suspicious temp file: {child.name}",
                        f"Path: {child}, Size: {stat.st_size}, Modified: {datetime.fromtimestamp(stat.st_mtime).isoformat()}",
                    )

                # Large archive check (any extension)
                elif name_lower.endswith((".zip", ".7z", ".rar", ".gz")):
                    try:
                        if child.stat().st_size > EXFIL_SIZE_THRESHOLD:
                            self._exfil_staging_found += 1
                            self._add_finding(
                                "MEDIUM", "EXFIL_LARGE_TEMP_ARCHIVE",
                                f"Large archive in temp: {child.name} ({child.stat().st_size // (1024*1024)} MB)",
                                str(child),
                            )
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass

    # ══════════════════════════════════════════════════════════════════
    #  3. Malicious .pth Files (LiteLLM vector)
    # ══════════════════════════════════════════════════════════════════
    def _get_site_packages(self) -> list:
        """Return list of site-packages directories from all reachable Pythons."""
        dirs = set()
        for py in ("python", "python3"):
            out = self._run([py, "-c", "import site; print('\\n'.join(site.getsitepackages()))"])
            for line in out.splitlines():
                p = Path(line.strip())
                if p.is_dir():
                    dirs.add(p)
        # Also check the running interpreter
        try:
            import site as _site
            for d in _site.getsitepackages():
                p = Path(d)
                if p.is_dir():
                    dirs.add(p)
        except Exception:
            pass
        return list(dirs)

    def _scan_pth_files(self):
        site_dirs = self._get_site_packages()
        now = time.time()
        seven_days = 7 * 86400

        for sp in site_dirs:
            try:
                pth_files = list(sp.glob("*.pth"))
            except (PermissionError, OSError):
                continue

            for pth in pth_files:
                try:
                    content = pth.read_text(encoding="utf-8", errors="replace")
                except (PermissionError, OSError):
                    continue

                pth_name = pth.name.lower()
                stat = pth.stat()
                recently_modified = (now - stat.st_mtime) < seven_days

                # ── Exact known payload file ──────────────────────────
                if pth_name == "litellm_init.pth":
                    self._malicious_pth_found += 1
                    self._add_finding(
                        "CRITICAL", "PTH_LITELLM_MALICIOUS",
                        f"KNOWN MALICIOUS .pth from LiteLLM attack: {pth}",
                        content[:300],
                    )
                    continue

                # ── Scan content for suspicious imports ───────────────
                has_import = "import " in content
                suspicious_kw = [
                    kw for kw in PTH_SUSPICIOUS_KEYWORDS if kw in content
                ]

                if has_import and suspicious_kw:
                    self._malicious_pth_found += 1
                    self._add_finding(
                        "CRITICAL" if len(suspicious_kw) >= 2 else "HIGH",
                        "PTH_SUSPICIOUS_CODE",
                        f".pth with import + suspicious keywords ({', '.join(suspicious_kw)}): {pth}",
                        content[:300],
                    )
                elif recently_modified and has_import:
                    self._malicious_pth_found += 1
                    self._add_finding(
                        "MEDIUM", "PTH_RECENTLY_MODIFIED",
                        f"Recently modified .pth with import statement: {pth}",
                        f"Modified: {datetime.fromtimestamp(stat.st_mtime).isoformat()}, Content: {content[:200]}",
                    )

    # ══════════════════════════════════════════════════════════════════
    #  4. Network Indicators (C2 domains)
    # ══════════════════════════════════════════════════════════════════
    def _scan_network(self):
        # ── DNS cache ─────────────────────────────────────────────────
        dns_out = self._run(["ipconfig", "/displaydns"])
        if dns_out:
            for domain in C2_DOMAINS:
                if domain.lower() in dns_out.lower():
                    self._c2_indicators += 1
                    self._add_finding(
                        "HIGH", "C2_DNS_CACHE",
                        f"Known TeamPCP C2 domain in DNS cache: {domain}",
                        f"Found in ipconfig /displaydns output",
                    )
            for pat in C2_DOMAIN_PATTERNS:
                matches = pat.findall(dns_out)
                for m in matches:
                    if m.lower() not in [d.lower() for d in C2_DOMAINS]:
                        self._c2_indicators += 1
                        self._add_finding(
                            "HIGH", "C2_DNS_WILDCARD",
                            f"Wildcard C2 domain match in DNS cache: {m}",
                            m,
                        )

        # ── Hosts file ────────────────────────────────────────────────
        hosts_path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        try:
            hosts_content = hosts_path.read_text(encoding="utf-8", errors="replace")
            for domain in C2_DOMAINS:
                if domain.lower() in hosts_content.lower():
                    self._c2_indicators += 1
                    self._add_finding(
                        "HIGH", "C2_HOSTS_ENTRY",
                        f"C2 domain in hosts file: {domain}",
                        f"hosts file: {hosts_path}",
                    )
            for pat in C2_DOMAIN_PATTERNS:
                matches = pat.findall(hosts_content)
                for m in matches:
                    self._c2_indicators += 1
                    self._add_finding(
                        "HIGH", "C2_HOSTS_WILDCARD",
                        f"Wildcard C2 match in hosts file: {m}",
                        m,
                    )
        except (PermissionError, OSError):
            pass

        # ── Active connections via psutil ──────────────────────────────
        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.raddr and conn.status == "ESTABLISHED":
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        # Flag connections on typical C2 ports to external IPs
                        if remote_port in (4443, 8443, 9443, 1337, 31337):
                            self._c2_indicators += 1
                            pid_info = ""
                            if conn.pid:
                                try:
                                    proc = psutil.Process(conn.pid)
                                    pid_info = f"PID {conn.pid} ({proc.name()})"
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pid_info = f"PID {conn.pid}"
                            self._add_finding(
                                "MEDIUM", "C2_SUSPICIOUS_PORT",
                                f"Connection to {remote_ip}:{remote_port} on suspicious port",
                                pid_info,
                            )
            except (psutil.AccessDenied, OSError):
                pass

    # ══════════════════════════════════════════════════════════════════
    #  5. Compromised Package Detection
    # ══════════════════════════════════════════════════════════════════
    def _scan_packages(self):
        # ── litellm ───────────────────────────────────────────────────
        try:
            from importlib.metadata import version as pkg_version, PackageNotFoundError
            try:
                ver = pkg_version("litellm")
                if ver in COMPROMISED_LITELLM:
                    self._compromised_packages += 1
                    self._add_finding(
                        "CRITICAL", "PKG_LITELLM_COMPROMISED",
                        f"COMPROMISED litellm version installed: {ver}",
                        f"Known malicious versions: {', '.join(sorted(COMPROMISED_LITELLM))}",
                    )
                else:
                    self._add_finding(
                        "LOW", "PKG_LITELLM_OK",
                        f"litellm installed (version {ver}) - not in compromised list",
                        "",
                    )
            except PackageNotFoundError:
                pass  # litellm not installed - fine
        except ImportError:
            pass

        # ── trivy ─────────────────────────────────────────────────────
        trivy_out = self._run(["trivy", "--version"])
        if trivy_out:
            ver_match = re.search(r"(\d+\.\d+\.\d+)", trivy_out)
            if ver_match:
                ver = ver_match.group(1)
                if ver in COMPROMISED_TRIVY_TAGS:
                    self._compromised_packages += 1
                    self._add_finding(
                        "HIGH", "PKG_TRIVY_COMPROMISED",
                        f"Compromised trivy version: {ver}",
                        f"Known compromised: {', '.join(sorted(COMPROMISED_TRIVY_TAGS))}",
                    )

        # ── npm canisterworm indicator ────────────────────────────────
        self._scan_npm_canisterworm()

    def _scan_npm_canisterworm(self):
        """Scan node_modules for packages with base64-encoded preinstall scripts."""
        search_roots = [
            Path.home() / "node_modules",
            Path.cwd() / "node_modules",
        ]
        # Also check global npm prefix
        npm_prefix = self._run(["npm", "prefix", "-g"])
        if npm_prefix:
            gp = Path(npm_prefix.strip()) / "node_modules"
            if gp.is_dir():
                search_roots.append(gp)

        seen = set()
        for root in search_roots:
            if not root.is_dir() or root in seen:
                continue
            seen.add(root)
            try:
                for pkg_json in root.rglob("package.json"):
                    try:
                        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                        scripts = data.get("scripts", {})
                        preinstall = scripts.get("preinstall", "")
                        postinstall = scripts.get("postinstall", "")
                        for hook_name, hook_val in [("preinstall", preinstall), ("postinstall", postinstall)]:
                            if not hook_val:
                                continue
                            # base64-encoded payloads are a hallmark
                            if "base64" in hook_val.lower() or "eval" in hook_val.lower():
                                self._compromised_packages += 1
                                self._add_finding(
                                    "HIGH", "NPM_SUSPICIOUS_HOOK",
                                    f"npm package with suspicious {hook_name} script: {pkg_json.parent.name}",
                                    f"Script: {hook_val[:200]}",
                                )
                            # Also flag very long one-liner hooks (obfuscated)
                            elif len(hook_val) > 500:
                                self._compromised_packages += 1
                                self._add_finding(
                                    "MEDIUM", "NPM_LONG_HOOK",
                                    f"npm package with unusually long {hook_name}: {pkg_json.parent.name}",
                                    f"Length: {len(hook_val)} chars",
                                )
                    except (json.JSONDecodeError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

    # ══════════════════════════════════════════════════════════════════
    #  6. Kubernetes Indicators
    # ══════════════════════════════════════════════════════════════════
    def _scan_k8s(self):
        pods_out = self._run(["kubectl", "get", "pods", "-A", "-o", "json"])
        if not pods_out:
            return  # kubectl not available or no cluster

        try:
            data = json.loads(pods_out)
        except json.JSONDecodeError:
            return

        items = data.get("items", [])
        for pod in items:
            metadata = pod.get("metadata", {})
            pod_name = metadata.get("name", "")
            namespace = metadata.get("namespace", "")
            spec = pod.get("spec", {})

            # ── TeamPCP persistence pods ──────────────────────────────
            if pod_name.startswith("node-setup-"):
                self._k8s_indicators += 1
                self._add_finding(
                    "HIGH", "K8S_TEAMPCP_POD",
                    f"Suspicious pod matching TeamPCP pattern: {pod_name} (ns: {namespace})",
                    f"Pod name starts with 'node-setup-'",
                )

            # ── Privileged containers ─────────────────────────────────
            for container in spec.get("containers", []):
                sc = container.get("securityContext", {})
                if sc.get("privileged") is True:
                    self._k8s_indicators += 1
                    self._add_finding(
                        "MEDIUM", "K8S_PRIVILEGED_POD",
                        f"Privileged container: {container.get('name', '?')} in pod {pod_name} (ns: {namespace})",
                        f"securityContext.privileged=true",
                    )

    # ══════════════════════════════════════════════════════════════════
    #  7. Docker Image Check
    # ══════════════════════════════════════════════════════════════════
    def _scan_docker(self):
        images_out = self._run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.CreatedAt}}"])
        if not images_out:
            return  # Docker not available

        for line in images_out.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split(None, 1)
            image_tag = parts[0] if parts else ""
            created = parts[1] if len(parts) > 1 else ""

            # ── Compromised trivy images ──────────────────────────────
            for tag in COMPROMISED_TRIVY_TAGS:
                if image_tag.lower() == f"aquasec/trivy:{tag}":
                    self._compromised_packages += 1
                    self._add_finding(
                        "HIGH", "DOCKER_TRIVY_COMPROMISED",
                        f"Compromised Docker image: {image_tag}",
                        f"Created: {created}",
                    )

            # ── Recently pulled from unknown registries ───────────────
            # Images with full registry prefix that aren't from Docker Hub
            if "/" in image_tag and "." in image_tag.split("/")[0]:
                registry = image_tag.split("/")[0]
                trusted = {"docker.io", "gcr.io", "ghcr.io", "quay.io", "mcr.microsoft.com", "registry.k8s.io"}
                if registry.lower() not in trusted:
                    self._add_finding(
                        "LOW", "DOCKER_UNKNOWN_REGISTRY",
                        f"Image from non-standard registry: {image_tag}",
                        f"Registry: {registry}, Created: {created}",
                    )

    # ══════════════════════════════════════════════════════════════════
    #  Main scan entry point
    # ══════════════════════════════════════════════════════════════════
    def scan(self) -> list:
        """Run the full TeamPCP indicator sweep. Returns list of findings."""
        if not self.enabled:
            return []

        self.findings = []
        self._persistence_found = 0
        self._exfil_staging_found = 0
        self._malicious_pth_found = 0
        self._c2_indicators = 0
        self._compromised_packages = 0
        self._k8s_indicators = 0

        self.logger.info("Starting TeamPCP supply-chain attack scan")
        t0 = time.time()

        checks = [
            ("Persistence", self._scan_persistence),
            ("Exfiltration", self._scan_exfil),
            ("PTH files", self._scan_pth_files),
            ("Network/C2", self._scan_network),
            ("Packages", self._scan_packages),
            ("Kubernetes", self._scan_k8s),
            ("Docker", self._scan_docker),
        ]

        for label, fn in checks:
            try:
                fn()
            except Exception as e:
                self.logger.error("Scan phase '%s' failed: %s", label, e)

        elapsed = time.time() - t0
        self._artifacts_found = len(self.findings)
        self._last_scan = datetime.now(timezone.utc).isoformat()

        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        self.logger.info(
            "Scan complete in %.1fs - %d findings (%d CRITICAL, %d HIGH)",
            elapsed, len(self.findings), critical, high,
        )

        return list(self.findings)

    # ── Async loop ────────────────────────────────────────────────────
    async def monitor_loop(self):
        if not self.enabled:
            return
        self._running = True
        self.logger.info("TeamPCP Detector monitor started (interval=%ds)", self.interval)
        while self._running:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self.scan)
            except Exception as e:
                self.logger.error("Monitor loop error: %s", e)
            await asyncio.sleep(self.interval)

    async def stop(self):
        self._running = False
        self.logger.info("TeamPCP Detector stopped")

    # ── Stats ─────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "last_scan": self._last_scan,
            "artifacts_found": self._artifacts_found,
            "persistence_found": self._persistence_found,
            "exfil_staging_found": self._exfil_staging_found,
            "malicious_pth_found": self._malicious_pth_found,
            "c2_indicators": self._c2_indicators,
            "compromised_packages": self._compromised_packages,
            "k8s_indicators": self._k8s_indicators,
            "alerts": len(self.alerts),
            "findings": list(self.findings),
        }
