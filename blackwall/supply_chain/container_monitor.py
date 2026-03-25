"""
Container Security Monitor - Monitors Docker/container activity for malicious behavior.
Detects privileged containers, crypto miners, reverse shells, suspicious images,
and dangerous mount points. Inspired by supply chain attacks deploying rogue containers.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
    "DAC_READ_SEARCH", "NET_RAW", "AUDIT_WRITE", "MKNOD", "SYS_CHROOT",
}

DANGEROUS_HOST_MOUNTS = {"/", "/etc", "/var", "/home", "/root", "/proc", "/sys"}

CRYPTO_MINER_NAMES = {
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer",
    "claymore", "phoenixminer", "t-rex", "nbminer", "gminer", "lolminer",
    "ccminer", "srbminer", "teamredminer", "nanominer", "bminer",
    "wildrig", "xmr-stak", "randomx", "cryptonight",
}

REVERSE_SHELL_PATTERNS = [
    re.compile(r"(bash|sh|zsh)\s+-i\s+.*[>&]\s*/dev/tcp", re.IGNORECASE),
    re.compile(r"nc\s+(-e|--exec)\s+", re.IGNORECASE),
    re.compile(r"ncat\s+(-e|--exec)\s+", re.IGNORECASE),
    re.compile(r"socat\s+.*exec:", re.IGNORECASE),
    re.compile(r"python.*socket.*connect", re.IGNORECASE),
    re.compile(r"perl.*socket.*INET", re.IGNORECASE),
    re.compile(r"ruby.*TCPSocket", re.IGNORECASE),
    re.compile(r"mkfifo\s+.*\|\s*(nc|ncat|bash)", re.IGNORECASE),
]

SUSPICIOUS_OUTBOUND_PORTS = {
    4444, 4445, 5555, 6666, 6667, 6697,   # common C2 / IRC
    1337, 31337, 12345, 9001, 9050, 9150,  # backdoors / Tor
    3389,                                   # RDP from container is unusual
    1080, 8080, 8443,                       # common proxy / alt-HTTP
}

DEFAULT_TRUSTED_REGISTRIES = {
    "docker.io", "registry.hub.docker.com", "ghcr.io",
    "gcr.io", "quay.io", "mcr.microsoft.com",
    "public.ecr.aws", "registry.k8s.io",
}

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ---------------------------------------------------------------------------
# ContainerSecurityMonitor
# ---------------------------------------------------------------------------

class ContainerSecurityMonitor:
    """Async monitor for Docker container security threats."""

    def __init__(
        self,
        alert_callback: Optional[Callable[..., Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        log_dir: str = "logs",
    ):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.scan_interval = config.get("scan_interval_seconds", 120)
        self.trusted_registries: Set[str] = set(
            config.get("trusted_registries", [])
        ) or DEFAULT_TRUSTED_REGISTRIES
        self.compose_scan_paths: List[str] = config.get("compose_scan_paths", ["."])

        self.alert_callback = alert_callback
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._known_container_ids: Set[str] = set()
        self._image_pull_times: Dict[str, float] = {}
        self._alerts: List[Dict[str, Any]] = []

        # Logging
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("ContainerSecurityMonitor")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                self.log_dir / "container_monitor.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            self._logger.addHandler(handler)

        # Docker availability
        self._docker_available = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the container security monitor loop."""
        if not self.enabled:
            self._logger.info("Container monitor disabled in config.")
            return
        self._docker_available = await self._check_docker()
        if not self._docker_available:
            self._logger.warning(
                "Docker is not installed or not running. "
                "Container monitoring will retry each cycle."
            )
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        self._logger.info("Container Security Monitor started (interval=%ds).", self.scan_interval)

    async def stop(self) -> None:
        """Stop the monitor gracefully."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._logger.info("Container Security Monitor stopped.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._docker_available = await self._check_docker()
                if self._docker_available:
                    await self._run_full_scan()
                else:
                    self._logger.debug("Docker not available, skipping scan cycle.")
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._logger.error("Scan cycle failed: %s", exc, exc_info=True)
            try:
                await asyncio.sleep(self.scan_interval)
            except asyncio.CancelledError:
                break

    async def _run_full_scan(self) -> None:
        """Execute all scan stages."""
        self._logger.debug("Starting full container scan.")
        containers = await self._list_containers()
        for container in containers:
            cid = container.get("ID", "")
            is_new = cid not in self._known_container_ids
            self._known_container_ids.add(cid)

            inspect = await self._inspect_container(cid)
            if not inspect:
                continue

            if is_new:
                self._logger.info("New container detected: %s (%s)", cid[:12], container.get("Image", ""))

            await self._check_privileged(cid, inspect)
            await self._check_capabilities(cid, inspect)
            await self._check_namespace_sharing(cid, inspect)
            await self._check_host_mounts(cid, inspect)
            await self._check_image_security(cid, inspect)
            await self._check_runtime_processes(cid, inspect)
            await self._check_container_networking(cid)

        # Compose file scanning
        await self._scan_compose_files()

        self._logger.debug("Scan cycle complete. %d containers inspected.", len(containers))

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    async def _check_docker(self) -> bool:
        """Return True if Docker daemon is reachable."""
        ok, _ = await self._docker_cmd(["docker", "info", "--format", "{{.ServerVersion}}"])
        return ok

    async def _docker_cmd(self, cmd: List[str], timeout: int = 30) -> tuple:
        """Run a docker CLI command asynchronously. Returns (success, stdout)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode == 0:
                return True, stdout.decode("utf-8", errors="replace").strip()
            self._logger.debug("Docker cmd failed (%s): %s", " ".join(cmd), stderr.decode(errors="replace").strip())
            return False, ""
        except FileNotFoundError:
            return False, ""
        except asyncio.TimeoutError:
            self._logger.warning("Docker command timed out: %s", " ".join(cmd))
            return False, ""
        except OSError as exc:
            self._logger.debug("Docker command OSError: %s", exc)
            return False, ""

    async def _list_containers(self) -> List[Dict[str, str]]:
        """List all running containers."""
        ok, output = await self._docker_cmd([
            "docker", "ps", "--no-trunc", "--format",
            "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}"
        ])
        if not ok or not output:
            return []
        containers = []
        for line in output.splitlines():
            parts = line.split("|", 4)
            if len(parts) >= 4:
                containers.append({
                    "ID": parts[0],
                    "Image": parts[1],
                    "Names": parts[2],
                    "Status": parts[3],
                    "Ports": parts[4] if len(parts) > 4 else "",
                })
        return containers

    async def _inspect_container(self, container_id: str) -> Optional[Dict]:
        """Return parsed JSON from docker inspect."""
        ok, output = await self._docker_cmd(["docker", "inspect", container_id])
        if not ok or not output:
            return None
        try:
            data = json.loads(output)
            return data[0] if isinstance(data, list) and data else data
        except (json.JSONDecodeError, IndexError):
            self._logger.warning("Failed to parse inspect output for %s", container_id[:12])
            return None

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    async def _check_privileged(self, cid: str, inspect: Dict) -> None:
        """Detect containers running with --privileged."""
        host_config = inspect.get("HostConfig", {})
        if host_config.get("Privileged", False):
            # Check if also mounting host root — that's CRITICAL
            mounts = host_config.get("Binds") or []
            has_root_mount = any(
                self._is_dangerous_mount(m) for m in mounts
            )
            severity = "CRITICAL" if has_root_mount else "HIGH"
            await self._emit_alert(
                severity=severity,
                category="privileged_container",
                message=f"Container {cid[:12]} running with --privileged flag"
                        + (" AND host filesystem mount" if has_root_mount else ""),
                container_id=cid,
                details={"image": inspect.get("Config", {}).get("Image", "")},
            )

    async def _check_capabilities(self, cid: str, inspect: Dict) -> None:
        """Flag containers with dangerous Linux capabilities."""
        host_config = inspect.get("HostConfig", {})
        cap_add = set(host_config.get("CapAdd") or [])
        dangerous = cap_add & DANGEROUS_CAPABILITIES
        if dangerous:
            await self._emit_alert(
                severity="HIGH",
                category="dangerous_capabilities",
                message=f"Container {cid[:12]} has dangerous capabilities: {', '.join(sorted(dangerous))}",
                container_id=cid,
                details={"capabilities": sorted(dangerous)},
            )

    async def _check_namespace_sharing(self, cid: str, inspect: Dict) -> None:
        """Flag containers sharing host network/PID/IPC namespace."""
        host_config = inspect.get("HostConfig", {})
        issues = []
        if host_config.get("NetworkMode") == "host":
            issues.append("host network")
        if host_config.get("PidMode") == "host":
            issues.append("host PID")
        if host_config.get("IpcMode") == "host":
            issues.append("host IPC")
        if issues:
            await self._emit_alert(
                severity="HIGH",
                category="namespace_sharing",
                message=f"Container {cid[:12]} shares: {', '.join(issues)}",
                container_id=cid,
            )

    async def _check_host_mounts(self, cid: str, inspect: Dict) -> None:
        """Flag containers mounting sensitive host paths."""
        mounts = inspect.get("Mounts") or []
        binds = (inspect.get("HostConfig") or {}).get("Binds") or []
        dangerous_found = []

        for mount in mounts:
            src = mount.get("Source", "")
            if self._is_dangerous_mount(src):
                dangerous_found.append(src)

        for bind in binds:
            host_path = bind.split(":")[0] if ":" in bind else bind
            if self._is_dangerous_mount(host_path):
                dangerous_found.append(host_path)

        if dangerous_found:
            unique = sorted(set(dangerous_found))
            is_root = "/" in unique and len(unique[unique.index("/")]) == 1
            severity = "CRITICAL" if is_root else "HIGH"
            await self._emit_alert(
                severity=severity,
                category="host_mount",
                message=f"Container {cid[:12]} mounts sensitive host paths: {', '.join(unique)}",
                container_id=cid,
                details={"mounts": unique},
            )

    async def _check_image_security(self, cid: str, inspect: Dict) -> None:
        """Check image origin, tag pinning, and pull recency."""
        image = inspect.get("Config", {}).get("Image", "")
        if not image:
            return

        # :latest tag check
        if image.endswith(":latest") or ":" not in image.split("/")[-1]:
            await self._emit_alert(
                severity="MEDIUM",
                category="unpinned_image",
                message=f"Container {cid[:12]} uses unpinned image tag: {image}",
                container_id=cid,
                details={"image": image},
            )

        # Trusted registry check
        registry = self._extract_registry(image)
        if registry and registry not in self.trusted_registries:
            await self._emit_alert(
                severity="MEDIUM",
                category="untrusted_registry",
                message=f"Container {cid[:12]} uses image from untrusted registry: {registry}",
                container_id=cid,
                details={"image": image, "registry": registry},
            )

        # Recently pulled image check
        created = inspect.get("Created", "")
        if created:
            try:
                # Docker timestamps: 2024-01-15T10:30:00.123456789Z
                created_clean = re.sub(r"\.\d+Z$", "+00:00", created)
                created_dt = datetime.fromisoformat(created_clean)
                age_seconds = (datetime.now(timezone.utc) - created_dt).total_seconds()
                if age_seconds < 3600:
                    await self._emit_alert(
                        severity="MEDIUM",
                        category="recently_created",
                        message=f"Container {cid[:12]} was created less than 1 hour ago (image: {image})",
                        container_id=cid,
                        details={"image": image, "age_seconds": int(age_seconds)},
                    )
            except (ValueError, TypeError):
                pass

    async def _check_runtime_processes(self, cid: str, inspect: Dict) -> None:
        """Monitor processes inside a running container for miners and shells."""
        ok, output = await self._docker_cmd(["docker", "top", cid, "-eo", "pid,comm,args"])
        if not ok or not output:
            return

        for line in output.splitlines()[1:]:  # skip header
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            proc_name = parts[1].lower()
            full_cmd = parts[2].lower() if len(parts) > 2 else proc_name

            # Crypto miner detection
            for miner in CRYPTO_MINER_NAMES:
                if miner in proc_name or miner in full_cmd:
                    await self._emit_alert(
                        severity="HIGH",
                        category="crypto_miner",
                        message=f"Possible crypto miner in container {cid[:12]}: {parts[1]} ({full_cmd[:120]})",
                        container_id=cid,
                        details={"process": parts[1], "cmdline": full_cmd[:256]},
                    )
                    break

            # Reverse shell detection
            for pattern in REVERSE_SHELL_PATTERNS:
                if pattern.search(full_cmd):
                    await self._emit_alert(
                        severity="CRITICAL",
                        category="reverse_shell",
                        message=f"Possible reverse shell in container {cid[:12]}: {full_cmd[:120]}",
                        container_id=cid,
                        details={"cmdline": full_cmd[:256]},
                    )
                    break

    async def _check_container_networking(self, cid: str) -> None:
        """Check for outbound connections to unusual ports from a container."""
        # Use docker exec to inspect network connections inside the container.
        # Not all containers have 'ss' or 'netstat'; we try ss first, then netstat.
        ok, output = await self._docker_cmd(
            ["docker", "exec", cid, "ss", "-tnp"], timeout=10,
        )
        if not ok:
            ok, output = await self._docker_cmd(
                ["docker", "exec", cid, "netstat", "-tnp"], timeout=10,
            )
        if not ok or not output:
            return

        for line in output.splitlines():
            # Look for ESTAB connections with remote port in suspicious set
            match = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            if match:
                remote_port = int(match.group(4))
                remote_ip = match.group(3)
                if remote_port in SUSPICIOUS_OUTBOUND_PORTS:
                    await self._emit_alert(
                        severity="HIGH",
                        category="suspicious_outbound",
                        message=(
                            f"Container {cid[:12]} has outbound connection to "
                            f"{remote_ip}:{remote_port}"
                        ),
                        container_id=cid,
                        details={"remote_ip": remote_ip, "remote_port": remote_port},
                    )

    # ------------------------------------------------------------------
    # Docker Compose scanning
    # ------------------------------------------------------------------

    async def _scan_compose_files(self) -> None:
        """Scan docker-compose.yml files for security issues."""
        for base_path in self.compose_scan_paths:
            for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                fpath = Path(base_path) / name
                if fpath.is_file():
                    await self._analyze_compose_file(fpath)

    async def _analyze_compose_file(self, fpath: Path) -> None:
        """Parse a compose file (plain text, no PyYAML dependency) for red flags."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._logger.debug("Cannot read compose file %s: %s", fpath, exc)
            return

        file_str = str(fpath)

        # Privileged flag
        if re.search(r"privileged:\s*true", content, re.IGNORECASE):
            await self._emit_alert(
                severity="HIGH",
                category="compose_privileged",
                message=f"Compose file {file_str} contains privileged: true",
                details={"file": file_str},
            )

        # Exposed to 0.0.0.0
        exposed = re.findall(r'"?0\.0\.0\.0:(\d+):\d+"?', content)
        if exposed:
            await self._emit_alert(
                severity="MEDIUM",
                category="compose_exposed_ports",
                message=f"Compose file {file_str} exposes ports to 0.0.0.0: {', '.join(exposed)}",
                details={"file": file_str, "ports": exposed},
            )

        # Secrets in environment variables
        secret_patterns = re.findall(
            r"(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_SECRET)\s*[:=]\s*\S+",
            content,
            re.IGNORECASE,
        )
        if secret_patterns:
            # Redact values for the alert
            redacted = [p.split("=")[0].split(":")[0].strip() for p in secret_patterns]
            await self._emit_alert(
                severity="MEDIUM",
                category="compose_secrets",
                message=f"Compose file {file_str} may contain secrets in env vars: {', '.join(redacted)}",
                details={"file": file_str, "variable_names": redacted},
            )

        # Dangerous volume mounts
        mount_matches = re.findall(r"- [\"']?(/[^:\"']*?):", content)
        dangerous = [m for m in mount_matches if self._is_dangerous_mount(m)]
        if dangerous:
            await self._emit_alert(
                severity="HIGH",
                category="compose_host_mount",
                message=f"Compose file {file_str} mounts sensitive host paths: {', '.join(dangerous)}",
                details={"file": file_str, "mounts": dangerous},
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_dangerous_mount(path: str) -> bool:
        """Check if a host path is a sensitive mount point."""
        normalized = path.rstrip("/") or "/"
        return normalized in DANGEROUS_HOST_MOUNTS

    @staticmethod
    def _extract_registry(image: str) -> Optional[str]:
        """Extract registry hostname from an image reference.

        Returns None for official Docker Hub short names (e.g. 'nginx:latest').
        """
        parts = image.split("/")
        if len(parts) == 1:
            # Official image like 'nginx' — from Docker Hub
            return "docker.io"
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            return parts[0]
        # e.g. 'library/nginx' — Docker Hub
        return "docker.io"

    async def _emit_alert(
        self,
        severity: str,
        category: str,
        message: str,
        container_id: str = "",
        details: Optional[Dict] = None,
    ) -> None:
        """Create alert, log it, store it, and dispatch callback."""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "category": category,
            "message": message,
            "container_id": container_id[:12] if container_id else "",
            "details": details or {},
            "source": "ContainerSecurityMonitor",
        }
        self._alerts.append(alert)
        log_level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH": logging.ERROR,
            "MEDIUM": logging.WARNING,
            "LOW": logging.INFO,
        }.get(severity, logging.INFO)
        self._logger.log(log_level, "[%s] %s", severity, message)

        if self.alert_callback:
            try:
                result = self.alert_callback(alert)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                self._logger.error("Alert callback error: %s", exc)

    def get_alerts(self, min_severity: str = "LOW") -> List[Dict[str, Any]]:
        """Return stored alerts filtered by minimum severity."""
        threshold = SEVERITY_ORDER.get(min_severity, 0)
        return [
            a for a in self._alerts
            if SEVERITY_ORDER.get(a["severity"], 0) >= threshold
        ]

    def get_status(self) -> Dict[str, Any]:
        """Return current monitor status summary."""
        return {
            "running": self._running,
            "docker_available": self._docker_available,
            "known_containers": len(self._known_container_ids),
            "total_alerts": len(self._alerts),
            "critical_alerts": sum(1 for a in self._alerts if a["severity"] == "CRITICAL"),
            "high_alerts": sum(1 for a in self._alerts if a["severity"] == "HIGH"),
            "scan_interval_seconds": self.scan_interval,
        }

    def clear_alerts(self) -> None:
        """Clear all stored alerts."""
        self._alerts.clear()
