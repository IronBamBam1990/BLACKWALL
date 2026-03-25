"""
===============================================================================
  ████████╗██╗  ██╗███████╗    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
  ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
     ██║   ███████║█████╗      ██████╔╝██║     ███████║██║     █████╔╝
     ██║   ██╔══██║██╔══╝      ██╔══██╗██║     ██╔══██║██║     ██╔═██╗
     ██║   ██║  ██║███████╗    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
     ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
  ██╗    ██╗ █████╗ ██╗     ██╗
  ██║    ██║██╔══██╗██║     ██║
  ██║ █╗ ██║███████║██║     ██║
  ██║███╗██║██╔══██║██║     ██║
  ╚███╔███╔╝██║  ██║███████╗███████╗
   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝

  THE BLACKWALL  v4.0  -  Last Line of Defense
===============================================================================
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows (cp1250/cp1252 can't handle box-drawing chars)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Path setup - ensure blackwall/ subpackage is importable
# ---------------------------------------------------------------------------
BLACKWALL_DIR = Path(__file__).parent
sys.path.insert(0, str(BLACKWALL_DIR))
sys.path.insert(0, str(BLACKWALL_DIR / "blackwall"))

# ---------------------------------------------------------------------------
# Honeypots
# ---------------------------------------------------------------------------
from blackwall.honeypots.honeypot_manager import HoneypotManager

# ---------------------------------------------------------------------------
# Monitors - core
# ---------------------------------------------------------------------------
from blackwall.monitor.network_monitor import NetworkMonitor
from blackwall.monitor.intrusion_detector import IntrusionDetector
from blackwall.monitor.auto_ban import AutoBan
from blackwall.monitor.geoip import GeoIPLookup
from blackwall.monitor.threat_intel import ThreatIntelChecker
from blackwall.monitor.arp_monitor import ARPMonitor
from blackwall.monitor.process_monitor import ProcessMonitor
from blackwall.monitor.file_integrity import FileIntegrityMonitor
from blackwall.monitor.alerting import AlertManager
from blackwall.monitor.outbound_analyzer import OutboundAnalyzer
from blackwall.monitor.registry_monitor import RegistryMonitor
from blackwall.monitor.bandwidth_monitor import BandwidthMonitor
from blackwall.monitor.canary_tokens import CanaryTokens
from blackwall.monitor.eventlog_monitor import EventLogMonitor
from blackwall.monitor.usb_monitor import USBMonitor
from blackwall.monitor.threat_scorer import ThreatScorer
from blackwall.monitor.rate_limiter import RateLimiter
from blackwall.monitor.behavior_engine import BehaviorEngine
from blackwall.monitor.safe_loop import safe_monitor_loop

# ---------------------------------------------------------------------------
# Monitors - defense
# ---------------------------------------------------------------------------
from blackwall.monitor.anti_ddos import AntiDDoS
from blackwall.monitor.anti_keylogger import AntiKeylogger
from blackwall.monitor.privacy_guard import PrivacyGuard
from blackwall.monitor.browser_guard import BrowserGuard

# ---------------------------------------------------------------------------
# Supply chain modules
# ---------------------------------------------------------------------------
from blackwall.supply_chain.guardian import SupplyChainGuardian
from blackwall.supply_chain.credential_monitor import CredentialVaultMonitor
from blackwall.supply_chain.dependency_auditor import DependencyAuditor
from blackwall.supply_chain.container_monitor import ContainerSecurityMonitor

# ---------------------------------------------------------------------------
# Utils & Dashboard
# ---------------------------------------------------------------------------
from blackwall.utils.crypto import LogEncryptor
from blackwall.dashboard.web_dashboard import WebDashboard
from blackwall.gui.app import BlackwallGUI

# ═══════════════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════════════

BANNER = r"""
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║                                                                        ║
 ║   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗    ██╗ █████╗ ██╗     ██╗║
 ║   ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║    ██║██╔══██╗██║     ██║║
 ║   ██████╔╝██║     ███████║██║     █████╔╝ ██║ █╗ ██║███████║██║     ██║║
 ║   ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║███╗██║██╔══██║██║     ██║║
 ║   ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚███╔███╔╝██║  ██║███████╗██║║
 ║   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝║
 ║                                                                        ║
 ║           THE  BLACKWALL  -  Last  Line  of  Defense                   ║
 ║                          Version 4.0                                   ║
 ║                                                                        ║
 ╠════════════════════════════════════════════════════════════════════════╣
 ║                                                                        ║
 ║   [■] 9 Honeypots + Catch-All ............... 68 ports armed           ║
 ║   [■] 24 Security Monitors .................. Behavioral Analysis      ║
 ║   [■] Supply Chain Guardian ................. Package Integrity        ║
 ║   [■] Credential Vault ...................... DPAPI Sealed             ║
 ║   [■] Dependency Auditor .................... Typosquat Detection      ║
 ║   [■] Container Security .................... Perimeter Locked         ║
 ║   [■] Anti-DDoS + Anti-Keylogger ........... Active Shielding         ║
 ║   [■] Privacy Guard + Browser Guard ......... Tracking Blocked        ║
 ║                                                                        ║
 ║   "Beyond the Blackwall, only rogue code survives."                    ║
 ║                                                                        ║
 ╚══════════════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════
# Startup messages
# ═══════════════════════════════════════════════════════════════════════════

STARTUP_SEQUENCE = [
    ("[BLACKWALL] Initializing defensive barrier...", 0.08),
    ("[BLACKWALL] Loading threat intelligence feeds...", 0.05),
    ("[BLACKWALL] Deploying honeypot grid... 68 ports armed", 0.06),
    ("[BLACKWALL] IDS + Auto-Ban + Behavioral Engine online", 0.04),
    ("[BLACKWALL] ARP Guard + Process Monitor + File Integrity active", 0.04),
    ("[BLACKWALL] Registry Monitor + USB Guard + Event Log watcher ready", 0.04),
    ("[BLACKWALL] Anti-DDoS shield raised", 0.03),
    ("[BLACKWALL] Anti-Keylogger hooks installed", 0.03),
    ("[BLACKWALL] Privacy Guard engaged - DNS leak protection active", 0.03),
    ("[BLACKWALL] Browser Guard locked - fingerprint spoofing enabled", 0.03),
    ("[BLACKWALL] Supply Chain Guardian online", 0.06),
    ("[BLACKWALL] Credential Vault sealed", 0.05),
    ("[BLACKWALL] Dependency tree scanning...", 0.06),
    ("[BLACKWALL] Container perimeter locked", 0.05),
    ("[BLACKWALL] Canary tokens deploying...", 0.04),
    ("[BLACKWALL] Dashboard rendering engine ready", 0.03),
    ("", 0.1),
    ("[BLACKWALL] ══════════════════════════════════════════", 0.02),
    ("[BLACKWALL]  The wall is up. Nothing gets through.", 0.02),
    ("[BLACKWALL] ══════════════════════════════════════════", 0.02),
    ("", 0.0),
]


def _print_startup():
    """Print startup sequence with a brief delay per line for visual effect."""
    for msg, delay in STARTUP_SEQUENCE:
        if msg:
            print(msg)
        else:
            print()
        if delay > 0:
            time.sleep(delay)


# ═══════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    """Load configuration from config/config.json."""
    p = BLACKWALL_DIR / "config" / "config.json"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[BLACKWALL] WARNING: Failed to load config: {e}")
            print("[BLACKWALL] Using default configuration.")
    return {}


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    """Main async entry point - starts all BLACKWALL subsystems."""

    print(BANNER)
    config = load_config()
    log_dir = str(BLACKWALL_DIR / config.get("logging", {}).get("log_dir", "logs"))

    _print_startup()

    # ===================================================================
    # SHARED COMPONENTS
    # ===================================================================
    geoip = GeoIPLookup(config.get("geoip", {}))
    threat_intel = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)
    alert_mgr = AlertManager(config.get("alerts", {}), log_dir=log_dir)
    threat_scorer = ThreatScorer()
    rate_limiter = RateLimiter(config.get("rate_limiter", {}))
    behavior = BehaviorEngine(config.get("behavior_engine", {}))

    # ===================================================================
    # HONEYPOTS
    # ===================================================================
    honeypot_mgr = HoneypotManager(
        config, log_dir=log_dir, geoip=geoip, threat_intel=threat_intel
    )

    # ===================================================================
    # MONITORS - Core
    # ===================================================================
    net_monitor = NetworkMonitor(config, log_dir=log_dir)
    ids = IntrusionDetector(config, log_dir=log_dir)
    auto_ban = AutoBan(config, log_dir=log_dir)
    arp_monitor = ARPMonitor(config.get("arp_monitor", {}), log_dir=log_dir)
    proc_monitor = ProcessMonitor(config.get("process_monitor", {}), log_dir=log_dir)
    fim = FileIntegrityMonitor(config.get("file_integrity", {}), log_dir=log_dir)
    outbound = OutboundAnalyzer(config.get("outbound_analyzer", {}), log_dir=log_dir)
    reg_monitor = RegistryMonitor(config.get("registry_monitor", {}), log_dir=log_dir)
    bw_monitor = BandwidthMonitor(config.get("bandwidth_monitor", {}), log_dir=log_dir)
    canary = CanaryTokens(config.get("canary_tokens", {}), log_dir=log_dir)
    eventlog = EventLogMonitor(config.get("eventlog_monitor", {}), log_dir=log_dir)
    usb_mon = USBMonitor(config.get("usb_monitor", {}), log_dir=log_dir)

    # ===================================================================
    # MONITORS - Defense
    # ===================================================================
    anti_ddos = AntiDDoS(config.get("anti_ddos", {}), log_dir=log_dir, auto_ban=auto_ban)
    anti_keylogger = AntiKeylogger(config.get("anti_keylogger", {}), log_dir=log_dir)
    privacy_guard = PrivacyGuard(config.get("privacy_guard", {}), log_dir=log_dir)
    browser_guard = BrowserGuard(config.get("browser_guard", {}), log_dir=log_dir)

    # ===================================================================
    # SUPPLY CHAIN MODULES
    # ===================================================================

    # Shared async alert callback for supply chain → alert_mgr + auto_ban
    async def _supply_chain_alert(event):
        """Route supply chain alerts to alert manager and auto-ban for critical."""
        alert_mgr.handle_alert({
            "type": "SUPPLY_CHAIN_" + event.get("type", "UNKNOWN"),
            "severity": event.get("severity", "HIGH"),
            "description": event.get("description", str(event)),
            "source": "SupplyChainGuardian",
            "timestamp": event.get("timestamp", ""),
        })
        if event.get("severity") == "CRITICAL":
            src_ip = event.get("source_ip", "")
            if src_ip:
                auto_ban.ban_ip(
                    src_ip,
                    reason=f"Supply Chain: {event.get('type', 'unknown')}",
                    severity="CRITICAL",
                )

    async def _credential_alert(event):
        """Route credential monitor alerts to alert manager."""
        alert_mgr.handle_alert({
            "type": "CREDENTIAL_" + event.get("type", "ACCESS"),
            "severity": event.get("severity", "HIGH"),
            "description": event.get("description", str(event)),
            "source": "CredentialVaultMonitor",
            "timestamp": event.get("timestamp", ""),
        })

    async def _dependency_alert(event):
        """Route dependency auditor alerts to alert manager."""
        alert_mgr.handle_alert({
            "type": "DEPENDENCY_" + event.get("type", "RISK"),
            "severity": event.get("severity", "MEDIUM"),
            "description": event.get("description", str(event)),
            "source": "DependencyAuditor",
            "timestamp": event.get("timestamp", ""),
        })

    async def _container_alert(event):
        """Route container monitor alerts to alert manager and auto-ban for critical."""
        alert_mgr.handle_alert({
            "type": "CONTAINER_" + event.get("type", "THREAT"),
            "severity": event.get("severity", "HIGH"),
            "description": event.get("description", str(event)),
            "source": "ContainerSecurityMonitor",
            "timestamp": event.get("timestamp", ""),
        })
        if event.get("severity") == "CRITICAL":
            src_ip = event.get("source_ip", "")
            if src_ip:
                auto_ban.ban_ip(
                    src_ip,
                    reason=f"Container: {event.get('type', 'unknown')}",
                    severity="CRITICAL",
                )

    supply_chain = SupplyChainGuardian(
        config=config.get("supply_chain", {}),
        alert_callback=_supply_chain_alert,
        log_dir=log_dir,
    )

    credential_monitor = CredentialVaultMonitor(
        config=config.get("credential_monitor", {}),
        alert_callback=_credential_alert,
        log_dir=log_dir,
    )

    dependency_auditor = DependencyAuditor(
        alert_callback=_dependency_alert,
        log_dir=log_dir,
    )

    container_monitor = ContainerSecurityMonitor(
        alert_callback=_container_alert,
        config=config.get("container_monitor", {}),
        log_dir=log_dir,
    )

    # ===================================================================
    # WIRING - Event Callbacks
    # ===================================================================

    def on_honeypot_event(event):
        """Central handler for honeypot events - IDS, auto-ban, scoring, behavior."""
        attack = ids.analyze_honeypot_event(event)
        auto_ban.process_honeypot_event(event)
        threat_scorer.process_honeypot_event(event)

        # Behavioral analysis - detects unknown attacks by behavior patterns
        behavior_alerts = behavior.process_event(event)
        for ba in behavior_alerts:
            if ba.get("severity") in ("CRITICAL", "HIGH"):
                auto_ban.ban_ip(
                    ba.get("source_ip", ""),
                    reason=f"Behavior: {ba.get('type', 'unknown')}",
                    severity=ba.get("severity", "HIGH"),
                )

        alert_mgr.handle_alert({
            "type": event.get("honeypot", "?").upper() + "_HIT",
            "severity": "HIGH" if attack else "MEDIUM",
            "source_ip": event.get("source_ip", ""),
            "description": f"Honeypot: {event.get('honeypot', '?')} from {event.get('source_ip', '?')}",
            "timestamp": event.get("timestamp", ""),
        })

        ti = event.get("threat_intel", {})
        if ti.get("threat"):
            sources = ti.get("sources", [])
            feed = sources[0].get("feed", "?") if sources else "unknown"
            auto_ban.ban_ip(
                event.get("source_ip", ""),
                reason=f"Threat Intel: {feed}",
                severity="CRITICAL",
            )

    honeypot_mgr.on_alert(on_honeypot_event)

    def on_attack(a):
        """IDS attack callback - auto-ban + alert + scoring."""
        auto_ban.process_attack(a)
        alert_mgr.handle_alert(a)
        threat_scorer.process_attack(a)

    ids.on_attack(on_attack)

    def on_net_alert(a):
        """Network monitor alert callback."""
        if a.get("type") == "PORT_SCAN_DETECTED":
            auto_ban.process_port_scan(a.get("source_ip", ""))
        alert_mgr.handle_alert(a)

    net_monitor.on_alert(on_net_alert)

    # Wire all monitors to alert manager
    arp_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))
    proc_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))
    fim.on_alert(lambda a: alert_mgr.handle_alert(a))
    outbound.on_alert(lambda a: alert_mgr.handle_alert(a))
    behavior.on_alert(lambda a: alert_mgr.handle_alert(a))
    anti_ddos.on_alert(lambda a: alert_mgr.handle_alert(a))
    anti_keylogger.on_alert(lambda a: alert_mgr.handle_alert(a))
    privacy_guard.on_alert(lambda a: alert_mgr.handle_alert(a))
    browser_guard.on_alert(lambda a: alert_mgr.handle_alert(a))
    reg_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))
    bw_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))
    canary.on_alert(lambda a: alert_mgr.handle_alert(a))
    eventlog.on_alert(lambda a: alert_mgr.handle_alert(a))
    usb_mon.on_alert(lambda a: alert_mgr.handle_alert(a))

    # ===================================================================
    # WEB DASHBOARD
    # ===================================================================
    dashboard = WebDashboard(
        honeypot_manager=honeypot_mgr,
        network_monitor=net_monitor,
        intrusion_detector=ids,
        auto_ban=auto_ban,
        geoip=geoip,
        threat_intel=threat_intel,
        arp_monitor=arp_monitor,
        process_monitor=proc_monitor,
        file_integrity=fim,
        alert_manager=alert_mgr,
        threat_scorer=threat_scorer,
        canary_tokens=canary,
        usb_monitor=usb_mon,
        eventlog_monitor=eventlog,
        bandwidth_monitor=bw_monitor,
        outbound_analyzer=outbound,
        registry_monitor=reg_monitor,
        supply_chain=supply_chain,
        credential_monitor=credential_monitor,
        dependency_auditor=dependency_auditor,
        container_monitor=container_monitor,
    )

    # ===================================================================
    # LAUNCH ALL TASKS
    # ===================================================================
    print("\n[BLACKWALL] All systems nominal. Ctrl+C to disengage.\n")

    # Wrap each subsystem in a shielded task so one crash doesn't kill everything
    async def _guarded(coro, name="?"):
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[BLACKWALL] WARNING: {name} crashed: {type(e).__name__}: {e}")

    # Heavy monitors run their scans sequentially in one background task
    # so they don't block the async event loop (each scan calls PowerShell)
    async def _heavy_monitor_runner():
        """Run all heavy (subprocess-based) monitors sequentially in a loop."""
        await asyncio.sleep(12)  # Let honeypots + dashboard start first
        monitors = [
            (arp_monitor, "ARP"),
            (reg_monitor, "Registry"),
            (eventlog, "EventLog"),
            (usb_mon, "USB"),
            (anti_keylogger, "AntiKeylogger"),
            (privacy_guard, "PrivacyGuard"),
            (browser_guard, "BrowserGuard"),
        ]
        # Initialize all
        for mon, _ in monitors:
            mon._running = True

        while any(mon._running for mon, _ in monitors):
            for mon, label in monitors:
                if not mon._running or not getattr(mon, "enabled", True):
                    continue
                try:
                    mon.scan()
                except Exception as e:
                    pass  # Logged internally
                # Yield to event loop between each scan!
                await asyncio.sleep(0.5)
            # Wait between full rounds
            await asyncio.sleep(15)

    try:
        await asyncio.gather(
            # --- Honeypots (async, lightweight) ---
            _guarded(honeypot_mgr.start_all(), "Honeypots"),

            # --- Lightweight async monitors (pure async, no blocking) ---
            _guarded(net_monitor.monitor_loop(), "NetworkMonitor"),
            _guarded(threat_intel.refresh_loop(), "ThreatIntel"),
            _guarded(proc_monitor.monitor_loop(), "ProcessMonitor"),
            _guarded(fim.monitor_loop(), "FileIntegrity"),
            _guarded(outbound.monitor_loop(), "OutboundAnalyzer"),
            _guarded(bw_monitor.monitor_loop(), "BandwidthMonitor"),
            _guarded(canary.monitor_loop(), "CanaryTokens"),
            _guarded(anti_ddos.monitor_loop(), "AntiDDoS"),

            # --- Heavy monitors (ONE sequential runner, yields between scans) ---
            _guarded(_heavy_monitor_runner(), "HeavyMonitors"),

            # --- Supply Chain modules ---
            _guarded(supply_chain.start(), "SupplyChainGuardian"),
            _guarded(credential_monitor.start(), "CredentialVault"),
            _guarded(dependency_auditor.start(), "DependencyAuditor"),
            _guarded(container_monitor.start(), "ContainerSecurity"),

            # --- Web Dashboard (Flask in background thread + browser auto-open) ---
            _guarded(dashboard.start_async(), "WebDashboard"),
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    except Exception as e:
        print(f"\n[BLACKWALL] CRITICAL ERROR: {e}")
    finally:
        print("\n[BLACKWALL] Disengaging defensive systems...")

        # --- Generate final report ---
        try:
            from blackwall.utils.report_generator import generate_report
            rp = generate_report(
                honeypot_manager=honeypot_mgr,
                auto_ban=auto_ban,
                intrusion_detector=ids,
                threat_intel=threat_intel,
                network_monitor=net_monitor,
                arp_monitor=arp_monitor,
                process_monitor=proc_monitor,
                file_integrity=fim,
                registry_monitor=reg_monitor,
                bandwidth_monitor=bw_monitor,
                outbound_analyzer=outbound,
                output_dir=str(BLACKWALL_DIR / "reports"),
            )
            print(f"[BLACKWALL] Final report: {rp}")
        except Exception:
            pass

        # --- Stop all modules ---
        stop_coros = [
            # Core monitors
            honeypot_mgr.stop_all(),
            net_monitor.stop(),
            threat_intel.stop(),
            arp_monitor.stop(),
            proc_monitor.stop(),
            fim.stop(),
            outbound.stop(),
            reg_monitor.stop(),
            bw_monitor.stop(),
            canary.stop(),
            eventlog.stop(),
            usb_mon.stop(),
            # Defense monitors
            anti_ddos.stop(),
            anti_keylogger.stop(),
            privacy_guard.stop(),
            browser_guard.stop(),
            # Supply chain modules
            supply_chain.stop(),
            credential_monitor.stop(),
            dependency_auditor.stop(),
            container_monitor.stop(),
        ]

        for coro in stop_coros:
            try:
                await coro
            except Exception:
                pass

        # Web dashboard runs in daemon thread - stops automatically
        geoip.close()

        print("[BLACKWALL] All systems offline. The wall sleeps.")


# ═══════════════════════════════════════════════════════════════════════════
# CLI Commands
# ═══════════════════════════════════════════════════════════════════════════

def run_firewall_hardening():
    """Run Windows Firewall hardening script (requires Admin)."""
    script = BLACKWALL_DIR / "config" / "harden_firewall.ps1"
    if not script.exists():
        print(f"[BLACKWALL] ERROR: Firewall script not found: {script}")
        return
    os.system(f'powershell -ExecutionPolicy Bypass -File "{script}"')


def run_anti_tracking():
    """Run anti-tracking/telemetry script (requires Admin)."""
    script = BLACKWALL_DIR / "config" / "anti_tracking.ps1"
    if not script.exists():
        print(f"[BLACKWALL] ERROR: Anti-tracking script not found: {script}")
        return
    os.system(f'powershell -ExecutionPolicy Bypass -File "{script}"')


def generate_report_cmd():
    """Generate HTML security report from current logs."""
    config = load_config()
    log_dir = str(BLACKWALL_DIR / config.get("logging", {}).get("log_dir", "logs"))

    hm = HoneypotManager(config, log_dir=log_dir)
    ab = AutoBan(config, log_dir=log_dir)
    ids_i = IntrusionDetector(config, log_dir=log_dir)
    ti = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)

    from blackwall.utils.report_generator import generate_report
    rp = generate_report(
        honeypot_manager=hm,
        auto_ban=ab,
        intrusion_detector=ids_i,
        threat_intel=ti,
        output_dir=str(BLACKWALL_DIR / "reports"),
    )
    print(f"[BLACKWALL] Report generated: {rp}")
    try:
        os.startfile(rp)
    except Exception:
        print(f"[BLACKWALL] Open manually: {rp}")


def print_help():
    """Print CLI usage information."""
    print(r"""
 ╔══════════════════════════════════════════════════════════════╗
 ║              BLACKWALL v4.0 - Command Reference             ║
 ╠══════════════════════════════════════════════════════════════╣
 ║                                                              ║
 ║  python blackwall.py              Start full monitoring      ║
 ║  python blackwall.py harden       Firewall hardening (Admin) ║
 ║  python blackwall.py antitrack    Anti-tracking (Admin)      ║
 ║  python blackwall.py all          Everything (Admin)         ║
 ║  python blackwall.py report       Generate HTML report       ║
 ║  python blackwall.py help         This message               ║
 ║                                                              ║
 ╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def run_gui():
    """Launch BLACKWALL with desktop GUI (default mode)."""
    import threading

    print(BANNER)
    _print_startup()

    config = load_config()
    log_dir = str(BLACKWALL_DIR / config.get("logging", {}).get("log_dir", "logs"))

    # --- Initialize all backend modules (same as main()) ---
    from blackwall.monitor.geoip import GeoIPLookup
    geoip = GeoIPLookup(config.get("geoip", {}))
    threat_intel = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)
    alert_mgr = AlertManager(config.get("alerts", {}), log_dir=log_dir)
    threat_scorer = ThreatScorer()
    rate_limiter = RateLimiter(config.get("rate_limiter", {}))
    behavior = BehaviorEngine(config.get("behavior_engine", {}))
    honeypot_mgr = HoneypotManager(config, log_dir=log_dir, geoip=geoip, threat_intel=threat_intel)
    net_monitor = NetworkMonitor(config, log_dir=log_dir)
    ids = IntrusionDetector(config, log_dir=log_dir)
    auto_ban = AutoBan(config, log_dir=log_dir)

    # Supply chain
    async def _noop_alert(e): pass
    supply_chain = SupplyChainGuardian(config=config.get("supply_chain", {}), alert_callback=_noop_alert, log_dir=log_dir)
    credential_monitor = CredentialVaultMonitor(config=config.get("credential_monitor", {}), alert_callback=_noop_alert, log_dir=log_dir)
    dependency_auditor = DependencyAuditor(alert_callback=_noop_alert, log_dir=log_dir)
    container_monitor = ContainerSecurityMonitor(alert_callback=_noop_alert, config=config.get("container_monitor", {}), log_dir=log_dir)

    # --- Create GUI ---
    gui = BlackwallGUI()
    gui.set_backend({
        "honeypot_manager": honeypot_mgr,
        "network_monitor": net_monitor,
        "intrusion_detector": ids,
        "auto_ban": auto_ban,
        "geoip": geoip,
        "threat_intel": threat_intel,
        "threat_scorer": threat_scorer,
        "behavior_engine": behavior,
        "alert_manager": alert_mgr,
        "supply_chain": supply_chain,
        "credential_monitor": credential_monitor,
        "dependency_auditor": dependency_auditor,
        "container_monitor": container_monitor,
    })

    # --- Start backend in background thread ---
    def _run_backend():
        asyncio.run(main())

    backend_thread = threading.Thread(target=_run_backend, daemon=True)
    backend_thread.start()

    print("[BLACKWALL] GUI launching...\n")

    # --- GUI mainloop (must be on main thread) ---
    gui.start()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        commands = {
            "harden": run_firewall_hardening,
            "antitrack": run_anti_tracking,
            "report": generate_report_cmd,
            "help": print_help,
        }

        if cmd in commands:
            commands[cmd]()
        elif cmd == "all":
            run_firewall_hardening()
            print()
            run_anti_tracking()
            print()
            run_gui()
        elif cmd == "headless":
            # Run without GUI (background/service mode)
            asyncio.run(main())
        else:
            print(f"[BLACKWALL] Unknown command: {cmd}")
            print_help()
    else:
        run_gui()
