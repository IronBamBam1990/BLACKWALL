"""
BLACKWALL Launcher - Full module startup.
Flask backend on main thread. Honeypots + threat_intel get own asyncio threads.
Supply chain modules each get own asyncio thread.
Heavy monitors share one sequential scan thread.
Lightweight monitors share another sequential scan thread.
"""

import sys
import os
import threading
import time
import json
import logging
import subprocess
import shutil
import webbrowser

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Suppress noise
logging.getLogger("werkzeug").setLevel(logging.ERROR)

BLACKWALL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BLACKWALL_DIR)
os.chdir(BLACKWALL_DIR)

from blackwall.dashboard.web_dashboard import WebDashboard


def _open_app_window(url):
    """Open Edge/Chrome in app mode."""
    edge = os.path.expandvars(
        r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
    )
    if not os.path.isfile(edge):
        edge = os.path.expandvars(
            r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
        )
    if os.path.isfile(edge):
        subprocess.Popen([edge, f"--app={url}", "--new-window", "--window-size=1400,900"])
        return
    webbrowser.open(url)


def load_config():
    p = os.path.join(BLACKWALL_DIR, "config", "config.json")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def main():
    config = load_config()
    log_dir = os.path.join(BLACKWALL_DIR, config.get("logging", {}).get("log_dir", "logs"))
    os.makedirs(log_dir, exist_ok=True)

    # ---- Init backend modules ----
    from blackwall.monitor.geoip import GeoIPLookup
    from blackwall.monitor.threat_intel import ThreatIntelChecker
    from blackwall.monitor.alerting import AlertManager
    from blackwall.monitor.threat_scorer import ThreatScorer
    from blackwall.monitor.behavior_engine import BehaviorEngine
    from blackwall.honeypots.honeypot_manager import HoneypotManager
    from blackwall.monitor.network_monitor import NetworkMonitor
    from blackwall.monitor.intrusion_detector import IntrusionDetector
    from blackwall.monitor.auto_ban import AutoBan

    # Heavy monitors
    from blackwall.monitor.arp_monitor import ARPMonitor
    from blackwall.monitor.registry_monitor import RegistryMonitor
    from blackwall.monitor.eventlog_monitor import EventLogMonitor
    from blackwall.monitor.usb_monitor import USBMonitor
    from blackwall.monitor.anti_keylogger import AntiKeylogger
    from blackwall.monitor.privacy_guard import PrivacyGuard
    from blackwall.monitor.browser_guard import BrowserGuard

    # Lightweight monitors
    from blackwall.monitor.process_monitor import ProcessMonitor
    from blackwall.monitor.file_integrity import FileIntegrityMonitor
    from blackwall.monitor.outbound_analyzer import OutboundAnalyzer
    from blackwall.monitor.bandwidth_monitor import BandwidthMonitor
    from blackwall.monitor.canary_tokens import CanaryTokens
    from blackwall.monitor.anti_ddos import AntiDDoS

    # RAM checker + TeamPCP detector
    from blackwall.monitor.ram_checker import RAMChecker
    from blackwall.monitor.teampcp_detector import TeamPCPDetector

    # Supply chain modules
    from blackwall.supply_chain.guardian import SupplyChainGuardian
    from blackwall.supply_chain.credential_monitor import CredentialVaultMonitor
    from blackwall.supply_chain.dependency_auditor import DependencyAuditor
    from blackwall.supply_chain.container_monitor import ContainerSecurityMonitor

    # ---- Instantiate core modules ----
    geoip = GeoIPLookup(config.get("geoip", {}))
    threat_intel = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)
    alert_mgr = AlertManager(config.get("alerts", {}), log_dir=log_dir)
    threat_scorer = ThreatScorer()
    behavior = BehaviorEngine(config.get("behavior_engine", {}))
    honeypot_mgr = HoneypotManager(config, log_dir=log_dir, geoip=geoip, threat_intel=threat_intel)
    net_monitor = NetworkMonitor(config, log_dir=log_dir)
    ids = IntrusionDetector(config, log_dir=log_dir)
    auto_ban = AutoBan(config, log_dir=log_dir)

    # ---- Instantiate heavy monitors ----
    arp_monitor = ARPMonitor(config=config.get("arp_monitor", {}), log_dir=log_dir)
    registry_monitor = RegistryMonitor(config=config.get("registry_monitor", {}), log_dir=log_dir)
    eventlog_monitor = EventLogMonitor(config=config.get("eventlog_monitor", {}), log_dir=log_dir)
    usb_monitor = USBMonitor(config=config.get("usb_monitor", {}), log_dir=log_dir)
    anti_keylogger = AntiKeylogger(config=config.get("anti_keylogger", {}), log_dir=log_dir)
    privacy_guard = PrivacyGuard(config=config.get("privacy_guard", {}), log_dir=log_dir)
    browser_guard = BrowserGuard(config=config.get("browser_guard", {}), log_dir=log_dir)

    # ---- Instantiate lightweight monitors ----
    process_monitor = ProcessMonitor(config=config.get("process_monitor", {}), log_dir=log_dir)
    file_integrity = FileIntegrityMonitor(config=config.get("file_integrity", {}), log_dir=log_dir)
    outbound_analyzer = OutboundAnalyzer(config=config.get("outbound_analyzer", {}), log_dir=log_dir)
    bandwidth_monitor = BandwidthMonitor(config=config.get("bandwidth_monitor", {}), log_dir=log_dir)
    canary_tokens = CanaryTokens(config=config.get("canary_tokens", {}), log_dir=log_dir)
    anti_ddos = AntiDDoS(config=config.get("anti_ddos", {}), log_dir=log_dir, auto_ban=auto_ban)

    # ---- Instantiate RAM checker + TeamPCP detector ----
    ram_checker = RAMChecker(config=config.get("ram_checker", {}), log_dir=log_dir)
    teampcp_detector = TeamPCPDetector(config=config.get("teampcp_detector", {}), log_dir=log_dir)

    # ---- Instantiate supply chain modules ----
    def _sc_alert(event):
        try:
            alert_mgr.handle_alert({
                "type": "SUPPLY_CHAIN_" + str(event.get("type", "")),
                "severity": event.get("severity", "HIGH"),
                "description": event.get("description", ""),
                "timestamp": event.get("timestamp", ""),
            })
        except Exception:
            pass

    supply_chain = SupplyChainGuardian(
        config=config.get("supply_chain", {}), alert_callback=_sc_alert, log_dir=log_dir,
    )
    credential_monitor = CredentialVaultMonitor(
        config=config.get("credential_monitor", {}), alert_callback=_sc_alert, log_dir=log_dir,
    )
    dependency_auditor = DependencyAuditor(
        alert_callback=_sc_alert, log_dir=log_dir,
    )
    container_monitor = ContainerSecurityMonitor(
        alert_callback=_sc_alert, config=config.get("container_monitor", {}), log_dir=log_dir,
    )

    # Wire events
    def on_hp_event(event):
        try:
            ids.analyze_honeypot_event(event)
            auto_ban.process_honeypot_event(event)
            threat_scorer.process_honeypot_event(event)
            alert_mgr.handle_alert({
                "type": event.get("honeypot", "?").upper() + "_HIT",
                "severity": "MEDIUM",
                "source_ip": event.get("source_ip", ""),
                "timestamp": event.get("timestamp", ""),
                "description": f"{event.get('honeypot','?')} from {event.get('source_ip','?')}",
            })
        except Exception:
            pass
    honeypot_mgr.on_alert(on_hp_event)

    def on_attack(a):
        try:
            auto_ban.process_attack(a)
            alert_mgr.handle_alert(a)
            threat_scorer.process_attack(a)
        except Exception:
            pass
    ids.on_attack(on_attack)
    net_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))

    # ---- Start honeypots in asyncio thread (DO NOT CHANGE) ----
    import asyncio

    def _run_honeypots():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(honeypot_mgr.start_all())
        except Exception as e:
            print(f"[BLACKWALL] Honeypots error: {e}")

    hp_thread = threading.Thread(target=_run_honeypots, daemon=True, name="honeypots")
    hp_thread.start()

    # ---- Start threat intel refresh in its own asyncio loop (DO NOT CHANGE) ----
    def _run_threat_intel():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(threat_intel.refresh_loop())
        except Exception:
            pass

    ti_thread = threading.Thread(target=_run_threat_intel, daemon=True, name="threat_intel")
    ti_thread.start()

    # ---- Start network monitor in its own asyncio loop ----
    def _run_network_monitor():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(net_monitor.monitor_loop())
        except Exception as e:
            print(f"[BLACKWALL] Network monitor error: {e}")

    threading.Thread(target=_run_network_monitor, daemon=True, name="network_monitor").start()

    # ---- Supply chain modules: each gets own asyncio event loop in own thread ----
    def _run_async_module(name, coro_func):
        """Start an async module's start() in its own event loop + thread."""
        def _runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(coro_func())
            except Exception as e:
                print(f"[BLACKWALL] {name} error: {e}")
        threading.Thread(target=_runner, daemon=True, name=name).start()

    _run_async_module("supply_chain", supply_chain.start)
    _run_async_module("credential_monitor", credential_monitor.start)
    _run_async_module("dependency_auditor", dependency_auditor.start)
    _run_async_module("container_monitor", container_monitor.start)

    # ---- Deploy canary tokens before scan loops ----
    try:
        canary_tokens.deploy()
    except Exception as e:
        print(f"[BLACKWALL] Canary deploy error: {e}")

    # ---- Build file integrity baseline ----
    try:
        if not file_integrity.load_baseline():
            file_integrity.build_baseline()
    except Exception as e:
        print(f"[BLACKWALL] FIM baseline error: {e}")

    # ---- Heavy monitors: sequential scan thread ----
    #  ARP, registry, eventlog, USB, anti_keylogger, privacy_guard, browser_guard
    def _heavy_monitor_loop():
        """Run heavy monitors one after another, forever, with sleep."""
        heavy_modules = [
            ("ARP", arp_monitor),
            ("Registry", registry_monitor),
            ("EventLog", eventlog_monitor),
            ("USB", usb_monitor),
            ("AntiKeylogger", anti_keylogger),
            ("PrivacyGuard", privacy_guard),
            ("BrowserGuard", browser_guard),
        ]
        print(f"[BLACKWALL] Heavy monitors started ({len(heavy_modules)} modules)")
        while True:
            for name, mod in heavy_modules:
                try:
                    mod.scan()
                except Exception as e:
                    print(f"[BLACKWALL] {name}.scan() error: {e}")
                time.sleep(2)
            # Full cycle done, pause before next round
            time.sleep(30)

    threading.Thread(target=_heavy_monitor_loop, daemon=True, name="heavy_monitors").start()

    # ---- Lightweight monitors: sequential scan thread ----
    #  process_monitor, file_integrity, outbound_analyzer, bandwidth_monitor,
    #  canary_tokens, anti_ddos, ram_checker
    def _light_monitor_loop():
        """Run lightweight monitors one after another, forever, with sleep."""
        light_modules = [
            ("ProcessMonitor", process_monitor, "scan"),
            ("FileIntegrity", file_integrity, "check"),
            ("OutboundAnalyzer", outbound_analyzer, "scan"),
            ("BandwidthMonitor", bandwidth_monitor, "sample"),
            ("CanaryTokens", canary_tokens, "check"),
            ("AntiDDoS", anti_ddos, "scan"),
            ("RAMChecker", ram_checker, "scan"),
            ("TeamPCP", teampcp_detector, "scan"),
        ]
        print(f"[BLACKWALL] Light monitors started ({len(light_modules)} modules)")
        while True:
            for name, mod, method in light_modules:
                try:
                    getattr(mod, method)()
                except Exception as e:
                    print(f"[BLACKWALL] {name}.{method}() error: {e}")
                time.sleep(1)
            # Full cycle done, pause before next round
            time.sleep(10)

    threading.Thread(target=_light_monitor_loop, daemon=True, name="light_monitors").start()

    # ---- Create dashboard (Flask) with ALL modules ----
    dashboard = WebDashboard(
        honeypot_manager=honeypot_mgr,
        network_monitor=net_monitor,
        intrusion_detector=ids,
        auto_ban=auto_ban,
        geoip=geoip,
        threat_intel=threat_intel,
        alert_manager=alert_mgr,
        threat_scorer=threat_scorer,
        arp_monitor=arp_monitor,
        process_monitor=process_monitor,
        file_integrity=file_integrity,
        canary_tokens=canary_tokens,
        usb_monitor=usb_monitor,
        eventlog_monitor=eventlog_monitor,
        bandwidth_monitor=bandwidth_monitor,
        outbound_analyzer=outbound_analyzer,
        registry_monitor=registry_monitor,
        supply_chain=supply_chain,
        credential_monitor=credential_monitor,
        dependency_auditor=dependency_auditor,
        container_monitor=container_monitor,
        ram_checker=ram_checker,
        teampcp_detector=teampcp_detector,
    )

    flask_app = dashboard._create_app()

    # ---- Open browser after Flask starts ----
    def _open_delayed():
        time.sleep(2)
        url = "http://127.0.0.1:5000"
        print(f"\n[BLACKWALL] Dashboard: {url}")
        print("[BLACKWALL] Press Ctrl+C to stop.\n")
        _open_app_window(url)

    threading.Thread(target=_open_delayed, daemon=True).start()

    # ---- Run Flask on main thread (stable, no crashes) ----
    print("[BLACKWALL] Starting...")
    flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
