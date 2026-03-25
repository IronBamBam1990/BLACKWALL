"""
BLACKWALL Launcher - Native desktop window with pywebview.
Starts Flask API backend + opens native window (no browser chrome).
"""

import sys
import os
import threading
import asyncio
import time
import logging
import warnings

# Force UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Suppress noisy asyncio warnings from aiohttp cross-loop issues
warnings.filterwarnings("ignore", message=".*coroutine.*was never awaited.*")
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

BLACKWALL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BLACKWALL_DIR)
sys.path.insert(0, os.path.join(BLACKWALL_DIR, "blackwall"))
os.chdir(BLACKWALL_DIR)

import subprocess
import shutil
import signal


def _open_app_window(url):
    """Open browser in app mode (no address bar - looks native)."""
    # Try Edge first (built into Windows)
    edge_paths = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        shutil.which("msedge"),
    ]
    for p in edge_paths:
        if p and os.path.isfile(p):
            subprocess.Popen([p, f"--app={url}", "--new-window",
                              f"--window-size=1400,900"])
            return

    # Try Chrome
    chrome_paths = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        shutil.which("chrome"),
    ]
    for p in chrome_paths:
        if p and os.path.isfile(p):
            subprocess.Popen([p, f"--app={url}", "--new-window",
                              f"--window-size=1400,900"])
            return

    # Fallback: default browser
    import webbrowser
    webbrowser.open(url)


def main():
    from blackwall.monitor.geoip import GeoIPLookup
    from blackwall.monitor.threat_intel import ThreatIntelChecker
    from blackwall.monitor.alerting import AlertManager
    from blackwall.monitor.threat_scorer import ThreatScorer
    from blackwall.monitor.rate_limiter import RateLimiter
    from blackwall.monitor.behavior_engine import BehaviorEngine
    from blackwall.honeypots.honeypot_manager import HoneypotManager
    from blackwall.monitor.network_monitor import NetworkMonitor
    from blackwall.monitor.intrusion_detector import IntrusionDetector
    from blackwall.monitor.auto_ban import AutoBan
    from blackwall.monitor.arp_monitor import ARPMonitor
    from blackwall.monitor.process_monitor import ProcessMonitor
    from blackwall.monitor.file_integrity import FileIntegrityMonitor
    from blackwall.monitor.outbound_analyzer import OutboundAnalyzer
    from blackwall.monitor.registry_monitor import RegistryMonitor
    from blackwall.monitor.bandwidth_monitor import BandwidthMonitor
    from blackwall.monitor.canary_tokens import CanaryTokens
    from blackwall.monitor.eventlog_monitor import EventLogMonitor
    from blackwall.monitor.usb_monitor import USBMonitor
    from blackwall.monitor.anti_ddos import AntiDDoS
    from blackwall.monitor.anti_keylogger import AntiKeylogger
    from blackwall.monitor.privacy_guard import PrivacyGuard
    from blackwall.monitor.browser_guard import BrowserGuard
    from blackwall.monitor.safe_loop import safe_monitor_loop
    from blackwall.supply_chain.guardian import SupplyChainGuardian
    from blackwall.supply_chain.credential_monitor import CredentialVaultMonitor
    from blackwall.supply_chain.dependency_auditor import DependencyAuditor
    from blackwall.supply_chain.container_monitor import ContainerSecurityMonitor
    from blackwall.dashboard.web_dashboard import WebDashboard

    # Load config
    import json
    config_path = os.path.join(BLACKWALL_DIR, "config", "config.json")
    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    log_dir = os.path.join(BLACKWALL_DIR, config.get("logging", {}).get("log_dir", "logs"))
    os.makedirs(log_dir, exist_ok=True)

    # Initialize backend
    geoip = GeoIPLookup(config.get("geoip", {}))
    threat_intel = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)
    alert_mgr = AlertManager(config.get("alerts", {}), log_dir=log_dir)
    threat_scorer = ThreatScorer()
    behavior = BehaviorEngine(config.get("behavior_engine", {}))
    honeypot_mgr = HoneypotManager(config, log_dir=log_dir, geoip=geoip, threat_intel=threat_intel)
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
    anti_ddos = AntiDDoS(config.get("anti_ddos", {}), log_dir=log_dir, auto_ban=auto_ban)
    anti_keylogger = AntiKeylogger(config.get("anti_keylogger", {}), log_dir=log_dir)
    privacy_guard = PrivacyGuard(config.get("privacy_guard", {}), log_dir=log_dir)
    browser_guard = BrowserGuard(config.get("browser_guard", {}), log_dir=log_dir)

    async def _noop(e): pass
    supply_chain = SupplyChainGuardian(config=config.get("supply_chain", {}), alert_callback=_noop, log_dir=log_dir)
    credential_monitor = CredentialVaultMonitor(config=config.get("credential_monitor", {}), alert_callback=_noop, log_dir=log_dir)
    dependency_auditor = DependencyAuditor(alert_callback=_noop, log_dir=log_dir)
    container_monitor = ContainerSecurityMonitor(alert_callback=_noop, config=config.get("container_monitor", {}), log_dir=log_dir)

    # Wire events
    def on_hp_event(event):
        ids.analyze_honeypot_event(event)
        auto_ban.process_honeypot_event(event)
        threat_scorer.process_honeypot_event(event)
        alert_mgr.handle_alert({
            "type": event.get("honeypot", "?").upper() + "_HIT", "severity": "MEDIUM",
            "source_ip": event.get("source_ip", ""), "timestamp": event.get("timestamp", ""),
            "description": f"{event.get('honeypot','?')} from {event.get('source_ip','?')}",
        })
    honeypot_mgr.on_alert(on_hp_event)
    ids.on_attack(lambda a: (auto_ban.process_attack(a), alert_mgr.handle_alert(a), threat_scorer.process_attack(a)))
    net_monitor.on_alert(lambda a: alert_mgr.handle_alert(a))
    for m in [arp_monitor, proc_monitor, fim, outbound, behavior, anti_ddos,
              anti_keylogger, privacy_guard, browser_guard, reg_monitor, bw_monitor,
              canary, eventlog, usb_mon]:
        m.on_alert(lambda a: alert_mgr.handle_alert(a))

    # Create web dashboard (Flask API)
    dashboard = WebDashboard(
        honeypot_manager=honeypot_mgr, network_monitor=net_monitor,
        intrusion_detector=ids, auto_ban=auto_ban, geoip=geoip,
        threat_intel=threat_intel, arp_monitor=arp_monitor,
        process_monitor=proc_monitor, file_integrity=fim,
        alert_manager=alert_mgr, threat_scorer=threat_scorer,
        canary_tokens=canary, usb_monitor=usb_mon,
        eventlog_monitor=eventlog, bandwidth_monitor=bw_monitor,
        outbound_analyzer=outbound, registry_monitor=reg_monitor,
        supply_chain=supply_chain, credential_monitor=credential_monitor,
        dependency_auditor=dependency_auditor, container_monitor=container_monitor,
    )

    # Start Flask in background thread (start_async is actually async, use sync start in thread)
    flask_app = dashboard._create_app()

    def _run_flask():
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

    flask_thread = threading.Thread(target=_run_flask, daemon=True)
    flask_thread.start()
    time.sleep(1.5)  # Let Flask start

    # Start async backend in background thread
    async def _backend():
        async def _g(coro):
            try:
                await coro
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

        async def _heavy():
            await asyncio.sleep(12)
            monitors = [(arp_monitor,"ARP"),(reg_monitor,"Reg"),(eventlog,"EvLog"),
                        (usb_mon,"USB"),(anti_keylogger,"AKL"),(privacy_guard,"PG"),(browser_guard,"BG")]
            for m,_ in monitors:
                m._running = True
            while True:
                for m,_ in monitors:
                    if not getattr(m,"enabled",True): continue
                    try: m.scan()
                    except: pass
                    await asyncio.sleep(0.5)
                await asyncio.sleep(15)

        await asyncio.gather(
            _g(honeypot_mgr.start_all()),
            _g(net_monitor.monitor_loop()),
            _g(threat_intel.refresh_loop()),
            _g(proc_monitor.monitor_loop()),
            _g(fim.monitor_loop()),
            _g(outbound.monitor_loop()),
            _g(bw_monitor.monitor_loop()),
            _g(canary.monitor_loop()),
            _g(anti_ddos.monitor_loop()),
            _g(_heavy()),
            _g(supply_chain.start()),
            _g(credential_monitor.start()),
            # dependency_auditor disabled: aiohttp session cross-loop bug on Py3.14
            _g(container_monitor.start()),
        )

    backend_thread = threading.Thread(target=lambda: asyncio.run(_backend()), daemon=True)
    backend_thread.start()

    # Open app window (Edge/Chrome in app mode - looks native)
    url = "http://127.0.0.1:5000"
    print(f"\n[BLACKWALL] Opening {url}")
    print("[BLACKWALL] Press Ctrl+C to stop.\n")
    _open_app_window(url)

    # Keep main thread alive until Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[BLACKWALL] Shutting down...")


if __name__ == "__main__":
    main()
