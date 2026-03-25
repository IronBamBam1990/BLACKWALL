"""
BLACKWALL Launcher - SIMPLE, STABLE version.
Flask backend + Edge app mode. No asyncio. No threading nightmares.
Honeypots start as simple TCP servers in threads.
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

    # ---- Init backend modules (NO asyncio) ----
    from blackwall.monitor.geoip import GeoIPLookup
    from blackwall.monitor.threat_intel import ThreatIntelChecker
    from blackwall.monitor.alerting import AlertManager
    from blackwall.monitor.threat_scorer import ThreatScorer
    from blackwall.monitor.behavior_engine import BehaviorEngine
    from blackwall.honeypots.honeypot_manager import HoneypotManager
    from blackwall.monitor.network_monitor import NetworkMonitor
    from blackwall.monitor.intrusion_detector import IntrusionDetector
    from blackwall.monitor.auto_ban import AutoBan

    geoip = GeoIPLookup(config.get("geoip", {}))
    threat_intel = ThreatIntelChecker(config.get("threat_intel", {}), log_dir=log_dir)
    alert_mgr = AlertManager(config.get("alerts", {}), log_dir=log_dir)
    threat_scorer = ThreatScorer()
    behavior = BehaviorEngine(config.get("behavior_engine", {}))
    honeypot_mgr = HoneypotManager(config, log_dir=log_dir, geoip=geoip, threat_intel=threat_intel)
    net_monitor = NetworkMonitor(config, log_dir=log_dir)
    ids = IntrusionDetector(config, log_dir=log_dir)
    auto_ban = AutoBan(config, log_dir=log_dir)

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

    # ---- Start honeypots in asyncio thread ----
    import asyncio

    def _run_honeypots():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(honeypot_mgr.start_all())
        except Exception as e:
            print(f"[BLACKWALL] Honeypots error: {e}")

    hp_thread = threading.Thread(target=_run_honeypots, daemon=True)
    hp_thread.start()

    # ---- Start threat intel refresh in its own asyncio loop ----
    def _run_threat_intel():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(threat_intel.refresh_loop())
        except Exception:
            pass

    ti_thread = threading.Thread(target=_run_threat_intel, daemon=True)
    ti_thread.start()

    # ---- Create dashboard (Flask) ----
    dashboard = WebDashboard(
        honeypot_manager=honeypot_mgr,
        network_monitor=net_monitor,
        intrusion_detector=ids,
        auto_ban=auto_ban,
        geoip=geoip,
        threat_intel=threat_intel,
        alert_manager=alert_mgr,
        threat_scorer=threat_scorer,
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
