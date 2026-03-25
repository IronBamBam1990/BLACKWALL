"""
HTML Report Generator - Generuje czytelny raport bezpieczenstwa w HTML.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(
    honeypot_manager=None, auto_ban=None, intrusion_detector=None,
    threat_intel=None, network_monitor=None, arp_monitor=None,
    process_monitor=None, file_integrity=None, registry_monitor=None,
    bandwidth_monitor=None, outbound_analyzer=None,
    output_dir: str = "reports",
) -> str:
    """Generuje HTML raport i zwraca sciezke do pliku."""

    now = datetime.now(timezone.utc)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"security_report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    filepath = out_dir / filename

    # Zbierz dane
    hp_stats = honeypot_manager.get_stats() if honeypot_manager else {}
    ban_list = auto_ban.get_ban_list() if auto_ban else {}
    ban_stats = auto_ban.get_stats() if auto_ban else {}
    ids_stats = intrusion_detector.get_attack_stats() if intrusion_detector else {}
    ti_stats = threat_intel.get_stats() if threat_intel else {}
    arp_stats = arp_monitor.get_stats() if arp_monitor else {}
    proc_stats = process_monitor.get_stats() if process_monitor else {}
    fim_stats = file_integrity.get_stats() if file_integrity else {}
    reg_stats = registry_monitor.get_stats() if registry_monitor else {}
    bw_stats = bandwidth_monitor.get_stats() if bandwidth_monitor else {}
    ob_stats = outbound_analyzer.get_stats() if outbound_analyzer else {}

    # Top attackers
    top_ips = sorted(hp_stats.get("by_ip", {}).items(), key=lambda x: x[1], reverse=True)[:20]
    top_countries = sorted(hp_stats.get("by_country", {}).items(), key=lambda x: x[1], reverse=True)[:15]

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report - {now.strftime('%Y-%m-%d %H:%M')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a1a;color:#e0e0e0;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}
h1{{color:#ff4444;font-size:28px;padding:20px 0;border-bottom:2px solid #ff4444;margin-bottom:20px}}
h2{{color:#00bcd4;font-size:20px;margin:25px 0 10px;padding:8px 0;border-bottom:1px solid #1a3a4a}}
h3{{color:#ff9800;font-size:16px;margin:15px 0 8px}}
.meta{{color:#888;font-size:13px;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;margin:15px 0}}
.card{{background:#111;border:1px solid #222;border-radius:8px;padding:15px}}
.card-title{{color:#00bcd4;font-size:14px;font-weight:bold;margin-bottom:10px;text-transform:uppercase}}
.stat{{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a2a}}
.stat-label{{color:#888}}
.stat-value{{color:#fff;font-weight:bold}}
.stat-value.danger{{color:#ff4444}}
.stat-value.warning{{color:#ff9800}}
.stat-value.ok{{color:#4caf50}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th{{background:#1a1a2a;color:#00bcd4;text-align:left;padding:8px 12px;font-size:13px}}
td{{padding:8px 12px;border-bottom:1px solid #1a1a2a;font-size:13px}}
tr:hover{{background:#111}}
.severity-CRITICAL{{color:#ff0000;font-weight:bold}}
.severity-HIGH{{color:#ff4444}}
.severity-MEDIUM{{color:#ff9800}}
.severity-LOW{{color:#888}}
.tag{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}}
.tag-red{{background:#4a0000;color:#ff4444;border:1px solid #ff4444}}
.tag-green{{background:#004a00;color:#4caf50;border:1px solid #4caf50}}
.tag-yellow{{background:#4a4a00;color:#ff9800;border:1px solid #ff9800}}
.summary{{background:#1a0000;border:1px solid #ff4444;border-radius:8px;padding:20px;margin:15px 0}}
.summary h3{{color:#ff4444;margin-bottom:10px}}
footer{{text-align:center;color:#555;padding:30px 0;font-size:12px;border-top:1px solid #222;margin-top:30px}}
</style>
</head>
<body>
<div class="container">
<h1>SECURITY SUITE - RAPORT BEZPIECZENSTWA</h1>
<p class="meta">Wygenerowany: {now.strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Suite v2.1</p>

<div class="summary">
<h3>PODSUMOWANIE</h3>
<div class="grid">
<div class="card">
<div class="card-title">Honeypot Events</div>
<div class="stat"><span class="stat-label">Total</span><span class="stat-value {'danger' if hp_stats.get('total_events',0)>0 else 'ok'}">{hp_stats.get('total_events', 0)}</span></div>
<div class="stat"><span class="stat-label">Unique IPs</span><span class="stat-value">{len(hp_stats.get('by_ip',{}))}</span></div>
<div class="stat"><span class="stat-label">Countries</span><span class="stat-value">{len(hp_stats.get('by_country',{}))}</span></div>
</div>
<div class="card">
<div class="card-title">Security</div>
<div class="stat"><span class="stat-label">Banned IPs</span><span class="stat-value {'danger' if len(ban_list)>0 else 'ok'}">{len(ban_list)}</span></div>
<div class="stat"><span class="stat-label">Attacks Detected</span><span class="stat-value {'danger' if ids_stats.get('total_attacks',0)>0 else 'ok'}">{ids_stats.get('total_attacks', 0)}</span></div>
<div class="stat"><span class="stat-label">Threat Intel IPs</span><span class="stat-value">{ti_stats.get('total_bad_ips', 0)}</span></div>
</div>
<div class="card">
<div class="card-title">Integrity</div>
<div class="stat"><span class="stat-label">FIM Changes</span><span class="stat-value {'danger' if fim_stats.get('changes_detected',0)>0 else 'ok'}">{fim_stats.get('changes_detected', 0)}</span></div>
<div class="stat"><span class="stat-label">ARP Alerts</span><span class="stat-value {'danger' if arp_stats.get('alerts',0)>0 else 'ok'}">{arp_stats.get('alerts', 0)}</span></div>
<div class="stat"><span class="stat-label">Registry Changes</span><span class="stat-value">{reg_stats.get('alerts', 0)}</span></div>
</div>
<div class="card">
<div class="card-title">Network</div>
<div class="stat"><span class="stat-label">Bandwidth Upload</span><span class="stat-value">{bw_stats.get('send_rate', 'N/A')}</span></div>
<div class="stat"><span class="stat-label">Bandwidth Download</span><span class="stat-value">{bw_stats.get('recv_rate', 'N/A')}</span></div>
<div class="stat"><span class="stat-label">Outbound Alerts</span><span class="stat-value {'danger' if ob_stats.get('alerts',0)>0 else 'ok'}">{ob_stats.get('alerts', 0)}</span></div>
</div>
</div>
</div>

<h2>HONEYPOT ACTIVITY</h2>
<table>
<tr><th>Honeypot</th><th>Hits</th></tr>
"""
    for hp_type, count in sorted(hp_stats.get("by_type", {}).items(), key=lambda x: x[1], reverse=True):
        html += f"<tr><td>{hp_type.upper()}</td><td>{count}</td></tr>\n"
    html += "</table>\n"

    if top_ips:
        html += "<h2>TOP ATTACKER IPs</h2>\n<table>\n<tr><th>IP</th><th>Hits</th><th>Country</th><th>Banned</th></tr>\n"
        for ip, count in top_ips:
            cc = ""  # GeoIP lookup would be needed per-IP; by_country is keyed by country code not IP
            banned = "Yes" if ip in ban_list else "No"
            b_class = "tag-red" if banned == "Yes" else "tag-green"
            html += f'<tr><td>{ip}</td><td>{count}</td><td>{cc}</td><td><span class="tag {b_class}">{banned}</span></td></tr>\n'
        html += "</table>\n"

    if top_countries:
        html += "<h2>ATTACK ORIGINS</h2>\n<table>\n<tr><th>Country</th><th>Hits</th></tr>\n"
        for cc, count in top_countries:
            html += f"<tr><td>{cc}</td><td>{count}</td></tr>\n"
        html += "</table>\n"

    if ban_list:
        html += "<h2>BANNED IPs</h2>\n<table>\n<tr><th>IP</th><th>Reason</th><th>Severity</th><th>Firewall</th><th>Banned At</th></tr>\n"
        for ip, info in ban_list.items():
            reasons = info.get("reasons", [])
            reason = reasons[-1] if reasons else "?"
            sev = info.get("severity", "")
            fw = "Yes" if info.get("firewall_rule_added") else "No"
            html += f'<tr><td>{ip}</td><td>{reason}</td><td class="severity-{sev}">{sev}</td><td>{fw}</td><td>{info.get("banned_at","")}</td></tr>\n'
        html += "</table>\n"

    # Attacks
    if ids_stats.get("recent"):
        html += "<h2>RECENT ATTACKS</h2>\n<table>\n<tr><th>Time</th><th>Type</th><th>IP</th><th>Severity</th><th>Description</th></tr>\n"
        for a in ids_stats["recent"]:
            html += f'<tr><td>{a.get("timestamp","")[:19]}</td><td>{a.get("type","")}</td><td>{a.get("source_ip","")}</td><td class="severity-{a.get("severity","")}">{a.get("severity","")}</td><td>{a.get("description","")}</td></tr>\n'
        html += "</table>\n"

    # Threat Intel
    if ti_stats.get("feeds"):
        html += "<h2>THREAT INTELLIGENCE FEEDS</h2>\n<table>\n<tr><th>Feed</th><th>Bad IPs</th><th>Last Update</th></tr>\n"
        for name, fi in ti_stats["feeds"].items():
            html += f'<tr><td>{fi.get("description", name)}</td><td>{fi.get("count",0)}</td><td>{fi.get("last_update","")[:19]}</td></tr>\n'
        html += "</table>\n"

    html += f"""
<footer>
Security Suite v2.1 | Report generated at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
</footer>
</div>
</body>
</html>"""

    filepath.write_text(html, encoding="utf-8")
    return str(filepath)
