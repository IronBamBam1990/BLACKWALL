"""
BLACKWALL Web Dashboard - Flask-based security monitoring backend.
Serves real-time JSON status from all BLACKWALL modules and a web UI.
"""

import asyncio
import ipaddress
import json
import logging
import os
import threading
import webbrowser
from datetime import datetime, timezone

import psutil

try:
    from flask import Flask, jsonify, render_template, request
except ImportError:
    raise ImportError("Flask is required: pip install flask")


class WebDashboard:
    """Flask-powered web dashboard for the BLACKWALL security suite."""

    def __init__(
        self,
        honeypot_manager=None,
        network_monitor=None,
        intrusion_detector=None,
        auto_ban=None,
        geoip=None,
        threat_intel=None,
        arp_monitor=None,
        process_monitor=None,
        file_integrity=None,
        alert_manager=None,
        threat_scorer=None,
        canary_tokens=None,
        usb_monitor=None,
        eventlog_monitor=None,
        bandwidth_monitor=None,
        outbound_analyzer=None,
        registry_monitor=None,
        supply_chain=None,
        credential_monitor=None,
        dependency_auditor=None,
        container_monitor=None,
        ram_checker=None,
    ):
        self.honeypot_mgr = honeypot_manager
        self.net_monitor = network_monitor
        self.ids = intrusion_detector
        self.auto_ban = auto_ban
        self.geoip = geoip
        self.threat_intel = threat_intel
        self.arp_monitor = arp_monitor
        self.proc_monitor = process_monitor
        self.fim = file_integrity
        self.alert_mgr = alert_manager
        self.threat_scorer = threat_scorer
        self.canary = canary_tokens
        self.usb_mon = usb_monitor
        self.eventlog = eventlog_monitor
        self.bw_mon = bandwidth_monitor
        self.outbound = outbound_analyzer
        self.reg_mon = registry_monitor
        self.supply_chain = supply_chain
        self.credential_monitor = credential_monitor
        self.dependency_auditor = dependency_auditor
        self.container_monitor = container_monitor
        self.ram_checker = ram_checker

        self._app = None
        self._thread = None

    # ------------------------------------------------------------------
    #  Flask app factory
    # ------------------------------------------------------------------

    def _create_app(self) -> Flask:
        app = Flask(__name__, template_folder="templates")
        app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

        # Silence Flask/Werkzeug request logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        app.logger.setLevel(logging.ERROR)

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/api/status")
        def api_status():
            return jsonify(self._collect_status())

        # --------------------------------------------------------------
        #  Action endpoints (POST, JSON)
        # --------------------------------------------------------------

        @app.route("/api/honeypot/toggle", methods=["POST"])
        def api_honeypot_toggle():
            try:
                if not self.honeypot_mgr:
                    return jsonify({"ok": False, "error": "Honeypot manager not available"}), 503
                data = request.get_json(force=True)
                name = data.get("name")
                enabled = data.get("enabled")
                if name is None or enabled is None:
                    return jsonify({"ok": False, "error": "Missing 'name' or 'enabled'"}), 400
                target = None
                for hp in self.honeypot_mgr.honeypots:
                    if hp.name.lower() == name.lower():
                        target = hp
                        break
                if target is None:
                    return jsonify({"ok": False, "error": f"Honeypot '{name}' not found"}), 404
                if enabled:
                    def _start_hp():
                        asyncio.run(target.start())
                    threading.Thread(target=_start_hp, daemon=True).start()
                else:
                    def _stop_hp():
                        asyncio.run(target.stop())
                    threading.Thread(target=_stop_hp, daemon=True).start()
                return jsonify({"ok": True, "name": name, "enabled": enabled})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/honeypot/start_all", methods=["POST"])
        def api_honeypot_start_all():
            try:
                if not self.honeypot_mgr:
                    return jsonify({"ok": False, "error": "Honeypot manager not available"}), 503
                def _start():
                    asyncio.run(self.honeypot_mgr.start_all())
                threading.Thread(target=_start, daemon=True).start()
                return jsonify({"ok": True, "message": "Starting all honeypots"})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/honeypot/stop_all", methods=["POST"])
        def api_honeypot_stop_all():
            try:
                if not self.honeypot_mgr:
                    return jsonify({"ok": False, "error": "Honeypot manager not available"}), 503
                def _stop():
                    asyncio.run(self.honeypot_mgr.stop_all())
                threading.Thread(target=_stop, daemon=True).start()
                return jsonify({"ok": True, "message": "Stopping all honeypots"})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/ban", methods=["POST"])
        def api_ban():
            try:
                if not self.auto_ban:
                    return jsonify({"ok": False, "error": "Auto-ban module not available"}), 503
                data = request.get_json(force=True)
                ip = data.get("ip")
                reason = data.get("reason", "manual ban")
                if not ip:
                    return jsonify({"ok": False, "error": "Missing 'ip'"}), 400
                self.auto_ban.ban_ip(ip, reason=reason, severity="HIGH")
                return jsonify({"ok": True, "ip": ip})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/unban", methods=["POST"])
        def api_unban():
            try:
                if not self.auto_ban:
                    return jsonify({"ok": False, "error": "Auto-ban module not available"}), 503
                data = request.get_json(force=True)
                ip = data.get("ip")
                if not ip:
                    return jsonify({"ok": False, "error": "Missing 'ip'"}), 400
                threading.Thread(target=self.auto_ban.unban_ip, args=(ip,), daemon=True).start()
                return jsonify({"ok": True, "ip": ip})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/whitelist/add", methods=["POST"])
        def api_whitelist_add():
            try:
                if not self.auto_ban:
                    return jsonify({"ok": False, "error": "Auto-ban module not available"}), 503
                data = request.get_json(force=True)
                ip = data.get("ip")
                if not ip:
                    return jsonify({"ok": False, "error": "Missing 'ip'"}), 400
                # Parse to ip_network/ip_address to match whitelist type
                try:
                    entry = ipaddress.ip_network(ip, strict=False)
                except ValueError:
                    try:
                        entry = ipaddress.ip_address(ip)
                    except ValueError:
                        return jsonify({"ok": False, "error": f"Invalid IP/CIDR: {ip}"}), 400
                # Avoid duplicates
                for existing in self.auto_ban.whitelist:
                    if str(existing) == str(entry):
                        return jsonify({"ok": True, "message": "Already in whitelist"})
                self.auto_ban.whitelist.append(entry)
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/whitelist/remove", methods=["POST"])
        def api_whitelist_remove():
            try:
                if not self.auto_ban:
                    return jsonify({"ok": False, "error": "Auto-ban module not available"}), 503
                data = request.get_json(force=True)
                ip = data.get("ip")
                if not ip:
                    return jsonify({"ok": False, "error": "Missing 'ip'"}), 400
                # Find and remove by string comparison (whitelist has ip_network objects)
                removed = False
                for i, entry in enumerate(self.auto_ban.whitelist):
                    if str(entry) == ip:
                        self.auto_ban.whitelist.pop(i)
                        removed = True
                        break
                if not removed:
                    return jsonify({"ok": False, "error": f"'{ip}' not in whitelist"}), 404
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/scan/supply_chain", methods=["POST"])
        def api_scan_supply_chain():
            try:
                if not self.dependency_auditor:
                    return jsonify({"ok": False, "error": "Dependency auditor not available"}), 503

                def _run_audit():
                    asyncio.run(self.dependency_auditor.run_full_audit())

                threading.Thread(target=_run_audit, daemon=True).start()
                return jsonify({"ok": True, "message": "Scan started"})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        @app.route("/api/config/save", methods=["POST"])
        def api_config_save():
            try:
                data = request.get_json(force=True)
                config_path = os.path.join("config", "config.json")
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

        return app

    # ------------------------------------------------------------------
    #  Data collectors  (each returns a safe dict, never raises)
    # ------------------------------------------------------------------

    def _collect_status(self) -> dict:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        net_data = self._get_network()
        return {
            "time": now,
            "honeypots": self._get_honeypots(),
            "alerts": self._get_alerts(),
            "banned": self._get_banned(),
            "network": net_data,
            "connections": net_data.get("connections", []),
            "whitelist": self._get_whitelist(),
            "countries": self._get_countries(),
            "feeds": self._get_feeds(),
            "attackers": self._get_attackers(),
            "system": self._get_system(),
            "arp": self._get_arp(),
            "fim": self._get_fim(),
            "processes": self._get_processes(),
            "scores": self._get_scores(),
            "canary": self._get_canary(),
            "usb": self._get_usb(),
            "eventlog": self._get_eventlog(),
            "bandwidth": self._get_bandwidth(),
            "registry": self._get_registry(),
            "outbound": self._get_outbound(),
            "supply_chain": self._get_supply_chain(),
            "credentials": self._get_credentials(),
            "dependencies": self._get_dependencies(),
            "containers": self._get_containers(),
            "ram_checker": self._get_ram_checker(),
            "totals": self._get_totals(),
            "config": self._get_config(),
        }

    # -- honeypots -----------------------------------------------------

    def _get_honeypots(self) -> list:
        try:
            if not self.honeypot_mgr:
                return []
            stats = self.honeypot_mgr.get_stats()
            by_type = stats.get("by_type", {})
            last_event = stats.get("last_event")

            # Build set of running honeypot names for status lookup
            running_names = set()
            running_ports = {}
            for hp in self.honeypot_mgr.honeypots:
                running_names.add(hp.name.lower())
                if hp.port:
                    running_ports[hp.name.lower()] = hp.port

            # Build honeypot list from config so they always appear
            # even before start_all() populates self.honeypot_mgr.honeypots
            hp_config = self.honeypot_mgr.config.get("honeypots", {})
            result = []
            seen = set()

            # Port-to-service name mapping for catch-all
            PORT_NAMES = {
                23: "TELNET-REAL", 3389: "RDP-REAL", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
                80: "HTTP-80", 443: "HTTPS", 8000: "HTTP-8000", 8443: "HTTPS-8443",
                8888: "HTTP-8888", 9090: "HTTP-9090", 9443: "HTTPS-9443",
                1433: "MSSQL", 1434: "MSSQL-UDP", 3306: "MYSQL-REAL", 5432: "POSTGRES",
                6379: "REDIS", 27017: "MONGODB", 27018: "MONGO-2", 9200: "ELASTIC",
                9300: "ELASTIC-T", 5984: "COUCHDB", 11211: "MEMCACHED",
                5672: "RABBITMQ", 15672: "RABBIT-UI", 9092: "KAFKA",
                21: "FTP-REAL", 69: "TFTP", 873: "RSYNC",
                25: "SMTP-25", 110: "POP3", 143: "IMAP", 465: "SMTPS",
                587: "SMTP-587", 993: "IMAPS", 995: "POP3S",
                389: "LDAP", 636: "LDAPS", 88: "KERBEROS",
                161: "SNMP", 162: "SNMP-TRAP", 514: "SYSLOG",
                10050: "ZABBIX-A", 10051: "ZABBIX-S",
                2375: "DOCKER", 2376: "DOCKER-TLS", 6443: "K8S-API", 10250: "KUBELET",
                8081: "NEXUS", 8082: "ARTIFACTORY", 9000: "SONARQUBE",
                4444: "C2-4444", 5555: "C2-5555", 6666: "C2-6666", 6667: "IRC",
                1337: "C2-LEET", 31337: "C2-ELITE", 12345: "C2-12345", 54321: "C2-54321",
                4443: "C2-4443", 9001: "TOR-OR", 9030: "TOR-DIR",
                1883: "MQTT", 8883: "MQTT-TLS", 502: "MODBUS", 47808: "BACNET",
                25565: "MINECRAFT", 27015: "SOURCE-ENG",
            }

            for name, cfg in hp_config.items():
                if name == "catchall":
                    continue  # handled separately below
                port = cfg.get("port", 0)
                enabled = cfg.get("enabled", False)
                is_running = name.lower() in running_names
                status = "ON" if is_running else ("OFF" if enabled else "DISABLED")
                hits = by_type.get(name, 0)
                last_conn = "--"
                if last_event and last_event.get("honeypot", "").lower() == name.lower():
                    ts = last_event.get("timestamp", "")
                    try:
                        last_conn = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                    except Exception:
                        last_conn = str(ts)[:8] if ts else "--"
                elif hits > 0:
                    last_conn = "Active"

                result.append({
                    "name": name.upper(),
                    "port": running_ports.get(name.lower(), port),
                    "hits": hits,
                    "status": status,
                    "last_connection": last_conn,
                })
                seen.add(name.lower())

            # Add catch-all ports as individual honeypot entries
            catchall_running = "catchall" in running_names
            catchall_cfg = hp_config.get("catchall", {})
            catchall_enabled = catchall_cfg.get("enabled", True)
            catchall_hits = by_type.get("catchall", 0)

            # Get the actual ports from the catch-all honeypot
            from blackwall.honeypots.catchall_honeypot import CATCH_ALL_PORTS
            dedicated_ports = {cfg.get("port", 0) for n, cfg in hp_config.items() if n != "catchall"}

            for port in CATCH_ALL_PORTS:
                if port in dedicated_ports:
                    continue  # skip ports already covered by dedicated honeypots
                svc_name = PORT_NAMES.get(port, f"PORT-{port}")
                status = "ON" if catchall_running else ("OFF" if catchall_enabled else "DISABLED")
                result.append({
                    "name": svc_name,
                    "port": port,
                    "hits": 0,  # catch-all doesn't track per-port hits yet
                    "status": status,
                    "last_connection": "--",
                })

            return result
        except Exception:
            return []

    # -- alerts --------------------------------------------------------

    def _get_alerts(self) -> list:
        try:
            alerts = []
            if self.net_monitor:
                alerts.extend(self.net_monitor.get_recent_alerts(20))
            if self.ids:
                alerts.extend(self.ids.detected_attacks[-20:])
            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            result = []
            for a in alerts[:50]:
                ts = a.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = str(ts)[:8]
                result.append({
                    "time": ts,
                    "severity": a.get("severity", "LOW"),
                    "type": a.get("type", ""),
                    "ip": a.get("source_ip", a.get("ip", "")),
                    "description": a.get("description", "") or "",
                })
            return result
        except Exception:
            return []

    # -- banned --------------------------------------------------------

    def _get_banned(self) -> list:
        try:
            if not self.auto_ban:
                return []
            bans = self.auto_ban.get_ban_list()
            result = []
            for ip, info in bans.items():
                reasons = info.get("reasons", [])
                result.append({
                    "ip": ip,
                    "reason": reasons[-1] if reasons else "Unknown",
                    "severity": info.get("severity", ""),
                    "firewall": bool(info.get("firewall_rule_added")),
                })
            return result
        except Exception:
            return []

    # -- whitelist -----------------------------------------------------

    def _get_whitelist(self) -> list:
        try:
            if not self.auto_ban:
                return []
            return [str(x) for x in getattr(self.auto_ban, "whitelist", [])]
        except Exception:
            return []

    # -- network -------------------------------------------------------

    def _get_network(self) -> dict:
        try:
            if not self.net_monitor:
                return {"established": 0, "listeners": 0, "bytes_sent": 0,
                        "bytes_recv": 0, "errors": 0, "connections": []}
            s = self.net_monitor.get_network_stats()
            c = self.net_monitor.get_active_connections()
            est = sum(1 for x in c if x.get("status") == "ESTABLISHED")
            lis = sum(1 for x in c if x.get("status") == "LISTEN")

            # Build connections list for the frontend
            conn_list = []
            for conn in c[:150]:
                local = conn.get("local_addr", "")
                remote = conn.get("remote_addr", "")
                conn_list.append({
                    "local_port": local.rsplit(":", 1)[-1] if ":" in local else local,
                    "remote_ip": remote.rsplit(":", 1)[0] if ":" in remote else remote,
                    "remote_port": remote.rsplit(":", 1)[-1] if ":" in remote else "",
                    "status": conn.get("status", ""),
                    "process": conn.get("process", "unknown"),
                })

            return {
                "established": est,
                "listeners": lis,
                "bytes_sent": s.get("bytes_sent", 0),
                "bytes_recv": s.get("bytes_recv", 0),
                "errors": s.get("errors_in", 0) + s.get("errors_out", 0),
                "connections": conn_list,
            }
        except Exception:
            return {"established": 0, "listeners": 0, "bytes_sent": 0,
                    "bytes_recv": 0, "errors": 0, "connections": []}

    # -- countries -----------------------------------------------------

    def _get_countries(self) -> list:
        try:
            if not self.honeypot_mgr:
                return []
            bc = self.honeypot_mgr.get_stats().get("by_country", {})
            result = []
            for cc, cnt in sorted(bc.items(), key=lambda x: x[1], reverse=True):
                name = cc
                if self.geoip:
                    for d in self.geoip._cache.values():
                        if d.get("country") == cc:
                            name = d.get("country_name", cc)
                            break
                result.append({"cc": cc, "name": name, "hits": cnt})
            return result
        except Exception:
            return []

    # -- feeds ---------------------------------------------------------

    def _get_feeds(self) -> list:
        try:
            if not self.threat_intel:
                return []
            result = []
            for name, fi in self.threat_intel.get_stats().get("feeds", {}).items():
                updated = fi.get("last_update", "")
                try:
                    updated = datetime.fromisoformat(updated).strftime("%H:%M:%S")
                except Exception:
                    pass
                result.append({
                    "name": fi.get("description", name),
                    "count": fi.get("count", 0),
                    "updated": updated,
                })
            return result
        except Exception:
            return []

    # -- attackers -----------------------------------------------------

    def _get_attackers(self) -> list:
        try:
            if not self.honeypot_mgr:
                return []
            by_ip = self.honeypot_mgr.get_stats().get("by_ip", {})
            top = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:20]
            result = []
            for ip, hits in top:
                cc = ""
                ti = False
                if self.geoip:
                    cc = self.geoip.get_cached(ip).get("country", "")
                if self.threat_intel:
                    ti = bool(self.threat_intel.check_ip(ip))
                result.append({
                    "ip": ip,
                    "hits": hits,
                    "country": cc,
                    "threat_intel": ti,
                })
            return result
        except Exception:
            return []

    # -- system --------------------------------------------------------

    def _get_system(self) -> dict:
        try:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("C:\\")
            return {
                "cpu": round(cpu, 1),
                "ram": round(mem.percent, 1),
                "ram_used_mb": mem.used // (1024 ** 2),
                "ram_total_mb": mem.total // (1024 ** 2),
                "disk": round(disk.percent, 1),
            }
        except Exception:
            return {"cpu": 0.0, "ram": 0.0, "ram_used_mb": 0,
                    "ram_total_mb": 0, "disk": 0.0}

    # -- arp -----------------------------------------------------------

    def _get_arp(self) -> dict:
        try:
            if not self.arp_monitor:
                return {"gateway_ip": "", "gateway_mac": "", "entries": 0, "alerts": 0}
            s = self.arp_monitor.get_stats()
            return {
                "gateway_ip": s.get("gateway_ip", "") or "",
                "gateway_mac": s.get("gateway_mac", "") or "",
                "entries": s.get("entries", 0),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"gateway_ip": "", "gateway_mac": "", "entries": 0, "alerts": 0}

    # -- file integrity ------------------------------------------------

    def _get_fim(self) -> dict:
        try:
            if not self.fim:
                return {"monitored": 0, "baseline": 0, "changes": 0, "alerts": 0}
            s = self.fim.get_stats()
            return {
                "monitored": s.get("monitored_files", 0),
                "baseline": s.get("baseline_files", 0),
                "changes": s.get("changes_detected", 0),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"monitored": 0, "baseline": 0, "changes": 0, "alerts": 0}

    # -- processes -----------------------------------------------------

    def _get_processes(self) -> list:
        try:
            if not self.proc_monitor:
                return []
            result = []
            for p in self.proc_monitor.get_recent_processes(20):
                ts = p.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = str(ts)[:8]
                result.append({
                    "time": ts,
                    "name": p.get("name", ""),
                    "parent": p.get("parent_name", ""),
                    "severity": p.get("severity", "LOW"),
                })
            return result
        except Exception:
            return []

    # -- threat scores -------------------------------------------------

    def _get_scores(self) -> list:
        try:
            if not self.threat_scorer:
                return []
            result = []
            for th in self.threat_scorer.get_top_threats(20):
                result.append({
                    "ip": th.get("ip", ""),
                    "score": th.get("score", 0),
                    "severity": th.get("severity", ""),
                    "country": th.get("country", ""),
                    "honeypots_hit": th.get("honeypots_hit", 0),
                })
            return result
        except Exception:
            return []

    # -- canary tokens -------------------------------------------------

    def _get_canary(self) -> dict:
        try:
            if not self.canary:
                return {"deployed": 0, "triggered": 0, "locations": 0}
            s = self.canary.get_stats()
            return {
                "deployed": s.get("deployed", 0),
                "triggered": s.get("alerts", 0),
                "locations": len(s.get("locations", [])),
            }
        except Exception:
            return {"deployed": 0, "triggered": 0, "locations": 0}

    # -- usb -----------------------------------------------------------

    def _get_usb(self) -> dict:
        try:
            if not self.usb_mon:
                return {"devices": 0, "alerts": 0}
            s = self.usb_mon.get_stats()
            return {
                "devices": s.get("known_devices", 0),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"devices": 0, "alerts": 0}

    # -- eventlog ------------------------------------------------------

    def _get_eventlog(self) -> list:
        try:
            if not self.eventlog:
                return []
            result = []
            for a in self.eventlog.alerts[-20:]:
                ts = a.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = str(ts)[:8]
                result.append({
                    "time": ts,
                    "event": a.get("type", ""),
                    "severity": a.get("severity", "LOW"),
                })
            return result
        except Exception:
            return []

    # -- bandwidth -----------------------------------------------------

    def _get_bandwidth(self) -> dict:
        try:
            if not self.bw_mon:
                return {"upload": "0 B/s", "download": "0 B/s", "alerts": 0}
            s = self.bw_mon.get_stats()
            return {
                "upload": s.get("send_rate", "0 B/s"),
                "download": s.get("recv_rate", "0 B/s"),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"upload": "0 B/s", "download": "0 B/s", "alerts": 0}

    # -- registry ------------------------------------------------------

    def _get_registry(self) -> dict:
        try:
            if not self.reg_mon:
                return {"services": 0, "tasks": 0, "alerts": 0}
            s = self.reg_mon.get_stats()
            return {
                "services": s.get("services", 0),
                "tasks": s.get("scheduled_tasks", 0),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"services": 0, "tasks": 0, "alerts": 0}

    # -- outbound ------------------------------------------------------

    def _get_outbound(self) -> dict:
        try:
            if not self.outbound:
                return {"tracked": 0, "alerts": 0}
            s = self.outbound.get_stats()
            return {
                "tracked": s.get("tracked_connections", 0),
                "alerts": s.get("alerts", 0),
            }
        except Exception:
            return {"tracked": 0, "alerts": 0}

    # -- supply chain --------------------------------------------------

    def _get_supply_chain(self) -> dict:
        try:
            if not self.supply_chain:
                return {"status": "offline", "compromised_found": 0,
                        "pth_files": 0, "typosquats": 0, "pip_monitoring": False}
            s = (self.supply_chain.get_stats()
                 if hasattr(self.supply_chain, "get_stats") else {})
            return {
                "status": "active",
                "compromised_found": s.get("compromised_packages", 0),
                "pth_files": s.get("pth_files_detected", 0),
                "typosquats": s.get("typosquatting_alerts", 0),
                "pip_monitoring": bool(s.get("pip_monitoring", False)),
            }
        except Exception:
            return {"status": "error", "compromised_found": 0,
                    "pth_files": 0, "typosquats": 0, "pip_monitoring": False}

    # -- credentials ---------------------------------------------------

    def _get_credentials(self) -> dict:
        try:
            if not self.credential_monitor:
                return {"monitored_files": 0, "baseline_ok": False,
                        "access_alerts": 0, "exfiltration_attempts": 0}
            s = (self.credential_monitor.get_stats()
                 if hasattr(self.credential_monitor, "get_stats") else {})
            baseline = s.get("baseline_status", "Unknown")
            return {
                "monitored_files": s.get("monitored_files", 0),
                "baseline_ok": baseline in ("OK", "Valid", True),
                "access_alerts": s.get("recent_access_alerts", 0),
                "exfiltration_attempts": s.get("exfiltration_attempts", 0),
            }
        except Exception:
            return {"monitored_files": 0, "baseline_ok": False,
                    "access_alerts": 0, "exfiltration_attempts": 0}

    # -- dependencies --------------------------------------------------

    def _get_dependencies(self) -> dict:
        try:
            if not self.dependency_auditor:
                return {"total_packages": 0, "direct": 0, "transitive": 0,
                        "abandoned": 0, "integrity_fails": 0}
            s = (self.dependency_auditor.get_stats()
                 if hasattr(self.dependency_auditor, "get_stats") else {})
            return {
                "total_packages": s.get("total_packages", 0),
                "direct": s.get("direct_deps", 0),
                "transitive": s.get("transitive_deps", 0),
                "abandoned": s.get("abandoned_packages", 0),
                "integrity_fails": s.get("integrity_failures", 0),
            }
        except Exception:
            return {"total_packages": 0, "direct": 0, "transitive": 0,
                    "abandoned": 0, "integrity_fails": 0}

    # -- containers ----------------------------------------------------

    def _get_containers(self) -> dict:
        try:
            if not self.container_monitor:
                return {"docker_available": False, "running": 0,
                        "privileged": 0, "crypto_miners": 0}
            s = (self.container_monitor.get_stats()
                 if hasattr(self.container_monitor, "get_stats") else {})
            docker = s.get("docker_status", "Unknown")
            return {
                "docker_available": docker in ("Running", "Active", "OK"),
                "running": s.get("running_containers", 0),
                "privileged": s.get("privileged_containers", 0),
                "crypto_miners": s.get("crypto_miners", 0),
            }
        except Exception:
            return {"docker_available": False, "running": 0,
                    "privileged": 0, "crypto_miners": 0}

    # -- ram checker ---------------------------------------------------

    def _get_ram_checker(self) -> dict:
        try:
            if not self.ram_checker:
                return {"processes_scanned": 0, "suspicious_found": 0,
                        "credential_exposures": 0, "alerts": 0,
                        "last_scan": "--", "recent_alerts": []}
            s = (self.ram_checker.get_stats()
                 if hasattr(self.ram_checker, "get_stats") else {})
            last_scan = s.get("last_scan", "")
            if last_scan:
                try:
                    last_scan = datetime.fromisoformat(last_scan).strftime("%H:%M:%S")
                except Exception:
                    last_scan = str(last_scan)[:8] if last_scan else "--"
            else:
                last_scan = "--"
            recent = []
            for a in s.get("recent_alerts", [])[-20:]:
                ts = a.get("timestamp", a.get("time", ""))
                try:
                    ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
                except Exception:
                    ts = str(ts)[:8]
                recent.append({
                    "time": ts,
                    "type": a.get("type", ""),
                    "process": a.get("process", ""),
                    "severity": a.get("severity", "LOW"),
                    "description": a.get("description", ""),
                })
            return {
                "processes_scanned": s.get("processes_scanned", 0),
                "suspicious_found": s.get("suspicious_found", 0),
                "credential_exposures": s.get("credential_exposures", 0),
                "alerts": s.get("alerts", 0),
                "last_scan": last_scan,
                "recent_alerts": recent,
            }
        except Exception:
            return {"processes_scanned": 0, "suspicious_found": 0,
                    "credential_exposures": 0, "alerts": 0,
                    "last_scan": "--", "recent_alerts": []}

    # -- config --------------------------------------------------------

    def _get_config(self) -> dict:
        """Return current config for the Settings page."""
        try:
            config_path = os.path.join("config", "config.json")
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            # Fallback: build from honeypot manager config
            if self.honeypot_mgr:
                return self.honeypot_mgr.config
            return {}
        except Exception:
            return {}

    # -- totals --------------------------------------------------------

    def _get_totals(self) -> dict:
        try:
            events = 0
            bans = 0
            alerts = 0
            if self.honeypot_mgr:
                events = getattr(self.honeypot_mgr, "_event_count", 0)
            if self.auto_ban:
                bans = len(self.auto_ban.get_ban_list())
            if self.net_monitor:
                alerts = len(getattr(self.net_monitor, "alerts", []))
            return {"events": events, "bans": bans, "alerts": alerts}
        except Exception:
            return {"events": 0, "bans": 0, "alerts": 0}

    # ------------------------------------------------------------------
    #  Startup methods
    # ------------------------------------------------------------------

    def start(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        """Start the web dashboard (blocking). Opens browser automatically."""
        self._app = self._create_app()
        url = f"http://{host}:{port}"
        # Open browser after a short delay so Flask is ready
        timer = threading.Timer(1.5, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()
        self._app.run(host=host, port=port, debug=False, use_reloader=False)

    async def start_async(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        """Start Flask in a background daemon thread. Keeps running as async task."""
        import asyncio
        self._app = self._create_app()
        url = f"http://{host}:{port}"

        def _run_server():
            self._app.run(host=host, port=port, debug=False, use_reloader=False)

        self._thread = threading.Thread(target=_run_server, daemon=True)
        self._thread.start()

        # Open browser after Flask starts
        await asyncio.sleep(2)
        webbrowser.open(url)

        # Keep this coroutine alive so gather() doesn't exit
        while self._thread.is_alive():
            await asyncio.sleep(5)
