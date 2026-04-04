# BLACKWALL

![BLACKWALL Banner](docs/blackwall_banner.avif)

> *"Wove the Blackwall into existence. Not a firewall. Not encryption. A boundary between civilization and digital wilderness."*

> *"The Blackwall's task was to secure an area of cyberspace for human use while holding at bay the threat of the dangerous rogue AIs that were released decades earlier into the Net."*
> — Cyberpunk 2077

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗    ██╗ █████╗ ██╗     ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║    ██║██╔══██╗██║     ██║
██████╔╝██║     ███████║██║     █████╔╝ ██║ █╗ ██║███████║██║     ██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║███╗██║██╔══██║██║     ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚███╔███╔╝██║  ██║███████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                    T H E   L A S T   L I N E   O F   D E F E N S E            v4.0
```

**BLACKWALL** is a real-time defensive security framework for Windows. It combines honeypot deception, intrusion detection, behavioral analysis, supply chain protection, and threat intelligence into a single unified barrier between your machine and the threats lurking in the Net.

Inspired by the [Blackwall from Cyberpunk 2077](https://cyberpunk.fandom.com/wiki/Blackwall) — a protective barrier keeping the fragmented Net safe from rogue AIs. Our BLACKWALL does the same for your real-world infrastructure.

---

## Why BLACKWALL?

On March 19, 2026, attackers compromised **Trivy** (a security scanner), used stolen credentials to hijack **LiteLLM** (an AI proxy with 97M monthly downloads), and published poisoned packages to PyPI. The malware fired on install via `.pth` files — no import needed. It harvested SSH keys, cloud tokens, Kubernetes secrets, and crypto wallets. Five package ecosystems were hit in two weeks.

**BLACKWALL was built to stop exactly this.**

---

## Architecture

```
                    ╔══════════════════════════════╗
                    ║     EXTERNAL THREATS          ║
                    ║  scanners · exploits · APTs   ║
                    ╚══════════════╦═══════════════╝
                                   ║
                    ╔══════════════╩═══════════════╗
                    ║     HONEYPOT GRID             ║
                    ║  SSH · HTTP · FTP · RDP · SMB ║
                    ║  Telnet · MySQL · SMTP · DNS  ║
                    ║  + 58 Catch-All Ports         ║
                    ╚══════════════╦═══════════════╝
                                   ║
              ╔════════════════════╩════════════════════╗
              ║          DETECTION PIPELINE              ║
              ║                                          ║
              ║  IDS ──► Threat Scorer ──► Behavior AI   ║
              ║   │            │               │         ║
              ║   └────────────┴───────┬───────┘         ║
              ║                        ▼                  ║
              ║                   AUTO-BAN                ║
              ║            (Windows Firewall)              ║
              ╚════════════════════╦════════════════════╝
                                   ║
     ╔═════════════════════════════╩═════════════════════════════╗
     ║                    MONITOR GRID (30 modules)               ║
     ║                                                            ║
     ║  Network    │ ARP Guard   │ Process     │ File Integrity   ║
     ║  Outbound   │ Registry    │ Event Log   │ USB Monitor      ║
     ║  Bandwidth  │ Canary Tkns │ Anti-DDoS   │ Anti-Keylogger   ║
     ║  Privacy    │ Browser     │ Rate Limit  │ Behavior Engine  ║
     ║  RAM Check  │ TeamPCP Det │             │                  ║
     ╚═════════════════════════════╦═════════════════════════════╝
                                   ║
     ╔═════════════════════════════╩═════════════════════════════╗
     ║              SUPPLY CHAIN DEFENSE (NEW in v4.0)            ║
     ║                                                            ║
     ║  Supply Chain Guardian  │ Credential Vault Monitor         ║
     ║  Dependency Auditor     │ Container Security Monitor       ║
     ╚═════════════════════════╦═════════════════════════════════╝
                               ║
                ╔══════════════╩══════════════╗
                ║   BLACKWALL WEB DASHBOARD    ║
                ║   6-page real-time display    ║
                ║   Auto-opens in Edge          ║
                ╚═════════════════════════════╝
```

---

## Features

### Honeypot Grid (9 protocols + 68 catch-all ports)

| Honeypot | Port | Emulates | Captures |
|----------|------|----------|----------|
| SSH | 2222 | OpenSSH 8.9p1 | Credentials, client banners |
| HTTP | 8080 | Apache/nginx | Login attempts, trap pages (WordPress, phpMyAdmin, .env) |
| FTP | 2121 | ProFTPD 1.3.5e | USER/PASS in plaintext |
| RDP | 3390 | Windows RDP | X.224 handshake, RDP cookies |
| SMB | 4450 | Windows SMB | SMB1/2/3 detection, usernames |
| Telnet | 2323 | Linux server | Full virtual filesystem, 120+ commands, session recording |
| MySQL | 3307 | MySQL 5.7.42 | Login credentials, database names |
| SMTP | 2525 | Postfix | AUTH credentials (LOGIN/PLAIN), email content |
| DNS | 5354 | DNS server | Query logging, DNS tunneling detection |
| Catch-All | 68 ports | Auto-detect | Protocol fingerprinting on FTP, HTTP, SSH, SMTP, TLS, SMB, Telnet |

### Detection Pipeline

- **Intrusion Detection (IDS)** — 60+ exploit patterns (SQLi, RCE, Log4Shell, Spring4Shell, SSRF, directory traversal)
- **Behavioral Analysis** — 21 indicators including timing anomalies, credential stuffing, beaconing, entropy analysis
- **Threat Scoring** — Weighted multi-factor scoring with TOR/country multipliers (LOW/MEDIUM/HIGH/CRITICAL)
- **Auto-Ban** — Automatic Windows Firewall rule creation for confirmed threats

### Monitor Grid (30 modules)

| Module | What It Does |
|--------|-------------|
| Network Monitor | Port scan + brute force detection via connection analysis |
| ARP Guard | ARP spoofing + gateway MAC change detection |
| Process Monitor | Suspicious parent-child chains (Word→PowerShell), privilege escalation |
| File Integrity | SHA-256 baseline monitoring of critical system files |
| Registry Monitor | Watches autostart keys, new services, scheduled tasks |
| Event Log Monitor | Windows security events (failed logins, privilege use) |
| USB Monitor | New device detection + storage activity alerts |
| Bandwidth Monitor | Anomaly detection on sustained data rate spikes (5x baseline) |
| Outbound Analyzer | Reverse shell + data exfiltration pattern detection |
| Anti-DDoS | Connection rate analysis (>50/sec alert, >20/IP flooding) |
| Anti-Keylogger | Keyboard hook injection + suspicious input driver detection |
| Privacy Guard | DNS leak detection + VPN status + promiscuous mode |
| Browser Guard | Malicious extension + cookie/password store access detection |
| Canary Tokens | Fake credentials deployed as tripwires |
| Rate Limiter | Per-IP connection limiting with tarpit (5s delay after 3 attempts) |
| Threat Intel | 5 free feeds (ET, Feodo, TOR exits, Blocklist.de, CINS Army) |
| **RAM Checker** | Scans process memory for credential exposure (AWS/OpenAI/Stripe keys in env vars), detects crypto miners (xmrig), credential dumpers (mimikatz, lazagne), reverse shells, processes running from temp dirs, base64-encoded PowerShell, and memory pressure anomalies |
| **TeamPCP Detector** | Dedicated scanner for the March 2026 TeamPCP/Trivy/LiteLLM supply chain attack — checks for persistence artifacts (fake sysmon.py, malicious scheduled tasks), exfil staging files (tpcp.tar.gz, session.key, payload.enc), malicious `.pth` files (litellm_init.pth), C2 domains (models.litellm.cloud, checkmarx.zone), compromised package versions (litellm 1.82.7/1.82.8, trivy 0.69.4-0.69.6), Kubernetes node-setup pods, and npm CanisterWorm indicators |

### Supply Chain Defense (v4.0)

Purpose-built to detect attacks like the TeamPCP/Trivy/LiteLLM compromise that hit 97M monthly downloads and yielded 500,000 stolen credentials across five package ecosystems in two weeks.

| Module | What It Does |
|--------|-------------|
| **Supply Chain Guardian** | Detects `.pth` file attacks (the exact LiteLLM vector), malicious `setup.py`, compromised package database (19 known malicious packages including axios CVE-2026-AXIOS), pip process monitoring, typosquatting detection via Levenshtein distance, npm preinstall/postinstall script scanning |
| **Credential Vault Monitor** | Watches `.env`, SSH keys, AWS/GCP/K8s credentials, Docker auth, crypto wallets, browser password stores. SHA-256 baselines, process tracking, multi-file exfiltration detection |
| **Dependency Auditor** | Full dependency tree mapping, transitive dependency risk scoring, package integrity verification against PyPI, abandoned package detection (>2yr), circular dependency detection, npm audit integration |
| **Container Security** | Privileged container detection, dangerous capability flags, host mount scanning, crypto miner process detection, untrusted registry alerts, Docker Compose security scanning |

### Web Dashboard

6-page real-time web interface that auto-opens in Microsoft Edge on launch:

| Page | Content |
|------|---------|
| **Dashboard** | Honeypot hits, recent alerts, banned IPs, network stats overview |
| **Honeypots** | Live honeypot activity, connection logs, captured credentials |
| **Network** | Network traffic analysis, ARP guard, bandwidth, outbound connections |
| **Threats** | Threat scores, top attackers, threat intel feeds, behavioral alerts |
| **Supply Chain** | Guardian status, credential vault, dependency audit, container security |
| **Settings** | Configuration, whitelist management, alert preferences, module toggles |

---

## Quick Start

> **Python 3.12 is recommended.** Other 3.10+ versions may work but are not tested.

```bash
# Clone
git clone https://github.com/IronBamBam1990/BLACKWALL.git
cd BLACKWALL

# Install dependencies
pip install -r requirements.txt

# Launch BLACKWALL (web dashboard opens in Edge automatically)
py -3.12 launcher.py          # or: python launcher.py

# Launch with firewall hardening (requires Admin)
py -3.12 launcher.py all

# Generate security report
py -3.12 launcher.py report
```

### Commands

```
py -3.12 launcher.py              Start BLACKWALL monitoring + web dashboard
py -3.12 launcher.py harden       Apply firewall hardening (Admin required)
py -3.12 launcher.py antitrack    Apply anti-tracking rules (Admin required)
py -3.12 launcher.py all          Everything: harden + antitrack + monitor
py -3.12 launcher.py report       Generate HTML security report
py -3.12 launcher.py help         Show help
```

---

## Configuration

Edit `config/config.json` to customize:

```json
{
  "honeypots": {
    "ssh": {"enabled": true, "port": 2222},
    "http": {"enabled": true, "port": 8080},
    "...": "all 9 honeypots configurable"
  },
  "monitor": {
    "port_scan_threshold": 5,
    "brute_force_threshold": 3,
    "auto_ban_enabled": true
  },
  "whitelist": ["127.0.0.1", "192.168.0.0/24"],
  "alerts": {
    "sound_enabled": false,
    "toast_enabled": false,
    "webhook_url": ""
  },
  "supply_chain": {
    "scan_interval": 300,
    "monitor_pip_installs": true,
    "check_pth_files": true
  }
}
```

---

## Requirements

- **Python** 3.12 recommended (3.10+ minimum)
- **Windows** 10/11 (some monitors use Windows-specific APIs)
- **Admin privileges** recommended for firewall rules and system monitoring
- Optional: MaxMind GeoIP2 database for local geolocation

### Dependencies

```
psutil>=5.9.0         # System monitoring
rich>=13.0.0          # Terminal UI
aiohttp>=3.9.0        # Async HTTP (threat feeds, PyPI API)
flask>=3.0.0          # Web dashboard backend
scapy>=2.5.0          # Network analysis
cryptography>=41.0.0  # Log encryption
geoip2>=4.8.0         # GeoIP lookups (optional)
```

---

## How It Works

1. **Honeypots** deploy fake services on 68+ ports. Attackers scanning your network hit these traps instead of real services.

2. **Detection pipeline** analyzes every connection through signature matching (IDS), behavioral analysis (21 indicators), and weighted threat scoring.

3. **Auto-ban** creates Windows Firewall rules to block confirmed threats in real-time.

4. **Supply chain modules** continuously audit your installed packages, monitor credential files, scan dependency trees, and watch Docker containers — catching the exact attack patterns used in real-world supply chain compromises.

5. **Web Dashboard** shows everything in real-time across 6 pages. Auto-opens in Edge on launch for a full browser-based monitoring experience.

6. **RAM Checker** continuously scans all running processes for credential exposure in environment variables, crypto miners, credential dumpers (mimikatz), reverse shells, and memory pressure anomalies.

7. **TeamPCP Detector** hunts for specific indicators of compromise from the March 2026 TeamPCP/Trivy/LiteLLM attack — the largest supply chain compromise in history, yielding 500,000 stolen credentials across five package ecosystems.

---

## The Story

In Cyberpunk 2077, the Blackwall is a protective barrier created by NetWatch — a powerful AI masquerading as ICE, whose job is to keep rogue AIs from destroying what's left of the Net. It's humanity's last line of defense.

In the real world, supply chain attacks are the rogue AIs. They hide inside trusted packages, propagate through dependency chains, and compromise everything they touch. The LiteLLM attack proved that a single poisoned package can exfiltrate credentials from thousands of production environments in hours. On March 30, 2026, North Korean threat actors (UNC1069/Sapphire Sleet) compromised the axios npm package — 100M weekly downloads — injecting a cross-platform RAT via a malicious `plain-crypto-js` postinstall hook. BLACKWALL's Supply Chain Guardian now detects both the compromised axios versions and the malicious loader package.

**BLACKWALL** is our answer. Deploy it. Let the wall hold.

---

## License

MIT License. See [LICENSE](LICENSE).

---

*"The wall is up. Nothing gets through."*
