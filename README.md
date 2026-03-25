# BLACKWALL

![BLACKWALL Banner](docs/blackwall_banner.avif)

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
     ║                    MONITOR GRID (24 modules)               ║
     ║                                                            ║
     ║  Network    │ ARP Guard   │ Process     │ File Integrity   ║
     ║  Outbound   │ Registry    │ Event Log   │ USB Monitor      ║
     ║  Bandwidth  │ Canary Tkns │ Anti-DDoS   │ Anti-Keylogger   ║
     ║  Privacy    │ Browser     │ Rate Limit  │ Behavior Engine  ║
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
                ║   BLACKWALL DASHBOARD (TUI)  ║
                ║   5-page real-time display    ║
                ║   Zero-flicker rendering      ║
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

### Monitor Grid (24 modules)

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

### Supply Chain Defense (v4.0)

The modules that make BLACKWALL unique — purpose-built to detect attacks like the LiteLLM/Trivy compromise.

| Module | What It Does |
|--------|-------------|
| **Supply Chain Guardian** | Detects `.pth` file attacks (the exact LiteLLM vector), malicious `setup.py`, compromised package database, pip process monitoring, typosquatting detection via Levenshtein distance, npm preinstall/postinstall script scanning |
| **Credential Vault Monitor** | Watches `.env`, SSH keys, AWS/GCP/K8s credentials, Docker auth, crypto wallets, browser password stores. SHA-256 baselines, process tracking, multi-file exfiltration detection |
| **Dependency Auditor** | Full dependency tree mapping, transitive dependency risk scoring, package integrity verification against PyPI, abandoned package detection (>2yr), circular dependency detection, npm audit integration |
| **Container Security** | Privileged container detection, dangerous capability flags, host mount scanning, crypto miner process detection, untrusted registry alerts, Docker Compose security scanning |

### Dashboard

5-page real-time TUI with zero-flicker rendering:

| Page | Content |
|------|---------|
| **1: Overview** | Honeypot hits, recent alerts, banned IPs, network stats |
| **2: Threat Intel** | Top countries, threat feeds, top attackers, system resources |
| **3: Integrity** | ARP guard, file integrity, process monitor, system stats |
| **4: Defense** | Threat scores, canary tokens, event log, bandwidth/registry |
| **5: Supply Chain** | Guardian status, credential vault, dependency audit, containers |

Auto-rotates every 15 seconds. Press `1-5` to jump to any page.

---

## Quick Start

```bash
# Clone
git clone https://github.com/IronBamBam1990/BLACKWALL.git
cd BLACKWALL

# Install dependencies
pip install -r requirements.txt

# Run BLACKWALL
python blackwall.py

# Run with firewall hardening (requires Admin)
python blackwall.py all

# Generate security report
python blackwall.py report
```

### Commands

```
python blackwall.py              Start BLACKWALL monitoring
python blackwall.py harden       Apply firewall hardening (Admin required)
python blackwall.py antitrack    Apply anti-tracking rules (Admin required)
python blackwall.py all          Everything: harden + antitrack + monitor
python blackwall.py report       Generate HTML security report
python blackwall.py help         Show help
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

- **Python** 3.10+
- **Windows** 10/11 (some monitors use Windows-specific APIs)
- **Admin privileges** recommended for firewall rules and system monitoring
- Optional: MaxMind GeoIP2 database for local geolocation

### Dependencies

```
psutil>=5.9.0         # System monitoring
rich>=13.0.0          # Terminal UI
aiohttp>=3.9.0        # Async HTTP (threat feeds, PyPI API)
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

5. **Dashboard** shows everything in real-time across 5 pages. No web server, no external dependencies — pure terminal UI.

---

## The Story

In Cyberpunk 2077, the Blackwall is a protective barrier created by NetWatch — a powerful AI masquerading as ICE, whose job is to keep rogue AIs from destroying what's left of the Net. It's humanity's last line of defense.

In the real world, supply chain attacks are the rogue AIs. They hide inside trusted packages, propagate through dependency chains, and compromise everything they touch. The LiteLLM attack proved that a single poisoned package can exfiltrate credentials from thousands of production environments in hours.

**BLACKWALL** is our answer. Deploy it. Let the wall hold.

---

## License

MIT License. See [LICENSE](LICENSE).

---

*"The wall is up. Nothing gets through."*
