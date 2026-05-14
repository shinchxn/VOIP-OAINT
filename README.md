<div align="center">

```text
                                        __   __    ___ ___     ___  __  _  _  _____
                                         \ \ / /__ |_ _| _ \   / _ \/ _\| \| ||_   _|
                                         \ V / _ \ | ||  _/  | (_) \__ \ .` |  | |
                                          \_/\___/|___|_|     \___/|___/_|\_|  |_|
                                            VoIP OSINT APEX v3.0 | LEA EDITION
```

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Kali_Linux_%7C_Docker-orange.svg)](https://www.kali.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/status-v3.0_Production-success.svg)]()
[![Forensic](https://img.shields.io/badge/forensic-SHA--256_Integrity-blueviolet.svg)]()

**Enterprise-grade VoIP Forensic Intelligence Platform for Law Enforcement & Cybersecurity Professionals**

*Fully asynchronous · Real-time event bus · SHA-256 audit trail · Docker-ready*

</div>

---

## ✨ Key Capabilities

### Core Modules

| Module | Description |
| :--- | :--- |
| 📞 **Number Intelligence** | Phone number parsing, disposable/VOIP detection, carrier lookup, fraud scoring (IPQualityScore, Numverify). |
| 🌍 **IP Intelligence** | Multi-source IP correlation: AbuseIPDB, Shodan, VirusTotal, ProxyCheck, Tor exit nodes — async with rate-limiting. |
| 🔍 **Domain Reconnaissance** | WHOIS, DNS, Certificate Transparency (`crt.sh`), SRV records, integrated `theHarvester`. |
| 📡 **SIP & RTP Analysis** | Live network sniffing and PCAP parsing — extracts SIP headers, user agents, forwarding trails, media server IPs. |
| 🧠 **Threat Correlation** | Confidence-scored attribution engine with MITRE ATT&CK mappings, real LEA contact lookup, subpoena target generation. |
| ⚡ **Real-time Event Bus** | Async pub/sub bus (`realtime.py`) — broadcasts THREAT_HIT, HLR_ALERT events to live CLI and future integrations. |

### v3.0 Intelligence Modules

| Module | Description |
| :--- | :--- |
| 🛰️ **WebRTC/STUN Tracker** | Captures real IPs leaking from WhatsApp, Telegram, Google Meet via STUN — bypasses VPN cover. |
| 📶 **HLR / Carrier Intel** | IMSI/SS7 awareness — roaming, porting, active status via `Numverify` (free tier ready). |
| 🛡️ **Threat Feeds** | Autonomous blacklist checking against 6+ VoIP/abuse feeds with 6-hour local cache. |
| 🌳 **Call Graph Visualizer** | ASCII call flow trees from SIP data + Mermaid diagram export for HTML reports. |
| 🗄️ **Case Management** | Async SQLite case storage — save, search, reload, export all investigations. |
| 🔢 **Number Permutator** | Generates scammer cluster variants (last-digit, sequential, area-code swap). |
| 🌐 **Passive DNS** | Historical IP tracking for domains via HackerTarget, SecurityTrails, crt.sh. |
| 📜 **Subpoena Generator** | Legally-formatted PDF records request with SHA-256 integrity hash. |

---

## 🚀 Quick Start — Docker (Recommended)

The fastest way to run APEX with zero dependency conflicts.

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) **or** `docker.io` (Kali/Ubuntu)

```bash
git clone https://github.com/shinchxn/VOIP-OAINT.git
cd VOIP-OAINT/voip-osint-apex
cp .env.example .env
nano .env   # Add your API keys
```

### One-command Launch

**Kali Linux / Ubuntu:**
```bash
chmod +x quickstart.sh && ./quickstart.sh
```

**Windows (PowerShell as Admin):**
```powershell
.\quickstart.ps1
```

**Manual:**
```bash
docker compose build
docker compose up -d redis
docker compose run --rm apex --help
```

### Docker Usage Examples

```bash
# Phone number investigation
docker compose run --rm apex number +14155552671 --save --pdf

# IP deep-dive with port scan
docker compose run --rm apex ip 104.21.45.67 --ports --save

# HLR carrier lookup
docker compose run --rm apex hlr +447911123456

# Analyze a PCAP file
docker compose run --rm -v $(pwd)/evidence:/evidence:ro apex pcap /evidence/capture.pcap --rtp --save

# Live sniffer (requires privileged + host network)
docker compose run --rm --privileged --network host apex live --iface eth0 --alert

# Full correlated forensic report
docker compose run --rm apex full --number +14155552671 --ip 104.21.45.67 --domain evil.com --save --pdf

# Generate subpoena PDF
docker compose run --rm apex subpoena \
  --case-id CASE-2026-001 --number "+14155552671" \
  --platform "Twilio" --ip "104.21.45.67" \
  --officer "Det. Jane Smith" --badge "B-4521" \
  --agency "Cyber Crime Division"
```

---

## 🐉 Native Install — Kali Linux

For live investigations requiring raw packet capture.

### 1️⃣ System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    nmap masscan tshark wireshark tcpdump traceroute \
    whois net-tools curl wget git jq \
    libpcap-dev libssl-dev libffi-dev \
    python3.11 python3-pip python3-venv

# Allow tshark without sudo
sudo usermod -aG wireshark $USER && newgrp wireshark
```

### 2️⃣ External Tools

```bash
# SIPVicious (svmap, svwar)
pip3 install sipvicious

# theHarvester
sudo git clone https://github.com/laramies/theHarvester /opt/theHarvester
cd /opt/theHarvester && pip3 install -r requirements/base.txt
sudo ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
```

### 3️⃣ Python Environment

```bash
cd /opt
sudo git clone https://github.com/shinchxn/VOIP-OAINT.git voip-apex
cd voip-apex/voip-osint-apex

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt
```

### 4️⃣ Raw Socket Privileges (Scapy)

```bash
# Option A: Run as root
sudo python main.py live --iface eth0 --alert

# Option B: Grant raw socket capability (recommended — no root for normal commands)
sudo setcap cap_net_raw+eip $(readlink -f venv/bin/python3)
# Now scapy and nmap UDP work without sudo
python main.py fingerprint 104.21.45.67
```

### 5️⃣ Configure API Keys

```bash
cp .env.example .env && nano .env
```

### 6️⃣ Verify & Run

```bash
source venv/bin/activate
python main.py keys      # Check key status
python main.py number +14155552671
```

### Recommended Kali Aliases

```bash
# Add to ~/.zshrc
alias apex='cd /opt/voip-apex/voip-osint-apex && source venv/bin/activate && python main.py'
alias apex-d='docker compose -f /opt/voip-apex/voip-osint-apex/docker-compose.yml run --rm apex'

# Usage:
apex number +14155552671
apex-d ip 8.8.8.8 --ports
```

---

## ⚙️ API Keys (`.env`)

Copy `.env.example` to `.env` and populate:

| Key | Service | Free? |
| :--- | :--- | :--- |
| `IPQS_KEY` | [IPQualityScore](https://ipqualityscore.com/) | ✅ Free tier |
| `SHODAN_KEY` | [Shodan.io](https://shodan.io/) | ✅ Free (limited) |
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://abuseipdb.com/) | ✅ Free tier |
| `VIRUSTOTAL_KEY` | [VirusTotal](https://virustotal.com/) | ✅ Free tier |
| `NUMVERIFY_KEY` | [Numverify](https://numverify.com/) | ✅ 100 req/mo |
| `SECURITYTRAILS_KEY` | [SecurityTrails](https://securitytrails.com/) | ✅ Free tier |
| `HIBP_KEY` | [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | 💰 Paid |

---

## 🖥️ Full CLI Reference

```bash
python main.py --help   # All commands
```

| Command | Description |
| :--- | :--- |
| `number <phone>` | Phone number intelligence + fraud scoring |
| `ip <addr>` | IP reputation, VPN/Tor detection, ports |
| `domain <domain>` | WHOIS, DNS, certs, theHarvester |
| `hlr <phone>` | HLR carrier lookup (roaming, porting) |
| `full` | Correlated number + IP + domain report |
| `scan <range>` | High-speed VoIP port scan |
| `fingerprint <ip>` | SIP server fingerprinting + hop trace |
| `pcap <file>` | Parse PCAP for SIP/RTP metadata |
| `live` | Live interface sniffing with alerts |
| `feeds <ip>` | Check IP against 6+ threat feed blacklists |
| `stun` | WebRTC/STUN IP leak detection |
| `graph` | Render SIP call flow ASCII + Mermaid |
| `cases` | List, search, export past investigations |
| `permute <phone>` | Generate number variants for cluster analysis |
| `pdns <domain>` | Passive DNS history lookup |
| `subpoena` | Generate legal records request PDF |
| `keys` | Show API key configuration status |

---

## 📊 Outputs & Evidence

| Directory | Contents |
| :--- | :--- |
| `outputs/reports/` | JSON, PDF, CSV reports with SHA-256 hashes |
| `outputs/logs/` | Timestamped forensic audit trail |
| `outputs/pcaps/` | Captured SIP/RTP traffic |
| `outputs/subpoenas/` | Legal request PDFs |
| `outputs/feed_cache/` | Threat feed cache (6-hour TTL) |
| `outputs/cases.db` | SQLite investigation database |

---

## 📁 Project Structure

```
voip-osint-apex/
├── main.py                      # CLI entry point (18+ commands)
├── realtime.py                  # Async event bus (pub/sub)
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Production Docker image
├── docker-compose.yml           # Docker Compose stack (apex + redis)
├── quickstart.sh                # Linux/Kali one-command launch
├── quickstart.ps1               # Windows PowerShell launch
├── .env.example                 # API key template
├── modules/
│   ├── number_lookup.py         # Phone number intelligence
│   ├── ip_intel.py              # IP reputation & geolocation
│   ├── domain_lookup.py         # WHOIS, DNS, crt.sh
│   ├── sip_parser.py            # SIP/RTP packet parsing
│   ├── port_scan.py             # Nmap, Masscan, SIPVicious
│   ├── osint_engine.py          # Holehe, theHarvester, DNSRecon
│   ├── network_mapper.py        # VoIP path tracing & fingerprinting
│   ├── threat_correlator.py     # Evidence correlation + MITRE ATT&CK
│   ├── report.py                # JSON/PDF/CSV + SHA-256 evidence log
│   ├── webrtc_tracker.py        # WebRTC/STUN IP leak detection
│   ├── carrier_intel.py         # HLR/carrier intelligence
│   ├── threat_feeds.py          # Blacklist checking (6+ feeds)
│   ├── call_graph.py            # SIP call flow visualizer
│   ├── number_permutator.py     # Phone number variant generator
│   ├── passive_dns.py           # Historical DNS tracking
│   └── subpoena_generator.py    # Legal document PDF builder
├── utils/
│   ├── config.py                # APIKeys singleton (all keys)
│   ├── logger.py                # Forensic audit logging
│   ├── cache.py                 # Redis caching layer
│   ├── case_db.py               # Async SQLite case management
│   ├── rate_limiter.py          # Per-API token-bucket rate limiter
│   └── exceptions.py            # Custom exception hierarchy
└── outputs/                     # All generated files
```

---

## 🔗 Kali Linux Tool Integrations

| APEX Module | Pairs With |
| :--- | :--- |
| `port_scan.py` | `zenmap`, `msfconsole` SIP auxiliaries |
| `sip_parser.py` | `sngrep`, Wireshark VoIP filter |
| `network_mapper.py` | `mtr`, `netdiscover`, `traceroute` |
| `osint_engine.py` | Maltego, `recon-ng`, `amass` |
| `domain_lookup.py` | `dig`, `dnsx`, `subfinder` |
| `webrtc_tracker.py` | Burp Suite, `mitmproxy` |
| `report.py` + `subpoena_generator.py` | Chain-of-custody evidence packages |

---

> ⚠️ **LEGAL DISCLAIMER**
> **FOR LAW ENFORCEMENT AND AUTHORIZED SECURITY PERSONNEL ONLY.**
> This tool is intended exclusively for legal and authorized investigative purposes.
> Ensure you have explicit written authorization before monitoring networks or analyzing any targets.
> Unauthorized use may violate computer crime laws including the CFAA, CMA, and GDPR.
