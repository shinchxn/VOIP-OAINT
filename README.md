<div align="center">

```text
                                        __   __    ___ ___     ___  __  _  _  _____
                                         \ \ / /__ |_ _| _ \   / _ \/ _\| \| ||_   _|
                                         \ V / _ \ | ||  _/  | (_) \__ \ .` |  | |
                                          \_/\___/|___|_|     \___/|___/_|\_|  |_|
                                            VoIP OSINT APEX v2.0 | LEA EDITION
```

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Ubuntu_22.04-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Status](https://img.shields.io/badge/status-Active-success.svg)]()

**Advanced, CLI-based Threat Intelligence Tool for Law Enforcement & Cybersecurity Professionals**

</div>

---

## ✨ Key Capabilities

### Core Modules

| Module | Description |
| :--- | :--- |
| 📞 **Number Intelligence** | Phone number parsing, disposable/VOIP detection, carrier lookup, and fraud scoring (IPQualityScore, Numverify). |
| 🌍 **IP Intelligence** | Correlates IP data from IP-API, AbuseIPDB, Shodan, VirusTotal, ProxyCheck, and Tor exit nodes. |
| 🔍 **Domain Reconnaissance** | Gathers WHOIS, DNS records, Certificate Transparency logs (`crt.sh`), and integrates `theHarvester`. |
| 📡 **SIP & RTP Analysis** | Live network sniffing and PCAP parsing to extract SIP headers, user agents, forwarding trails, and media server IPs. |
| 🧠 **Threat Correlation** | Automates evidence chain building, confidence scoring, attribution, and generates structured subpoena targets. |

### Upgrade Modules (v2.0)

| Module | Description |
| :--- | :--- |
| 🛰️ **WebRTC/STUN Tracker** | Captures real IPs leaking from WhatsApp, Telegram, and Google Meet via STUN binding requests — bypasses VPN cover. |
| 📶 **HLR / Carrier Intel** | IMSI/SS7 awareness — checks if a number is roaming, ported, or active without real SS7 access using HLR lookup APIs. |
| 🛡️ **Threat Feeds** | Autonomous blacklist integration — checks IPs against 6+ VoIP/abuse feeds (Emerging Threats, Blocklist.de VoIP/SIP, Spamhaus DROP, etc.) with local caching. |
| 🌳 **Call Graph Visualizer** | Builds ASCII call flow trees from SIP packet data using Rich and exports Mermaid sequence diagrams for HTML reports. |
| 🗄️ **Case Management** | SQLite-based persistent case storage — save, search, reload, and export past investigations without PostgreSQL. |
| 🔢 **Number Permutator** | Generates neighboring/related number variants used by scammer clusters (last-digit, sequential, area-code swap modes). |
| 🌐 **Passive DNS** | Tracks historical IP changes for a domain using HackerTarget, SecurityTrails, and crt.sh. |
| 📜 **Subpoena Generator** | Produces properly formatted legal PDF documents (Law Enforcement Request for Records) with SHA-256 integrity hashes. |

---

## 🚀 Quick Start

Get the environment up and running in minutes:

```bash
# Clone the repository
git clone https://github.com/shinchxn/VOIP-OAINT.git
cd VOIP-OAINT/voip-osint-apex
```

---

## 🖥️ Premium CLI Experience

VOIP-OAINT is designed with a high-fidelity Command Line Interface (CLI) using the **`rich`** library to provide investigators with a clear and actionable view of complex data:

*   **📊 Live Progress Monitoring**: Real-time status indicators during multi-threaded API lookups and network scans.
*   **🎨 Color-Coded Intelligence**: Instant visual feedback on risk levels (Green = Low, Yellow = Medium, Red = High, Crimson = Critical).
*   **📋 Structured Data Panels**: Cleanly formatted tables and panels for SIP packet headers, WHOIS records, and attribution hints.
*   **📑 Interactive Audit Logs**: Styled console logging that separates investigative findings from system status messages.

---

## 🛠️ Environment Setup

### 1️⃣ System Prerequisites
Run the following commands on a clean **Ubuntu 22.04** environment:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y asterisk nmap sngrep tshark wireshark \
  sipp redis-server masscan whois \
  python3.11 python3-pip python3-venv \
  git curl jq net-tools
```

### 2️⃣ External Tool Integration
```bash
# SIPVicious
pip install sipvicious

# theHarvester
cd /opt && sudo git clone https://github.com/laramies/theHarvester
cd theHarvester && pip install -r requirements/base.txt

# DNSRecon
sudo git clone https://github.com/darkoperator/dnsrecon /opt/dnsrecon
pip install -r /opt/dnsrecon/requirements.txt
```

---

## 📞 ASTERISK LAB SETUP — EXACT COMMANDS

For analyzing live SIP traffic, configure a local Asterisk laboratory to simulate illicit VoIP forwarding:

### 1️⃣ Configure PJSIP Endpoints
Edit `/etc/asterisk/pjsip.conf`:
```ini
[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0

[6001]
type=endpoint
context=from-internal
disallow=all
allow=ulaw
auth=6001
aors=6001

[6001]
type=auth
auth_type=userpass
password=unsecurepassword
username=6001

[6001]
type=aor
max_contacts=1
```

### 2️⃣ Configure Dialplan (Forwarding Simulation)
Edit `/etc/asterisk/extensions.conf`:
```ini
[from-internal]
exten => 100,1,NoOp(VOIP OSINT TEST CALL)
 same => n,Dial(PJSIP/6001,20)
 same => n,Hangup()

exten => 200,1,NoOp(FORWARDING TRACE TEST)
 same => n,Set(CALLERID(num)=+14155552671)
 same => n,Dial(PJSIP/6001,,b(handler^s^1))
```

### 3️⃣ Initialize Service & Sniffing
```bash
# Restart Asterisk
sudo systemctl restart asterisk

# Verify endpoints
sudo asterisk -rx "pjsip show endpoints"

# Start the VOIP-OAINT live sniffer
sudo python3 main.py live --iface lo --alert
```

---

## ⚙️ Project Configuration

### 1️⃣ Python Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies:

```bash
# Create the environment
python3.11 -m venv venv

# Activate on Linux/macOS
source venv/bin/activate

# Activate on Windows (PowerShell)
# .\venv\Scripts\Activate.ps1
```

### 2️⃣ Dependency Installation
Navigate to the project directory and install the required forensic libraries:

```bash
cd voip-osint-apex
pip install --upgrade pip
pip install -r requirements.txt
```

### API Keys (`.env`)
To protect your credentials, we use a `.env` file that is ignored by Git. 

1. Copy the template file: `cp .env.example .env`
2. Open `.env` and add your keys:

| Key | Service | Use Case |
| :--- | :--- | :--- |
| `IPQS_KEY` | [IPQualityScore](https://www.ipqualityscore.com/) | Fraud scoring & Carrier detection |
| `SHODAN_KEY` | [Shodan.io](https://www.shodan.io/) | Infrastructure & Port scanning |
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation & Reporting |
| `VIRUSTOTAL_KEY` | [VirusTotal](https://www.virustotal.com/) | Malware & Domain analysis |
| `NUMVERIFY_KEY` | [Numverify](https://numverify.com/) | Number validation & HLR fallback |
| `SECURITYTRAILS_KEY` | [SecurityTrails](https://securitytrails.com/) | Passive DNS historical lookups (optional) |

---

## 🚀 Usage Guide

To see the global help menu and all 18 available commands:
```bash
python main.py --help
```

### 1️⃣ Number Analysis
Analyze phone numbers for carrier data, fraud scores, and line types.
```bash
python main.py number +14155552671 --save --pdf
```

### 2️⃣ IP Intelligence
Deep-dive into IP reputation, VPN/Tor detection, and open ports.
```bash
python main.py ip 104.21.45.67 --ports --save
```

### 3️⃣ Domain Reconnaissance
Gather WHOIS, DNS, and Certificate Transparency data.
```bash
python main.py domain target-voip.com --harvest --save
```

### 4️⃣ Email & Domain OSINT
Cross-reference emails with breached databases and social platforms.
```bash
# Analyze email
python main.py osint --email investigator@example.com

# Run domain reconnaissance (Harvester + DNSRecon)
python main.py osint --domain target-voip.com
```

### 5️⃣ Network Scanning
Perform high-speed scans for VoIP infrastructure.
```bash
python main.py scan 192.168.1.0/24
```

### 6️⃣ SIP Fingerprinting
Identify media server types and trace network paths.
```bash
python main.py fingerprint 104.21.45.67
```

### 7️⃣ PCAP Forensics
Parse existing network captures for SIP and RTP metadata.
```bash
python main.py pcap evidence.pcap --rtp --save
```

### 8️⃣ Live Investigative Sniffing
Monitor live network interfaces for real-time SIP traffic.
```bash
sudo python main.py live --iface eth0 --alert
```

### 9️⃣ Full Intelligence Pipeline
Correlate multiple entities (Number + IP + Domain) into a single forensic report.
```bash
python main.py full --number +14155552671 --ip 1.1.1.1 --domain example.com --save --pdf
```

### 🔟 Report Correlation
Correlate existing investigative reports.
```bash
python main.py correlate --report outputs/reports/investigation_123.json
```

---

## 🆕 Upgrade Module Commands (v2.0)

### 1️⃣ WebRTC/STUN Detection
Detect real IPs leaking through WebRTC STUN binding requests from WhatsApp, Telegram, Google Meet, etc.
```bash
# Sniff for 60 seconds on eth0
sudo python main.py stun --iface eth0 --duration 60

# Sniff for 120 seconds, save results
sudo python main.py stun --iface wlan0 --duration 120 --save
```

### 2️⃣ HLR Carrier Lookup
Query carrier intelligence — roaming status, ported flag, line type.
```bash
python main.py hlr +14155552671
```

### 3️⃣ Threat Feed Checking
Check an IP against 6+ VoIP/abuse blacklists with weighted scoring.
```bash
# Standard check (uses 6-hour cache)
python main.py feeds 104.21.45.67

# Force-refresh all feeds first
python main.py feeds 104.21.45.67 --refresh
```

### 4️⃣ Call Graph Visualization
Render SIP call flows as ASCII trees and optionally export Mermaid diagrams.
```bash
# From a PCAP file
python main.py graph --pcap evidence.pcap

# From a saved case, with Mermaid export
python main.py graph --case-id 5 --mermaid
```

### 5️⃣ Case Management
Persistent SQLite case storage for all investigations.
```bash
# List all past investigations
python main.py cases

# Reload a specific case
python main.py cases --id 5

# Search cases by number, IP, or domain
python main.py cases --search "14155"

# Export all cases to CSV
python main.py cases --export
```

### 6️⃣ Number Permutation
Generate neighboring number variants used by scammer clusters.
```bash
# Default modes (last_digit + sequential)
python main.py permute +14155552671

# Custom modes
python main.py permute +14155552671 --modes "last_digit,sequential,swap_area"
```

### 7️⃣ Passive DNS History
Track historical IP changes for any domain.
```bash
# Full aggregated lookup
python main.py pdns target-voip.com

# Timeline view (sorted chronologically)
python main.py pdns target-voip.com --timeline
```

### 8️⃣ Subpoena PDF Generation
Generate a formatted legal records request document.
```bash
python main.py subpoena \
  --case-id CASE-2026-001 \
  --number "+14155552671" \
  --platform "TextNow" \
  --ip "104.21.45.67" \
  --officer "Det. John Smith" \
  --badge "B-4521" \
  --agency "Cyber Crime Division"
```

---

## 📊 Outputs & Evidence

All outputs are organized under the `outputs/` directory:

| Directory | Contents |
| :--- | :--- |
| `outputs/reports/` | JSON, PDF, CSV investigation reports with SHA-256 integrity hashes |
| `outputs/logs/` | Timestamped audit trail logs |
| `outputs/pcaps/` | Captured network traffic files |
| `outputs/subpoenas/` | Generated legal request PDFs |
| `outputs/feed_cache/` | Locally cached threat feed data (6-hour TTL) |
| `outputs/cases.db` | SQLite database of all saved investigations |
| `outputs/stun_events.json` | Captured WebRTC/STUN leak events |

---

## 📁 Project Structure

```
voip-osint-apex/
├── main.py                          # CLI entry point (18 commands)
├── requirements.txt                 # Python dependencies
├── .env.example                     # API key template
├── .env                             # Your API keys (git-ignored)
├── realtime.py                      # Realtime streaming placeholder
├── modules/
│   ├── number_lookup.py             # Phone number intelligence
│   ├── ip_intel.py                  # IP reputation & geolocation
│   ├── domain_lookup.py             # WHOIS, DNS, crt.sh
│   ├── sip_parser.py                # SIP/RTP packet parsing
│   ├── port_scan.py                 # Nmap, Masscan, SIPVicious
│   ├── osint_engine.py              # Holehe, theHarvester, DNSRecon
│   ├── network_mapper.py            # VoIP path tracing & fingerprinting
│   ├── threat_correlator.py         # Evidence correlation engine
│   ├── report.py                    # JSON/PDF/CSV report generation
│   ├── webrtc_tracker.py            # WebRTC/STUN IP leak detection
│   ├── carrier_intel.py             # HLR / carrier intelligence
│   ├── threat_feeds.py              # Autonomous blacklist checking
│   ├── call_graph.py                # SIP call flow visualizer
│   ├── number_permutator.py         # Phone number variant generator
│   ├── passive_dns.py               # Historical DNS tracking
│   └── subpoena_generator.py        # Legal document PDF builder
├── utils/
│   ├── logger.py                    # Audit logging
│   ├── cache.py                     # Redis caching layer
│   └── case_db.py                   # SQLite case management
└── outputs/                         # All generated files
```

---

> ⚠️ **LEGAL DISCLAIMER**  
> **FOR LAW ENFORCEMENT AND AUTHORIZED SECURITY PERSONNEL ONLY.**  
> This tool is intended for legal and authorized investigative purposes. Ensure you have explicit authorization to monitor networks or analyze specified targets.
