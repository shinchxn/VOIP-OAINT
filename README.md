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

| Module | Description |
| :--- | :--- |
| 📞 **Number Intelligence** | Phone number parsing, disposable/VoIP detection, carrier lookup, and fraud scoring (IPQualityScore, Numverify). |
| 🌍 **IP Intelligence** | Correlates IP data from IP-API, AbuseIPDB, Shodan, VirusTotal, ProxyCheck, and Tor exit nodes. |
| 🔍 **Domain Reconnaissance** | Gathers WHOIS, DNS records, Certificate Transparency logs (`crt.sh`), and integrates `theHarvester`. |
| 📡 **SIP & RTP Analysis** | Live network sniffing and PCAP parsing to extract SIP headers, user agents, forwarding trails, and media server IPs. |
| 🧠 **Threat Correlation** | Automates evidence chain building, confidence scoring, attribution, and generates structured subpoena targets. |

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
sudo python main.py live --iface lo --alert
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
Configure your keys in `voip-osint-apex/.env`:
| Key | Service | Use Case |
| :--- | :--- | :--- |
| `IPQS_KEY` | [IPQualityScore](https://www.ipqualityscore.com/) | Fraud scoring & Carrier detection |
| `SHODAN_KEY` | [Shodan.io](https://www.shodan.io/) | Infrastructure & Port scanning |
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation & Reporting |
| `VIRUSTOTAL_KEY` | [VirusTotal](https://www.virustotal.com/) | Malware & Domain analysis |
| `NUMVERIFY_KEY` | [Numverify](https://numverify.com/) | Number validation |

---

## 🚀 Usage Guide

To see the global help menu and available commands:
```bash
python main.py --help
```

### 1️⃣ Number Analysis
Analyze phone numbers for carrier data, fraud scores, and line types.
```bash
# View specific options
python main.py number --help

# Run analysis
python main.py number +14155552671 --save --pdf
```

### 2️⃣ IP Intelligence
Deep-dive into IP reputation, VPN/Tor detection, and open ports.
```bash
# View specific options
python main.py ip --help

# Run analysis
python main.py ip 104.21.45.67 --ports --save
```

### 3️⃣ Domain Reconnaissance
Gather WHOIS, DNS, and Certificate Transparency data.
```bash
# View specific options
python main.py domain --help

# Run analysis
python main.py domain target-voip.com --save
```

### 4️⃣ PCAP Forensics
Parse existing network captures for SIP and RTP metadata.
```bash
# View specific options
python main.py pcap --help

# Run analysis
python main.py pcap evidence.pcap --rtp --save
```

### 5️⃣ Live Investigative Sniffing
Monitor live network interfaces for real-time SIP traffic.
```bash
# View specific options
python main.py live --help

# Run sniffing (requires sudo for packet capture)
sudo python main.py live --iface eth0 --alert
```

### 6️⃣ Full Intelligence Pipeline
Correlate multiple entities (Number + IP + Domain) into a single forensic report.
```bash
# View specific options
python main.py full --help

# Run full pipeline
python main.py full --number +14155552671 --ip 1.1.1.1 --domain example.com --save --pdf
```

---

## 📊 Outputs & Evidence
Reports are generated in `outputs/reports/` and are available in:
* 📄 **PDF**: High-fidelity investigation report with SHA-256 integrity hash.
* 🔢 **JSON**: Structured data for integration with other tools.
* 📑 **CSV**: Flat data for spreadsheet analysis.
* 📝 **Audit Logs**: Comprehensive audit trail in `outputs/logs/`.

---

> ⚠️ **LEGAL DISCLAIMER**  
> **FOR LAW ENFORCEMENT AND AUTHORIZED SECURITY PERSONNEL ONLY.**  
> This tool is intended for legal and authorized investigative purposes. Ensure you have explicit authorization to monitor networks or analyze specified targets.
