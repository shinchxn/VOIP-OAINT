<div align="center">

# 🌐 VOIP-OAINT (VoIP OSINT APEX v2.0)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Ubuntu_22.04-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Status](https://img.shields.io/badge/status-Active-success.svg)]()

**Advanced, CLI-based Threat Intelligence Tool for Law Enforcement & Cybersecurity Professionals**

*Automate the extraction, correlation, and analysis of OSINT data from phone numbers, IP addresses, domains, and live SIP network traffic to expose illicit VoIP infrastructure.*

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

## ⚙️ Project Configuration

### Python Environment
```bash
python3 -m venv venv
source venv/bin/activate
cd voip-osint-apex
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

### 📋 Number & IP Intelligence
```bash
# Analyze a virtual number
python main.py number +14155552671 --save --pdf

# Deep-dive into an IP
python main.py ip 104.21.45.67 --ports --save
```

### 🔍 Network & PCAP Forensics
```bash
# Analyze SIP traffic from PCAP
python main.py pcap capture.pcap --rtp --save

# Live investigative sniffing
sudo python main.py live --iface eth0 --alert
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
