# 🚀 VoIP OSINT APEX v2.0 - Documentation

Welcome to the core documentation for **VoIP OSINT APEX**. This guide covers everything from system-level dependencies to advanced CLI usage for field investigators.

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
pip install -r requirements.txt
```

### API Keys (`.env`)
Configure your keys in the root `.env` file:
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

### 🧩 Full Intelligence Pipeline
```bash
# Correlate all entities into one report
python main.py full --number +14155552671 --ip 104.21.45.67 --domain target.com --save --pdf
```

---

## 📊 Outputs & Evidence
Reports are generated in `outputs/reports/` and are available in:
* 📄 **PDF**: High-fidelity investigation report with SHA-256 integrity hash.
* 🔢 **JSON**: Structured data for integration with other tools.
* 📑 **CSV**: Flat data for spreadsheet analysis.
* 📝 **Audit Logs**: Comprehensive audit trail in `outputs/logs/`.

---

> 💼 **LEA Note**: This tool automates evidence chain building to significantly reduce the time required for generating subpoena requests and identifying attribution hints.
