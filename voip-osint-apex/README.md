# VoIP OSINT APEX v2.0 - LEA EDITION

An advanced CLI-based VoIP OSINT Tool designed for law enforcement investigators and cybersecurity professionals to analyze virtual numbers and VoIP calls legally using only open source tools and free APIs.

## Features
- **Number Intelligence**: Phone number parsing, disposable/VoIP detection, carrier lookup, fraud scoring via IPQualityScore, and Numverify.
- **IP Intelligence**: Correlates IP data from IP-API, AbuseIPDB, Shodan, VirusTotal, ProxyCheck, and Tor exit node lists.
- **Domain Reconnaissance**: Gathers WHOIS, DNS records, Certificate Transparency logs (crt.sh), and integrates `theHarvester`.
- **SIP & RTP Analysis**: Live network sniffing and PCAP parsing to extract SIP headers, user agents, forwarding trails, and media server IPs.
- **Threat Correlation**: Automates evidence chain building, confidence scoring, attribution, and generates structured subpoena targets.
- **Comprehensive Reporting**: Automatically produces rich JSON, CSV, and PDF reports with SHA-256 integrity hashing and timestamped audit logs.

## Environment Requirements
- **OS**: Ubuntu 22.04 (Recommended)
- **Python**: 3.11+
- **Lab**: Asterisk PBX

## Installation

### 1. System Packages
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y asterisk nmap sngrep tshark wireshark \
  sipp redis-server masscan whois \
  python3.11 python3-pip python3-venv \
  git curl jq net-tools
```

### 2. External Tools
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

### 3. Project Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl start redis-server
sudo systemctl start asterisk
```

## API Configuration
Create or edit the `.env` file in the project root to include your API keys:
```env
IPQS_KEY=your_key         # ipqualityscore.com (free 200/day)
SHODAN_KEY=your_key       # shodan.io (free)
ABUSEIPDB_KEY=your_key    # abuseipdb.com (free)
VIRUSTOTAL_KEY=your_key   # virustotal.com (free)
NUMVERIFY_KEY=your_key    # numverify.com (free 100/mo)
```

## Usage

```bash
# 1. Number Lookup
python main.py number +14155552671 --save --pdf

# 2. IP Intelligence
python main.py ip 104.21.45.67 --ports --save

# 3. Domain OSINT
python main.py domain textnow.com --harvest --save

# 4. PCAP Analysis
python main.py pcap capture.pcap --rtp --save

# 5. Live Sniffing
sudo python main.py live --iface eth0 --alert

# 6. Full Correlated Investigation
python main.py full --number +14155552671 --ip 104.21.45.67 --domain textnow.com --save --pdf

# 7. OSINT Platform Checks
python main.py osint --email user@textnow.com --domain textnow.com

# 8. Network SIP Scanning
sudo python main.py scan 192.168.1.0/24

# 9. Server Fingerprinting
python main.py fingerprint 192.168.1.10
```

## Outputs
All findings are routed to the `outputs/` folder:
- **`outputs/reports/`**: JSON, CSV, and secure PDF investigation reports.
- **`outputs/logs/`**: Immutable daily audit trail of all commands run.
- **`outputs/pcaps/`**: Storage for capture files.

## Future Upgrade Path (v3.0 Roadmap)
1. **FastAPI Wrapper**: Exposing the core modules as REST endpoints and WebSockets for live mode.
2. **PostgreSQL Integration**: Adding SQLAlchemy for advanced case management and historic searches.
3. **React Dashboard**: Moving from CLI to a comprehensive web UI with Map visualizations and dynamic charts.
4. **Dockerization**: Orchestrating the backend, frontend, PostgreSQL, Redis, and Asterisk via `docker-compose`.

## Disclaimer
> **FOR LAW ENFORCEMENT AND AUTHORIZED SECURITY PERSONNEL ONLY.**
> Ensure you have explicit authorization to monitor networks or analyze specified targets. The tool is designed to work passively using OSINT datasets and safely fingerprint servers. Do not conduct active network attacks outside of approved lab environments.
