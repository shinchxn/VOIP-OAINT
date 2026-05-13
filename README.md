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

## 📂 Repository Structure

* 📁 **[`/voip-osint-apex`](voip-osint-apex/)**: The core engine containing the complete source code, CLI application, and individual intelligence modules.
  * 📖 **[View the Detailed Setup & Usage Guide](voip-osint-apex/README.md)** for installation instructions, environment variables, and CLI examples.

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

> ⚠️ **LEGAL DISCLAIMER**  
> **FOR LAW ENFORCEMENT AND AUTHORIZED SECURITY PERSONNEL ONLY.**  
> Ensure you have explicit authorization to monitor networks or analyze specified targets. This tool is intended for legal and authorized investigative purposes.
