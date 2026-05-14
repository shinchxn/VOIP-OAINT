"""
VoIP OSINT APEX v3.0 — Threat Correlator
Fuses IP, Domain, Number, and SIP data into a single confidence score.
"""

import logging
from typing import Dict, Any

from realtime import emit

log = logging.getLogger("threat_correlator")


class Correlator:
    def __init__(self):
        self.weights = {
            "ip_tor": 25,
            "ip_vpn": 15,
            "ip_abuse": 20,
            "ip_malicious_vt": 20,
            "num_voip": 15,
            "num_fraud": 25,
            "num_disposable": 15,
            "sip_spoofing": 30,
            "dom_malicious": 25
        }
        
    def score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate correlation score."""
        score = 0
        evidence = []
        
        # IP Intel
        ip_data = data.get("ip", {})
        if ip_data.get("tor_node"):
            score += self.weights["ip_tor"]
            evidence.append("Originating IP is Tor exit node")
            
        proxy = ip_data.get("proxycheck", {})
        if isinstance(proxy, dict) and proxy.get("vpn"):
            score += self.weights["ip_vpn"]
            evidence.append(f"Originating IP is VPN ({proxy.get('provider')})")
            
        abuse = ip_data.get("abuseipdb", {})
        if isinstance(abuse, dict) and abuse.get("abuseConfidenceScore", 0) > 40:
            score += self.weights["ip_abuse"]
            evidence.append("Originating IP has high abuse score")
            
        vt_ip = ip_data.get("virustotal", {})
        if isinstance(vt_ip, dict) and vt_ip.get("malicious", 0) > 0:
            score += self.weights["ip_malicious_vt"]
            evidence.append("IP flagged as malicious in VirusTotal")
            
        # Number Intel
        num_data = data.get("number", {})
        ipqs = num_data.get("ipqs", {})
        if isinstance(ipqs, dict):
            if ipqs.get("voip"):
                score += self.weights["num_voip"]
                evidence.append("Phone number is VoIP")
            if ipqs.get("fraud_score", 0) > 75:
                score += self.weights["num_fraud"]
                evidence.append("Phone number has high fraud score")
            if ipqs.get("disposable"):
                score += self.weights["num_disposable"]
                evidence.append("Phone number is disposable/temporary")
                
        # SIP Intel
        sip_data = data.get("sip", {})
        spoof = sip_data.get("spoofing", {})
        if isinstance(spoof, dict) and spoof.get("spoofing_detected"):
            score += self.weights["sip_spoofing"]
            evidence.append(f"SIP Caller ID Spoofing detected: {spoof.get('evidence')}")
            
        # Domain Intel
        dom_data = data.get("domain", {})
        vt_dom = dom_data.get("virustotal", {})
        if isinstance(vt_dom, dict) and vt_dom.get("malicious", 0) > 0:
            score += self.weights["dom_malicious"]
            evidence.append("Domain flagged as malicious in VirusTotal")
            
        # Normalize score (Cap at 100)
        final_score = min(score, 100)
        
        if final_score >= 75:
            risk = "CRITICAL"
        elif final_score >= 50:
            risk = "HIGH"
        elif final_score >= 25:
            risk = "MEDIUM"
        else:
            risk = "LOW"
            
        return {
            "confidence_score": final_score,
            "risk_level": risk,
            "evidence": evidence
        }

_correlator = Correlator()

async def run_correlation(data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute correlation and emit results."""
    log.info("[Correlator] Fusing intelligence streams...")
    result = _correlator.score(data)
    
    if result["confidence_score"] > 50:
        await emit("CORRELATION_ALERT", result, severity=result["risk_level"])
        
    return result
