# pyrefly: ignore [missing-import]
import pandas as pd
import json

def correlate(number_data, ip_data, domain_data, sip_data):
    confidence = 0
    
    if number_data.get("line_type") == "voip": confidence += 20
    if number_data.get("disposable"): confidence += 20
    if number_data.get("fraud_score", 0) > 75: confidence += 15
    if ip_data.get("is_vpn"): confidence += 15
    if ip_data.get("is_tor"): confidence += 10
    if ip_data.get("abuse_score", 0) > 50: confidence += 10
    if ip_data.get("vt_malicious", 0) > 0: confidence += 10
    
    confidence = min(confidence, 100)
    
    attribution = []
    if number_data.get("carrier"): attribution.append(f"Carrier: {number_data['carrier']}")
    if ip_data.get("isp"): attribution.append(f"ISP: {ip_data['isp']}")
    if sip_data and isinstance(sip_data, list) and len(sip_data)>0:
        ua = sip_data[0].get("user_agent")
        if ua: attribution.append(f"User-Agent: {ua}")
        
    subpoena_target = {
        "platform": number_data.get("carrier", "Unknown"),
        "legal_contact": f"legal@{number_data.get('carrier', 'unknown').lower().replace(' ', '')}.com",
        "law_enforcement_url": "...",
        "data_to_request": [
            "account registration IP",
            "payment records",
            "device fingerprint",
            "login history"
        ]
    }
    
    return {
        "confidence": confidence,
        "attribution_hints": attribution,
        "subpoena_target": subpoena_target,
        "mitre_mapping": ["T1566 - Phishing via VoIP", "T1598 - Spearphishing Voice (Vishing)", "T1036 - Masquerading"]
    }
