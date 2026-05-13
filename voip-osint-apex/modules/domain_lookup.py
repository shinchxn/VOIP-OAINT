# pyrefly: ignore [missing-import]
import whois
# pyrefly: ignore [missing-import]
import dns.resolver
import requests
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

def lookup_domain(domain: str) -> dict:
    result = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "vt": {},
        "crt": [],
        "harvest": {}
    }

    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiry_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails
        }
    except:
        pass

    for record in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, record)
            result["dns"][record] = [str(rdata) for rdata in answers]
        except:
            pass
            
    try:
        answers = dns.resolver.resolve(f"_sip._tcp.{domain}", 'SRV')
        result["dns"]["_sip._tcp"] = [str(r) for r in answers]
    except: pass
    try:
        answers = dns.resolver.resolve(f"_sip._udp.{domain}", 'SRV')
        result["dns"]["_sip._udp"] = [str(r) for r in answers]
    except: pass

    if VIRUSTOTAL_KEY and VIRUSTOTAL_KEY != "your_key":
        try:
            headers = {"x-apikey": VIRUSTOTAL_KEY}
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["vt"] = stats
        except:
            pass

    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        if r.status_code == 200:
            subs = set()
            for cert in r.json():
                subs.add(cert.get("name_value"))
            result["crt"] = list(subs)
    except:
        pass

    return result

def run_harvester(domain: str) -> dict:
    out_file = f"outputs/{domain}_harvest"
    try:
        subprocess.run([
            "python3", "/opt/theHarvester/theHarvester.py",
            "-d", domain,
            "-b", "google,bing,shodan",
            "-f", out_file
        ], capture_output=True, text=True)
    except:
        pass
    return {"file": out_file}
