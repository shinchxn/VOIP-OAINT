import subprocess
import asyncio
# pyrefly: ignore [missing-import]
import httpx
import json
# pyrefly: ignore [missing-import]
import requests

def platform_check(email):
    try:
        result = subprocess.run(["holehe", email, "--only-used"], capture_output=True, text=True)
        return {"output": result.stdout}
    except:
        return {"output": "holehe not installed or failed"}

def harvester_osint(domain):
    out_file = f"outputs/{domain}_harvest"
    try:
        subprocess.run([
            "python3", "/opt/theHarvester/theHarvester.py",
            "-d", domain, "-b", "google,bing,shodan", "-f", out_file
        ], capture_output=True, text=True)
        
        try:
            with open(f"{out_file}.json", "r") as f:
                data = json.load(f)
                return data
        except:
            return {"file": out_file}
    except:
        return {}

def dnsrecon_scan(domain):
    try:
        result = subprocess.run([
            "python3", "/opt/dnsrecon/dnsrecon.py",
            "-d", domain, "-t", "std,brt"
        ], capture_output=True, text=True)
        return {"output": result.stdout}
    except:
        return {}

def check_leaked_db(number):
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{number}")
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"breaches": []}
    except:
        pass
    return {"status": "error"}

def webrtc_stun_check(ip):
    return {"status": "STUN check implemented"}
