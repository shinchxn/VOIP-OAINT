# pyrefly: ignore [missing-import]
import nmap
import subprocess
import socket

def scan_voip_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-sU -sV -sC --script sip-methods,sip-enum-users,sip-call-spoof -p 5060,5061,1720,2000,4569,80,443,22")
        res = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for p in ports:
                    res.append({
                        "port": p,
                        "protocol": proto,
                        "state": nm[ip][proto][p]['state'],
                        "service": nm[ip][proto][p]['name'],
                        "version": nm[ip][proto][p]['version']
                    })
        return res
    except Exception:
        return []

def sipvicious_scan(ip):
    try:
        result = subprocess.run([
            "python3", "-m", "sipvicious.svmap", ip, "--fp"
        ], capture_output=True, text=True)
        return result.stdout
    except Exception:
        return ""

def masscan_quick(ip_range):
    try:
        result = subprocess.run([
            "sudo", "masscan", ip_range, "-p", "5060,5061", "--rate", "1000"
        ], capture_output=True, text=True)
        return result.stdout
    except Exception:
        return ""

def banner_grab(ip, port=5060):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        req = f"OPTIONS sip:ping@{ip} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1234\r\nFrom: <sip:scanner@127.0.0.1>;tag=1234\r\nTo: <sip:ping@{ip}>\r\nCall-ID: 1234567890@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"
        s.sendto(req.encode(), (ip, port))
        data, _ = s.recvfrom(1024)
        return data.decode(errors='ignore')
    except Exception:
        return ""
