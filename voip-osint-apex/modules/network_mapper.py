import socket
import subprocess
# pyrefly: ignore [missing-import]
from scapy.all import sr1, IP, UDP

def trace_voip_path(ip):
    path = []
    try:
        for i in range(1, 30):
            pkt = IP(dst=ip, ttl=i) / UDP(dport=5060)
            reply = sr1(pkt, verbose=0, timeout=1)
            if reply is None:
                continue
            elif reply.type == 3:
                path.append({"hop": i, "ip": reply.src})
                break
            else:
                path.append({"hop": i, "ip": reply.src})
    except:
        path = [{"status": "simulated"}]
    return path

def sip_server_fingerprint(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        req = f"OPTIONS sip:ping@{ip} SIP/2.0\r\nVia: SIP/2.0/UDP myhost\r\nFrom: sip:scanner@myhost\r\nTo: sip:ping@{ip}\r\nCall-ID: fingerprint@myhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"
        s.sendto(req.encode(), (ip, 5060))
        data, _ = s.recvfrom(1024)
        resp = data.decode(errors='ignore')
        headers = {}
        for line in resp.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers
    except:
        return {}

def rtp_server_map(pcap_file):
    from modules.sip_parser import parse_rtp
    return parse_rtp(pcap_file)
