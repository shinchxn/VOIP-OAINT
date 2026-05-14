import socket
import subprocess
import platform
import logging
# pyrefly: ignore [missing-import]
from scapy.all import sr1, IP, UDP

log = logging.getLogger("network_mapper")

def trace_voip_path(ip: str) -> list:
    """
    Traceroute to target IP using SIP/UDP (port 5060).
    Falls back to system traceroute/tracert on scapy failure (Windows).
    Returns list of {"hop": N, "ip": "x.x.x.x"} dicts.
    """
    path = []
    try:
        for ttl in range(1, 30):
            pkt = IP(dst=ip, ttl=ttl) / UDP(dport=5060)
            reply = sr1(pkt, verbose=0, timeout=1)
            if reply is None:
                path.append({"hop": ttl, "ip": "*"})
                continue
            hop_ip = reply.src
            path.append({"hop": ttl, "ip": hop_ip})
            # ICMP type 3 = Destination Unreachable (port closed = target reached)
            if reply.haslayer("ICMP") and reply["ICMP"].type == 3 and reply.src == ip:
                break
        return path
    except Exception as e:
        log.debug(f"[Traceroute] Scapy failed ({e}), falling back to system traceroute")

    # System traceroute fallback (works without raw socket privileges on Windows)
    try:
        cmd = ["tracert", "-d", "-w", "1000", ip] if platform.system() == "Windows" \
              else ["traceroute", "-n", "-q", "1", "-w", "1", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        hop_num = 0
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if not parts or not parts[0].isdigit():
                continue
            hop_num = int(parts[0])
            # Extract IPs from tracert/traceroute output
            ips = [p for p in parts if _is_ip(p)]
            if ips:
                path.append({"hop": hop_num, "ip": ips[-1]})
            else:
                path.append({"hop": hop_num, "ip": "*"})
        return path
    except Exception as e:
        log.warning(f"[Traceroute] System fallback also failed: {e}")
        return []

def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False

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
    except Exception:
        return {}

def rtp_server_map(pcap_file):
    from modules.sip_parser import parse_rtp
    return parse_rtp(pcap_file)
