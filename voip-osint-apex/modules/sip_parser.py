# pyrefly: ignore [missing-import]
import pyshark
# pyrefly: ignore [missing-import]
from scapy.all import sniff, IP, UDP, Raw
# pyrefly: ignore [missing-import]
import dpkt

def parse_pcap(file_path):
    results = []
    try:
        cap = pyshark.FileCapture(file_path, display_filter="sip")
        for pkt in cap:
            try:
                sip = pkt.sip
                data = {
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "method": getattr(sip, "method", "Response"),
                    "from": getattr(sip, "from", ""),
                    "to": getattr(sip, "to", ""),
                    "user_agent": getattr(sip, "user_agent", ""),
                    "call_id": getattr(sip, "call_id", ""),
                    "via": getattr(sip, "via", ""),
                    "x_forwarded_for": getattr(sip, "x_forwarded_for", ""),
                    "p_asserted_identity": getattr(sip, "p_asserted_identity", "")
                }
                results.append(data)
            except AttributeError:
                pass
        cap.close()
    except Exception:
        pass
    return results

def parse_rtp(file_path):
    results = set()
    try:
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        if isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            if udp.sport >= 10000 and udp.dport >= 10000:
                                import socket
                                results.add(socket.inet_ntoa(ip.src))
                except Exception:
                    pass
    except Exception:
        pass
    return list(results)

def live_sniff(callback, iface="eth0"):
    def process_pkt(pkt):
        if pkt.haslayer(UDP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "SIP/2.0" in payload and "INVITE" in payload:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    data = {"src_ip": src_ip, "dst_ip": dst_ip, "method": "INVITE"}
                    lines = payload.split("\r\n")
                    for line in lines:
                        if line.startswith("From:"): data["from"] = line
                        elif line.startswith("To:"): data["to"] = line
                        elif line.startswith("User-Agent:"): data["user_agent"] = line
                        elif line.startswith("X-Forwarded-For:"): data["x_forwarded_for"] = line
                    
                    callback(data)
            except Exception:
                pass
    try:
        sniff(filter="udp port 5060", prn=process_pkt, store=0, iface=iface)
    except Exception as e:
        print(f"Error sniffing: {e}")
