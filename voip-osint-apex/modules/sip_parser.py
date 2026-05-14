"""
VoIP OSINT APEX v3.0 — SIP Parser
Deep packet inspection for SIP, RTP, and TLS using pyshark, scapy, and dpkt.
"""

import asyncio
import logging
import dpkt
import socket
from pathlib import Path
from typing import Dict, Any, List, Callable

try:
    import pyshark
except ImportError:
    pyshark = None

try:
    from scapy.all import sniff, IP, UDP, Raw
except ImportError:
    pass

from realtime import emit

log = logging.getLogger("sip_parser")


def extract_via_chain(via_header: str) -> List[str]:
    """Extract ordered list of proxy hop IPs from Via chain."""
    if not via_header:
        return []
        
    chain = []
    # Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK, SIP/2.0/UDP 5.6.7.8:5060
    hops = [h.strip() for h in via_header.split(',')]
    for hop in hops:
        # Example hop: SIP/2.0/UDP 1.2.3.4:5060;branch=...
        parts = hop.split()
        if len(parts) >= 2:
            address_part = parts[1].split(';')[0]
            ip = address_part.split(':')[0]
            if ip:
                chain.append(ip)
    return chain


def detect_spoofing(sip_packet: Dict[str, Any]) -> Dict[str, Any]:
    """Basic caller ID spoofing detection heuristics."""
    evidence = []
    
    src_ip = sip_packet.get("src_ip", "")
    from_uri = sip_packet.get("from", "")
    contact = sip_packet.get("contact", "")
    p_asserted = sip_packet.get("p_asserted_identity", "")
    via_chain = sip_packet.get("via_chain", [])
    
    # 1. P-Asserted-Identity mismatch
    if p_asserted and from_uri:
        # Extract number/user part roughly
        from_user = from_uri.split("sip:")[1].split("@")[0] if "sip:" in from_uri else ""
        pai_user = p_asserted.split("sip:")[1].split("@")[0] if "sip:" in p_asserted else ""
        
        if from_user and pai_user and from_user != pai_user:
            evidence.append(f"From ({from_user}) != P-Asserted-Identity ({pai_user})")
            
    # 2. Contact vs Source IP mismatch (if contact has IP)
    if contact and "@" in contact:
        contact_domain = contact.split("@")[1].split(">")[0].split(":")[0]
        # Very rough check, contact might be a domain
        if contact_domain.replace(".", "").isdigit() and src_ip and contact_domain != src_ip:
            if not via_chain: # If no proxies involved, this is suspicious
                evidence.append(f"Contact IP ({contact_domain}) != Source IP ({src_ip})")

    is_spoofed = len(evidence) > 0
    return {
        "spoofing_detected": is_spoofed,
        "evidence": "; ".join(evidence)
    }


def parse_sip_pcap(file_path: str) -> List[Dict[str, Any]]:
    """Parse SIP packets using pyshark."""
    if not pyshark:
        log.error("pyshark not installed")
        return []
        
    log.info(f"[SIP] Parsing PCAP: {file_path}")
    results = []
    
    try:
        cap = pyshark.FileCapture(file_path, display_filter="sip", keep_packets=False)
        for pkt in cap:
            try:
                if not hasattr(pkt, 'ip') or not hasattr(pkt, 'sip'):
                    continue
                    
                sip = pkt.sip
                method = getattr(sip, "Method", None)
                if not method: # Might be a response
                    status_code = getattr(sip, "Status-Code", None)
                    method = f"Response {status_code}" if status_code else "UNKNOWN"
                    
                packet_data = {
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "src_port": pkt[pkt.transport_layer].srcport,
                    "dst_port": pkt[pkt.transport_layer].dstport,
                    "method": method,
                    "from": getattr(sip, "From", ""),
                    "to": getattr(sip, "To", ""),
                    "user_agent": getattr(sip, "User-Agent", ""),
                    "contact": getattr(sip, "Contact", ""),
                    "call_id": getattr(sip, "Call-ID", ""),
                    "x_forwarded_for": getattr(sip, "X-Forwarded-For", ""),
                    "p_asserted_identity": getattr(sip, "P-Asserted-Identity", ""),
                    "diversion": getattr(sip, "Diversion", ""),
                    "record_route": getattr(sip, "Record-Route", ""),
                    "sdp_media_ip": "",
                    "sdp_media_port": "",
                    "sdp_codec": ""
                }
                
                # Extract Via chain
                via = getattr(sip, "Via", "")
                packet_data["via_chain"] = extract_via_chain(via)
                
                # Check for SDP
                if hasattr(pkt, 'sdp'):
                    sdp = pkt.sdp
                    # pyshark sdp parsing is a bit tricky, try to extract connection info
                    if hasattr(sdp, "connection_info_address"):
                        packet_data["sdp_media_ip"] = sdp.connection_info_address
                    if hasattr(sdp, "media_port"):
                        packet_data["sdp_media_port"] = sdp.media_port
                    if hasattr(sdp, "media_format"):
                        packet_data["sdp_codec"] = sdp.media_format
                
                # Auto-spoofing detect
                spoof_check = detect_spoofing(packet_data)
                packet_data["spoofing"] = spoof_check
                
                results.append(packet_data)
            except Exception as e:
                log.debug(f"[SIP] Packet parse error: {e}")
        cap.close()
    except Exception as e:
        log.error(f"[SIP] PCAP read error: {e}")
        
    return results


def parse_rtp_pcap(file_path: str) -> List[Dict[str, Any]]:
    """Fast raw RTP parsing using dpkt."""
    log.info(f"[RTP] Parsing PCAP: {file_path}")
    streams = {}
    
    try:
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.udp.UDP):
                        continue
                        
                    udp = ip.data
                    # Standard RTP ports
                    if not (10000 <= udp.dport <= 20000) and not (10000 <= udp.sport <= 20000):
                        continue
                        
                    # RTP Header parsing (RFC 3550)
                    # 1st byte: V (2 bits), P (1), X (1), CC (4)
                    # 2nd byte: M (1), PT (7)
                    if len(udp.data) < 12:
                        continue
                        
                    v_p_x_cc = udp.data[0]
                    version = v_p_x_cc >> 6
                    if version != 2: # RTP version is almost always 2
                        continue
                        
                    m_pt = udp.data[1]
                    payload_type = m_pt & 0x7F
                    seq = int.from_bytes(udp.data[2:4], byteorder='big')
                    ssrc = int.from_bytes(udp.data[8:12], byteorder='big')
                    
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    
                    if ssrc not in streams:
                        streams[ssrc] = {
                            "ssrc": hex(ssrc),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": udp.dport,
                            "payload_type": payload_type,
                            "packet_count": 0,
                            "first_ts": ts,
                            "last_ts": ts
                        }
                    
                    streams[ssrc]["packet_count"] += 1
                    streams[ssrc]["last_ts"] = ts
                    
                except Exception:
                    continue
    except Exception as e:
        log.error(f"[RTP] Parse error: {e}")
        
    return list(streams.values())


def extract_tls_fingerprint(file_path: str) -> List[Dict[str, Any]]:
    """Extract TLS Client Hello info for fingerprinting."""
    if not pyshark:
        return []
        
    log.info(f"[TLS] Parsing PCAP: {file_path}")
    results = []
    try:
        cap = pyshark.FileCapture(file_path, display_filter="tls.handshake.type == 1", keep_packets=False)
        for pkt in cap:
            try:
                tls = pkt.tls
                src_ip = pkt.ip.src
                sni = getattr(tls, "handshake_extensions_server_name", "N/A")
                version = getattr(tls, "handshake_version", "N/A")
                ciphers = getattr(tls, "handshake_ciphersuites", "N/A")
                
                # Check if we already recorded this SNI from this IP
                if not any(r["src_ip"] == src_ip and r["sni"] == sni for r in results):
                    results.append({
                        "src_ip": src_ip,
                        "sni": sni,
                        "tls_version": version,
                        "ciphers": ciphers[:50] + "..." if len(str(ciphers)) > 50 else ciphers
                    })
            except Exception:
                pass
        cap.close()
    except Exception as e:
        log.error(f"[TLS] Parse error: {e}")
    return results


def live_sniff(callback: Callable, iface: str = "eth0"):
    """Scapy live SIP sniffer."""
    log.info(f"[Live] Sniffing SIP on {iface}...")
    
    def pkt_handler(pkt):
        if pkt.haslayer(UDP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "SIP/2.0" in payload and "INVITE" in payload[:10]:
                    src_ip = pkt[IP].src
                    
                    # Basic rough parsing from raw text
                    lines = payload.split("\r\n")
                    method = lines[0].split()[0]
                    from_header = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("from:")), "")
                    user_agent = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("user-agent:")), "")
                    via = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("via:")), "")
                    
                    sip_data = {
                        "src_ip": src_ip,
                        "method": method,
                        "from": from_header,
                        "user_agent": user_agent,
                        "via_chain": extract_via_chain(via)
                    }
                    
                    spoofing = detect_spoofing(sip_data)
                    sip_data["spoofing"] = spoofing
                    
                    # Async event emit needs to be scheduled
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(emit("SIP_INVITE", sip_data, severity="WARNING" if spoofing["spoofing_detected"] else "INFO"))
                        
                    callback(sip_data)
            except Exception:
                pass

    try:
        sniff(filter="udp port 5060", prn=pkt_handler, store=0, iface=iface)
    except Exception as e:
        log.error(f"[Live] Sniff error: {e}")


def pcap_summary(file_path: str) -> Dict[str, Any]:
    """Generate overall PCAP stats."""
    sip_pkts = parse_sip_pcap(file_path)
    rtp_streams = parse_rtp_pcap(file_path)
    
    methods_seen = {}
    src_ips = set()
    dst_ips = set()
    
    for p in sip_pkts:
        m = p.get("method", "UNKNOWN")
        methods_seen[m] = methods_seen.get(m, 0) + 1
        src_ips.add(p.get("src_ip"))
        dst_ips.add(p.get("dst_ip"))
        
    codecs = set(s.get("payload_type") for s in rtp_streams)
    
    return {
        "file": Path(file_path).name,
        "total_sip_packets": len(sip_pkts),
        "total_rtp_streams": len(rtp_streams),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "methods_seen": methods_seen,
        "rtp_codecs_detected": list(codecs)
    }
