"""
WebRTC/STUN Detection Module
Captures real IPs leaking from WhatsApp, Telegram, Google Meet
before VPN covers them via STUN binding requests.
"""

import struct
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# pyrefly: ignore [missing-import]
from scapy.all import sniff, UDP, IP, Raw

log = logging.getLogger("webrtc_tracker")

STUN_MAGIC        = 0x2112A442
STUN_BINDING_REQ  = 0x0001
STUN_BINDING_RESP = 0x0101
STUN_ATTR_XOR_MAP = 0x0020
STUN_PORTS        = {3478, 3479, 5349, 19302, 19305}


@dataclass
class STUNEvent:
    timestamp:   str
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    msg_type:    str
    mapped_ip:   Optional[str] = None
    mapped_port: Optional[int] = None
    transaction: Optional[str] = None


class WebRTCTracker:
    def __init__(self, iface: str = "eth0", output_file: str = "outputs/stun_events.json"):
        self.iface       = iface
        self.output_file = output_file
        self.events:  list[STUNEvent]  = []
        self.sessions: dict            = {}  # tx_id -> STUNEvent list

    # ── public ──────────────────────────────────────────────

    def start(self, duration: int = 60):
        log.info(f"[WebRTC] Sniffing STUN on {self.iface} for {duration}s ...")
        sniff(
            iface=self.iface,
            filter="udp",
            prn=self._process_packet,
            store=False,
            timeout=duration,
        )
        self._save()
        return self.events

    # ── internals ───────────────────────────────────────────

    def _process_packet(self, pkt):
        if not (pkt.haslayer(UDP) and pkt.haslayer(IP)):
            return

        udp = pkt[UDP]
        if udp.dport not in STUN_PORTS and udp.sport not in STUN_PORTS:
            return

        payload = bytes(pkt[UDP].payload)
        if len(payload) < 20:
            return

        msg_type, _, magic = struct.unpack_from("!HHI", payload, 0)
        if magic != STUN_MAGIC:
            return   # not a STUN packet

        tx_id = payload[8:20].hex()

        if msg_type == STUN_BINDING_REQ:
            kind = "BINDING_REQUEST"
        elif msg_type == STUN_BINDING_RESP:
            kind = "BINDING_RESPONSE"
        else:
            return

        mapped_ip, mapped_port = self._parse_xor_mapped(payload)

        ev = STUNEvent(
            timestamp   = datetime.utcnow().isoformat(),
            src_ip      = pkt[IP].src,
            dst_ip      = pkt[IP].dst,
            src_port    = udp.sport,
            dst_port    = udp.dport,
            msg_type    = kind,
            mapped_ip   = mapped_ip,
            mapped_port = mapped_port,
            transaction = tx_id,
        )
        self.events.append(ev)
        self.sessions.setdefault(tx_id, []).append(ev)

        if mapped_ip:
            log.warning(f"[!] REAL IP LEAKED via STUN: {mapped_ip}:{mapped_port}  (tx={tx_id})")

    def _parse_xor_mapped(self, data: bytes) -> tuple[Optional[str], Optional[int]]:
        """Parse XOR-MAPPED-ADDRESS attribute from STUN message body."""
        offset = 20
        while offset + 4 <= len(data):
            attr_type, attr_len = struct.unpack_from("!HH", data, offset)
            offset += 4
            if attr_type == STUN_ATTR_XOR_MAP:
                if attr_len >= 8:
                    _, family, xport = struct.unpack_from("!BBH", data, offset)
                    port = xport ^ (STUN_MAGIC >> 16)
                    xip, = struct.unpack_from("!I", data, offset + 4)
                    ip_int = xip ^ STUN_MAGIC
                    ip = ".".join(str((ip_int >> s) & 0xFF) for s in (24, 16, 8, 0))
                    return ip, port
            offset += attr_len + (4 - attr_len % 4) % 4   # 4-byte aligned
        return None, None

    def _save(self):
        import json, os
        os.makedirs("outputs", exist_ok=True)
        records = [vars(e) for e in self.events]
        with open(self.output_file, "w") as f:
            json.dump(records, f, indent=2)
        log.info(f"[WebRTC] Saved {len(records)} STUN events → {self.output_file}")
