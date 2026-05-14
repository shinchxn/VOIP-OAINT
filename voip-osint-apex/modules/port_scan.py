"""
VoIP OSINT APEX — Port Scanner Module
Real network scanning using python-nmap, sipvicious, and masscan.
Windows-compatible: no 'sudo' prefix; masscan is Linux-only.
"""

# pyrefly: ignore [missing-import]
import nmap
import subprocess
import socket
import platform
import shutil
import logging
import sys

log = logging.getLogger("port_scan")

# VoIP-specific ports to always check
VOIP_PORTS = "5060,5061,1720,2000,4569,80,443,22,8080,8443"


def scan_voip_ports(ip: str) -> list:
    """
    Full nmap scan: UDP + TCP SIP service detection with VoIP NSE scripts.
    Requires nmap installed and on PATH. On Windows, run as Administrator
    for UDP scanning (-sU requires raw sockets).
    """
    nm = nmap.PortScanner()
    res = []
    try:
        # -sV: service version detection
        # -sU -sT: UDP + TCP (UDP needs admin/root)
        # NSE scripts: sip-methods, sip-enum-users
        args = f"-sV -sT -p {VOIP_PORTS} --script sip-methods,sip-enum-users"
        if platform.system() != "Windows":
            # UDP scan requires raw sockets (root on Linux)
            args = f"-sU {args}"
        nm.scan(ip, arguments=args)
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    info = nm[ip][proto][port]
                    res.append({
                        "port":     port,
                        "protocol": proto,
                        "state":    info.get("state", ""),
                        "service":  info.get("name", ""),
                        "version":  info.get("version", ""),
                        "product":  info.get("product", ""),
                    })
    except nmap.PortScannerError as e:
        log.error(f"[PortScan] nmap error: {e} — is nmap installed and on PATH?")
    except Exception as e:
        log.error(f"[PortScan] Unexpected error: {e}")
    return res


def sipvicious_scan(ip: str) -> str:
    """
    Run sipvicious svmap against an IP for SIP device fingerprinting.
    Install with: pip install sipvicious
    The 'svmap' console script is registered by the package.
    """
    svmap = shutil.which("svmap")
    if not svmap:
        log.warning("[SIPVicious] svmap not found — run: pip install sipvicious")
        return "svmap not installed — run: pip install sipvicious"
    try:
        result = subprocess.run(
            [svmap, ip, "--fp"],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        log.warning(f"[SIPVicious] svmap timed out for {ip}")
        return "svmap timed out"
    except Exception as e:
        log.error(f"[SIPVicious] Error: {e}")
        return str(e)


def masscan_quick(ip_range: str) -> str:
    """
    High-speed SIP port scan via masscan (Linux/macOS only).
    On Windows, returns a clear message instead of failing silently.
    Install: sudo apt-get install masscan
    """
    if platform.system() == "Windows":
        log.warning("[Masscan] masscan is not available on Windows — use nmap instead")
        return "masscan is not supported on Windows. Use 'nmap' scan instead."

    masscan_bin = shutil.which("masscan")
    if not masscan_bin:
        log.warning("[Masscan] masscan not installed")
        return "masscan not installed — sudo apt-get install masscan"

    try:
        result = subprocess.run(
            [masscan_bin, ip_range, "-p", "5060,5061", "--rate", "1000"],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "masscan timed out"
    except Exception as e:
        log.error(f"[Masscan] Error: {e}")
        return str(e)


def banner_grab(ip: str, port: int = 5060) -> str:
    """
    Send a real SIP OPTIONS request and capture the server's response banner.
    Uses UDP (standard SIP). Returns raw SIP response or empty string on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        local_ip = "127.0.0.1"
        branch   = "z9hG4bK-osint-apex-scan"
        call_id  = f"osintapex-{port}@{local_ip}"
        req = (
            f"OPTIONS sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"From: <sip:scanner@{local_ip}>;tag=osint001\r\n"
            f"To: <sip:{ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"User-Agent: VoIP-OSINT-APEX/3.0\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        s.sendto(req.encode(), (ip, port))
        data, _ = s.recvfrom(4096)
        return data.decode(errors="ignore")
    except socket.timeout:
        log.debug(f"[BannerGrab] No response from {ip}:{port} (timeout)")
        return ""
    except OSError as e:
        log.debug(f"[BannerGrab] Socket error for {ip}:{port}: {e}")
        return ""
    except Exception as e:
        log.error(f"[BannerGrab] Unexpected error: {e}")
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass
