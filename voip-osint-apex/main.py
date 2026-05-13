# pyrefly: ignore [missing-import]
import click
import asyncio
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.table import Table
# pyrefly: ignore [missing-import]
from rich.panel import Panel
# pyrefly: ignore [missing-import]
from rich.progress import Progress, SpinnerColumn, TextColumn
# pyrefly: ignore [missing-import]
from rich.pretty import pprint
import json
import sys
import os
import logging

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding='utf-8')
    except Exception as e:
        logging.getLogger("main").debug(f"UTF-8 reconfigure failed: {e}")

from modules.number_lookup import analyze_number
from modules.ip_intel import analyze_ip
from modules.domain_lookup import lookup_domain, run_harvester
from modules.sip_parser import parse_pcap, parse_rtp, live_sniff
from modules.port_scan import scan_voip_ports, banner_grab, masscan_quick, sipvicious_scan
from modules.osint_engine import platform_check, harvester_osint, dnsrecon_scan
from modules.threat_correlator import correlate
from modules.network_mapper import trace_voip_path, sip_server_fingerprint
from modules.report import generate_json, generate_pdf, generate_csv, generate_evidence_log
from utils.logger import log_action
from utils.config import get_config, print_key_status

log = logging.getLogger("main")
console = Console()

BANNER = r"""
 __   __    ___ ___     ___  __  _  _  _____
 \ \ / /__ |_ _| _ \   / _ \/ _\| \| ||_   _|
  \ V / _ \ | ||  _/  | (_) \__ \ .` |  | |
   \_/\___/|___|_|     \___/|___/_|\_|  |_|
  VoIP OSINT APEX v3.0 | LEA EDITION
"""

def print_banner():
    console.print(f"[cyan]{BANNER}[/cyan]")
    console.print("-" * 60)

def print_risk_panel(risk, data):
    color = "green"
    if risk == "CRITICAL": color = "red bold"
    elif risk == "HIGH": color = "yellow"
    
    text = f"Confidence: {data.get('confidence', 'N/A')}%\n"
    for k, v in data.items():
        if k != "confidence":
            text += f"{k}: {v}\n"
            
    console.print(Panel(text, title=f"[{color}]⚠ {risk} RISK DETECTED[/{color}]", border_style=color))

@click.group()
def cli():
    """VoIP OSINT APEX v3.0 — Advanced Threat Intelligence CLI"""
    pass

@cli.command("number")
@click.argument('number')
@click.option('--save', is_flag=True, help="Save intelligence to JSON report")
@click.option('--pdf', is_flag=True, help="Generate forensic PDF report")
def cmd_number(number, save, pdf):
    """Analyze phone numbers for carrier data, fraud scores, and line types."""
    print_banner()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        progress.add_task(description="Analyzing number...", total=None)
        res = analyze_number(number)
    
    table = Table(title="Number Intelligence", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    
    for k, v in res.items():
        table.add_row(str(k), str(v))
        
    console.print(table)
    
    if save:
        path = generate_json(res)
        console.print(f"Report -> {path}")
    if pdf:
        path = generate_pdf(res)
        console.print(f"PDF -> {path}")
        
    log_action("number", number, res.get("risk_level"), "number_lookup")

@cli.command("ip")
@click.argument('ip')
@click.option('--ports', is_flag=True, help="Scan for common VoIP/SIP ports")
@click.option('--save', is_flag=True, help="Save reputation data to JSON")
def cmd_ip(ip, ports, save):
    """Deep-dive into IP reputation, VPN/Tor detection, and open ports."""
    print_banner()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        progress.add_task(description="Analyzing IP...", total=None)
        try:
            res = asyncio.run(analyze_ip(ip))
        except Exception as e:
            console.print(f"[red]IP analysis failed: {e}[/red]")
            log.error(f"IP analysis failed for {ip}: {e}")
            return
        
    if ports:
        res["port_scan"] = scan_voip_ports(ip)
        res["banner"] = banner_grab(ip)

    table = Table(title="IP Intelligence")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    
    for k, v in res.items():
        if k not in ['port_scan', 'banner']:
            table.add_row(str(k), str(v))
            
    console.print(table)
    print_risk_panel(res.get("risk_level", "LOW"), {"Abuse Score": res.get("abuse_score")})
    
    if save:
        generate_json(res)

@cli.command("domain")
@click.argument('domain')
@click.option('--harvest', is_flag=True, help="Run theHarvester for OSINT")
@click.option('--save', is_flag=True, help="Save domain intelligence to JSON")
def cmd_domain(domain, harvest, save):
    """Gather WHOIS, DNS, and Certificate Transparency data."""
    print_banner()
    res = lookup_domain(domain)
    if harvest:
        res["harvester"] = run_harvester(domain)
        
    console.print(res)
    if save:
        generate_json(res)

@cli.command("pcap")
@click.argument('file_path')
@click.option('--rtp', is_flag=True, help="Extract media (RTP) server details")
@click.option('--save', is_flag=True, help="Save packet analysis to JSON")
def cmd_pcap(file_path, rtp, save):
    """Parse existing network captures for SIP and RTP metadata."""
    print_banner()
    res = {"sip_packets": parse_pcap(file_path)}
    if rtp:
        res["rtp_servers"] = parse_rtp(file_path)
    
    console.print(f"Found {len(res['sip_packets'])} SIP packets")
    if rtp:
        console.print(f"RTP servers: {res['rtp_servers']}")
        for server in res["rtp_servers"]:
            try:
                asyncio.run(analyze_ip(server))
            except Exception as e:
                console.print(f"[yellow]IP analysis failed for {server}: {e}[/yellow]")
        
    if save:
        generate_json(res)

@cli.command("live")
@click.option('--iface', default='eth0', help="Network interface (e.g., eth0, wlan0)")
@click.option('--alert', is_flag=True, help="Auto-analyze risk for detected IPs")
def cmd_live(iface, alert):
    """Monitor live network interfaces for real-time SIP traffic."""
    print_banner()
    console.print(f"[cyan]Listening on {iface}...[/cyan]")
    
    def on_packet(data):
        console.print(Panel(
            f"From: {data.get('from')}\nSRC IP: {data.get('src_ip')}\nVia: {data.get('via')}\nAgent: {data.get('user_agent')}",
            title="⚡ LIVE INVITE DETECTED",
            border_style="blue"
        ))
        if alert:
            try:
                ip_res = asyncio.run(analyze_ip(data.get('src_ip')))
                risk = ip_res.get('risk_level', 'LOW')
                if risk in ['CRITICAL', 'HIGH']:
                    print_risk_panel(risk, ip_res)
                    generate_json(ip_res)
            except Exception as e:
                console.print(f"[yellow]Alert analysis failed: {e}[/yellow]")
            
    live_sniff(on_packet, iface)

@cli.command("full")
@click.option('--number', help="Target phone number")
@click.option('--ip', help="Target IP address")
@click.option('--domain', help="Target domain name")
@click.option('--save', is_flag=True, help="Generate comprehensive JSON/CSV/Evidence logs")
@click.option('--pdf', is_flag=True, help="Generate master forensic PDF report")
def cmd_full(number, ip, domain, save, pdf):
    """Correlate multiple entities (Number + IP + Domain) into a single forensic report."""
    print_banner()
    num_data = analyze_number(number) if number else {}

    ip_data = {}
    if ip:
        try:
            ip_data = asyncio.run(analyze_ip(ip))
        except Exception as e:
            console.print(f"[yellow]IP analysis failed: {e}[/yellow]")

    dom_data = lookup_domain(domain) if domain else {}
    
    corr = correlate(num_data, ip_data, dom_data, [])
    res = {
        "number": num_data,
        "ip": ip_data,
        "domain": dom_data,
        "correlation": corr
    }
    
    console.print(res)
    if save: 
        generate_json(res)
        generate_csv(res)
        generate_evidence_log(res)
    if pdf: 
        generate_pdf(res)

@cli.command("osint")
@click.option('--email', help="Check email for breaches and linked profiles")
@click.option('--domain', help="Harvest subdomains and DNS records")
def cmd_osint(email, domain):
    """Cross-reference emails with breached databases and social platforms."""
    print_banner()
    if email:
        console.print(platform_check(email))
    if domain:
        console.print(harvester_osint(domain))
        console.print(dnsrecon_scan(domain))

@cli.command("scan")
@click.argument('ip_range')
def cmd_scan(ip_range):
    """Perform high-speed scans for VoIP infrastructure."""
    print_banner()
    console.print(masscan_quick(ip_range))

@cli.command("correlate")
@click.option('--report', required=True, help="Path to investigative JSON report")
def cmd_correlate(report):
    """Correlate existing investigative reports."""
    print_banner()
    try:
        with open(report, 'r') as f:
            data = json.load(f)
        console.print(correlate(data.get('number',{}), data.get('ip',{}), data.get('domain',{}), []))
    except FileNotFoundError:
        console.print(f"[red]Report file not found: {report}[/red]")
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON in report: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error loading report: {e}[/red]")

@cli.command("fingerprint")
@click.argument('ip')
def cmd_fingerprint(ip):
    """Identify media server types and trace network paths."""
    print_banner()
    console.print(sip_server_fingerprint(ip))
    console.print(trace_voip_path(ip))

# ── Helper ──────────────────────────────────────────────────

def _load_sip_packets(pcap_path, case_id):
    """Load SIP packets from a PCAP file or a saved case."""
    if pcap_path:
        return parse_pcap(pcap_path)
    elif case_id:
        from utils.case_db import get_case
        case = get_case(case_id)
        if case and 'findings' in case and 'sip_packets' in case['findings']:
            return case['findings']['sip_packets']
    return []

# ── Upgrade Modules CLI ─────────────────────────────────────

@cli.command("stun")
@click.option("--iface", default="eth0", help="Network interface to sniff")
@click.option("--duration", default=60, type=int, help="Capture duration in seconds")
@click.option("--save/--no-save", default=True)
def cmd_stun(iface, duration, save):
    """Detect real IPs leaking via WebRTC/STUN (WhatsApp, Telegram, Meet)."""
    print_banner()
    from modules.webrtc_tracker import WebRTCTracker
    tracker = WebRTCTracker(iface=iface)
    events  = tracker.start(duration=duration)
    console.print(f"[green]Captured {len(events)} STUN events.[/green]")


@cli.command("hlr")
@click.argument("number")
def cmd_hlr(number):
    """HLR lookup — carrier, roaming, ported status."""
    print_banner()
    from modules.carrier_intel import hlr_lookup
    result = hlr_lookup(number)
    # Use dataclasses.asdict for clean output
    from dataclasses import asdict
    pprint(asdict(result))


@cli.command("feeds")
@click.argument("ip")
@click.option("--refresh", is_flag=True, help="Force re-download all feeds first")
def cmd_feeds(ip, refresh):
    """Check IP against VoIP threat blacklists."""
    print_banner()
    from modules.threat_feeds import check_threat_feeds, refresh_feeds
    if refresh:
        refresh_feeds()
    result = check_threat_feeds(ip)
    pprint(result)


@cli.command("graph")
@click.option("--pcap", "pcap_path", default=None, help="Parse from PCAP file")
@click.option("--case-id", default=None, type=int, help="Reload SIP data from saved case")
@click.option("--mermaid", is_flag=True, help="Also output Mermaid diagram string")
def cmd_graph(pcap_path, case_id, mermaid):
    """Visualize SIP call flow as ASCII tree."""
    print_banner()
    from modules.call_graph import build_call_graph, to_mermaid
    sip_packets = _load_sip_packets(pcap_path, case_id)
    if not sip_packets:
        console.print("[red]No SIP packets found. Provide --pcap or --case-id.[/red]")
        return
    build_call_graph(sip_packets)
    if mermaid:
        console.print("\n[cyan]--- Mermaid Diagram ---[/cyan]\n")
        console.print(to_mermaid(sip_packets))


@cli.command("cases")
@click.option("--id",     "case_id", default=None, type=int)
@click.option("--search", default=None)
@click.option("--export", is_flag=True)
def cmd_cases(case_id, search, export):
    """List, search, or reload past investigations."""
    print_banner()
    from utils.case_db import list_cases, get_case, search_cases, export_csv, print_cases_table
    if export:
        path = export_csv()
        console.print(f"[green]Exported → {path}[/green]")
    elif case_id:
        case = get_case(case_id)
        if case:
            pprint(case)
        else:
            console.print(f"[red]Case #{case_id} not found.[/red]")
    elif search:
        print_cases_table(search_cases(search))
    else:
        print_cases_table(list_cases())


@cli.command("permute")
@click.argument("number")
@click.option("--modes", default="last_digit,sequential", help="Comma-separated modes")
def cmd_permute(number, modes):
    """Generate neighboring number variants used by scammer clusters."""
    print_banner()
    from modules.number_permutator import generate_permutations
    mode_list = [m.strip() for m in modes.split(",")]
    variants  = generate_permutations(number, modes=mode_list)
    for v in variants:
        console.print(v)
    console.print(f"\n[cyan]Total variants: {len(variants)}[/cyan]")


@cli.command("pdns")
@click.argument("domain")
@click.option("--timeline", is_flag=True)
def cmd_pdns(domain, timeline):
    """Passive DNS history — track IP changes over time."""
    print_banner()
    from modules.passive_dns import passive_dns, ip_history_timeline
    if timeline:
        pprint(ip_history_timeline(domain))
    else:
        pprint(passive_dns(domain))


@cli.command("subpoena")
@click.option("--case-id",   required=True)
@click.option("--number",    default="")
@click.option("--platform",  default="[Service Provider]")
@click.option("--ip",        default="")
@click.option("--domain",    default="")
@click.option("--officer",   default="[Officer Name]")
@click.option("--badge",     default="N/A")
@click.option("--agency",    default="[Agency Name]")
def cmd_subpoena(case_id, number, platform, ip, domain, officer, badge, agency):
    """Generate a formatted subpoena PDF for legal records request."""
    print_banner()
    from modules.subpoena_generator import generate_subpoena
    path = generate_subpoena({
        "case_id"      : case_id,
        "number"       : number,
        "platform"     : platform,
        "ip"           : ip,
        "domain"       : domain,
        "officer_name" : officer,
        "badge_number" : badge,
        "agency_name"  : agency,
    })
    console.print(f"[green]Subpoena PDF → {path}[/green]")


@cli.command("status")
def cmd_status():
    """Show API key status and system configuration."""
    print_banner()
    from utils.config import get_keys
    keys = get_keys()
    status = keys.report_status()

    table = Table(title="API Key Status")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="bold")

    for service, configured in status.items():
        icon = "[green]✓ Active[/green]" if configured else "[red]✗ Missing[/red]"
        table.add_row(service.upper(), icon)

    console.print(table)


# ── Entry Point ─────────────────────────────────────────────

if __name__ == '__main__':
    config = get_config()
    config.ensure_output_dirs()
    print_key_status()
    cli()
