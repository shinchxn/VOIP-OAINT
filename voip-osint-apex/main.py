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
import json
import os

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

console = Console()

BANNER = """
 __   __    ___ ___     ___  __  _  _  _____
 \ \ / /__ |_ _| _ \   / _ \/ _\| \| ||_   _|
  \ V / _ \ | ||  _/  | (_) \__ \ .` |  | |
   \_/\___/|___|_|     \___/|___/_|\_|  |_|
  VoIP OSINT APEX v2.0 | LEA EDITION
"""

def print_banner():
    console.print(f"[cyan]{BANNER}[/cyan]")
    console.print("─────────────────────────────────────────")

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
    """VoIP OSINT APEX CLI"""
    pass

@cli.command()
@click.argument('number')
@click.option('--save', is_flag=True, help="Save to JSON")
@click.option('--pdf', is_flag=True, help="Save to PDF")
def number(number, save, pdf):
    print_banner()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        progress.add_task(description="Analyzing number...", total=None)
        res = analyze_number(number)
    
    table = Table(title="Number Intelligence", box=click.Choice(['ROUNDED']) if False else None, show_header=False)
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

@cli.command()
@click.argument('ip')
@click.option('--ports', is_flag=True, help="Scan VoIP ports")
@click.option('--save', is_flag=True, help="Save to JSON")
def ip(ip, ports, save):
    print_banner()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        progress.add_task(description="Analyzing IP...", total=None)
        res = asyncio.run(analyze_ip(ip))
        
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

@cli.command()
@click.argument('domain')
@click.option('--harvest', is_flag=True)
@click.option('--save', is_flag=True)
def domain(domain, harvest, save):
    print_banner()
    res = lookup_domain(domain)
    if harvest:
        res["harvester"] = run_harvester(domain)
        
    console.print(res)
    if save:
        generate_json(res)

@cli.command()
@click.argument('file_path')
@click.option('--rtp', is_flag=True)
@click.option('--save', is_flag=True)
def pcap(file_path, rtp, save):
    print_banner()
    res = {"sip_packets": parse_pcap(file_path)}
    if rtp:
        res["rtp_servers"] = parse_rtp(file_path)
    
    console.print(f"Found {len(res['sip_packets'])} SIP packets")
    if rtp:
        console.print(f"RTP servers: {res['rtp_servers']}")
        for server in res["rtp_servers"]:
            asyncio.run(analyze_ip(server))
        
    if save:
        generate_json(res)

@cli.command()
@click.option('--iface', default='eth0')
@click.option('--alert', is_flag=True)
def live(iface, alert):
    print_banner()
    console.print(f"[cyan]Listening on {iface}...[/cyan]")
    
    def on_packet(data):
        console.print(Panel(
            f"From: {data.get('from')}\nSRC IP: {data.get('src_ip')}\nVia: {data.get('via')}\nAgent: {data.get('user_agent')}",
            title="⚡ LIVE INVITE DETECTED",
            border_style="blue"
        ))
        if alert:
            ip_res = asyncio.run(analyze_ip(data.get('src_ip')))
            risk = ip_res.get('risk_level', 'LOW')
            if risk in ['CRITICAL', 'HIGH']:
                print_risk_panel(risk, ip_res)
                generate_json(ip_res)
            
    live_sniff(on_packet, iface)

@cli.command()
@click.option('--number')
@click.option('--ip')
@click.option('--domain')
@click.option('--save', is_flag=True)
@click.option('--pdf', is_flag=True)
def full(number, ip, domain, save, pdf):
    print_banner()
    num_data = analyze_number(number) if number else {}
    ip_data = asyncio.run(analyze_ip(ip)) if ip else {}
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

@cli.command()
@click.option('--email')
@click.option('--domain')
def osint(email, domain):
    print_banner()
    if email:
        console.print(platform_check(email))
    if domain:
        console.print(harvester_osint(domain))
        console.print(dnsrecon_scan(domain))

@cli.command()
@click.argument('ip_range')
def scan(ip_range):
    print_banner()
    console.print(masscan_quick(ip_range))

@cli.command()
@click.option('--report')
def correlate_cmd(report):
    print_banner()
    try:
        with open(report, 'r') as f:
            data = json.load(f)
        console.print(correlate(data.get('number',{}), data.get('ip',{}), data.get('domain',{}), []))
    except Exception as e:
        console.print(f"Error loading report: {e}")

@cli.command()
@click.argument('ip')
def fingerprint(ip):
    print_banner()
    console.print(sip_server_fingerprint(ip))
    console.print(trace_voip_path(ip))

if __name__ == '__main__':
    os.makedirs("outputs/reports", exist_ok=True)
    os.makedirs("outputs/logs", exist_ok=True)
    os.makedirs("outputs/pcaps", exist_ok=True)
    cli()
