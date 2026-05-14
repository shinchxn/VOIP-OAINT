#!/usr/bin/env python3
"""
VoIP OSINT APEX v3.0 — Main CLI Entry Point
Rich CLI interface for investigative workflows.
"""

import asyncio
import click
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from utils.config import get_config, get_keys, print_key_status
from utils.logger import setup_logging, log_investigation, log_error
from utils.case_db import init_db, save_case, list_cases, search_cases, export_cases
import modules

console = Console()
cfg = get_config()

# Ensure dirs and logs exist
cfg.ensure_output_dirs()
setup_logging()

@click.group()
def cli():
    """VoIP OSINT APEX v3.0 — Advanced Communications Intelligence"""
    pass

@cli.command()
def setup():
    """Initialize database and caches."""
    asyncio.run(init_db())
    console.print("[green]Database initialized successfully.[/green]")

@cli.command()
def keys():
    """Show API key status (replaces old status cmd)."""
    k = get_keys()
    status = k.status()
    t = Table(title="API Keys Status")
    t.add_column("Service")
    t.add_column("Status")
    
    for srv, st in status.items():
        color = "green" if st == "SET" else "red"
        t.add_row(srv.upper(), f"[{color}]{st}[/{color}]")
        
    console.print(t)
    
def print_json(data: dict):
    console.print_json(json.dumps(data, default=str))

@cli.command()
@click.argument('number')
def number(number):
    """Analyze a phone number."""
    try:
        res = asyncio.run(modules.analyze_number(number))
        print_json(res)
        log_investigation("number", number, res.get("risk_level", "UNKNOWN"), ["number_lookup"])
    except Exception as e:
        log_error("number_lookup", e)
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.argument('ip')
def ip(ip):
    """Analyze an IP address."""
    try:
        res = asyncio.run(modules.analyze_ip(ip))
        print_json(res)
        log_investigation("ip", ip, res.get("risk_level", "UNKNOWN"), ["ip_intel"])
    except Exception as e:
        log_error("ip_intel", e)
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.argument('domain')
def domain(domain):
    """Analyze a domain name."""
    try:
        res = asyncio.run(modules.lookup_domain(domain))
        print_json(res)
        log_investigation("domain", domain, res.get("risk_level", "UNKNOWN"), ["domain_lookup"])
    except Exception as e:
        log_error("domain_lookup", e)
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.argument('pcap_file')
def pcap(pcap_file):
    """Parse a SIP/RTP PCAP file."""
    try:
        sip = modules.parse_sip_pcap(pcap_file)
        rtp = modules.parse_rtp_pcap(pcap_file)
        res = {"sip_packets": len(sip), "rtp_streams": len(rtp), "sip_data": sip[:5], "rtp_data": rtp[:5]}
        print_json(res)
        log_investigation("pcap", pcap_file, f"SIP:{len(sip)} RTP:{len(rtp)}", ["sip_parser"])
    except Exception as e:
        log_error("sip_parser", e)
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.option('--iface', default='eth0', help='Interface to sniff on')
def live(iface):
    """Live SIP packet sniffing."""
    console.print(f"[bold yellow]Starting live capture on {iface}... Press Ctrl+C to stop.[/bold yellow]")
    try:
        modules.live_sniff(lambda x: print_json(x), iface=iface)
    except KeyboardInterrupt:
        console.print("\n[green]Capture stopped.[/green]")
    except Exception as e:
        log_error("live_sniff", e)
        console.print(f"[red]Error: {e}[/red]")

@cli.command()
@click.option('--number', '-n', help='Phone number')
@click.option('--ip', '-i', help='IP address')
@click.option('--domain', '-d', help='Domain')
def correlate(number, ip, domain):
    """Deep correlation of multiple artifacts."""
    async def run_all():
        data = {}
        if number:
            data["number"] = await modules.analyze_number(number)
        if ip:
            data["ip"] = await modules.analyze_ip(ip)
        if domain:
            data["domain"] = await modules.lookup_domain(domain)
            
        corr = await modules.run_correlation(data)
        data["correlation"] = corr
        
        # Save to DB
        case_id = await save_case(data)
        
        # Reports
        pdf_path = modules.generate_pdf(case_id, data)
        modules.generate_json(case_id, data)
        
        console.print(Panel(
            f"Case: {case_id}\nRisk: {corr.get('risk_level')}\nScore: {corr.get('confidence_score')}/100",
            title="Correlation Complete", style="bold green"
        ))
        console.print(f"[green]Report generated: {pdf_path}[/green]")
        
        log_investigation("correlate", f"{number}|{ip}|{domain}", corr.get("risk_level", "UNKNOWN"), ["correlator"], pdf_path)
        
    asyncio.run(run_all())

@cli.command(name='db-list')
@click.option('--limit', default=20, help='Number of records to show')
def db_list(limit):
    """List recent investigations."""
    cases = asyncio.run(list_cases(limit))
    t = Table(title=f"Recent Investigations (Last {limit})")
    t.add_column("Case ID")
    t.add_column("Date")
    t.add_column("Target(s)")
    t.add_column("Risk")
    
    for c in cases:
        targets = " | ".join(filter(None, [c.get("number"), c.get("ip"), c.get("domain")]))
        t.add_row(c.get("case_id"), c.get("timestamp")[:10], targets, c.get("risk_level"))
        
    console.print(t)

@cli.command(name='db-search')
@click.argument('query')
def db_search(query):
    """Search investigations."""
    cases = asyncio.run(search_cases(query))
    t = Table(title=f"Search Results for '{query}'")
    t.add_column("Case ID")
    t.add_column("Date")
    t.add_column("Target(s)")
    t.add_column("Risk")
    
    for c in cases:
        targets = " | ".join(filter(None, [c.get("number"), c.get("ip"), c.get("domain")]))
        t.add_row(c.get("case_id"), c.get("timestamp")[:10], targets, c.get("risk_level"))
        
    console.print(t)

@cli.command(name='db-export')
def db_export():
    """Export DB to JSON."""
    path = asyncio.run(export_cases())
    console.print(f"[green]Exported database to: {path}[/green]")

if __name__ == '__main__':
    cli()
