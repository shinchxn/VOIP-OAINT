"""
Call Graph Visualizer
Builds ASCII call flow trees from SIP packet data using Rich.
Also exports a Mermaid diagram string for HTML reports.
"""

import logging
from typing import Optional
# pyrefly: ignore [missing-import]
from rich.tree  import Tree
# pyrefly: ignore [missing-import]
from rich.table import Table
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.panel import Panel
# pyrefly: ignore [missing-import]
from rich import box

log = logging.getLogger("call_graph")


def build_call_graph(sip_packets: list[dict], title: str = "SIP Call Flow") -> Tree:
    """
    Renders a Rich tree of the call path to stdout.

    Each sip_packet dict should contain:
        src_ip, dst_ip, method, via (optional),
        user_agent (optional), x_forwarded (optional),
        call_id (optional), timestamp (optional)
    """
    console = Console()
    root    = Tree(f"📞 [bold white]{title}[/bold white]")
    seen_calls: dict[str, Tree] = {}

    for idx, pkt in enumerate(sip_packets, 1):
        call_id  = pkt.get("call_id", f"call-{idx}")
        method   = pkt.get("method", "SIP")
        src      = pkt.get("src_ip",  "?")
        dst      = pkt.get("dst_ip",  "?")
        via      = pkt.get("via",         "N/A")
        agent    = pkt.get("user_agent",  "unknown")
        fwd      = pkt.get("x_forwarded", None)
        ts       = pkt.get("timestamp",   "")

        # Group legs by Call-ID
        if call_id not in seen_calls:
            call_label = (
                f"[bold yellow]Call-ID:[/bold yellow] {call_id[:24]}..."
                if len(call_id) > 24 else
                f"[bold yellow]Call-ID:[/bold yellow] {call_id}"
            )
            seen_calls[call_id] = root.add(call_label)

        leg = seen_calls[call_id].add(
            f"[cyan]{src}[/cyan]"
            f" [bold]──[{_method_color(method)}]{method}[/]──▶[/bold] "
            f"[green]{dst}[/green]"
            + (f"  [dim]{ts}[/dim]" if ts else "")
        )
        leg.add(f"[dim]Via:        [/dim]{via}")
        leg.add(f"[dim]User-Agent: [/dim]{agent}")
        if fwd:
            leg.add(f"[bold red]X-Forwarded: {fwd}[/bold red]")

    console.print(Panel(root, title="[bold]VoIP OSINT — Call Graph[/bold]", box=box.DOUBLE_EDGE))
    return root


def build_stats_table(sip_packets: list[dict]) -> Table:
    """Companion table: unique IPs, methods, and user-agents seen."""
    console = Console()
    table   = Table(title="SIP Traffic Summary", box=box.SIMPLE_HEAVY)
    table.add_column("Metric",  style="cyan",  no_wrap=True)
    table.add_column("Value",   style="white")

    unique_ips     = {p.get("src_ip") for p in sip_packets} | {p.get("dst_ip") for p in sip_packets}
    unique_agents  = {p.get("user_agent", "?") for p in sip_packets}
    methods        = {}
    for p in sip_packets:
        m = p.get("method", "?")
        methods[m] = methods.get(m, 0) + 1

    table.add_row("Total Packets",    str(len(sip_packets)))
    table.add_row("Unique IPs",       str(len(unique_ips)))
    table.add_row("Unique Agents",    ", ".join(list(unique_agents)[:5]))
    for method, count in sorted(methods.items(), key=lambda x: -x[1]):
        table.add_row(f"Method: {method}", str(count))

    console.print(table)
    return table


def to_mermaid(sip_packets: list[dict]) -> str:
    """
    Export call graph as a Mermaid sequence diagram string.
    Paste into any Markdown renderer or HTML report.
    """
    lines = ["sequenceDiagram"]
    for pkt in sip_packets:
        src    = pkt.get("src_ip", "Unknown").replace(".", "_")
        dst    = pkt.get("dst_ip", "Unknown").replace(".", "_")
        method = pkt.get("method", "SIP")
        lines.append(f"    {src}->>{dst}: {method}")
    return "\n".join(lines)


# ── helpers ─────────────────────────────────────────────────

def _method_color(method: str) -> str:
    return {
        "INVITE" : "bold green",
        "BYE"    : "bold red",
        "CANCEL" : "red",
        "REGISTER": "bold cyan",
        "OPTIONS": "yellow",
    }.get(method.upper(), "white")
