"""
VoIP OSINT APEX v3.0 — Real-time SIP/RTP Alert Streaming
Streams live forensic events to connected consumers (CLI, Telegram bot,
WebSocket clients) without polling. Uses asyncio.Queue as an internal bus.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import AsyncIterator, Callable, Optional

log = logging.getLogger("realtime")


# ── Internal event bus ──────────────────────────────────────────────────────

class EventBus:
    """
    Lightweight pub/sub bus backed by asyncio.Queue.
    Publishers push events; multiple subscribers consume independently.
    """

    def __init__(self, maxsize: int = 512):
        self._subscribers: list[asyncio.Queue] = []
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue:
        """Register a new subscriber. Returns a dedicated queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subscribers.append(q)
        log.debug(f"[EventBus] New subscriber — total: {len(self._subscribers)}")
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Deregister a subscriber queue."""
        try:
            self._subscribers.remove(q)
            log.debug(f"[EventBus] Subscriber removed — total: {len(self._subscribers)}")
        except ValueError:
            pass

    async def publish(self, event: dict) -> None:
        """Broadcast an event to all subscribers (non-blocking, drops if full)."""
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                log.warning("[EventBus] Subscriber queue full — event dropped")

    async def stream(self, q: asyncio.Queue) -> AsyncIterator[dict]:
        """Async generator yielding events from a subscriber queue."""
        while True:
            event = await q.get()
            yield event
            q.task_done()


# ── Singleton bus ────────────────────────────────────────────────────────────

_bus = EventBus()


def get_bus() -> EventBus:
    return _bus


# ── Event helpers (called by modules) ────────────────────────────────────────

async def emit(event_type: str, payload: dict, severity: str = "INFO") -> None:
    """
    Emit a real-time forensic event to all consumers.

    Args:
        event_type: e.g. "SIP_ALERT", "HLR_RESULT", "PORT_OPEN", "THREAT_HIT"
        payload:    The data dict to broadcast
        severity:   "INFO" | "WARNING" | "CRITICAL"
    """
    event = {
        "type":     event_type,
        "severity": severity,
        "payload":  payload,
    }
    await _bus.publish(event)
    log.info(f"[Realtime] {severity} {event_type}: {json.dumps(payload, default=str)[:120]}")


# ── CLI live printer ─────────────────────────────────────────────────────────

async def cli_live_printer(
    stop_event: Optional[asyncio.Event] = None,
    filter_types: Optional[list[str]] = None,
) -> None:
    """
    Consumes the event bus and prints to stdout using Rich.
    Run as a background task alongside sniffers/scanners.

    Args:
        stop_event:   Signal to stop printing
        filter_types: Only print these event types (None = all)
    """
    from rich.console import Console
    from rich.panel   import Panel
    from rich         import box

    console   = Console()
    queue     = _bus.subscribe()
    _stop     = stop_event or asyncio.Event()

    SEVERITY_COLOR = {
        "CRITICAL": "bold red",
        "WARNING":  "yellow",
        "INFO":     "green",
    }

    try:
        async for event in _bus.stream(queue):
            if _stop.is_set():
                break
            etype = event.get("type", "EVENT")
            if filter_types and etype not in filter_types:
                continue
            sev    = event.get("severity", "INFO")
            color  = SEVERITY_COLOR.get(sev, "white")
            ts     = event.get("ts", "")[:19].replace("T", " ")
            body   = json.dumps(event.get("payload", {}), indent=2, default=str)

            console.print(Panel(
                body,
                title=f"[{color}]{etype}[/]  [{sev}]  {ts}",
                border_style=color,
                box=box.ROUNDED,
            ))
    finally:
        _bus.unsubscribe(queue)


# ── Telegram event forwarder ─────────────────────────────────────────────────

async def telegram_event_forwarder(
    send_fn: Callable[[str], asyncio.coroutine],
    stop_event: Optional[asyncio.Event] = None,
    min_severity: str = "WARNING",
) -> None:
    """
    Forwards high-severity events to a Telegram chat via send_fn.

    Args:
        send_fn:      Async callable that sends a string message to Telegram
        stop_event:   Signal to stop forwarding
        min_severity: Minimum severity to forward ("INFO"|"WARNING"|"CRITICAL")
    """
    _severity_rank = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
    min_rank = _severity_rank.get(min_severity, 1)

    queue = _bus.subscribe()
    _stop = stop_event or asyncio.Event()

    try:
        async for event in _bus.stream(queue):
            if _stop.is_set():
                break
            sev = event.get("severity", "INFO")
            if _severity_rank.get(sev, 0) < min_rank:
                continue

            etype   = event.get("type", "EVENT")
            payload = event.get("payload", {})
            ts      = event.get("ts", "")[:19].replace("T", " ")

            # Format a compact Telegram message
            lines = [f"🚨 *{etype}* [{sev}]", f"`{ts} UTC`", ""]
            for k, v in list(payload.items())[:8]:   # Cap at 8 fields
                lines.append(f"• *{k}:* `{str(v)[:60]}`")

            try:
                await send_fn("\n".join(lines))
            except Exception as e:
                log.error(f"[Realtime] Telegram forward failed: {e}")
    finally:
        _bus.unsubscribe(queue)
