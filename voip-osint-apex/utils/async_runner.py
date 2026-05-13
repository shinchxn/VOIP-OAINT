"""
VoIP OSINT APEX — Async Runner Utility
Provides a safe asyncio runner for Click CLI commands.
"""

import asyncio
import logging
from typing import Coroutine, Any

log = logging.getLogger("async_runner")


def run_async(coro: Coroutine) -> Any:
    """
    Safely run an async coroutine from synchronous Click context.
    Handles event loop lifecycle correctly across platforms.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop — use nest_asyncio or thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)
