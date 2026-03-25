"""
Safe Monitor Loop - runs heavy (subprocess-based) monitors periodically.

Python 3.14 + Windows: subprocess.run() in threads causes segfault via
IOCP race condition. Solution: run scans directly in async loop with
asyncio.sleep() yielding between scans. Each scan blocks briefly (~1-8s)
but this is acceptable for non-critical monitors.
"""

import asyncio
import logging
import sys


async def safe_monitor_loop(monitor, scan_method_name="scan", label="Monitor"):
    if not getattr(monitor, "enabled", True):
        return

    monitor._running = True
    logger = getattr(monitor, "logger", logging.getLogger(label))
    interval = max(getattr(monitor, "interval", 15), 15)  # min 15s for heavy
    scan_fn = getattr(monitor, scan_method_name, None)

    if scan_fn is None:
        logger.error(f"{label}: no method '{scan_method_name}' found")
        return

    logger.info(f"{label} monitor started (interval={interval}s)")

    # Stagger start: wait 10-20s so honeypots and dashboard start first
    await asyncio.sleep(10)

    while monitor._running:
        try:
            scan_fn()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"{label} scan error: {e}")

        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
