"""
Safe Monitor Loop - zapobiega nakladaniu sie skanow i zawieszaniu.
Jesli scan trwa za dlugo, jest przerywany.
"""

import asyncio
import logging
import time
import concurrent.futures


# Wspolny thread pool z limitem watkow
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="monitor")


async def safe_monitor_loop(monitor, scan_method_name="scan", label="Monitor"):
    if not getattr(monitor, "enabled", True):
        return

    monitor._running = True
    logger = getattr(monitor, "logger", logging.getLogger(label))
    interval = getattr(monitor, "interval", 10)
    scan_fn = getattr(monitor, scan_method_name)
    max_scan_time = 25  # Max 25s per scan

    logger.info(f"{label} started (interval={interval}s)")

    while monitor._running:
        try:
            loop = asyncio.get_event_loop()
            # Timeout na scan - jesli trwa >25s, anuluj
            await asyncio.wait_for(
                loop.run_in_executor(_EXECUTOR, scan_fn),
                timeout=max_scan_time,
            )
        except asyncio.TimeoutError:
            logger.warning(f"{label}: scan timed out after {max_scan_time}s, skipping")
        except Exception as e:
            logger.error(f"{label} error: {e}")

        await asyncio.sleep(interval)
