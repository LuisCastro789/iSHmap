"""
TCP connect-scan engine for iSHMap.

Because iSH cannot craft raw SYN packets, this scanner uses full
TCP connect() scans (equivalent to nmap -sT) driven by asyncio for
speed. A configurable concurrency value lets users trade off speed
vs. reliability, similar to nmap's -T0..T5 timing templates.
"""
import asyncio

TIMING_TEMPLATES = {
    0: {"concurrency": 1,   "timeout": 5.0},   # paranoid
    1: {"concurrency": 5,   "timeout": 3.0},   # sneaky
    2: {"concurrency": 20,  "timeout": 2.0},   # polite
    3: {"concurrency": 100, "timeout": 1.0},   # normal (default)
    4: {"concurrency": 300, "timeout": 0.5},   # aggressive
    5: {"concurrency": 500, "timeout": 0.25},  # insane
}

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                  445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


async def scan_port(ip: str, port: int, timeout: float):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, "open"
    except asyncio.TimeoutError:
        return port, "filtered"
    except ConnectionRefusedError:
        return port, "closed"
    except OSError:
        return port, "closed"


async def scan_host(ip: str, ports, timing: int = 3, progress_cb=None):
    tmpl = TIMING_TEMPLATES.get(timing, TIMING_TEMPLATES[3])
    sem = asyncio.Semaphore(tmpl["concurrency"])
    results = {}

    async def _bound(port):
        async with sem:
            p, state = await scan_port(ip, port, tmpl["timeout"])
            results[p] = state
            if progress_cb:
                progress_cb(ip, p, state)

    await asyncio.gather(*[_bound(p) for p in ports])
    return dict(sorted(results.items()))


async def scan_targets(ip_list, ports, timing: int = 3, progress_cb=None):
    all_results = {}
    for ip in ip_list:
        all_results[str(ip)] = await scan_host(str(ip), ports, timing, progress_cb)
    return all_results
