"""
Host discovery module for iSHMap.

iSH cannot open raw sockets (no AF_NETLINK / IPPROTO_RAW support), so
classic ARP/ICMP-raw based discovery used by nmap will not work.
Instead this module uses two userspace-safe techniques:

1. ICMP echo via the system `ping` binary (busybox ping uses a
   SOCK_DGRAM "ping socket" which iSH supports, unlike raw ICMP).
2. TCP "connect scan" probes against a small set of commonly open
   ports (80, 443, 22, 445, 3389, 8080) as a fallback / cross-check,
   since a successful connect() or an RST both prove the host is up.
"""
import asyncio
import subprocess
import shutil

COMMON_DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 8080]
PING_TIMEOUT_S = 1


def _has_ping_binary() -> bool:
    return shutil.which("ping") is not None


def icmp_ping(ip: str, timeout: float = PING_TIMEOUT_S) -> bool:
    """Return True if host answers a single ICMP echo request."""
    if not _has_ping_binary():
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout) or 1), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


async def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (ConnectionRefusedError,):
        # RST means the host is alive, just closed on that port
        return True
    except Exception:
        return False


async def host_is_up(ip: str, timeout: float = 0.75) -> bool:
    """Combine ICMP + TCP heuristics to decide liveness (nmap -sn style)."""
    loop = asyncio.get_running_loop()
    icmp_task = loop.run_in_executor(None, icmp_ping, ip, timeout)
    tcp_tasks = [tcp_probe(ip, p, timeout) for p in COMMON_DISCOVERY_PORTS]
    results = await asyncio.gather(icmp_task, *tcp_tasks, return_exceptions=True)
    return any(r is True for r in results)


async def discover_hosts(ip_list, timeout: float, concurrency: int, progress_cb=None):
    """Yield IPs that respond to discovery probes."""
    sem = asyncio.Semaphore(concurrency)
    up_hosts = []

    async def _check(ip):
        async with sem:
            up = await host_is_up(ip, timeout)
            if progress_cb:
                progress_cb(ip, up)
            if up:
                up_hosts.append(ip)

    await asyncio.gather(*[_check(str(ip)) for ip in ip_list])
    return up_hosts
