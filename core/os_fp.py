"""
Passive-ish OS fingerprinting.

Real nmap OS detection (-O) needs raw IP/TCP packets to inspect TTL,
window size, and TCP option ordering from crafted SYN packets --
none of which iSH's syscall emulation layer currently allows.

iSHMap approximates this with a *TTL + open-port heuristic*:
  - It reads the TTL of ICMP replies (via `ping`) to bucket the
    likely OS family (Linux/Unix ~64, Windows ~128, network gear ~255).
  - It cross-checks that bucket against which "fingerprint" ports are
    open (e.g. 3389 => likely Windows, 22+no 445 => likely Unix/Linux).
This is a best-effort guess, not packet-level OS detection.
"""
import re
import subprocess

TTL_BUCKETS = [
    (60, 70, "Linux/Unix (TTL ~64)"),
    (110, 130, "Windows (TTL ~128)"),
    (240, 256, "Network device / Solaris (TTL ~255)"),
]


def get_ttl(ip: str, timeout: int = 1):
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 1,
        ).stdout
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def guess_os(ip: str, open_ports: list) -> str:
    ttl = get_ttl(ip)
    base_guess = "Unknown"
    if ttl is not None:
        for lo, hi, label in TTL_BUCKETS:
            if lo <= ttl <= hi:
                base_guess = label
                break

    if 3389 in open_ports or 445 in open_ports:
        refine = "Windows"
    elif 22 in open_ports and 445 not in open_ports:
        refine = "Linux/Unix"
    else:
        refine = None

    if refine and refine.split("/")[0] not in base_guess:
        return f"{base_guess} (port-based hint suggests {refine})"
    return base_guess
