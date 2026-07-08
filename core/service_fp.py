"""
Lightweight service/version fingerprinting.

nmap uses a large probe/signature database (nmap-service-probes).
iSHMap ships a small JSON signature file (probes/service_probes.json)
mapping common ports to a default protocol assumption, and performs
a banner-grab to confirm/refine the guess -- similar in spirit to
nmap's -sV but far lighter, which matters on a phone CPU/battery.
"""
import asyncio
import json
import os

_PROBE_PATH = os.path.join(os.path.dirname(__file__), "..", "probes", "service_probes.json")

with open(_PROBE_PATH) as f:
    _SIGNATURES = json.load(f)


async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        probe = _SIGNATURES.get(str(port), {}).get("probe")
        if probe:
            writer.write(probe.encode())
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode(errors="replace").strip()
    except Exception:
        return ""


async def identify_service(ip: str, port: int) -> dict:
    sig = _SIGNATURES.get(str(port), {})
    banner = await grab_banner(ip, port)
    service = sig.get("name", "unknown")
    if banner:
        for keyword, name in sig.get("keywords", {}).items():
            if keyword.lower() in banner.lower():
                service = name
                break
    return {"port": port, "service": service, "banner": banner[:120]}


async def fingerprint_open_ports(ip: str, open_ports):
    return await asyncio.gather(*[identify_service(ip, p) for p in open_ports])
