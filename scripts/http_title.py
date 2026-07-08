"""
Example iSHMap script: grabs the <title> of an HTTP service.
Mirrors nmap's http-title NSE script in spirit.
"""
import asyncio
import re

async def run(ip, open_ports, context):
    results = {}
    for port in (80, 8080, 443, 8443):
        if port not in open_ports:
            continue
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            writer.close()
            text = data.decode(errors="replace")
            match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            results[port] = match.group(1).strip() if match else "(no title found)"
        except Exception as e:
            results[port] = f"error: {e}"
    return results
