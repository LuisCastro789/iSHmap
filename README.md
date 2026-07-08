# iSHMap

**iSHMap** is a lightweight, pure-Python network mapping tool built specifically to run inside the [iSH](https://apps.apple.com/app/id1436902243) app on iOS/iPadOS, where standard `nmap` fails because iSH's syscall-translation kernel does not support raw sockets (`AF_NETLINK`, `AF_PACKET`) or libpcap.

iSHMap reimplements the core nmap workflow -- host discovery, port scanning, service detection, OS fingerprinting, and scripting -- using only syscalls and socket types that iSH's emulation layer actually supports (`SOCK_STREAM`/`SOCK_DGRAM` connect-style sockets and the busybox `ping` binary).

## Why nmap fails in iSH

iSH translates Linux syscalls to iOS/Darwin equivalents. Raw socket creation (`AF_NETLINK` for route lookups, `AF_PACKET`/`SOCK_RAW` for SYN scans and OS fingerprinting) is not implemented, which is why running `nmap` in iSH produces errors like:

```
route_dst_netlink: cannot create AF_NETLINK socket: Invalid argument
Couldn't open a raw socket. Error: Permission denied (13)
```

This is a known, long-standing limitation tracked in the iSH project itself, not something users can patch around with `sudo`. iSHMap avoids the problem entirely by never requiring raw sockets.

## How iSHMap Compares to nmap

| Capability | nmap (needs raw sockets) | iSHMap (iSH-safe) |
|---|---|---|
| Host discovery | ARP/ICMP raw ping (`-sn`) | ICMP via busybox `ping` + TCP probe fallback |
| Port scanning | SYN stealth scan (`-sS`) | Full TCP connect scan (`-sT` equivalent) |
| Scan speed control | `-T0` to `-T5` timing templates | `-T0` to `-T5` concurrency/timeout templates |
| Service/version detection | `-sV` with large probe DB | `-sV` with lightweight JSON signature file + banner grab |
| OS detection | `-O` via TCP/IP stack fingerprinting | `-O` heuristic using ICMP TTL + open-port hints |
| Scripting | NSE (Lua) | iSHMap Scripting Engine (ISE) -- plain Python `run()` scripts |

## Features

- Scan IP ranges using CIDR notation (e.g. `192.168.1.0/24`) or individual hosts/hostnames.
- Host discovery combining ICMP ping and TCP probes on common ports, so hosts that block ICMP are still found.
- Configurable scan speed via `-T0` (paranoid) through `-T5` (insane), mirroring nmap's timing templates.
- Service/version fingerprinting via lightweight banner grabbing against a JSON signature database.
- OS fingerprint heuristic based on ICMP TTL values and open-port patterns.
- Extensible scripting engine (ISE): drop a Python file with a `run(ip, open_ports, context)` coroutine into `scripts/` and it's auto-loaded, no compiled interpreter required (unlike NSE's Lua dependency).
- Pure Python 3 standard library -- no `pip install` required, which matters on iSH's constrained package ecosystem (Alpine `apk`).
- JSON output (`-oJ results.json`) for integration with other tools or scripts.

## Requirements

- iSH app installed from the [App Store](https://apps.apple.com/app/id1436902243).
- Python 3.7+ inside iSH: `apk add python3`
- No third-party pip packages needed.

## Quick Start

1. Install iSH from the App Store and open it.
2. Install Python 3 and git:
   ```
   apk update
   apk add python3 git
   ```
3. Clone this repository:
   ```
   git clone https://github.com/LuisCastro789/iSHmap
   cd ishmap
   ```
4. Run a basic host discovery scan on your local subnet:
   ```
   python3 main.py -sn 192.168.1.0/24
   ```
5. Run a full scan with service detection, OS guessing, and all scripts:
   ```
   python3 main.py -sV -O --script all -T4 192.168.1.0/24
   ```
6. Scan a specific port range on one host:
   ```
   python3 main.py -p 1-1024 -T3 192.168.1.10
   ```
7. Save results to JSON:
   ```
   python3 main.py -sV 192.168.1.10 -oJ results.json
   ```

## Command Reference

| Flag | Description |
|---|---|
| `targets` | One or more IPs, hostnames, or CIDR ranges (positional, required) |
| `-sn` | Host discovery only, skip port scanning |
| `-p / --ports` | Port spec, e.g. `22,80,1-1000` (default: 21 common ports) |
| `-sV` | Enable service/version detection |
| `-O` | Enable OS fingerprint heuristic |
| `-T / --timing` | Timing template 0 (paranoid) to 5 (insane), default 3 |
| `--script` | Comma-separated script names, or `all` |
| `--timeout` | Discovery probe timeout in seconds (default 0.75) |
| `-oJ / --output-json` | Write JSON results to the given file |

## Writing Your Own Script

Create a file in `scripts/`, e.g. `scripts/my_check.py`:

```python
async def run(ip, open_ports, context):
    # inspect open_ports, connect to services, etc.
    return {"note": "my custom finding"}
```

It will be auto-discovered and can be invoked with `--script my_check` or `--script all`.

## Project Structure

```
ishmap/
├── main.py                  # CLI entry point
├── core/
│   ├── discovery.py         # ICMP + TCP-based host discovery
│   ├── portscan.py          # asyncio TCP connect-scan engine + timing templates
│   ├── service_fp.py        # banner-grab based service/version detection
│   ├── os_fp.py             # TTL + port heuristic OS fingerprinting
│   └── scripting.py         # ISE plugin loader/runner
├── probes/
│   └── service_probes.json  # port -> protocol/probe/keyword signature table
├── scripts/
│   ├── http_title.py        # example script: grabs HTTP <title>
│   └── default_creds.py     # example script: flags default-cred-prone ports
├── requirements.txt
└── README.md
```

## Known Limitations

- No SYN stealth scan -- all port scans are full TCP connects, which are noisier and slightly slower but work without raw sockets.
- OS detection is a heuristic, not packet-level fingerprinting, and can be wrong for hosts with modified TTLs or firewalls.
- No UDP scanning yet (planned; would require `SOCK_DGRAM` probes per service, since iSH lacks raw ICMP for port-unreachable detection).
- Performance is bounded by iSH's syscall translation overhead and mobile CPU/battery, so very large ranges (e.g. `/16`) should be scanned in smaller batches.

## License

MIT License. See `LICENSE` for details.
