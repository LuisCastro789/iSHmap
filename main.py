#!/usr/bin/env python3
"""
iSHMap -- an nmap-inspired network scanner designed to run natively
inside the iSH iOS app, where raw sockets (AF_PACKET/AF_NETLINK) and
libpcap are unavailable.

Usage examples:
  python3 main.py -sn 192.168.1.0/24                # host discovery only
  python3 main.py -p 1-1000 -T4 192.168.1.10         # port scan, aggressive timing
  python3 main.py -sV -O 192.168.1.0/24              # + service + OS guess
  python3 main.py --script all 192.168.1.10          # run all scripts
  python3 main.py -sV --script http_title 10.0.0.5   # run one script
"""
import argparse
import asyncio
import ipaddress
import json
import sys
import time

from core import discovery, portscan, service_fp, os_fp, scripting


def parse_ports(spec: str):
    if not spec:
        return portscan.DEFAULT_PORTS
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def expand_targets(target: str):
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        # treat as hostname / single IP string
        return [target]


def build_parser():
    p = argparse.ArgumentParser(
        prog="ishmap",
        description="nmap-inspired scanner for iSH on iOS",
    )
    p.add_argument("targets", nargs="+", help="IP, hostname, or CIDR range(s)")
    p.add_argument("-sn", action="store_true", help="Host discovery only, no port scan")
    p.add_argument("-p", "--ports", default=None, help="Port spec, e.g. 22,80,1-1000 (default: top common ports)")
    p.add_argument("-sV", action="store_true", help="Enable service/version detection")
    p.add_argument("-O", action="store_true", help="Enable OS fingerprint heuristic")
    p.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                    help="Timing template 0 (paranoid) - 5 (insane), default 3")
    p.add_argument("--script", default=None,
                    help='Comma-separated script names, or "all"')
    p.add_argument("--timeout", type=float, default=0.75, help="Discovery probe timeout (s)")
    p.add_argument("-oJ", "--output-json", default=None, help="Write JSON results to file")
    return p


def progress(ip, *args):
    sys.stderr.write(f"\r[iSHMap] probing {ip}...        ")
    sys.stderr.flush()


async def main_async(args):
    all_targets = []
    for t in args.targets:
        all_targets.extend(expand_targets(t))

    print(f"[iSHMap] Expanding {len(args.targets)} target spec(s) -> {len(all_targets)} host(s)")
    start = time.time()

    print("[iSHMap] Phase 1: host discovery")
    up_hosts = await discovery.discover_hosts(
        all_targets, timeout=args.timeout, concurrency=100, progress_cb=progress
    )
    sys.stderr.write("\n")
    print(f"[iSHMap] {len(up_hosts)}/{len(all_targets)} host(s) up: {', '.join(up_hosts) if up_hosts else 'none'}")

    results = {}
    if not args.sn:
        ports = parse_ports(args.ports)
        print(f"[iSHMap] Phase 2: TCP connect scan of {len(ports)} port(s), timing=T{args.timing}")
        scan_results = await portscan.scan_targets(up_hosts, ports, timing=args.timing, progress_cb=progress)
        sys.stderr.write("\n")

        for ip, port_states in scan_results.items():
            open_ports = [p for p, s in port_states.items() if s == "open"]
            host_result = {"ports": port_states, "open_ports": open_ports}

            if args.sV and open_ports:
                print(f"[iSHMap] Phase 3: service detection on {ip}")
                fps = await service_fp.fingerprint_open_ports(ip, open_ports)
                host_result["services"] = fps

            if args.O:
                print(f"[iSHMap] Phase 4: OS heuristic on {ip}")
                host_result["os_guess"] = os_fp.guess_os(ip, open_ports)

            if args.script:
                names = None if args.script == "all" else args.script.split(",")
                print(f"[iSHMap] Phase 5: running script(s) on {ip}")
                host_result["scripts"] = await scripting.run_scripts(ip, open_ports, names)

            results[ip] = host_result
    else:
        results = {ip: {"status": "up"} for ip in up_hosts}

    elapsed = time.time() - start
    print(f"\n[iSHMap] Scan complete in {elapsed:.2f}s")
    print(json.dumps(results, indent=2))

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[iSHMap] Results written to {args.output_json}")


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[iSHMap] Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
