"""
Example iSHMap script: flags services commonly left with default
credentials, as a reminder to manually verify (does not attempt login).
"""
DEFAULT_CRED_PORTS = {
    23: "telnet - check for admin/admin or root/blank",
    3389: "RDP - check for weak/default local admin passwords",
    5900: "VNC - check for blank/weak VNC password",
    3306: "MySQL - check for root/blank or root/root",
}

async def run(ip, open_ports, context):
    findings = {}
    for port in open_ports:
        if port in DEFAULT_CRED_PORTS:
            findings[port] = DEFAULT_CRED_PORTS[port]
    return findings
