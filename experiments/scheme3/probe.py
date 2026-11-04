"""Probe HTTPS from the Lima client and correlate each request with Hestia interfaces."""

import concurrent.futures
import ipaddress
import os
import subprocess
import sys


def guest(instance, *args):
    """Build a limactl command for one of the two scheme 3 guests."""
    binary = os.environ.get("LIMACTL", "limactl")
    return [binary, "shell", instance, "--", *args]


def probe(site, gateway_ip):
    """Pin a fresh IPv4 request to one resolved address and report observed TCP SYNs."""
    client = os.environ["HESTIA_CLIENT_VM"]
    gateway = os.environ["HESTIA_GATEWAY_VM"]
    records = subprocess.check_output(
        guest(client, "getent", "ahostsv4", site), text=True, timeout=10
    )
    address = str(ipaddress.IPv4Address(records.split()[0]))
    packet_filter = f"dst host {address} and tcp dst port 443 and tcp[13] & 2 != 0"
    with subprocess.Popen(
        guest(gateway, "sudo", "timeout", "14", "tcpdump", "-nnl", "-i", "any", packet_filter),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ) as capture:
        for line in capture.stdout:
            if "listening on" in line:
                break
        else:
            raise RuntimeError("capture did not start")
        request = subprocess.run(
            guest(client, "curl", "-4", "--noproxy", "*", "--interface", "lima0",
                  "--resolve", f"{site}:443:{address}", "--max-time", "8", "-sS",
                  "-o", "/dev/null", "-w", "%{http_code}", f"https://{site}/"),
            capture_output=True, text=True, timeout=12
        )
        packets = capture.stdout.read()
        if capture.wait() not in (0, 124) or "0 packets dropped by kernel" not in packets:
            raise RuntimeError("capture incomplete")
    incoming = "wg-keenetic In" in packets
    outgoing = "lima0 Out" in packets and any(
        "lima0 Out" in line and f"IP {gateway_ip}." in line for line in packets.splitlines()
    )
    http = request.stdout.strip()
    success = request.returncode == 0 and http[:1] in ("2", "3")
    return f"{site} {address} HTTP={http} wg_in={incoming} lima_out={outgoing}", (
        success and incoming and outgoing
    )


def main():
    """Run the fixed control requests and exit successfully only if both traverse Hestia."""
    if not all(os.environ.get(key) for key in ("HESTIA_CLIENT_VM", "HESTIA_GATEWAY_VM")):
        sys.exit("Set HESTIA_CLIENT_VM and HESTIA_GATEWAY_VM to two dedicated lab VMs.")
    if os.environ["HESTIA_CLIENT_VM"] == os.environ["HESTIA_GATEWAY_VM"]:
        sys.exit("The client and the gateway must be distinct VMs.")
    raw = subprocess.check_output(guest(os.environ["HESTIA_GATEWAY_VM"], "ip", "-4", "-o", "addr",
                                        "show", "dev", "lima0", "scope", "global"), text=True, timeout=10)
    gateway_ip = ipaddress.IPv4Interface(raw.split()[3]).ip
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(probe, ("ya.ru", "example.com"), (gateway_ip, gateway_ip)))
    for report, _ in results:
        print(report)
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
