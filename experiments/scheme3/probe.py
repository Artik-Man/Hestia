"""Probe HTTPS from the Lima client and correlate each request with Hestia interfaces."""

import concurrent.futures
import ipaddress
import os
import subprocess
import sys


def guest(instance, *args):
    """Build a limactl command for one of the two scheme 3 guests."""
    binary = os.environ.get("LIMACTL", "/private/tmp/hestia-vm-run/bin/limactl")
    return [binary, "shell", instance, "--", *args]


def probe(site):
    """Pin a fresh IPv4 request to one resolved address and report observed TCP SYNs."""
    client = "hestia-test-client"
    gateway = "hestia-stage1"
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
        "lima0 Out" in line and "192.168.1.133." in line for line in packets.splitlines()
    )
    http = request.stdout.strip()
    success = request.returncode == 0 and http[:1] in ("2", "3")
    return f"{site} {address} HTTP={http} wg_in={incoming} lima_out={outgoing}", (
        success and incoming and outgoing
    )


def main():
    """Run the fixed control requests and exit successfully only if both traverse Hestia."""
    os.environ.setdefault("LIMA_HOME", "/private/tmp/hestia-vm-run/lima-state")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(probe, ("ya.ru", "example.com")))
    for report, _ in results:
        print(report)
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
