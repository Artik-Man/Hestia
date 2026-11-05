"""Send tagged underlay controls and verify that marked probes cannot use the same live path."""

import errno
import socket


def main() -> None:
    """Send allowed controls and require both marked IPv4/IPv6 attempts to fail in the gateway kernel."""
    for family, addr in ((socket.AF_INET, "198.18.0.2"), (socket.AF_INET6, "fd77::2")):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"underlay-control", (addr, 15999))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 515)
            try:
                sock.sendto(b"denied", (addr, 16000))
            except OSError as err:
                if err.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                    raise
            else:
                raise RuntimeError("marked packet escaped to the underlay")


if __name__ == "__main__":
    main()
