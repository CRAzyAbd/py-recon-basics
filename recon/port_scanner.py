#!/usr/bin/env python3
"""
port_scanner.py
---------------
Basic TCP port scanner using Python's built-in socket library.

How it works:
  1. Create a TCP socket
  2. Try to connect to host:port
  3. connect_ex() returns 0   → port is OPEN  (service running)
  4. connect_ex() returns != 0 → port is CLOSED (RST received)
  5. connect_ex() times out   → port is FILTERED (firewall blocking)
"""

import socket


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Seconds to wait before giving up on a port
# Lower = faster scan, higher = more reliable on slow networks
DEFAULT_TIMEOUT = 0.5

# Common port numbers and their service names — for nicer output
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_service_name(port: int) -> str:
    """Return a service name for a port number, or 'unknown' if not in our list."""
    return COMMON_PORTS.get(port, "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Core functions
# ─────────────────────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Try to open a TCP connection to host:port.

    Returns True if OPEN, False if CLOSED or FILTERED.

    Think of it like dialing a phone number:
      - Someone picks up → True  (port open, service running)
      - "Number not in service" → False (port closed, RST received)
      - Phone just rings and rings → False (port filtered, timeout)
    """
    try:
        # socket.AF_INET    = use IPv4 addresses (like 192.168.1.1)
        # socket.SOCK_STREAM = use TCP protocol (reliable, ordered)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Don't wait longer than 'timeout' seconds for a response
        sock.settimeout(timeout)

        # connect_ex() attempts the TCP handshake.
        # Returns 0       → handshake succeeded (port OPEN)
        # Returns non-zero → handshake failed  (port CLOSED or FILTERED)
        #
        # We use connect_ex() instead of connect() because connect() throws
        # a Python exception on failure — that would crash our scan.
        # connect_ex() just returns a number we can check cleanly.
        result = sock.connect_ex((host, port))

        # Always close the socket — don't leave connections hanging open
        sock.close()

        return result == 0  # True if open, False if not

    except socket.gaierror:
        # gaierror = "getaddrinfo error"
        # Means the hostname couldn't be resolved to an IP address
        # e.g. you typed a wrong domain, or you're offline
        print(f"\n  [!] Could not resolve hostname: '{host}'")
        print(f"      Is the target correct? Is your internet on?")
        return False

    except socket.error as e:
        # Some other socket-level error (permissions, network issue, etc.)
        print(f"\n  [!] Socket error on port {port}: {e}")
        return False


def scan_ports(
    host: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = DEFAULT_TIMEOUT,
) -> list:
    """
    Scan a range of TCP ports on a target host.

    Args:
        host:       hostname or IP  (e.g. "scanme.nmap.org" or "192.168.1.1")
        start_port: first port to scan  (default: 1)
        end_port:   last port to scan   (default: 1024)
        timeout:    seconds to wait per port (default: 0.5)

    Returns:
        A list of open port numbers, e.g. [22, 80, 443]
    """
    open_ports = []
    total = end_port - start_port + 1

    print(f"\n  {'─' * 44}")
    print(f"  Target  : {host}")
    print(f"  Range   : {start_port} - {end_port}  ({total} ports)")
    print(f"  Timeout : {timeout}s per port")
    print(f"  {'─' * 44}\n")

    for port in range(start_port, end_port + 1):

        # \r = "carriage return" — moves the cursor back to the START of the
        # current line (not a new line). So each update overwrites the previous
        # one, giving a live progress display without scrolling.
        print(f"\r  [*] Scanning {port}/{end_port}...", end="", flush=True)

        if scan_port(host, port, timeout):
            service = get_service_name(port)

            # Print the result on its own line so it's preserved.
            # The extra spaces at the end clear any leftover progress text.
            print(f"\r  [+] Port {port:<5}  OPEN  ({service})" + " " * 15)
            open_ports.append(port)

    # Clear the last "Scanning x/y..." progress line
    print("\r" + " " * 40)

    print(f"  {'─' * 44}")
    print(f"  Scan complete — {len(open_ports)} open port(s) found\n")

    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# Run this file directly for a quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    # scanme.nmap.org is Nmap's official test server.
    # You are EXPLICITLY allowed to scan it. It exists for this purpose.
    #
    # IMPORTANT: Never scan a host you don't have permission to scan.
    # Port scanning unauthorized targets is illegal in most countries.

    TARGET = "scanme.nmap.org"

    results = scan_ports(
        host=TARGET,
        start_port=1,
        end_port=1024,
        timeout=0.5,
    )

    if results:
        print("  Open ports found:")
        for p in results:
            print(f"    Port {p:<6} → {get_service_name(p)}")
    else:
        print("  No open ports found in this range.")
