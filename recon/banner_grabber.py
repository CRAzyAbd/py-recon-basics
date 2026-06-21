#!/usr/bin/env python3
"""
banner_grabber.py
-----------------
Service banner grabbing using raw TCP sockets.

A banner is the first message a service sends when you connect.
Examples:
  Port 22  (SSH)  → "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  Port 21  (FTP)  → "220 (vsFTPd 3.0.5)"
  Port 25  (SMTP) → "220 mail.example.com ESMTP Postfix"
  Port 80  (HTTP) → "HTTP/1.1 200 OK\r\nServer: Apache/2.4..." (needs a request first)

Why this matters in pentesting:
  "Port 22 open" is a door.
  "Port 22 → OpenSSH 7.2" is a door with a known lock — CVE-2016-6515 exists for it.
  Banner grabbing turns open ports into actionable intelligence.
"""

import socket
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Longer than the port scanner timeout — we're waiting for actual data now
DEFAULT_TIMEOUT = 3.0

# These ports use HTTP — they stay silent until WE send a request first.
# Every other common port (SSH, FTP, SMTP, MySQL...) sends a greeting automatically.
HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 8081}


# ─────────────────────────────────────────────────────────────────────────────
# Core function
# ─────────────────────────────────────────────────────────────────────────────

def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Optional[str]:
    """
    Connect to host:port and read the service banner.

    Returns the banner as a string, or None if nothing was received.

    Two strategies depending on the port:
      - HTTP ports  → we send a HEAD request, then receive the response headers
      - Everything else → just connect; the service greets us automatically
    """
    try:
        # Same socket creation as Day 2
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # ── For HTTP ports: send a request first ──────────────────────────
        #
        # HTTP is "request → response". The server won't send anything until
        # you ask for something. We send a HEAD request:
        #   HEAD = "give me just the headers, not the page body"
        #   /    = "for the root page"
        #
        # HTTP requires CRLF line endings: \r\n (not just \n)
        # This is a rule from the 1970s baked into the HTTP protocol.
        # \r = Carriage Return (move cursor to start of line)
        # \n = Line Feed       (move cursor down one line)
        # A blank line \r\n\r\n signals the end of the request.
        if port in HTTP_PORTS:
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.send(request.encode("utf-8"))

        # ── For everything else: just listen ─────────────────────────────
        # SSH, FTP, SMTP, MySQL, Redis... they all send their banner
        # the moment you connect. We don't send anything — we just wait.
        # (No else needed — if not HTTP, we skip the send and go straight to recv)

        # recv(4096) = "read up to 4096 bytes from this connection"
        # 4096 is plenty for any banner or HTTP header block.
        # This is the key new concept of Day 3 — reading data from a socket,
        # not just checking if it connects.
        banner_bytes = sock.recv(4096)
        sock.close()

        # Sockets give us raw bytes. We decode them into a human-readable string.
        # errors="ignore" skips any bytes that aren't valid UTF-8
        # (some services mix binary data into their banners — we skip those chars)
        banner = banner_bytes.decode("utf-8", errors="ignore").strip()

        return banner if banner else None

    except socket.timeout:
        # The connection was established, but the service sent nothing before timeout.
        # This can happen for non-standard services that wait for a specific probe.
        return None

    except (socket.error, ConnectionRefusedError, OSError):
        # Connection failed entirely (shouldn't happen much — we already know the port is open)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Multi-port function (feeds off port_scanner output)
# ─────────────────────────────────────────────────────────────────────────────

def grab_banners(
    host: str,
    open_ports: list,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Grab banners from a list of open ports.
    Designed to accept the output of scan_ports() directly.

    Args:
        host:       hostname or IP address
        open_ports: list of port numbers — e.g. [22, 80, 443]
        timeout:    seconds to wait per port

    Returns:
        dict of {port: banner_string}
        Only ports that returned something are included.

    Example:
        >>> grab_banners("scanme.nmap.org", [22, 80])
        {22: "SSH-2.0-OpenSSH_8.9p1 ...", 80: "HTTP/1.1 200 OK | Server: Apache ..."}
    """
    results = {}

    if not open_ports:
        print("  [!] No open ports provided — nothing to grab banners from.")
        return results

    print(f"\n  {'─' * 46}")
    print(f"  Banner grabbing on : {host}")
    print(f"  Probing {len(open_ports)} port(s)  : {open_ports}")
    print(f"  {'─' * 46}\n")

    for port in open_ports:
        print(f"  [*] Probing port {port}...", end="", flush=True)

        banner = grab_banner(host, port, timeout)

        if banner:
            # Take the first 3 non-empty lines and join them with " | "
            # Most useful info (version, status) is always at the top
            lines = [line.strip() for line in banner.splitlines() if line.strip()]
            summary = " | ".join(lines[:3])

            results[port] = summary

            # Truncate long summaries so the display stays clean
            display = summary[:68] + "..." if len(summary) > 68 else summary
            print(f"\r  [+] Port {port:<5}  →  {display}")
        else:
            print(f"\r  [-] Port {port:<5}  →  (no banner received)")

    print(f"\n  {'─' * 46}")
    print(f"  Done — {len(results)}/{len(open_ports)} port(s) returned banners\n")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Quick test — run the full pipeline: scan → grab
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # sys.path trick: lets us run this file directly from the project root
    # and still import from the recon/ package correctly.
    # Without this, Python wouldn't find recon.port_scanner.
    import sys, os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from recon.port_scanner import scan_ports

    TARGET = "scanme.nmap.org"

    # Step 1 — reuse our Day 2 port scanner to find open ports
    print(f"Step 1 — Scanning {TARGET} for open ports...\n")
    open_ports = scan_ports(TARGET, start_port=1, end_port=1024, timeout=0.5)

    if not open_ports:
        print("No open ports found. Nothing to grab banners from.")
    else:
        # Step 2 — grab banners from everything that's open
        print(f"\nStep 2 — Grabbing banners from {len(open_ports)} open port(s)...")
        banners = grab_banners(TARGET, open_ports)

        # Step 3 — show the full raw banner for each port (not just the summary)
        if banners:
            print("  Full banner output:")
            for port in banners:
                raw = grab_banner(TARGET, port)
                if raw:
                    print(f"\n  ── Port {port} " + "─" * 32)
                    for line in raw.splitlines()[:6]:
                        if line.strip():
                            print(f"  {line.strip()}")
