import socket
import sys
from datetime import datetime

def scan_ports(host, start_port=1, end_port=1024):
    """
    Scans a range of TCP ports on a target host.
    Returns a list of open ports.
    """
    print(f"\n{'='*50}")
    print(f" py-recon-basics | Port Scanner")
    print(f"{'='*50}")
    print(f" Target  : {host}")
    print(f" Ports   : {start_port} - {end_port}")
    print(f" Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

    open_ports = []

    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(host)
        print(f"[*] Resolved {host} -> {target_ip}\n")
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {host}")
        sys.exit(1)

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            print(f"[+] Port {port:5d} OPEN  ({service})")
            open_ports.append(port)

        sock.close()

    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")
    return open_ports


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 scanner.py <host> [start_port] [end_port]")
        print(f"Example: python3 scanner.py scanme.nmap.org 1 1024")
        sys.exit(1)

    host = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end   = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    scan_ports(host, start, end)
