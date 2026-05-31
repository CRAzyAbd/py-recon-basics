#!/usr/bin/env python3
"""
py-recon-basics
---------------
A Python CLI tool for basic network reconnaissance.
Built day-by-day as a cybersecurity learning project.
"""


def main():
    print("=" * 42)
    print("  py-recon-basics")
    print("  Network Reconnaissance Tool")
    print("=" * 42)
    print()
    print("Modules being built day by day:")
    print()

    modules = [
        ("Day 2", "Port Scanner",    "[ ]"),
        ("Day 3", "Banner Grabber",  "[ ]"),
        ("Day 4", "WHOIS Lookup",    "[ ]"),
        ("Day 5", "HTTP Inspector",  "[ ]"),
        ("Day 6", "CLI Interface",   "[ ]"),
    ]

    for day, name, status in modules:
        print(f"  {status}  {day}: {name}")

    print()
    print("Come back after Day 6 for the full CLI!")


if __name__ == "__main__":
    main()
