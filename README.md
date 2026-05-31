# py-recon-basics

A Python CLI tool for basic network reconnaissance — built from scratch.

## What This Tool Does

- **Port Scanner** — Discovers open TCP ports on a target host
- **Banner Grabber** — Pulls service banners from open ports
- **WHOIS Lookup** — Fetches domain registration information
- **HTTP Inspector** — Analyzes HTTP response headers for security issues

## Why This Exists

Port scanning is the first thing any penetration tester does. Building it from scratch
means understanding exactly what Nmap does under the hood — and that depth shows in interviews.

## Tech Stack

- Python 3.10+
- `socket` (built-in) — port scanning and banner grabbing
- `python-whois` — domain lookups
- `requests` — HTTP header inspection

## Quick Start

See [SETUP.md](SETUP.md) for installation instructions.

## Project Structure

<pre>
    py-recon-basics/
    ├── recon/
    │   ├── __init__.py
    │   ├── port_scanner.py      (Day 2)
    │   ├── banner_grabber.py    (Day 3)
    │   ├── whois_lookup.py      (Day 4)
    │   ├── http_inspector.py    (Day 5)
    │   └── cli.py               (Day 6)
    ├── main.py
    ├── requirements.txt
    ├── SETUP.md
    └── README.md
</pre>

## Build Log

| Day | What Was Built | Commit Type |
|-----|---------------|-------------|
| 1   | Project setup, README, .gitignore | `docs:` |
| 2   | Port scanner using `socket` | `feat:` |
| 3   | Banner grabber for open ports | `feat:` |
| 4   | WHOIS lookup via `python-whois` | `feat:` |
| 5   | HTTP header inspector | `feat:` |
| 6   | `argparse` CLI interface | `refactor:` |
| 7   | Usage examples and sample output | `docs:` |

## Author

Abdullah — B.Tech CSE (Cybersecurity)
