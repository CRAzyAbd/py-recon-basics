#!/usr/bin/env python3
"""
whois_lookup.py
---------------
Domain WHOIS lookup using the python-whois library.

What WHOIS is (RFC 3912):
  A TCP protocol running on port 43. Your tool connects to a chain of WHOIS
  servers (IANA root → TLD registry → registrar) and gets back raw text about
  a domain's registration. python-whois handles this chain automatically.

What the data is useful for in pentesting:
  - Registrar / name servers  → identifies hosting/DNS provider (attack surface)
  - Creation date             → new domain (<30 days) = major red flag
  - Expiry date               → near-expiry = domain squatting opportunity
  - Status flags              → clientTransferProhibited = theft protection on
  - Org / country             → jurisdiction, ownership, attribution
  - Emails                    → often REDACTED post-GDPR (this is normal, not a bug)

IMPORTANT — GDPR Note:
  Since May 2018, WHOIS data for individual registrants is heavily redacted.
  You will frequently see "REDACTED FOR PRIVACY" or proxy emails like:
  "abc123@privacy.whoisguard.com" — this is expected behavior.
  Business/corporate domains may still show org info.
"""

import whois
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Type-normalizer helpers
# These exist because python-whois returns inconsistent types across domains.
# The same field can be a string, a list of strings, a datetime, or None.
# These helpers normalize everything to a predictable type.
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_date(value) -> Optional[str]:
    """
    Normalize a WHOIS date field to a readable string.

    python-whois can return dates as:
      - a single datetime object
      - a list of datetime objects (from multiple WHOIS servers)
      - a plain string
      - None

    All cases → a formatted string "YYYY-MM-DD HH:MM:SS UTC", or None.
    """
    if value is None:
        return None

    # If multiple WHOIS servers responded, we get a list of dates.
    # They're usually duplicates — take the first non-None one.
    if isinstance(value, list):
        value = next((v for v in value if v is not None), None)

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")

    # It came back as a string for this particular TLD
    return str(value).strip() if value else None


def _normalize_list(value) -> list:
    """
    Normalize a WHOIS field that should be a list.

    python-whois sometimes returns a single string, sometimes a list.
    This always gives back a clean list of non-empty strings.
    """
    if value is None:
        return []
    if isinstance(value, list):
        # Filter out None/empty entries, stringify everything
        return [str(v).strip() for v in value if v and str(v).strip()]
    # Single value — wrap it in a list
    return [str(value).strip()] if str(value).strip() else []


def _calculate_age_days(creation_date_str: Optional[str]) -> Optional[int]:
    """
    Calculate how many days old a domain is.

    Why this matters:
      Domains registered less than 30 days ago are a strong red flag in
      threat intelligence — most phishing and malware domains are very fresh.
      Old domains (10+ years) are almost always legitimate.
    """
    if not creation_date_str:
        return None
    try:
        # Parse only the first 19 characters: "YYYY-MM-DD HH:MM:SS"
        created = datetime.strptime(creation_date_str[:19], "%Y-%m-%d %H:%M:%S")
        return (datetime.utcnow() - created).days
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Core function
# ─────────────────────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> Optional[dict]:
    """
    Perform a WHOIS lookup and return clean, consistently-typed data.

    Args:
        domain: The domain to look up.
                Works with or without 'www.' prefix.
                e.g. "google.com", "www.github.com", "bbc.co.uk"

    Returns:
        A dict with normalized fields, or None if the lookup failed.

    The returned dict always has these keys (no KeyError surprises):
        domain, registrar, org, country, dnssec,
        creation_date, expiry_date, updated_date, age_days,
        name_servers (list), status (list), emails (list)
    """
    # Strip 'www.' — WHOIS only works on the base domain
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        print(f"  [*] Querying WHOIS for: {domain} ...", end="", flush=True)

        # This single call fires up to 3 TCP connections on port 43
        # and parses the raw text responses into a Python object.
        raw = whois.whois(domain)

        print(" done.")

    except whois.parser.PywhoisError as e:
        # Thrown when: domain doesn't exist, TLD not supported, or
        # the WHOIS server is unreachable / rate-limiting us
        print(f"\n  [!] WHOIS query failed: {e}")
        return None

    except Exception as e:
        print(f"\n  [!] Unexpected error during WHOIS query: {e}")
        return None

    # Build a clean dict. Every value goes through a normalizer.
    # We never expose raw whois object attributes directly — their types
    # vary per domain and will cause crashes downstream.
    creation = _normalize_date(raw.get("creation_date"))
    expiry   = _normalize_date(raw.get("expiration_date"))
    updated  = _normalize_date(raw.get("updated_date"))

    result = {
        "domain":        domain,
        "registrar":     str(raw.get("registrar") or "N/A").strip(),
        "org":           str(raw.get("org")        or "N/A").strip(),
        "country":       str(raw.get("country")    or "N/A").strip(),
        "dnssec":        str(raw.get("dnssec")     or "N/A").strip(),
        "creation_date": creation or "N/A",
        "expiry_date":   expiry   or "N/A",
        "updated_date":  updated  or "N/A",
        "age_days":      _calculate_age_days(creation),
        "name_servers":  _normalize_list(raw.get("name_servers")),
        "status":        _normalize_list(raw.get("status")),
        "emails":        _normalize_list(raw.get("emails")),
    }

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────────────────

def print_whois(result: dict) -> None:
    """
    Pretty-print a WHOIS result dict to the terminal.

    Annotates the domain age with a threat-intel flag if it's very new.
    Deduplicates name servers (WHOIS often lists them twice in different cases).
    Truncates long status strings (they often have ICANN URLs appended).
    """
    if not result:
        print("  [!] No WHOIS data to display.")
        return

    W = 50  # divider line width

    print(f"\n  {'─' * W}")
    print(f"  WHOIS:  {result['domain'].upper()}")
    print(f"  {'─' * W}")

    print(f"  Registrar   : {result['registrar']}")
    print(f"  Org         : {result['org']}")
    print(f"  Country     : {result['country']}")
    print(f"  DNSSEC      : {result['dnssec']}")

    # ── Timeline ─────────────────────────────────────────────────────────
    print(f"\n  ── Timeline {'─' * (W - 12)}")
    print(f"  Created     : {result['creation_date']}")

    if result["age_days"] is not None:
        years  = result["age_days"] // 365
        months = (result["age_days"] % 365) // 30
        days   = result["age_days"] % 30

        if years > 0:
            age_str = f"{years}y {months}m"
        elif months > 0:
            age_str = f"{months} months, {days} days"
        else:
            age_str = f"{result['age_days']} days"

        # Threat intel signal: flag very fresh domains
        if result["age_days"] < 30:
            flag = "  ⚠  WARNING: VERY NEW DOMAIN — HIGH-RISK INDICATOR"
        elif result["age_days"] < 90:
            flag = "  ⚠  Note: domain < 90 days old"
        else:
            flag = ""

        print(f"  Age         : {result['age_days']} days  ({age_str}){flag}")

    print(f"  Updated     : {result['updated_date']}")
    print(f"  Expires     : {result['expiry_date']}")

    # ── Name Servers ──────────────────────────────────────────────────────
    # Name servers tell you who manages DNS for this domain.
    # e.g. ns1.googledomains.com → Google Domains
    #      ns1.cloudflare.com    → Cloudflare
    #      ns1.parkingcrew.net   → parked/unused domain
    if result["name_servers"]:
        print(f"\n  ── Name Servers {'─' * (W - 16)}")

        # WHOIS often lists the same name server twice in different cases.
        # Deduplicate by lowercasing before comparison.
        seen = set()
        for ns in result["name_servers"]:
            ns_lower = ns.lower()
            if ns_lower not in seen:
                print(f"    {ns}")
                seen.add(ns_lower)

    # ── Domain Status ──────────────────────────────────────────────────────
    # These are EPP (Extensible Provisioning Protocol) status codes.
    # The useful ones to know:
    #   clientTransferProhibited → registrar lock, prevents domain hijacking
    #   clientHold               → domain suspended (could mean abuse/legal issue)
    #   pendingDelete            → domain is about to be released — squatting opportunity
    #   serverTransferProhibited → registry-level lock (stronger protection)
    if result["status"]:
        print(f"\n  ── Domain Status {'─' * (W - 17)}")
        seen_status = set()
        for st in result["status"][:6]:   # cap at 6 — some WHOIS spam 15+ entries
            # Strip ICANN URL appended by most modern registrars
            # e.g. "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
            # → we only want "clientTransferProhibited"
            short = st.split(" ")[0] if " " in st else st
            if short.lower() not in seen_status:
                print(f"    {short}")
                seen_status.add(short.lower())

    # ── Emails ─────────────────────────────────────────────────────────────
    # Post-GDPR (2018): almost always empty or a privacy proxy address.
    # When present: useful for contact tracing, phishing analysis, OSINT.
    if result["emails"]:
        print(f"\n  ── Contact Emails {'─' * (W - 18)}")
        for email in result["emails"]:
            print(f"    {email}")
    else:
        print(f"\n  ── Contact Emails {'─' * (W - 18)}")
        print(f"    (none — typical post-GDPR redaction)")

    print(f"\n  {'─' * W}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Run directly for a quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test three domains:
    #   scanme.nmap.org → our recon target from Days 2 & 3
    #   github.com      → big corporate domain, good baseline
    #   google.com      → very old, very locked-down — see all the status flags

    test_domains = [
        "scanme.nmap.org",
        "github.com",
        "google.com",
    ]

    for domain in test_domains:
        result = whois_lookup(domain)
        if result:
            print_whois(result)
        else:
            print(f"  [!] WHOIS lookup failed for: {domain}\n")
