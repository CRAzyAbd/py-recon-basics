#!/usr/bin/env python3
"""
http_inspector.py
-----------------
HTTP response header security analysis using the requests library.

Two distinct categories of findings (understand the difference):

  1. INFORMATION DISCLOSURE
     Headers present that reveal server internals.
     e.g. "Server: Apache/2.4.7" → paste into CVE database → instant attack list.
     These are the pentester's priority. Fix: strip them at the server/proxy level.

  2. MISSING SECURITY HEADERS
     Headers absent that browsers use to enforce security policies.
     e.g. No Content-Security-Policy → browser has no instruction to block inline scripts.
     These are the defensive auditor's priority. Fix: add them in server config.

Why HEAD instead of GET?
  HTTP defines two methods for fetching headers:
    GET  → send request, receive full response (headers + body)
    HEAD → send request, receive headers ONLY (no body)
  HEAD is correct for inspection: faster, less bandwidth, less intrusive.
  Caveat: requests.head() defaults to allow_redirects=False (unlike get()).
  We override this explicitly — see inspect_url().
  Some servers don't support HEAD (return 405). We fall back to GET with
  stream=True, which lets us read headers without downloading the body.
"""

import re
import requests
from urllib.parse import urlparse
from typing import Optional

import urllib3
# Suppress the warning that appears when verify_ssl=False is used.
# We only use verify=False for targets with self-signed certs (labs, CTFs).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
# Disclosure header value analyzer
# ─────────────────────────────────────────────────────────────────────────────

def _server_value_is_revealing(value: str) -> bool:
    """
    Return True only if a Server header value reveals actual technical stack info.

    We distinguish between:
      "github.com"         → False  (just a domain name, tells attacker nothing)
      "Apache/2.4.7"       → True   (software + version, CVE-searchable)
      "nginx"              → True   (software name alone is a fingerprint)
      "cloudflare"         → True   (CDN identity, useful for WAF evasion research)
      "Apache/2.4.66 ()"   → True   (version number present even with empty parens)
    """
    # Any version number pattern is a finding (e.g. 2.4.7, 1.18.0, 4.0.30319)
    if re.search(r'\d+\.\d+', value):
        return True

    # Known server / proxy / CDN software names — revealing even without version
    known_software = [
        'apache', 'nginx', 'iis', 'lighttpd', 'caddy',
        'gunicorn', 'uvicorn', 'tomcat', 'jetty', 'openresty',
        'cloudflare', 'akamai', 'varnish', 'litespeed', 'kestrel',
    ]
    return any(s in value.lower() for s in known_software)


# ─────────────────────────────────────────────────────────────────────────────
# Security header check functions
#
# Each returns True if the header value is acceptable, False if misconfigured.
# Standalone functions (not lambdas) so they're readable and individually testable.
# ─────────────────────────────────────────────────────────────────────────────

def _check_hsts(value: str) -> bool:
    """
    Strict-Transport-Security must have max-age >= 31536000 (1 year).
    OWASP recommends also including 'includeSubDomains'.
    Example good value: max-age=31536000; includeSubDomains; preload
    """
    for part in value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                age = int(part[8:].strip())
                return age >= 31536000
            except ValueError:
                return False
    return False


def _check_csp(value: str) -> bool:
    """
    Content-Security-Policy fails if it contains directives that negate protection:
      'unsafe-inline' → allows inline scripts → XSS possible
      'unsafe-eval'   → allows eval() → many attack chains enabled
      default-src *   → wildcard → loads from anywhere → no protection
      script-src *    → same, specifically for scripts
    Note: CSP is extremely complex. This is a basic sanity check, not a full audit.
    """
    v = value.lower()
    dangerous = ["'unsafe-inline'", "'unsafe-eval'", "default-src *", "script-src *"]
    return not any(d in v for d in dangerous)


def _check_xfo(value: str) -> bool:
    """
    X-Frame-Options must be DENY or SAMEORIGIN.
    ALLOW-FROM is deprecated and ignored by modern browsers.
    """
    return value.strip().upper() in ("DENY", "SAMEORIGIN")


def _check_xcto(value: str) -> bool:
    """
    X-Content-Type-Options must be exactly 'nosniff'.
    Any other value provides no protection.
    """
    return value.strip().lower() == "nosniff"


def _check_referrer(value: str) -> bool:
    """
    Referrer-Policy can contain multiple comma-separated directives.
    e.g. "origin-when-cross-origin, strict-origin-when-cross-origin"
    We pass if ANY of the listed values is in our safe set.
    """
    safe = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    # Split on comma and check each value individually
    values = [v.strip().lower() for v in value.split(",")]
    return any(v in safe for v in values)


def _check_permissions(value: str) -> bool:
    """
    Permissions-Policy (formerly Feature-Policy) restricts browser APIs.
    Any explicit value is better than none — hard to validate without
    knowing which features the app intentionally uses.
    """
    return True   # Presence is the finding; content is app-specific


# ─────────────────────────────────────────────────────────────────────────────
# Security header definitions
# Each entry ties the header name to its check function and metadata.
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "short":    "HSTS",
        "why":      "Forces HTTPS. Without it, active attackers can downgrade to HTTP.",
        "fix":      "max-age=31536000; includeSubDomains",
        "check":    _check_hsts,
        "warn_msg": "max-age should be >= 31536000 (1 year); consider includeSubDomains",
    },
    "Content-Security-Policy": {
        "short":    "CSP",
        "why":      "Tells the browser which sources may load content. Mitigates XSS.",
        "fix":      "default-src 'self'; script-src 'self'  (then tune per your app)",
        "check":    _check_csp,
        "warn_msg": "Contains 'unsafe-inline', 'unsafe-eval', or wildcard — protection is significantly weakened",
    },
    "X-Frame-Options": {
        "short":    "XFO",
        "why":      "Prevents the page being embedded in iframes (clickjacking).",
        "fix":      "DENY  (or SAMEORIGIN if you embed your own pages)",
        "check":    _check_xfo,
        "warn_msg": "ALLOW-FROM is deprecated and ignored by Chrome/Firefox — use CSP frame-ancestors instead",
    },
    "X-Content-Type-Options": {
        "short":    "XCTO",
        "why":      "Stops browsers from MIME-sniffing a response away from the declared content-type.",
        "fix":      "nosniff",
        "check":    _check_xcto,
        "warn_msg": "Value must be exactly 'nosniff' — any other value has no effect",
    },
    "Referrer-Policy": {
        "short":    "RP",
        "why":      "Controls referrer info sent to third parties. Prevents URL leakage.",
        "fix":      "strict-origin-when-cross-origin",
        "check":    _check_referrer,
        "warn_msg": "Value sends more referrer info than recommended — consider strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "short":    "PP",
        "why":      "Restricts browser features (camera, mic, geolocation, USB). Reduces attack surface.",
        "fix":      "camera=(), microphone=(), geolocation=()",
        "check":    _check_permissions,
        "warn_msg": "",
    },
}

# Headers that SHOULD NOT be present (or should be stripped).
# Their presence is a finding because they reveal server internals.
DISCLOSURE_HEADERS = {
    "Server":                 "Reveals web server software and version",
    "X-Powered-By":           "Reveals backend language/framework and version",
    "X-AspNet-Version":       "Reveals ASP.NET version",
    "X-AspNetMvc-Version":    "Reveals ASP.NET MVC version",
    "X-Generator":            "Reveals CMS or framework (WordPress, Drupal, etc.)",
    "X-Drupal-Cache":         "Confirms Drupal CMS — known attack surface",
    "X-Drupal-Dynamic-Cache": "Confirms Drupal CMS",
    "X-WordPress-Cache":      "Confirms WordPress — plugin vulns are very common",
    "Via":                    "May reveal internal proxy/load balancer architecture",
    "X-Varnish":              "Reveals Varnish cache is in the stack",
}

DEFAULT_TIMEOUT = 10.0

# Use a real browser User-Agent.
# Some servers (especially WAFs) block Python's default "python-requests/x.x" string.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ─────────────────────────────────────────────────────────────────────────────
# Core function
# ─────────────────────────────────────────────────────────────────────────────

def inspect_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> Optional[dict]:
    """
    Fetch HTTP response headers and analyze them for security issues.

    Args:
        url:        URL to inspect. Accepts with or without scheme.
                    e.g. "example.com"       → treated as "https://example.com"
                    e.g. "http://192.168.1.1" → kept as-is (explicit HTTP)
        timeout:    Seconds to wait for a response (default: 10.0)
        verify_ssl: Verify SSL certificate (default: True).
                    Set False ONLY for self-signed cert targets you own (CTF labs, etc.)

    Returns:
        A dict with all findings, or None if the request failed entirely.
    """
    # ── Normalize URL ────────────────────────────────────────────────────
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    req_headers = {
        "User-Agent":      DEFAULT_USER_AGENT,
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "close",
    }

    # ── Fetch response headers ────────────────────────────────────────────
    response    = None
    method_used = None

    try:
        print(f"  [*] HEAD {url} ...", end="", flush=True)

        # IMPORTANT: allow_redirects=True is REQUIRED for HEAD requests.
        # Unlike requests.get(), requests.head() defaults to allow_redirects=False.
        # Without this, http://github.com returns the redirect's headers, not the
        # final destination's headers — you'd be analyzing a 301 response.
        response = requests.head(
            url,
            headers=req_headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )
        method_used = "HEAD"
        print(f" {response.status_code}")

        # 405 Method Not Allowed → this server doesn't support HEAD.
        # Raise so we fall into the GET fallback block below.
        if response.status_code == 405:
            raise requests.exceptions.HTTPError("HEAD not supported (405)")

    except (requests.exceptions.HTTPError, ConnectionError):
        # Fall back to GET with stream=True.
        # stream=True: make the connection and download headers, but do NOT
        # stream the body. We close immediately — we only needed the headers.
        print(f"\n  [*] HEAD failed — trying GET ...", end="", flush=True)
        try:
            response = requests.get(
                url,
                headers=req_headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                stream=True,
            )
            response.close()   # release the connection — body not needed
            method_used = "GET"
            print(f" {response.status_code}")
        except Exception as e:
            print(f"\n  [!] Both HEAD and GET failed: {e}")
            return None

    except requests.exceptions.SSLError as e:
        # SSL errors mean the cert is invalid or self-signed.
        # We do NOT fall back to HTTP here — that would silently downgrade
        # a secure connection and analyze the wrong thing.
        print(f"\n  [!] SSL certificate error: {e}")
        print(f"      Retry with verify_ssl=False if this is a self-signed cert target.")
        return None

    except requests.exceptions.ConnectionError as e:
        # "Connection refused" (errno 111) = host is alive, port is closed.
        # This is the ONLY case where an HTTP retry makes sense:
        #   - DNS failure     → HTTP won't fix DNS
        #   - Network error   → HTTP won't fix routing
        #   - Port 443 closed → port 80 might be open (e.g. scanme.nmap.org)
        if "Connection refused" in str(e) and url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            print(f"\n  [*] HTTPS port closed — retrying on HTTP ...", end="", flush=True)
            try:
                response = requests.head(
                    http_url,
                    headers=req_headers,
                    timeout=timeout,
                    verify=False,        # HTTP — no TLS, no cert to verify
                    allow_redirects=True,
                )
                method_used = "HEAD"
                print(f" {response.status_code}")
                url = http_url   # update url so the result reflects where we landed

                if response.status_code == 405:
                    response = requests.get(
                        http_url,
                        headers=req_headers,
                        timeout=timeout,
                        verify=False,
                        allow_redirects=True,
                        stream=True,
                    )
                    response.close()
                    method_used = "GET"

            except Exception as e2:
                print(f"\n  [!] HTTP also failed: {e2}")
                return None
        else:
            print(f"\n  [!] Connection failed: {e}")
            return None

    except requests.exceptions.Timeout:
        print(f"\n  [!] Request timed out after {timeout}s")
        return None

    if response is None:
        return None

    resp_headers = dict(response.headers)

    # ── Pass 1: Check security headers (should exist) ─────────────────────
    security_findings = []

    for header_name, meta in SECURITY_HEADERS.items():
        # HTTP headers are case-insensitive by spec — do case-insensitive lookup
        value = next(
            (v for k, v in resp_headers.items() if k.lower() == header_name.lower()),
            None,
        )

        if value is None:
            security_findings.append({
                "header":   header_name,
                "short":    meta["short"],
                "status":   "MISSING",
                "value":    None,
                "why":      meta["why"],
                "fix":      meta["fix"],
                "warn_msg": None,
            })
        else:
            try:
                passes = meta["check"](value)
            except Exception:
                passes = True   # Never crash if a check function hits an edge case

            security_findings.append({
                "header":   header_name,
                "short":    meta["short"],
                "status":   "PASS" if passes else "WARN",
                "value":    value,
                "why":      meta["why"],
                "fix":      meta["fix"] if not passes else None,
                "warn_msg": meta["warn_msg"] if not passes else None,
            })

    # ── Pass 2: Check disclosure headers (should NOT exist) ───────────────
    disclosure_findings = []

    for header_name, description in DISCLOSURE_HEADERS.items():
        value = next(
            (v for k, v in resp_headers.items() if k.lower() == header_name.lower()),
            None,
        )
        if value is not None:
            # Server header: presence alone is not enough.
            # "Server: github.com" reveals nothing. "Server: Apache/2.4.7" does.
            if header_name == "Server" and not _server_value_is_revealing(value):
                continue

            disclosure_findings.append({
                "header":      header_name,
                "value":       value,
                "description": description,
            })

    # ── Build result ──────────────────────────────────────────────────────
    counts = {
        "pass":      sum(1 for f in security_findings if f["status"] == "PASS"),
        "warn":      sum(1 for f in security_findings if f["status"] == "WARN"),
        "missing":   sum(1 for f in security_findings if f["status"] == "MISSING"),
        "disclosed": len(disclosure_findings),
    }

    return {
        "url":                 url,
        "final_url":           response.url,
        "status_code":         response.status_code,
        "method_used":         method_used,
        "all_headers":         resp_headers,
        "security_findings":   security_findings,
        "disclosure_findings": disclosure_findings,
        "summary":             counts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Display functions
# ─────────────────────────────────────────────────────────────────────────────

def print_report(result: dict) -> None:
    """
    Print a formatted security report from an inspect_url() result.

    Three sections:
      1. Request metadata (URL, status, redirect info)
      2. Information disclosure findings (present = bad)
      3. Security header analysis (PASS / WARN / MISSING)
    """
    if not result:
        print("  [!] No data to display.")
        return

    W = 56

    print(f"\n  {'═' * W}")
    print(f"  HTTP Header Security Report")
    print(f"  {'═' * W}")
    print(f"  Target     : {result['url']}")

    if result["final_url"] != result["url"]:
        print(f"  Landed at  : {result['final_url']}  (redirect followed)")

    print(f"  Status     : HTTP {result['status_code']}")
    print(f"  Method     : {result['method_used']}")

    s = result["summary"]
    print(
        f"\n  Score      : "
        f"{s['pass']} PASS  ·  {s['warn']} WARN  "
        f"·  {s['missing']} MISSING  ·  {s['disclosed']} DISCLOSED"
    )

    # ── Section 1: Information Disclosure ────────────────────────────────
    print(f"\n  {'─' * W}")
    print(f"  Information disclosure  (present = finding)")
    print(f"  {'─' * W}")

    if not result["disclosure_findings"]:
        print(f"  [PASS]  No stack-revealing headers found\n")
    else:
        for f in result["disclosure_findings"]:
            print(f"  [DISCLOSED]  {f['header']}: {f['value']}")
            print(f"               {f['description']}")
            print()

    # ── Section 2: Security Headers ──────────────────────────────────────
    print(f"  {'─' * W}")
    print(f"  Security headers  (missing or warn = finding)")
    print(f"  {'─' * W}")

    for f in result["security_findings"]:
        if f["status"] == "MISSING":
            print(f"  [MISSING]  {f['header']}")
            print(f"             Why: {f['why']}")
            print(f"             Fix: {f['header']}: {f['fix']}")

        elif f["status"] == "WARN":
            val_short = f["value"][:72] + "..." if len(f["value"]) > 72 else f["value"]
            print(f"  [WARN]     {f['header']}: {val_short}")
            if f.get("warn_msg"):
                print(f"             {f['warn_msg']}")

        else:   # PASS
            val_short = f["value"][:60] + "..." if f["value"] and len(f["value"]) > 60 else f["value"]
            print(f"  [PASS]     {f['header']}: {val_short}")

        print()

    print(f"  {'═' * W}\n")


def print_all_headers(result: dict) -> None:
    """Dump every raw response header — useful for manual review."""
    if not result:
        return
    print(f"\n  All response headers for {result['url']}:")
    print(f"  {'─' * 50}")
    for name, value in result["all_headers"].items():
        print(f"  {name}: {value}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_targets = [
        "scanme.nmap.org",       # HTTP only (port 443 closed) — tests HTTP fallback
        "https://github.com",    # well-configured — good baseline for PASS results
        "http://neverssl.com",   # intentionally HTTP-only — HSTS impossible here
    ]

    for url in test_targets:
        result = inspect_url(url)
        if result:
            print_report(result)
        else:
            print(f"  [!] Inspection failed for {url}\n")
