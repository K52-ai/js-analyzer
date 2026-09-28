#!/usr/bin/env python3
"""
JS Analyzer
by K52-ai

Extract endpoints, API keys, tokens, emails, and passwords
from JavaScript files on a target website.
"""

import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

C = {
    "banner":  Fore.CYAN + Style.BRIGHT,
    "accent":  Fore.MAGENTA + Style.BRIGHT,
    "ok":      Fore.GREEN,
    "warn":    Fore.YELLOW,
    "danger":  Fore.RED + Style.BRIGHT,
    "info":    Fore.CYAN,
    "dim":     Style.DIM + Fore.WHITE,
    "reset":   Style.RESET_ALL,
}

UA = "Mozilla/5.0 (compatible; JSAnalyzer/1.0)"
TIMEOUT = 10

# ---------------------------------------------------------------------------
# Rainbow banner
# ---------------------------------------------------------------------------

RAINBOW = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]


def rainbow(text):
    """Apply rainbow colors char by char."""
    out = ""
    for i, ch in enumerate(text):
        out += RAINBOW[i % len(RAINBOW)] + ch
    return out + Style.RESET_ALL


def banner():
    print()
    print(rainbow("  ██╗███████╗     █████╗ ███╗   ██╗ █████╗ ██╗   ██╗███████╗███████╗██████╗ "))
    print(rainbow("  ██║██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║   ██║╚══███╔╝██╔════╝██╔══██╗"))
    print(rainbow("  ██║███████╗    ███████║██╔██╗ ██║███████║██║   ██║  ███╔╝ █████╗  ██████╔╝"))
    print(rainbow("  ██║╚════██║    ██╔══██║██║╚██╗██║██╔══██║╚██╗ ██╔╝ ███╔╝  ██╔══╝  ██╔══██╗"))
    print(rainbow("  ██║███████║    ██║  ██║██║ ╚████║██║  ██║ ╚████╔╝███████╗███████╗██║  ██║"))
    print(rainbow("  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ╚═══╝ ╚══════╝╚══════╝╚═╝  ╚═╝"))
    print()
    print(f"                          {C['accent']}JS Analyzer {C['dim']}by{C['accent']} K52-ai")
    print(f"                          {C['dim']}{'─' * 32}")
    print()


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS = {
    "endpoints": re.compile(
        r"""(?:"|'|`)((?:/[a-zA-Z0-9._\-~%]+){2,}(?:\?[^"'`\s]*)?)(?:"|'|`)"""
    ),
    "urls": re.compile(
        r"""https?://[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?:/[^\s"'`<>]*)? """
    ),
    "aws_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "google_api": re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
    "stripe_live": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    "github_token": re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"),
    "slack_token": re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
    "jwt": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "internal_host": re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)*(?:internal|intranet|corp|local)\.[a-zA-Z]{2,}\b"
    ),
    "password": re.compile(
        r"""(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']""",
        re.IGNORECASE,
    ),
    "private_ip": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    ),
}


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA},
                         verify=False)
        r.raise_for_status()
        return r.text
    except Exception:
        return None


def find_js_files(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    js_urls = set()
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            js_urls.add(urljoin(base_url, src))
    return sorted(js_urls)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(js_content):
    findings = {}

    for name, pattern in PATTERNS.items():
        matches = set()
        for m in pattern.findall(js_content):
            val = m.strip() if isinstance(m, str) else m[0].strip()
            if val and len(val) < 300:
                matches.add(val)
        if matches:
            findings[name] = sorted(matches)

    return findings


def print_findings(js_url, findings):
    if not findings:
        return

    name = js_url.split("/")[-1] or js_url
    print(f"  {C['info']}[+] {name}{C['reset']}  {C['dim']}{js_url}{C['reset']}")

    for category, values in findings.items():
        is_secret = category in (
            "aws_key", "google_api", "stripe_live", "github_token",
            "slack_token", "jwt", "password"
        )
        color = C["danger"] if is_secret else C["warn"]
        marker = " ⚠️" if is_secret else ""

        print(f"      {color}├─ {category}:{marker}{C['reset']}")
        for v in values[:10]:  # cap at 10 per category
            print(f"      {C['dim']}│   {v}{C['reset']}")
        if len(values) > 10:
            print(f"      {C['dim']}│   ... +{len(values) - 10} more{C['reset']}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()

    target = input(f"{C['accent']}Target: {C['reset']}").strip()
    if not target:
        print(f"{C['danger']}[-] No target provided.{C['reset']}")
        sys.exit(1)

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print()
    print(f"  {C['ok']}[+] Target:{C['reset']} {target}")
    print(f"  {C['info']}[*] Fetching main page...{C['reset']}")

    html = fetch(target)
    if not html:
        print(f"  {C['danger']}[-] Failed to fetch target.{C['reset']}")
        sys.exit(1)

    js_files = find_js_files(html, target)
    if not js_files:
        print(f"  {C['warn']}[!] No JS files found.{C['reset']}")
        sys.exit(0)

    print(f"  {C['ok']}[+] Found {len(js_files)} JS files{C['reset']}")
    print()
    print(f"  {C['info']}[*] Analyzing...{C['reset']}")
    print()

    all_findings = {}
    total_secrets = 0

    for js_url in js_files:
        content = fetch(js_url)
        if not content:
            continue
        findings = analyze(content)
        if findings:
            print_findings(js_url, findings)
            all_findings[js_url] = findings
            for cat in findings:
                if cat in ("aws_key", "google_api", "stripe_live",
                           "github_token", "slack_token", "jwt", "password"):
                    total_secrets += len(findings[cat])

    # Save
    with open("results.txt", "w", encoding="utf-8") as f:
        for js_url, findings in all_findings.items():
            f.write(f"\n=== {js_url} ===\n")
            for cat, values in findings.items():
                f.write(f"\n[{cat}]\n")
                for v in values:
                    f.write(f"  {v}\n")

    # Summary
    print(f"  {C['dim']}{'─' * 60}{C['reset']}")
    print(f"  {C['ok']}[+] JS Files:  {len(js_files)}{C['reset']}")
    print(f"  {C['warn']}[+] Findings:  {len(all_findings)}{C['reset']}")

    if total_secrets > 0:
        print(f"  {C['danger']}[!] Secrets:   {total_secrets}  ⚠️{C['reset']}")
    else:
        print(f"  {C['dim']}[+] Secrets:   0{C['reset']}")

    print(f"  {C['info']}[+] Saved to:  results.txt{C['reset']}")
    print()


if __name__ == "__main__":
    main()
