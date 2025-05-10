#!/usr/bin/env python3
"""
phone_osint.py — FastMCP wrapper for *phoneinfoga-bin* (Go v3+)
with automatic follow-up of the Google dork links it emits.

MCP tools
─────────
▸ check_tools_installation()                 → confirm phoneinfoga-bin is present
▸ scan_phone_phoneinfoga(number, timeout=60) → run one scan + follow the links
▸ scan_phone_all(number, timeout=60)         → alias (in case you add more tools)

Dependencies (all pure-python, arch package names in brackets)
──────────────────────────────────────────────────────────────
• requests        (python-requests)
• beautifulsoup4  (python-beautifulsoup4)

Scraping disclaimer
───────────────────
Fetching Google search URLs may trigger CAPTCHAs or 403s.  This wrapper
handles common HTTP errors quietly but does **not** attempt to bypass
rate-limits or captchas.  For heavy use, consider the official
[Custom Search JSON API] or another OSINT source.

[Custom Search JSON API]: https://developers.google.com/custom-search/v1/overview
"""

import html
import json
import re
import shutil
import subprocess
import time
from typing import Dict, List, Union

import requests
from bs4 import BeautifulSoup
from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
CLI = "phoneinfoga-bin"                   # no fallback, it must exist
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
    )
}
REQUEST_TIMEOUT = 10                      # seconds
REQUEST_SLEEP = 2                         # polite gap between hits
MAX_LINKS = 40                            # safety net: stop after this many URLs

_PHONE_RE = re.compile(r"^\+?\d[\d\s\-.]{5,20}$")     # loose sanity check
_URL_RE = re.compile(r"https?://[^\s)\"'>]+")

mcp = FastMCP("phone")                    # route => /phone on MCP


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _cli_available() -> bool:
    return shutil.which(CLI) is not None


def _missing_msg() -> Dict[str, str]:
    return {
        "status": "missing_tools",
        "message": (
            "phoneinfoga-bin not found on PATH.  "
            "Install it (e.g. `yay -S phoneinfoga-bin`) or add it to $PATH."
        ),
    }


def _normalise_number(num: str) -> str:
    """ Strip spaces, dashes & dots so '+1 234-567.890' → '+1234567890'. """
    return re.sub(r"[ \-.]", "", num)


def _filter_links(number: str, urls: List[str]) -> List[str]:
    """
    Download each URL once, keep the ones where the phone number string
    (normalised) **appears in the HTML**.

    Returns just the 'hits'.
    """
    hits: List[str] = []
    norm_num = _normalise_number(number)

    for idx, url in enumerate(urls[:MAX_LINKS], 1):
        try:
            time.sleep(REQUEST_SLEEP)           # play nice
            r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                continue

            text = html.unescape(r.text).lower()
            if norm_num.lower() in text:
                hits.append(url)

        except requests.RequestException:
            continue

    return hits


# ──────────────────────────────────────────────────────────────────────────────
# MCP tools
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def check_tools_installation() -> Dict[str, Union[str, bool]]:
    if _cli_available():
        return {"status": "ok", "cli": CLI}
    return _missing_msg()


@mcp.tool()
def scan_phone_phoneinfoga(
    number: str,
    timeout: int = 60,
) -> Dict[str, Union[str, List[str], Dict]]:
    """
    1. Run `phoneinfoga-bin scan -n <number>`
    2. Extract HTTP/HTTPS URLs from stdout
    3. Fetch each URL (with polite delay) and keep only those pages where the
       phone number itself appears in the HTML.
    """
    if not _cli_available():
        return _missing_msg()

    number = number.strip()
    if not _PHONE_RE.fullmatch(number):
        return {"status": "error", "message": "Invalid phone number format"}

    # 1. Run PhoneInfoga
    try:
        proc = subprocess.run(
            [CLI, "scan", "-n", number],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"{CLI} timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"Could not execute {CLI}: {e}"}

    if proc.returncode != 0:
        return {
            "status": "error",
            "message": f"{CLI} exited {proc.returncode}: {proc.stderr.strip()[:800]}",
        }

    stdout = proc.stdout

    # 2. Extract URLs
    urls = _URL_RE.findall(stdout)
    urls = list(dict.fromkeys(urls))  # deduplicate while preserving order

    # 3. Follow & filter
    links_with_hits = _filter_links(number, urls)

    summary = {
        "total_links": len(urls),
        "links_with_hits": len(links_with_hits),
    }

    return {
        "status": "success",
        "number": number,
        "tool": CLI,
        "summary": summary,
        "links_all": urls,
        "links_with_hits": links_with_hits,
        "raw_output": stdout,     # keep original text for reference
    }


@mcp.tool()
def scan_phone_all(
    number: str,
    timeout: int = 60,
) -> Dict[str, Union[str, List[str], Dict]]:
    """
    Mimics email_osint’s *search_email_all*.  For now it only calls PhoneInfoga.
    """
    res = scan_phone_phoneinfoga(number, timeout)
    overall = {
        "status": res.get("status", "error"),
        "number": number,
        "tools_run": [CLI],
        "phoneinfoga": res,
    }
    if overall["status"] == "success":
        overall["summary"] = res.get("summary", {})
    return overall


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run(transport="stdio")
