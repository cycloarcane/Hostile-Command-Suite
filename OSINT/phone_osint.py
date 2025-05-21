#!/usr/bin/env python3
"""
phone_osint.py — FastMCP wrapper for *phoneinfoga-bin* (Go v3+)
v2025-05-11 — concurrent link follow-up, progress dots, --no-follow flag.

Extra deps:
    pacman -S python-requests python-beautifulsoup4
"""

import html
import json
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Union

try:
    import requests
    from bs4 import BeautifulSoup
except ModuleNotFoundError as e:
    sys.stderr.write(
        f"Missing {e.name}.  Install with `pip install requests beautifulsoup4`.\n"
    )
    sys.exit(1)

from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────
CLI = "phoneinfoga-bin"               # hard requirement
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " \
     "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
HTTP_TIMEOUT = 10                     # per-request
MAX_LINKS = 40
MAX_WORKERS = 12

_PHONE_RE = re.compile(r"^\+?\d[\d\s\-.]{5,20}$")
_URL_RE = re.compile(r"https?://[^\s)\"'>]+")

mcp = FastMCP("phone")                # MCP route → /phone

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _cli_available() -> bool:
    return shutil.which(CLI) is not None


def _missing_msg() -> Dict[str, str]:
    return {
        "status": "missing_tools",
        "message": "phoneinfoga-bin not found.  `yay -S phoneinfoga-bin` on Arch.",
    }


def _normalise(num: str) -> str:
    return re.sub(r"[ \-.]", "", num).lower()


def _title(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    t = soup.title.string if soup.title and soup.title.string else ""
    return t.strip()[:150] or "(untitled)"


def _fetch_worker(url: str, needle: str) -> Union[None, Dict[str, str]]:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": UA},
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        if r.status_code != 200:
            return None
        html_text = html.unescape(r.text)
        if needle in html_text.lower():
            return {"url": url, "title": _title(html_text)}
    except requests.RequestException:
        return None
    return None


def _follow_links(number: str, urls: List[str]) -> List[Dict[str, str]]:
    """Return [{'url', 'title'}, …] for pages that mention the phone number."""
    needle = _normalise(number)
    hits: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(_fetch_worker, url, needle): url
            for url in urls[:MAX_LINKS]
        }

        done = 0
        for fut in as_completed(futures):
            done += 1
            # progress dot every 3 completions
            if done % 3 == 0:
                sys.stderr.write(".")
                sys.stderr.flush()

            res = fut.result()
            if res:
                hits.append(res)

    if hits:
        sys.stderr.write(f" ({len(hits)} hits)\n")
    else:
        sys.stderr.write(" (no hits)\n")

    return hits


# ──────────────────────────────────────────────────────────────────────────────
# MCP tools
# ──────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def check_tools_installation() -> Dict[str, Union[str, bool]]:
    return {"status": "ok", "cli": CLI} if _cli_available() else _missing_msg()


@mcp.tool()
def scan_phone_phoneinfoga(
    number: str,
    timeout: int = 60,
    no_follow: bool = False,          # ← new cli flag
) -> Dict[str, Union[str, List, Dict]]:
    if not _cli_available():
        return _missing_msg()

    number = number.strip()
    if not _PHONE_RE.fullmatch(number):
        return {"status": "error", "message": "Invalid phone number"}

    # 1. Run PhoneInfoga
    try:
        proc = subprocess.run(
            [CLI, "scan", "-n", number],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"{CLI} timed out ({timeout}s)"}
    except Exception as e:
        return {"status": "error", "message": f"Exec failure: {e}"}

    if proc.returncode != 0:
        return {
            "status": "error",
            "message": f"{CLI} exit {proc.returncode}: {proc.stderr[:800]}",
        }

    stdout = proc.stdout
    urls_all = list(dict.fromkeys(_URL_RE.findall(stdout)))  # dedup

    # 2. Follow links concurrently (unless --no-follow)
    hits_info: List[Dict[str, str]] = []
    if not no_follow and urls_all:
        sys.stderr.write(f"[{len(urls_all)} links] fetching")
        hits_info = _follow_links(number, urls_all)

    hits_md = [
        f"{i}. [{h['title']}]({h['url']})" for i, h in enumerate(hits_info, 1)
    ]

    return {
        "status": "success",
        "number": number,
        "tool": CLI,
        "summary": {
            "total_links": len(urls_all),
            "links_with_hits": len(hits_info),
        },
        "links_all": urls_all,
        "links_hits": hits_info,
        "links_hits_markdown": hits_md,
        "raw_output": stdout,
    }


@mcp.tool()
def scan_phone_all(number: str, timeout: int = 60, no_follow: bool = False):
    res = scan_phone_phoneinfoga(number, timeout=timeout, no_follow=no_follow)
    overall = {
        "status": res.get("status", "error"),
        "number": number,
        "tools_run": [CLI],
        "phoneinfoga": res,
    }
    if overall["status"] == "success":
        overall["summary"] = res["summary"]
    return overall


if __name__ == "__main__":
    mcp.run(transport="stdio")