#!/usr/bin/env python3
"""
duckduckgo_osint.py — DuckDuckGo wrapper (HTML backend, rate-limited)

FastMCP tool
────────────
    search_duckduckgo_text(query, max_results=20, delay=3, …)

Returns
───────
    {
      "status": "success",
      "backend": "html",
      "query": "...",
      "results": [ {title, href, snippet}, … ],
      "results_markdown": ["1. [Title](url) — snippet", …]
    }
"""

import json
import sys
import time
from typing import Any, Dict, List

from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
from duckduckgo_search.exceptions import DuckDuckGoSearchException
from fastmcp import FastMCP

mcp = FastMCP("duckduckgo")          # MCP route → /duckduckgo
_BACKEND = "html"
_LAST_CALL_AT: float = 0.0           # global for simple throttle


def _rate_limit(delay: float) -> None:
    global _LAST_CALL_AT
    wait = _LAST_CALL_AT + delay - time.time()
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL_AT = time.time()


def _clean(html_snippet: str) -> str:
    return BeautifulSoup(html_snippet, "html.parser").get_text(" ", strip=True)


def _md(res: Dict[str, str], idx: int) -> str:
    return f"{idx}. [{res['title'] or '(no title)'}]({res['href']}) — {res['snippet']}"


@mcp.tool()
def search_duckduckgo_text(
    query: str,
    max_results: int = 20,
    delay: float = 1.0,
    region: str = "wt-wt",
    safesearch: str = "moderate",
    timelimit: str | None = None,
) -> Dict[str, Any]:
    """HTML backend search with polite delay + snippet cleanup."""
    _rate_limit(delay)

    try:
        with DDGS() as ddgs:
            hits_iter = ddgs.text(
                query,
                region=region,
                safesearch=safesearch,
                timelimit=timelimit,
                backend=_BACKEND,
                max_results=max_results,
            )
            raw = list(hits_iter)

        cleaned: List[Dict[str, str]] = [
            {
                "title": h.get("title", ""),
                "href": h.get("href", ""),
                "snippet": _clean(h.get("body", "")),
            }
            for h in raw
        ]
        md = [_md(r, i) for i, r in enumerate(cleaned, 1)]

        return {
            "status": "success",
            "backend": _BACKEND,
            "query": query,
            "results": cleaned,
            "results_markdown": md,
        }

    except DuckDuckGoSearchException as e:
        return {"status": "error", "query": query, "message": str(e)}

    except Exception as e:
        return {"status": "error", "query": query, "message": f"unexpected: {e}"}


# ───────────── CLI helper (optional) ─────────────
def _cli() -> None:
    import argparse

    p = argparse.ArgumentParser(description="DDG HTML search (rate-limited)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search")
    s.add_argument("query")
    s.add_argument("--max", type=int, default=20)
    s.add_argument("--delay", type=float, default=3.0)
    s.add_argument("--region", default="wt-wt")
    s.add_argument("--safesearch", choices=["off", "moderate", "on"], default="moderate")
    s.add_argument("--timelimit", choices=["d", "w", "m", "y"], default=None)

    sub.add_parser("check")

    args = p.parse_args()
    if args.cmd == "check":
        out = {"status": "ok", "message": "duckduckgo_osint ready"}
    else:
        out = search_duckduckgo_text(
            args.query,
            max_results=args.max,
            delay=args.delay,
            region=args.region,
            safesearch=args.safesearch,
            timelimit=args.timelimit,
        )

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"search", "check"}:
        _cli()
    else:
        mcp.run(transport="stdio")
