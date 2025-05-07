#!/usr/bin/env python3
"""
duckduckgo_osint.py — DuckDuckGo search wrapper for Hostile‑Command‑Suite

Usage (stdin JSON‑RPC, fastMCP style):
    echo '{"method":"search","params":["elon musk mars", 10]}' | \
         python duckduckgo_osint.py

Dependencies:
    pip install duckduckgo-search fastmcp psycopg2-binary

No API key required.
"""
from fastmcp import FastMCP
import duckduckgo_search  # noqa: E402
import os, json, psycopg2  # noqa: E402

mcp = FastMCP("duckduckgo")  # the route name exposed to the orchestrator

# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------
PG_DSN = os.getenv(
    "OSINT_PG_DSN", "dbname=osint_db user=osint_user host=/var/run/postgresql"
)


def _store(target: str, data):
    """Insert a result blob for <target> into osint_results."""
    try:
        with psycopg2.connect(PG_DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO osint_results (target, category, data) VALUES (%s, %s, %s)",
                (target, "duckduckgo", json.dumps(data)),
            )
    except Exception as e:  # pragma: no cover -- logging left to caller
        print(f"[duckduckgo_osint] DB insert failed: {e}", flush=True)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def search(
    query: str,
    max_results: int = 20,
    region: str = "wt-wt",
    safesearch: str = "Moderate",
) -> list:
    """Return a list of DuckDuckGo results for *query*.

    Args:
        query: search string, supports typical DDG operators (site:, intitle:, etc.).
        max_results: cap number of results (DuckDuckGo caps at ~250).
        region: region code like "us-en", "uk-en", "de-de". Defaults to worldwide.
        safesearch: "On", "Moderate", or "Off".

    Returns: list of dicts {title, href, body}.
    """
    results = ddg(
        query,
        region=region,
        safesearch=safesearch,
        max_results=max_results,
    )
    _store(query, results)
    return results or []


if __name__ == "__main__":
    mcp.run(transport="stdio")
