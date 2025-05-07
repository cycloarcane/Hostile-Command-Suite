#!/usr/bin/env python3
"""
username_osint.py — Sherlock wrapper
"""
from fastmcp import FastMCP
import subprocess, json, tempfile, os, psycopg2

mcp = FastMCP("username")
PG_DSN = os.getenv("OSINT_PG_DSN", "dbname=osint_db user=osint_user")

def _store(target, data):
    with psycopg2.connect(PG_DSN) as c, c.cursor() as cur:
        cur.execute("INSERT INTO osint_results (target, category, data) VALUES (%s,%s,%s)",
                    (target, "sherlock", json.dumps(data)))

@mcp.tool()
def sherlock(username: str) -> dict:
    """Return list of found profile URLs for <username>."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    try:
        subprocess.run(["sherlock", "--json", "--output", tmp.name, username],
                       check=True)
        data = json.load(open(tmp.name))
        _store(username, data)
        return data
    finally:
        os.unlink(tmp.name)

if __name__ == "__main__":
    mcp.run(transport="stdio")
