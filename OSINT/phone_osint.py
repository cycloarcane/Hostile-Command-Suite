#!/usr/bin/env python3
"""
phone_osint.py — PhoneInfoga wrapper
"""
from fastmcp import FastMCP
import subprocess, json, tempfile, os, psycopg2

mcp = FastMCP("phone")
PG_DSN = os.getenv("OSINT_PG_DSN", "dbname=osint_db user=osint_user")

def _store(target, data):
    with psycopg2.connect(PG_DSN) as c, c.cursor() as cur:
        cur.execute("INSERT INTO osint_results (target, category, data) VALUES (%s,%s,%s)",
                    (target, "phoneinfoga", json.dumps(data)))

@mcp.tool()
def scan(number: str) -> dict:
    """Return JSON scan result for phone number."""
    data = json.loads(subprocess.check_output(
                ["phoneinfoga", "scan", "-n", number, "-o", "json"],
                text=True))
    _store(number, data)
    return data

if __name__ == "__main__":
    mcp.run(transport="stdio")
