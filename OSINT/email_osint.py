#!/usr/bin/env python3
"""
email_osint.py — aggregate email-centric OSINT
"""
from fastmcp import FastMCP
import subprocess, json, tempfile, shutil, os, datetime
import psycopg2, os

mcp = FastMCP("email")     # route = /email

# -- helper ---------------------------------------------------------------
PG_DSN = os.getenv("OSINT_PG_DSN", "dbname=osint_db user=osint_user")

def _store(target, category, data: dict):
    with psycopg2.connect(PG_DSN) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO osint_results (target, category, data) VALUES (%s,%s,%s)",
            (target, category, json.dumps(data))
        )
    return "stored"

# ------------------------------------------------------------------------

@mcp.tool()
def mosint(email: str) -> dict:
    """Run `mosint <email>` and return parsed JSON."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    try:
        subprocess.run(["mosint", "-r", "-o", tmp.name, email],
                       check=True, text=True, capture_output=True)
        with open(tmp.name) as f:
            data = json.load(f)
        _store(email, "mosint", data)
        return data
    finally:
        os.unlink(tmp.name)

@mcp.tool()
def holehe(email: str) -> str:
    """Return raw Holehe output (sites where the email has an account)."""
    result = subprocess.check_output(["holehe", "--only-used", email], text=True)
    _store(email, "holehe", {"raw": result})
    return result

@mcp.tool()
def h8mail(email: str) -> str:
    """Quick HaveIBeenPwned check via h8mail."""
    out = subprocess.check_output(["h8mail", "-t", email, "-q"], text=True)
    _store(email, "h8mail", {"raw": out})
    return out

if __name__ == "__main__":
    mcp.run(transport="stdio")
