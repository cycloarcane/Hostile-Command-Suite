#!/usr/bin/env python3
"""
phone_osint.py — FastMCP wrapper for *phoneinfoga-bin* (Go v3+)

Exposed MCP tools
──────────────────
▸ check_tools_installation()                 → verify phoneinfoga-bin is present
▸ scan_phone_phoneinfoga(number, timeout=60) → run one scan, return JSON + summary
▸ scan_phone_all(number, timeout=60)         → alias, handy if you add more tools

Requires:
    • Arch / AUR package  : phoneinfoga-bin
      (or any other v3 build named 'phoneinfoga-bin' on PATH)
"""

import json
import re
import shutil
import subprocess
from typing import Dict, Union, Optional

from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────────────────────
# Constants & helpers
# ──────────────────────────────────────────────────────────────────────────────
CLI = "phoneinfoga-bin"  # hard-coded; no fallbacks

_PHONE_RE = re.compile(r"^\+?\d[\d\s\-.]{5,20}$")  # loose sanity check


def _cli_available() -> bool:
    """True if phoneinfoga-bin is on PATH and executable."""
    return shutil.which(CLI) is not None


def _missing_msg() -> Dict[str, str]:
    return {
        "status": "missing_tools",
        "message": (
            "phoneinfoga-bin not found on PATH.\n"
            "Install it (e.g. `yay -S phoneinfoga-bin`) or add it to $PATH."
        ),
    }


def _summary_from_json(data: Dict) -> Dict:
    """Pull a small, stable subset of keys out of PhoneInfoga’s JSON."""
    return {
        "valid": data.get("valid"),
        "international_format": data.get("internationalNumber"),
        "carrier": data.get("carrier"),
        "region": data.get("region"),
        "line_type": data.get("line_type", data.get("type")),
    }


# ──────────────────────────────────────────────────────────────────────────────
# FastMCP service
# ──────────────────────────────────────────────────────────────────────────────
mcp = FastMCP("phone")  # route → /phone


@mcp.tool()
def check_tools_installation() -> Dict[str, Union[str, bool]]:
    """Return 'ok' if phoneinfoga-bin is available, else install hint."""
    if _cli_available():
        return {"status": "ok", "cli": CLI}
    return _missing_msg()


@mcp.tool()
def scan_phone_phoneinfoga(
    number: str,
    timeout: int = 60,
) -> Dict[str, Union[str, Dict]]:
    """
    Run *one* PhoneInfoga scan and return:
        status   : success | partial_success | error
        summary  : small dict (on success)
        data     : full JSON (on success)
        raw_output: first 10 kB of stdout (on parse error)
    """
    if not _cli_available():
        return _missing_msg()

    number = number.strip()
    if not _PHONE_RE.fullmatch(number):
        return {"status": "error", "message": "Invalid phone number format"}

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

    stdout = proc.stdout.strip()

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as err:
        return {
            "status": "partial_success",
            "message": f"Output was not valid JSON: {err}",
            "raw_output": stdout[:10000],
        }

    return {
        "status": "success",
        "number": number,
        "tool": CLI,
        "summary": _summary_from_json(data),
        "data": data,
    }


@mcp.tool()
def scan_phone_all(
    number: str,
    timeout: int = 60,
) -> Dict[str, Union[str, Dict]]:
    """
    Convenience wrapper (mirrors email_osint’s style).
    For now it just calls PhoneInfoga, but you can bolt on more tools later.
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
