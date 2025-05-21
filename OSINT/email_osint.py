#!/usr/bin/env python3
"""
email_osint.py — FastMCP tool that performs email OSINT using Mosint, Holehe and H8mail
Arch Linux quick-install:
    sudo pacman -S go git
    go install github.com/alpkeskin/mosint/v3@latest    # puts mosint in ~/go/bin
    pip install holehe h8mail
"""

from fastmcp import FastMCP
import subprocess, shutil, json, os, re, tempfile
from typing import List, Dict, Union, Optional

mcp = FastMCP("email")                    # route: /email

# --------------------------------------------------------------------------- #
# Utilities                                                                   #
# --------------------------------------------------------------------------- #
def check_tool_installed(tool: str) -> bool:
    return shutil.which(tool) is not None

def get_installed_tools() -> Dict[str, bool]:
    return {t: check_tool_installed(t) for t in ("mosint", "holehe", "h8mail")}

EMAIL_RE = re.compile(r"[^@]+@[^@]+\.[^@]+")

# --------------------------------------------------------------------------- #
# MCP tools                                                                   #
# --------------------------------------------------------------------------- #
@mcp.tool()
def check_tools_installation() -> Dict[str, Union[str, Dict[str, bool]]]:
    tools = get_installed_tools()
    help_installs = {
        "mosint": "git install: go install github.com/alpkeskin/mosint/v3@latest",
        "holehe": "pip install holehe",
        "h8mail": "pip install h8mail",
    }
    missing = [f"{t}: {h}" for t, ok in tools.items() if not ok]
    return {
        "status": "ok" if all(tools.values()) else "missing_tools",
        "tools": tools,
        "installation_instructions": missing,
    }

# --------------------------------------------------------------------------- #
# Holehe                                                                      #
# --------------------------------------------------------------------------- #
@mcp.tool()
def search_email_holehe(email: str, timeout: Optional[int] = 60) -> Dict[str, Union[str, List[Dict[str, str]]]]:
    if not check_tool_installed("holehe"):
        return {"status": "error", "message": "holehe not installed ― pip install holehe"}
    if not EMAIL_RE.fullmatch(email):
        return {"status": "error", "message": "Invalid email address"}

    try:
        proc = subprocess.run(["holehe", email],
                              capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return {"status": "error", "message": f"holehe failed: {proc.stderr}"}

        results, found = [], 0
        for m in re.finditer(r"\[(.*?)\] (.*?) : (.*)", proc.stdout):
            icon, service, result = m.groups()
            hit = "+" in icon or "FOUND" in result.upper()
            results.append({"service": service.strip(),
                            "found": hit,
                            "status": "Account found" if hit else "Not found"})
            if hit:
                found += 1
        return {"status": "success", "email": email, "tool": "holehe",
                "results": results, "total_found": found,
                "total_checked": len(results)}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"holehe timed-out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"holehe error: {e}"}

# --------------------------------------------------------------------------- #
# Mosint (new CLI with graceful fallback)                                     #
# --------------------------------------------------------------------------- #
@mcp.tool()
def search_email_mosint(email: str, timeout: Optional[int] = 120) -> Dict[str, Union[str, List[Dict[str, str]]]]:
    if not check_tool_installed("mosint"):
        return {"status": "error", "message": "mosint not installed ― see https://github.com/alpkeskin/mosint"}
    if not EMAIL_RE.fullmatch(email):
        return {"status": "error", "message": "Invalid email address"}

    output_file = os.path.join(tempfile.gettempdir(),
                               f"mosint_{email.replace('@', '_at_')}.json")

    def run(cmd: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    try:
        # New-style CLI first
        proc = run(["mosint", email, "-o", output_file])

        # Fallback for legacy versions that don't recognise the new flags
        if proc.returncode != 0 and ("unknown flag" in proc.stderr.lower()
                                     or "unknown shorthand" in proc.stderr.lower()):
            proc = run(["mosint", "-e", email, "-json", output_file])

        # Still non-zero?
        if proc.returncode != 0 and not os.path.exists(output_file):
            return {"status": "error",
                    "message": f"mosint failed: {proc.stderr.strip()}"[:800]}

        # Parse result file if it exists
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
            finally:
                os.remove(output_file)

            # Quick metrics
            breach_cnt = len(data.get("breaches", [])) if isinstance(data, dict) else 0
            social_cnt = len(data.get("social_media", [])) if isinstance(data, dict) else 0

            return {"status": "success", "email": email, "tool": "mosint",
                    "data": data, "breach_count": breach_cnt,
                    "social_media_count": social_cnt}

        # No JSON came out – return whatever stdout we got
        return {"status": "partial_success", "email": email, "tool": "mosint",
                "raw_output": proc.stdout[:10000],
                "message": "mosint ran but produced no JSON"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"mosint timed-out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"mosint error: {e}"}

# --------------------------------------------------------------------------- #
# H8mail                                                                      #
# --------------------------------------------------------------------------- #
@mcp.tool()
def search_email_h8mail(email: str, timeout: Optional[int] = 60) -> Dict[str, Union[str, List[Dict[str, str]]]]:
    if not check_tool_installed("h8mail"):
        return {"status": "error", "message": "h8mail not installed ― pip install h8mail"}
    if not EMAIL_RE.fullmatch(email):
        return {"status": "error", "message": "Invalid email address"}

    output_file = os.path.join(tempfile.gettempdir(),
                               f"h8mail_{email.replace('@', '_at_')}.json")

    try:
        proc = subprocess.run(["h8mail", "-t", email, "-j", output_file],
                              capture_output=True, text=True, timeout=timeout)

        if os.path.exists(output_file) and os.path.getsize(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
            finally:
                os.remove(output_file)

            breaches = []
            if isinstance(data, list) and data and isinstance(data[0], dict):
                for entry in data[0].get("data", []):
                    breaches.append({"source": entry.get("source", "Unknown"),
                                     "breach_data": entry.get("breach", "")})

            return {"status": "success", "email": email, "tool": "h8mail",
                    "breaches": breaches, "breach_count": len(breaches),
                    "full_data": data}

        if proc.returncode != 0:
            return {"status": "error", "message": f"h8mail failed: {proc.stderr}"}

        # Fallback: parse stdout
        m = re.search(r"Found (\d+) results for", proc.stdout)
        return {"status": "partial_success", "email": email, "tool": "h8mail",
                "breach_count": int(m.group(1)) if m else 0,
                "raw_output": proc.stdout[:5000]}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": f"h8mail timed-out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "message": f"h8mail error: {e}"}

# --------------------------------------------------------------------------- #
# Aggregate                                                                   #
# --------------------------------------------------------------------------- #
@mcp.tool()
def search_email_all(email: str, timeout: Optional[int] = 180) -> Dict[str, Union[str, Dict]]:
    if not EMAIL_RE.fullmatch(email):
        return {"status": "error", "message": "Invalid email address"}

    tools = get_installed_tools()
    if not any(tools.values()):
        return {"status": "error",
                "message": "No email OSINT tools installed (mosint, holehe, h8mail)"}

    per_tool = max(30, (timeout or 180) // sum(tools.values()))
    res = {"email": email, "tools_run": []}

    if tools["holehe"]:
        res["holehe"] = search_email_holehe(email, per_tool)
        res["tools_run"].append("holehe")

    if tools["mosint"]:
        res["mosint"] = search_email_mosint(email, per_tool)
        res["tools_run"].append("mosint")

    if tools["h8mail"]:
        res["h8mail"] = search_email_h8mail(email, per_tool)
        res["tools_run"].append("h8mail")

    # overall status
    status_order = ["success", "partial_success"]
    for st in status_order:
        if any(t in res and res[t].get("status") == st for t in res["tools_run"]):
            res["status"] = st
            break
    else:
        res["status"] = "error"
        res["message"] = "All tools failed"

    # summary
    summary = {"accounts_found": 0, "breaches_found": 0, "services_checked": 0}
    if "holehe" in res:
        summary["accounts_found"] += res["holehe"].get("total_found", 0)
        summary["services_checked"] += res["holehe"].get("total_checked", 0)
    if "mosint" in res:
        summary["accounts_found"] += res["mosint"].get("social_media_count", 0)
        summary["breaches_found"] += res["mosint"].get("breach_count", 0)
    if "h8mail" in res:
        summary["breaches_found"] += res["h8mail"].get("breach_count", 0)

    res["summary"] = summary
    return res

if __name__ == "__main__":
    mcp.run(transport="stdio")