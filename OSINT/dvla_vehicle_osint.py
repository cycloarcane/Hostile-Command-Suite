#!/usr/bin/env python3
"""
dvla_vehicle_osint.py — FastMCP tool for UK vehicle intelligence using DVLA APIs

FastMCP tools
────────────
    get_vehicle_details(registration, ...)
    get_mot_history(registration, ...)
    comprehensive_vehicle_check(registration, ...)

Returns
───────
    {
      "status": "success",
      "registration": "AB12CDE",
      "vehicle_details": {...},
      "mot_history": [...],
      "risk_analysis": {...}
    }

Dependencies
────────────
    pip install requests

Setup
─────
    1. DVLA Vehicle Enquiry Service API key from:
       https://developer-portal.driver-vehicle-licensing.api.gov.uk/
    2. DVSA MOT History API credentials from:
       https://documentation.history.mot.api.gov.uk/
    
    Set environment variables:
    - DVLA_VES_API_KEY
    - DVSA_MOT_CLIENT_ID
    - DVSA_MOT_CLIENT_SECRET
    - DVSA_MOT_TENANT_ID
"""

import json
import os
import sys
import time
import logging
import hashlib
import re
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dvla_vehicle_osint")

mcp = FastMCP("dvla_vehicle")  # MCP route → /dvla_vehicle
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
DVLA_VES_API_KEY = os.environ.get("DVLA_VES_API_KEY", "")
DVSA_MOT_CLIENT_ID = os.environ.get("DVSA_MOT_CLIENT_ID", "")
DVSA_MOT_CLIENT_SECRET = os.environ.get("DVSA_MOT_CLIENT_SECRET", "")
DVSA_MOT_TENANT_ID = os.environ.get("DVSA_MOT_TENANT_ID", "")

# API endpoints
DVLA_VES_URL = "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles"
DVSA_MOT_TOKEN_URL = f"https://login.microsoftonline.com/{DVSA_MOT_TENANT_ID}/oauth2/v2.0/token"
DVSA_MOT_API_URL = "https://history.mot.api.gov.uk"

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second

# Cache for OAuth tokens
_oauth_token_cache = {"token": None, "expires_at": 0}


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for API calls"""
    global _LAST_CALL_AT
    
    min_interval = 1.0 / calls_per_second
    wait = _LAST_CALL_AT + min_interval - time.time()
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL_AT = time.time()


def _get_cache_key(operation: str, **kwargs) -> str:
    """Generate a cache key"""
    serializable_kwargs = {
        k: v for k, v in kwargs.items() 
        if isinstance(v, (str, int, float, bool, type(None)))
    }
    cache_str = f"{operation}_{json.dumps(serializable_kwargs, sort_keys=True)}"
    return hashlib.md5(cache_str.encode()).hexdigest()


def _get_from_cache(cache_key: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
    """Try to get results from cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        file_age = time.time() - os.path.getmtime(cache_file)
        if file_age < max_age:
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
    return None


def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save results to cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f)
    except IOError as e:
        logger.warning(f"Cache write error: {e}")


def _validate_uk_registration(registration: str) -> bool:
    """Validate UK vehicle registration number format"""
    if not registration or len(registration) < 2:
        return False
    
    # Remove spaces and convert to uppercase
    reg = registration.replace(" ", "").upper()
    
    # UK registration patterns
    patterns = [
        r'^[A-Z]{2}[0-9]{2}[A-Z]{3}$',  # Current format: AB12CDE
        r'^[A-Z][0-9]{1,3}[A-Z]{3}$',   # Prefix format: A123BCD
        r'^[A-Z]{3}[0-9]{1,3}[A-Z]$',   # Suffix format: ABC123D
        r'^[0-9]{1,4}[A-Z]{1,3}$',      # Dateless format: 1234AB
        r'^[A-Z]{1,3}[0-9]{1,4}$'       # Reversed dateless: AB1234
    ]
    
    return any(re.match(pattern, reg) for pattern in patterns)


def _get_mot_access_token() -> Optional[str]:
    """Get OAuth 2.0 access token for MOT API"""
    global _oauth_token_cache
    
    # Check if we have a valid cached token
    if (_oauth_token_cache["token"] and 
        time.time() < _oauth_token_cache["expires_at"] - 300):  # 5 min buffer
        return _oauth_token_cache["token"]
    
    if not all([DVSA_MOT_CLIENT_ID, DVSA_MOT_CLIENT_SECRET, DVSA_MOT_TENANT_ID]):
        return None
    
    try:
        _rate_limit()
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'client_credentials',
            'client_id': DVSA_MOT_CLIENT_ID,
            'client_secret': DVSA_MOT_CLIENT_SECRET,
            'scope': 'https://tapi.dvsa.gov.uk/.default'
        }
        
        response = requests.post(DVSA_MOT_TOKEN_URL, headers=headers, data=data, timeout=30)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get('access_token')
        expires_in = token_data.get('expires_in', 3600)
        
        # Cache the token
        _oauth_token_cache = {
            "token": access_token,
            "expires_at": time.time() + expires_in
        }
        
        return access_token
        
    except Exception as e:
        logger.error(f"Failed to get MOT access token: {e}")
        return None


def _analyze_vehicle_risk(vehicle_data: Dict[str, Any], mot_data: List[Dict] = None) -> Dict[str, Any]:
    """Analyze vehicle risk based on available data"""
    risk_score = 0
    risk_factors = []
    
    # Tax status analysis
    tax_status = vehicle_data.get("taxStatus", "").upper()
    if tax_status == "UNTAXED":
        risk_score += 30
        risk_factors.append("Vehicle is currently untaxed")
    elif tax_status == "SORN":
        risk_score += 20
        risk_factors.append("Vehicle is off-road (SORN)")
    
    # MOT status analysis
    mot_status = vehicle_data.get("motStatus", "").upper()
    if "NO MOT" in mot_status or "EXPIRED" in mot_status:
        risk_score += 40
        risk_factors.append("Vehicle has no valid MOT")
    
    # Age analysis
    year_of_manufacture = vehicle_data.get("yearOfManufacture")
    if year_of_manufacture:
        current_year = datetime.now().year
        age = current_year - year_of_manufacture
        if age > 20:
            risk_score += 15
            risk_factors.append(f"Vehicle is {age} years old")
        elif age > 15:
            risk_score += 10
            risk_factors.append(f"Vehicle is {age} years old")
    
    # Export marker
    if vehicle_data.get("markedForExport"):
        risk_score += 25
        risk_factors.append("Vehicle is marked for export")
    
    # MOT history analysis
    if mot_data:
        recent_failures = 0
        total_tests = len(mot_data)
        
        for test in mot_data[:5]:  # Check last 5 MOTs
            if test.get("testResult", "").upper() == "FAILED":
                recent_failures += 1
        
        if recent_failures > 2:
            risk_score += 20
            risk_factors.append(f"Multiple recent MOT failures ({recent_failures}/{min(5, total_tests)})")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 25:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "minimal"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "recommendation": "Avoid or inspect carefully" if risk_score > 50 else "Standard checks recommended"
    }


@mcp.tool()
def check_dvla_apis() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which DVLA/DVSA APIs are configured and available.
    
    Returns:
        A dictionary with API availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "dvla_ves_api": bool(DVLA_VES_API_KEY),
        "dvsa_mot_oauth": bool(DVSA_MOT_CLIENT_ID and DVSA_MOT_CLIENT_SECRET and DVSA_MOT_TENANT_ID)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["dvla_ves_api"]:
        missing.append("DVLA VES API key: Get from https://developer-portal.driver-vehicle-licensing.api.gov.uk/")
    if not deps["dvsa_mot_oauth"]:
        missing.append("DVSA MOT API credentials: Get from https://documentation.history.mot.api.gov.uk/")
    
    return {
        "status": "ok" if deps["requests"] else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing,
        "notes": {
            "dvla_ves": "Vehicle Enquiry Service provides tax, MOT status, and vehicle details",
            "dvsa_mot": "MOT History API provides detailed test history and defects"
        }
    }


@mcp.tool()
def get_vehicle_details(
    registration: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get vehicle details from DVLA Vehicle Enquiry Service.
    
    Args:
        registration: UK vehicle registration number
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with vehicle details from DVLA
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not DVLA_VES_API_KEY:
        return {
            "status": "error",
            "message": "DVLA VES API key not configured. Set DVLA_VES_API_KEY environment variable."
        }
    
    # Clean and validate registration
    registration = registration.replace(" ", "").upper()
    if not _validate_uk_registration(registration):
        return {
            "status": "error",
            "message": "Invalid UK vehicle registration format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("dvla_vehicle", registration=registration)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        _rate_limit()
        
        headers = {
            "x-api-key": DVLA_VES_API_KEY,
            "Content-Type": "application/json"
        }
        
        data = {"registrationNumber": registration}
        
        response = requests.post(DVLA_VES_URL, headers=headers, json=data, timeout=30)
        
        if response.status_code == 404:
            return {
                "status": "not_found",
                "registration": registration,
                "message": "Vehicle not found in DVLA database"
            }
        
        response.raise_for_status()
        vehicle_data = response.json()
        
        # Process and enhance the data
        result = {
            "status": "success",
            "registration": registration,
            "vehicle_details": vehicle_data,
            "processed_data": {
                "make_model": f"{vehicle_data.get('make', '')} {vehicle_data.get('model', '')}".strip(),
                "age_years": datetime.now().year - vehicle_data.get('yearOfManufacture', datetime.now().year),
                "tax_due_date": vehicle_data.get('taxDueDate'),
                "mot_expiry_date": vehicle_data.get('motExpiryDate'),
                "engine_size_liters": vehicle_data.get('engineCapacity', 0) / 1000 if vehicle_data.get('engineCapacity') else None,
                "co2_emissions_g_km": vehicle_data.get('co2Emissions'),
                "fuel_type": vehicle_data.get('fuelType'),
                "colour": vehicle_data.get('colour'),
                "marked_for_export": vehicle_data.get('markedForExport', False)
            }
        }
        
        # Add risk analysis
        result["risk_analysis"] = _analyze_vehicle_risk(vehicle_data)
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "registration": registration,
            "message": f"DVLA API request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "registration": registration,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def get_mot_history(
    registration: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get MOT test history from DVSA MOT History API.
    
    Args:
        registration: UK vehicle registration number
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with MOT test history
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Clean and validate registration
    registration = registration.replace(" ", "").upper()
    if not _validate_uk_registration(registration):
        return {
            "status": "error",
            "message": "Invalid UK vehicle registration format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("dvsa_mot", registration=registration)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    # Get OAuth token
    access_token = _get_mot_access_token()
    if not access_token:
        return {
            "status": "error",
            "message": "DVSA MOT API not configured or authentication failed"
        }
    
    try:
        _rate_limit()
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": DVSA_MOT_CLIENT_ID,  # API key is also required
            "Accept": "application/json"
        }
        
        url = f"{DVSA_MOT_API_URL}/trade/vehicles/mot-tests"
        params = {"registration": registration}
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 404:
            return {
                "status": "not_found",
                "registration": registration,
                "message": "No MOT history found for this vehicle"
            }
        
        response.raise_for_status()
        mot_data = response.json()
        
        # Process MOT data
        if isinstance(mot_data, list) and mot_data:
            vehicle_info = mot_data[0]
            mot_tests = vehicle_info.get("motTests", [])
            
            # Analyze MOT history
            total_tests = len(mot_tests)
            passed_tests = sum(1 for test in mot_tests if test.get("testResult", "").upper() == "PASSED")
            failed_tests = total_tests - passed_tests
            
            # Get latest test
            latest_test = mot_tests[0] if mot_tests else None
            
            # Analyze mileage progression
            mileage_readings = []
            for test in reversed(mot_tests):  # Chronological order
                if test.get("odometerValue") and test.get("odometerResultType") == "READ":
                    mileage_readings.append({
                        "date": test.get("completedDate"),
                        "mileage": int(test.get("odometerValue", 0)),
                        "test_result": test.get("testResult")
                    })
            
            result = {
                "status": "success",
                "registration": registration,
                "vehicle_info": {
                    "make": vehicle_info.get("make"),
                    "model": vehicle_info.get("model"),
                    "first_used_date": vehicle_info.get("firstUsedDate"),
                    "fuel_type": vehicle_info.get("fuelType"),
                    "primary_colour": vehicle_info.get("primaryColour"),
                    "engine_size": vehicle_info.get("engineSize")
                },
                "mot_summary": {
                    "total_tests": total_tests,
                    "passed_tests": passed_tests,
                    "failed_tests": failed_tests,
                    "pass_rate": round(passed_tests / total_tests * 100, 1) if total_tests > 0 else 0,
                    "latest_test_result": latest_test.get("testResult") if latest_test else None,
                    "latest_test_date": latest_test.get("completedDate") if latest_test else None
                },
                "mot_tests": mot_tests,
                "mileage_history": mileage_readings
            }
            
            # Cache successful results
            if use_cache:
                _save_to_cache(cache_key, result)
            
            return result
        else:
            return {
                "status": "not_found",
                "registration": registration,
                "message": "No MOT data found"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "status": "error", 
            "registration": registration,
            "message": f"DVSA MOT API request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "registration": registration,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def comprehensive_vehicle_check(
    registration: str,
    include_mot_history: bool = True,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Perform comprehensive vehicle check using all available DVLA/DVSA APIs.
    
    Args:
        registration: UK vehicle registration number
        include_mot_history: Whether to include detailed MOT history
        use_cache: Whether to use caching
        
    Returns:
        Dict with comprehensive vehicle intelligence
    """
    registration = registration.replace(" ", "").upper()
    if not _validate_uk_registration(registration):
        return {
            "status": "error",
            "message": "Invalid UK vehicle registration format"
        }
    
    result = {
        "status": "success",
        "registration": registration,
        "timestamp": time.time(),
        "vehicle_details": {},
        "mot_history": {},
        "comprehensive_analysis": {}
    }
    
    # Get vehicle details from DVLA
    logger.info(f"Getting vehicle details for {registration}")
    vehicle_result = get_vehicle_details(registration, use_cache=use_cache)
    result["vehicle_details"] = vehicle_result
    
    # Get MOT history if requested and vehicle found
    if include_mot_history and vehicle_result.get("status") == "success":
        logger.info(f"Getting MOT history for {registration}")
        mot_result = get_mot_history(registration, use_cache=use_cache)
        result["mot_history"] = mot_result
    
    # Comprehensive analysis
    analysis = {
        "vehicle_found": vehicle_result.get("status") == "success",
        "mot_data_available": False,
        "overall_risk_level": "unknown",
        "key_findings": [],
        "recommendations": []
    }
    
    if vehicle_result.get("status") == "success":
        vehicle_data = vehicle_result.get("vehicle_details", {})
        mot_tests = []
        
        if result["mot_history"].get("status") == "success":
            analysis["mot_data_available"] = True
            mot_tests = result["mot_history"].get("mot_tests", [])
        
        # Enhanced risk analysis with both datasets
        risk_analysis = _analyze_vehicle_risk(vehicle_data, mot_tests)
        analysis["overall_risk_level"] = risk_analysis["risk_level"]
        analysis["risk_score"] = risk_analysis["risk_score"]
        
        # Key findings
        if vehicle_data.get("taxStatus", "").upper() == "UNTAXED":
            analysis["key_findings"].append("⚠️ Vehicle is currently untaxed")
        
        if "NO MOT" in vehicle_data.get("motStatus", "").upper():
            analysis["key_findings"].append("⚠️ Vehicle has no valid MOT certificate")
        
        if vehicle_data.get("markedForExport"):
            analysis["key_findings"].append("🚨 Vehicle is marked for export")
        
        if mot_tests:
            recent_failures = sum(1 for test in mot_tests[:3] if test.get("testResult", "").upper() == "FAILED")
            if recent_failures > 1:
                analysis["key_findings"].append(f"⚠️ {recent_failures} recent MOT failures")
        
        # Recommendations
        if risk_analysis["risk_level"] in ["high", "critical"]:
            analysis["recommendations"].extend([
                "Conduct thorough inspection before purchase",
                "Verify all documentation",
                "Check for outstanding finance"
            ])
        
        if vehicle_data.get("taxStatus", "").upper() == "UNTAXED":
            analysis["recommendations"].append("Tax vehicle before use")
        
        if "NO MOT" in vehicle_data.get("motStatus", "").upper():
            analysis["recommendations"].append("Arrange MOT test immediately")
    
    else:
        analysis["key_findings"].append("❌ Vehicle not found in DVLA database")
        analysis["recommendations"].append("Verify registration number is correct")
    
    result["comprehensive_analysis"] = analysis
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")