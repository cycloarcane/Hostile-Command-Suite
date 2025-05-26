#!/usr/bin/env python3
"""
companies_house_osint.py — FastMCP tool for UK company intelligence using Companies House API

FastMCP tools
────────────
    search_companies(query, ...)
    get_company_profile(company_number, ...)
    get_company_officers(company_number, ...)
    get_company_filings(company_number, ...)
    comprehensive_company_check(company_number, ...)

Returns
───────
    {
      "status": "success",
      "company_number": "12345678",
      "company_profile": {...},
      "officers": [...],
      "filings": [...],
      "risk_analysis": {...}
    }

Dependencies
────────────
    pip install requests

Setup
─────
    1. Get API key from Companies House Developer Hub:
       https://developer.company-information.service.gov.uk/
    2. Set environment variable:
       COMPANIES_HOUSE_API_KEY=your_api_key_here
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
import base64

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
logger = logging.getLogger("companies_house_osint")

mcp = FastMCP("companies_house")  # MCP route → /companies_house
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
COMPANIES_HOUSE_API_KEY = os.environ.get("COMPANIES_HOUSE_API_KEY", "")
COMPANIES_HOUSE_BASE_URL = "https://api.company-information.service.gov.uk"

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


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


def _validate_company_number(company_number: str) -> bool:
    """Validate UK company number format"""
    if not company_number:
        return False
    
    # Remove spaces and convert to uppercase
    company_number = company_number.replace(" ", "").upper()
    
    # UK company number patterns
    patterns = [
        r'^[0-9]{8}$',        # Standard 8-digit: 12345678
        r'^[A-Z]{2}[0-9]{6}$', # Prefix format: AB123456
        r'^[0-9]{6}$',        # 6-digit: 123456
        r'^[A-Z]{1}[0-9]{7}$', # Single letter prefix: A1234567
        r'^[0-9]{2}[0-9]{6}$'  # Other formats
    ]
    
    return any(re.match(pattern, company_number) for pattern in patterns)


def _make_ch_request(endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Make authenticated request to Companies House API"""
    if not COMPANIES_HOUSE_API_KEY:
        raise ValueError("Companies House API key not configured")
    
    _rate_limit()
    
    # Use HTTP Basic Auth with API key as username, blank password
    auth = (COMPANIES_HOUSE_API_KEY, "")
    
    url = f"{COMPANIES_HOUSE_BASE_URL}/{endpoint}"
    
    try:
        response = requests.get(url, auth=auth, params=params or {}, timeout=30)
        
        if response.status_code == 404:
            return {"status": "not_found", "message": "Resource not found"}
        elif response.status_code == 401:
            raise ValueError("Invalid Companies House API key")
        elif response.status_code == 429:
            raise ValueError("Rate limit exceeded")
        
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Companies House API error: {e}")
        raise


def _analyze_company_risk(company_data: Dict[str, Any], officers: List[Dict] = None, filings: List[Dict] = None) -> Dict[str, Any]:
    """Analyze company risk based on available data"""
    risk_score = 0
    risk_factors = []
    
    # Company status
    company_status = company_data.get("company_status", "").lower()
    if company_status in ["liquidation", "receivership", "administration"]:
        risk_score += 100
        risk_factors.append(f"Company is in {company_status}")
    elif company_status in ["dissolved", "closed"]:
        risk_score += 80
        risk_factors.append(f"Company is {company_status}")
    elif company_status == "dormant":
        risk_score += 20
        risk_factors.append("Company is dormant")
    
    # Incorporation date (very new companies)
    date_of_creation = company_data.get("date_of_creation")
    if date_of_creation:
        try:
            creation_date = datetime.strptime(date_of_creation, "%Y-%m-%d")
            days_since_creation = (datetime.now() - creation_date).days
            if days_since_creation < 30:
                risk_score += 30
                risk_factors.append("Company incorporated very recently")
            elif days_since_creation < 90:
                risk_score += 15
                risk_factors.append("Company incorporated recently")
        except:
            pass
    
    # Accounts overdue
    accounts = company_data.get("accounts", {})
    if accounts.get("overdue"):
        risk_score += 40
        risk_factors.append("Accounts are overdue")
    
    # Confirmation statement overdue
    confirmation_statement = company_data.get("confirmation_statement", {})
    if confirmation_statement.get("overdue"):
        risk_score += 30
        risk_factors.append("Confirmation statement is overdue")
    
    # Officer analysis
    if officers:
        # Check for multiple resignations
        recent_resignations = 0
        active_officers = 0
        
        for officer in officers:
            if officer.get("resigned_on"):
                try:
                    resignation_date = datetime.strptime(officer["resigned_on"], "%Y-%m-%d")
                    if (datetime.now() - resignation_date).days < 365:
                        recent_resignations += 1
                except:
                    pass
            else:
                active_officers += 1
        
        if recent_resignations > 2:
            risk_score += 25
            risk_factors.append(f"{recent_resignations} officers resigned in past year")
        
        if active_officers == 0:
            risk_score += 50
            risk_factors.append("No active officers found")
    
    # Filing activity
    if filings:
        recent_filings = 0
        for filing in filings[:10]:  # Check last 10 filings
            try:
                filing_date = datetime.strptime(filing.get("date", ""), "%Y-%m-%d")
                if (datetime.now() - filing_date).days < 365:
                    recent_filings += 1
            except:
                pass
        
        if recent_filings == 0:
            risk_score += 35
            risk_factors.append("No recent filing activity")
    
    # Company type risks
    company_type = company_data.get("type", "").lower()
    if "community-interest-company" in company_type:
        risk_score -= 5  # Slight positive modifier for CICs
    elif "private-unlimited" in company_type:
        risk_score += 10
        risk_factors.append("Unlimited liability company")
    
    # Determine risk level
    if risk_score >= 100:
        risk_level = "critical"
    elif risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score >= 15:
        risk_level = "low"
    else:
        risk_level = "minimal"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "recommendation": "Exercise extreme caution" if risk_score >= 70 else "Standard due diligence recommended"
    }


@mcp.tool()
def check_companies_house_api() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check if Companies House API is configured and working.
    
    Returns:
        A dictionary with API status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "companies_house_api_key": bool(COMPANIES_HOUSE_API_KEY)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["companies_house_api_key"]:
        missing.append("Companies House API key: Get from https://developer.company-information.service.gov.uk/")
    
    # Test API if key is available
    api_status = "unknown"
    if COMPANIES_HOUSE_API_KEY:
        try:
            # Test with a known company (Companies House itself)
            test_result = _make_ch_request("company/RC000835")
            api_status = "working" if test_result.get("company_name") else "error"
        except Exception as e:
            api_status = f"error: {str(e)}"
    
    return {
        "status": "ok" if all(deps.values()) else "missing_dependencies",
        "dependencies": deps,
        "api_test": api_status,
        "installation_instructions": missing,
        "notes": {
            "free_api": "Companies House API is free to use",
            "data_coverage": "Covers all UK companies, LLPs, and other registered entities"
        }
    }


@mcp.tool()
def search_companies(
    query: str,
    items_per_page: int = 20,
    start_index: int = 0,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Search for companies by name or other criteria.
    
    Args:
        query: Search query (company name, number, etc.)
        items_per_page: Number of results per page
        start_index: Starting index for pagination
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with search results
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not query or len(query.strip()) < 2:
        return {
            "status": "error",
            "message": "Search query must be at least 2 characters"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("search_companies", query=query, items_per_page=items_per_page, start_index=start_index)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        params = {
            "q": query.strip(),
            "items_per_page": min(items_per_page, 100),
            "start_index": start_index
        }
        
        search_data = _make_ch_request("search/companies", params)
        
        if search_data.get("status") == "not_found":
            return {
                "status": "success",
                "query": query,
                "total_results": 0,
                "companies": [],
                "page_info": {
                    "items_per_page": items_per_page,
                    "start_index": start_index,
                    "total_results": 0
                }
            }
        
        companies = search_data.get("items", [])
        
        # Process search results
        processed_companies = []
        for company in companies:
            processed_company = {
                "company_number": company.get("company_number"),
                "company_name": company.get("title"),
                "company_status": company.get("company_status"),
                "company_type": company.get("company_type"),
                "date_of_creation": company.get("date_of_creation"),
                "address": company.get("address", {}),
                "match_snippet": company.get("snippet", ""),
                "description": company.get("description")
            }
            processed_companies.append(processed_company)
        
        result = {
            "status": "success",
            "query": query,
            "total_results": search_data.get("total_results", 0),
            "companies": processed_companies,
            "page_info": {
                "items_per_page": search_data.get("items_per_page", items_per_page),
                "start_index": search_data.get("start_index", start_index),
                "total_results": search_data.get("total_results", 0)
            }
        }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "query": query,
            "message": f"Company search failed: {str(e)}"
        }


@mcp.tool()
def get_company_profile(
    company_number: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get detailed company profile information.
    
    Args:
        company_number: Company registration number
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with company profile data
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Clean company number
    company_number = company_number.replace(" ", "").upper()
    if not _validate_company_number(company_number):
        return {
            "status": "error",
            "message": "Invalid UK company number format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("company_profile", company_number=company_number)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        company_data = _make_ch_request(f"company/{company_number}")
        
        if company_data.get("status") == "not_found":
            return {
                "status": "not_found",
                "company_number": company_number,
                "message": "Company not found"
            }
        
        # Process and enhance company data
        result = {
            "status": "success",
            "company_number": company_number,
            "company_profile": company_data,
            "processed_data": {
                "company_name": company_data.get("company_name"),
                "company_status": company_data.get("company_status"),
                "company_type": company_data.get("type"),
                "incorporation_date": company_data.get("date_of_creation"),
                "registered_office": company_data.get("registered_office_address", {}),
                "nature_of_business": company_data.get("sic_codes", []),
                "accounts_status": company_data.get("accounts", {}),
                "confirmation_statement": company_data.get("confirmation_statement", {}),
                "jurisdiction": company_data.get("jurisdiction"),
                "has_charges": company_data.get("has_charges", False),
                "has_insolvency_history": company_data.get("has_insolvency_history", False)
            }
        }
        
        # Calculate company age
        if company_data.get("date_of_creation"):
            try:
                creation_date = datetime.strptime(company_data["date_of_creation"], "%Y-%m-%d")
                age_days = (datetime.now() - creation_date).days
                result["processed_data"]["company_age_days"] = age_days
                result["processed_data"]["company_age_years"] = round(age_days / 365.25, 1)
            except:
                pass
        
        # Add basic risk analysis
        result["risk_analysis"] = _analyze_company_risk(company_data)
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "company_number": company_number,
            "message": f"Failed to get company profile: {str(e)}"
        }


@mcp.tool()
def get_company_officers(
    company_number: str,
    items_per_page: int = 35,
    start_index: int = 0,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get company officers (directors, secretaries, etc.).
    
    Args:
        company_number: Company registration number
        items_per_page: Number of officers per page
        start_index: Starting index for pagination
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with officer information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Clean company number
    company_number = company_number.replace(" ", "").upper()
    if not _validate_company_number(company_number):
        return {
            "status": "error",
            "message": "Invalid UK company number format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("company_officers", company_number=company_number, items_per_page=items_per_page, start_index=start_index)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        params = {
            "items_per_page": min(items_per_page, 100),
            "start_index": start_index
        }
        
        officers_data = _make_ch_request(f"company/{company_number}/officers", params)
        
        if officers_data.get("status") == "not_found":
            return {
                "status": "not_found",
                "company_number": company_number,
                "message": "Company not found or no officers data available"
            }
        
        officers = officers_data.get("items", [])
        
        # Process officers data
        processed_officers = []
        active_officers = []
        resigned_officers = []
        
        for officer in officers:
            processed_officer = {
                "name": officer.get("name"),
                "officer_role": officer.get("officer_role"),
                "appointed_on": officer.get("appointed_on"),
                "resigned_on": officer.get("resigned_on"),
                "nationality": officer.get("nationality"),
                "country_of_residence": officer.get("country_of_residence"),
                "occupation": officer.get("occupation"),
                "address": officer.get("address", {}),
                "date_of_birth": officer.get("date_of_birth", {}),  # Month/year only for privacy
                "links": officer.get("links", {})
            }
            
            processed_officers.append(processed_officer)
            
            # Categorize officers
            if officer.get("resigned_on"):
                resigned_officers.append(processed_officer)
            else:
                active_officers.append(processed_officer)
        
        result = {
            "status": "success",
            "company_number": company_number,
            "officers_summary": {
                "total_officers": officers_data.get("total_results", 0),
                "active_officers": len(active_officers),
                "resigned_officers": len(resigned_officers),
                "items_per_page": officers_data.get("items_per_page", items_per_page),
                "start_index": officers_data.get("start_index", start_index)
            },
            "active_officers": active_officers,
            "resigned_officers": resigned_officers,
            "all_officers": processed_officers
        }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "company_number": company_number,
            "message": f"Failed to get company officers: {str(e)}"
        }


@mcp.tool()
def get_company_filings(
    company_number: str,
    items_per_page: int = 25,
    start_index: int = 0,
    category: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get company filing history.
    
    Args:
        company_number: Company registration number
        items_per_page: Number of filings per page
        start_index: Starting index for pagination
        category: Filter by filing category
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with filing history
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Clean company number
    company_number = company_number.replace(" ", "").upper()
    if not _validate_company_number(company_number):
        return {
            "status": "error",
            "message": "Invalid UK company number format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("company_filings", company_number=company_number, items_per_page=items_per_page, start_index=start_index, category=category)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        params = {
            "items_per_page": min(items_per_page, 100),
            "start_index": start_index
        }
        
        if category:
            params["category"] = category
        
        filings_data = _make_ch_request(f"company/{company_number}/filing-history", params)
        
        if filings_data.get("status") == "not_found":
            return {
                "status": "not_found",
                "company_number": company_number,
                "message": "Company not found or no filing history available"
            }
        
        filings = filings_data.get("items", [])
        
        # Process filings data
        processed_filings = []
        filing_categories = {}
        
        for filing in filings:
            processed_filing = {
                "date": filing.get("date"),
                "category": filing.get("category"),
                "subcategory": filing.get("subcategory"),
                "description": filing.get("description"),
                "type": filing.get("type"),
                "action_date": filing.get("action_date"),
                "barcode": filing.get("barcode"),
                "links": filing.get("links", {})
            }
            
            processed_filings.append(processed_filing)
            
            # Count filing categories
            category = filing.get("category", "unknown")
            filing_categories[category] = filing_categories.get(category, 0) + 1
        
        result = {
            "status": "success",
            "company_number": company_number,
            "filings_summary": {
                "total_filings": filings_data.get("total_count", 0),
                "returned_filings": len(processed_filings),
                "items_per_page": filings_data.get("items_per_page", items_per_page),
                "start_index": filings_data.get("start_index", start_index),
                "filing_categories": filing_categories
            },
            "filings": processed_filings
        }
        
        # Recent filing activity analysis
        recent_filings = []
        for filing in processed_filings:
            try:
                filing_date = datetime.strptime(filing["date"], "%Y-%m-%d")
                if (datetime.now() - filing_date).days <= 365:
                    recent_filings.append(filing)
            except:
                pass
        
        result["recent_activity"] = {
            "filings_last_year": len(recent_filings),
            "most_recent_filing": processed_filings[0] if processed_filings else None
        }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "company_number": company_number,
            "message": f"Failed to get company filings: {str(e)}"
        }


@mcp.tool()
def comprehensive_company_check(
    company_number: str,
    include_officers: bool = True,
    include_filings: bool = True,
    max_officers: int = 50,
    max_filings: int = 50,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Perform comprehensive company intelligence check.
    
    Args:
        company_number: Company registration number
        include_officers: Whether to include officer information
        include_filings: Whether to include filing history
        max_officers: Maximum number of officers to retrieve
        max_filings: Maximum number of filings to retrieve
        use_cache: Whether to use caching
        
    Returns:
        Dict with comprehensive company intelligence
    """
    company_number = company_number.replace(" ", "").upper()
    if not _validate_company_number(company_number):
        return {
            "status": "error",
            "message": "Invalid UK company number format"
        }
    
    result = {
        "status": "success",
        "company_number": company_number,
        "timestamp": time.time(),
        "company_profile": {},
        "officers": {},
        "filings": {},
        "comprehensive_analysis": {}
    }
    
    # Get company profile
    logger.info(f"Getting company profile for {company_number}")
    profile_result = get_company_profile(company_number, use_cache=use_cache)
    result["company_profile"] = profile_result
    
    # Get officers if requested and company found
    if include_officers and profile_result.get("status") == "success":
        logger.info(f"Getting officers for {company_number}")
        officers_result = get_company_officers(company_number, items_per_page=max_officers, use_cache=use_cache)
        result["officers"] = officers_result
    
    # Get filings if requested and company found
    if include_filings and profile_result.get("status") == "success":
        logger.info(f"Getting filings for {company_number}")
        filings_result = get_company_filings(company_number, items_per_page=max_filings, use_cache=use_cache)
        result["filings"] = filings_result
    
    # Comprehensive analysis
    analysis = {
        "company_found": profile_result.get("status") == "success",
        "overall_risk_level": "unknown",
        "key_findings": [],
        "red_flags": [],
        "positive_indicators": [],
        "recommendations": []
    }
    
    if profile_result.get("status") == "success":
        company_data = profile_result.get("company_profile", {})
        officers_data = result["officers"].get("all_officers", []) if result["officers"].get("status") == "success" else []
        filings_data = result["filings"].get("filings", []) if result["filings"].get("status") == "success" else []
        
        # Enhanced risk analysis with all datasets
        risk_analysis = _analyze_company_risk(company_data, officers_data, filings_data)
        analysis["overall_risk_level"] = risk_analysis["risk_level"]
        analysis["risk_score"] = risk_analysis["risk_score"]
        
        # Key findings
        company_status = company_data.get("company_status", "").lower()
        if company_status == "active":
            analysis["positive_indicators"].append("✅ Company is active")
        elif company_status in ["liquidation", "receivership", "administration"]:
            analysis["red_flags"].append(f"🚨 Company is in {company_status}")
        elif company_status == "dissolved":
            analysis["red_flags"].append("🚨 Company is dissolved")
        
        # Accounts and compliance
        accounts = company_data.get("accounts", {})
        if accounts.get("overdue"):
            analysis["red_flags"].append("⚠️ Company accounts are overdue")
        
        confirmation_statement = company_data.get("confirmation_statement", {})
        if confirmation_statement.get("overdue"):
            analysis["red_flags"].append("⚠️ Confirmation statement is overdue")
        
        # Officer analysis
        if officers_data:
            active_count = len([o for o in officers_data if not o.get("resigned_on")])
            if active_count == 0:
                analysis["red_flags"].append("⚠️ No active officers found")
            else:
                analysis["positive_indicators"].append(f"✅ {active_count} active officers")
        
        # Filing activity
        if filings_data:
            recent_filings = result["filings"].get("recent_activity", {}).get("filings_last_year", 0)
            if recent_filings == 0:
                analysis["red_flags"].append("⚠️ No recent filing activity")
            else:
                analysis["positive_indicators"].append(f"✅ {recent_filings} filings in past year")
        
        # Business insights
        sic_codes = company_data.get("sic_codes", [])
        if sic_codes:
            analysis["key_findings"].append(f"📊 Business activities: {', '.join(sic_codes[:3])}")
        
        # Company age
        if company_data.get("date_of_creation"):
            try:
                creation_date = datetime.strptime(company_data["date_of_creation"], "%Y-%m-%d")
                age_years = (datetime.now() - creation_date).days / 365.25
                if age_years < 0.25:  # Less than 3 months
                    analysis["key_findings"].append(f"🕐 Very new company ({age_years:.1f} years old)")
                else:
                    analysis["key_findings"].append(f"🕐 Company age: {age_years:.1f} years")
            except:
                pass
        
        # Recommendations based on findings
        if risk_analysis["risk_level"] in ["critical", "high"]:
            analysis["recommendations"].extend([
                "Conduct enhanced due diligence",
                "Verify current trading status",
                "Check for any insolvency proceedings",
                "Consider credit checks and references"
            ])
        elif risk_analysis["risk_level"] == "medium":
            analysis["recommendations"].extend([
                "Standard due diligence recommended",
                "Verify key officer information",
                "Check recent filing activity"
            ])
        else:
            analysis["recommendations"].append("Standard business verification sufficient")
        
        # Specific compliance recommendations
        if accounts.get("overdue") or confirmation_statement.get("overdue"):
            analysis["recommendations"].append("Check Companies House compliance status")
    
    else:
        analysis["red_flags"].append("❌ Company not found in Companies House register")
        analysis["recommendations"].append("Verify company number is correct")
    
    result["comprehensive_analysis"] = analysis
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")