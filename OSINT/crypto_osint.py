#!/usr/bin/env python3
"""
crypto_osint.py — FastMCP tool for cryptocurrency address analysis and blockchain intelligence

FastMCP tools
────────────
    analyze_bitcoin_address(address, ...)
    analyze_ethereum_address(address, ...)
    check_crypto_sanctions(address, ...)
    trace_bitcoin_transactions(txid, depth=1, ...)

Returns
───────
    {
      "status": "success",
      "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "balance": 0.0,
      "transactions": 1,
      "first_seen": "2009-01-03",
      "risk_analysis": {...}
    }

Dependencies
────────────
    pip install requests

Setup
─────
    For enhanced features, get API keys from:
    1. BlockCypher: https://www.blockcypher.com/dev/
    2. Blockchain.info: https://www.blockchain.com/api
    3. OXT: https://oxt.me/api (Bitcoin analysis)
    
    Set environment variables:
    - BLOCKCYPHER_API_KEY
    - BLOCKCHAIN_INFO_API_KEY
    - OXT_API_KEY
"""

import json
import os
import sys
import time
import logging
import hashlib
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin
import base58

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
logger = logging.getLogger("crypto_osint")

mcp = FastMCP("crypto")  # MCP route → /crypto
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
BLOCKCYPHER_API_KEY = os.environ.get("BLOCKCYPHER_API_KEY", "")
BLOCKCHAIN_INFO_API_KEY = os.environ.get("BLOCKCHAIN_INFO_API_KEY", "")
OXT_API_KEY = os.environ.get("OXT_API_KEY", "")

# API endpoints
BLOCKCYPHER_BASE = "https://api.blockcypher.com/v1"
BLOCKCHAIN_INFO_BASE = "https://blockchain.info"
OXT_BASE = "https://api.oxt.me"

# Known sanctioned addresses (OFAC and other lists)
SANCTIONED_ADDRESSES = {
    # Sample sanctioned addresses - in production, this would be updated from official sources
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Genesis Block (Satoshi)",
    # Add more from OFAC SDN list
}

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


def _validate_bitcoin_address(address: str) -> bool:
    """Validate Bitcoin address format"""
    try:
        # Legacy address validation (1xxx)
        if address.startswith('1') and len(address) >= 26 and len(address) <= 35:
            decoded = base58.b58decode(address)
            if len(decoded) == 25:
                return True
        
        # P2SH address validation (3xxx)
        elif address.startswith('3') and len(address) >= 26 and len(address) <= 35:
            decoded = base58.b58decode(address)
            if len(decoded) == 25:
                return True
        
        # Bech32 address validation (bc1xxx)
        elif address.startswith('bc1') and len(address) >= 42:
            return True
        
        return False
    except:
        return False


def _validate_ethereum_address(address: str) -> bool:
    """Validate Ethereum address format"""
    # Ethereum addresses start with 0x and are 42 characters long
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return bool(re.match(pattern, address))


def _calculate_risk_score(address_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk score for cryptocurrency address"""
    risk_score = 0
    risk_factors = []
    
    # Check if address is sanctioned
    address = address_data.get("address", "")
    if address in SANCTIONED_ADDRESSES:
        risk_score += 100
        risk_factors.append(f"Sanctioned address: {SANCTIONED_ADDRESSES[address]}")
    
    # High transaction volume might indicate commercial use
    tx_count = address_data.get("n_tx", 0)
    if tx_count > 10000:
        risk_score += 30
        risk_factors.append("Very high transaction volume")
    elif tx_count > 1000:
        risk_score += 15
        risk_factors.append("High transaction volume")
    
    # Large balance might indicate exchange or institutional wallet
    balance = address_data.get("final_balance", 0) / 100000000  # Convert satoshis to BTC
    if balance > 1000:
        risk_score += 25
        risk_factors.append("Very large balance (>1000 BTC)")
    elif balance > 100:
        risk_score += 15
        risk_factors.append("Large balance (>100 BTC)")
    
    # Recent activity
    if "latest_tx" in address_data:
        latest_tx_time = address_data.get("latest_tx", {}).get("time", 0)
        if latest_tx_time:
            days_since_last_tx = (time.time() - latest_tx_time) / (24 * 60 * 60)
            if days_since_last_tx < 1:
                risk_score += 10
                risk_factors.append("Recent activity (last 24 hours)")
    
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
        "recommendation": "Monitor closely" if risk_score > 50 else "Standard monitoring"
    }


@mcp.tool()
def check_crypto_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which cryptocurrency analysis tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "blockcypher_api": bool(BLOCKCYPHER_API_KEY),
        "blockchain_info_api": bool(BLOCKCHAIN_INFO_API_KEY),
        "oxt_api": bool(OXT_API_KEY)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    
    return {
        "status": "ok" if deps["requests"] else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing,
        "notes": {
            "api_keys_optional": "API keys improve rate limits and access to advanced features",
            "free_tier": "Basic analysis works without API keys"
        }
    }


@mcp.tool()
def analyze_bitcoin_address(
    address: str,
    include_transactions: bool = False,
    tx_limit: int = 10,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Analyze a Bitcoin address for balance, transactions, and intelligence.
    
    Args:
        address: Bitcoin address to analyze
        include_transactions: Whether to include recent transactions
        tx_limit: Maximum number of transactions to return
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with Bitcoin address analysis
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_bitcoin_address(address):
        return {
            "status": "error",
            "message": "Invalid Bitcoin address format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("bitcoin_address", address=address, include_transactions=include_transactions)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "address": address,
        "address_type": "unknown",
        "balance_btc": 0.0,
        "balance_usd": 0.0,
        "transaction_count": 0,
        "first_seen": None,
        "last_seen": None,
        "transactions": [],
        "risk_analysis": {},
        "sources": []
    }
    
    # Determine address type
    if address.startswith('1'):
        result["address_type"] = "P2PKH (Legacy)"
    elif address.startswith('3'):
        result["address_type"] = "P2SH (Script Hash)"
    elif address.startswith('bc1'):
        result["address_type"] = "Bech32 (SegWit)"
    
    # Method 1: Blockchain.info API (free)
    try:
        _rate_limit()
        
        url = f"{BLOCKCHAIN_INFO_BASE}/rawaddr/{address}?limit={tx_limit if include_transactions else 0}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        result["balance_btc"] = data.get("final_balance", 0) / 100000000  # Convert satoshis
        result["transaction_count"] = data.get("n_tx", 0)
        result["total_received_btc"] = data.get("total_received", 0) / 100000000
        result["total_sent_btc"] = data.get("total_sent", 0) / 100000000
        
        # Process transactions
        if include_transactions and "txs" in data:
            transactions = []
            for tx in data["txs"][:tx_limit]:
                tx_data = {
                    "hash": tx.get("hash"),
                    "time": tx.get("time"),
                    "block_height": tx.get("block_height"),
                    "inputs": len(tx.get("inputs", [])),
                    "outputs": len(tx.get("out", [])),
                    "fee": tx.get("fee", 0) / 100000000 if tx.get("fee") else 0
                }
                
                # Calculate net value for this address
                net_value = 0
                for inp in tx.get("inputs", []):
                    if inp.get("prev_out", {}).get("addr") == address:
                        net_value -= inp.get("prev_out", {}).get("value", 0)
                
                for out in tx.get("out", []):
                    if out.get("addr") == address:
                        net_value += out.get("value", 0)
                
                tx_data["net_value_btc"] = net_value / 100000000
                transactions.append(tx_data)
            
            result["transactions"] = transactions
            
            # Determine first and last seen
            if transactions:
                result["first_seen"] = min(tx.get("time", 0) for tx in data["txs"])
                result["last_seen"] = max(tx.get("time", 0) for tx in data["txs"])
        
        result["sources"].append("Blockchain.info")
        
    except Exception as e:
        logger.warning(f"Blockchain.info lookup failed: {e}")
    
    # Method 2: BlockCypher API (if API key available)
    if BLOCKCYPHER_API_KEY and not result["sources"]:
        try:
            _rate_limit()
            
            url = f"{BLOCKCYPHER_BASE}/btc/main/addrs/{address}/balance"
            params = {"token": BLOCKCYPHER_API_KEY}
            
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            
            result["balance_btc"] = data.get("balance", 0) / 100000000
            result["transaction_count"] = data.get("n_tx", 0)
            result["total_received_btc"] = data.get("total_received", 0) / 100000000
            result["total_sent_btc"] = data.get("total_sent", 0) / 100000000
            
            result["sources"].append("BlockCypher")
            
        except Exception as e:
            logger.warning(f"BlockCypher lookup failed: {e}")
    
    # Get current BTC/USD rate for balance conversion
    try:
        _rate_limit()
        
        rate_response = requests.get("https://api.coindesk.com/v1/bpi/currentprice.json", timeout=10)
        if rate_response.status_code == 200:
            rate_data = rate_response.json()
            usd_rate = float(rate_data["bpi"]["USD"]["rate_float"])
            result["balance_usd"] = result["balance_btc"] * usd_rate
            result["btc_usd_rate"] = usd_rate
    except:
        pass
    
    # Risk analysis
    address_data = {
        "address": address,
        "final_balance": result["balance_btc"] * 100000000,  # Convert back to satoshis for analysis
        "n_tx": result["transaction_count"]
    }
    result["risk_analysis"] = _calculate_risk_score(address_data)
    
    # Check sanctions list
    if address in SANCTIONED_ADDRESSES:
        result["sanctions_match"] = {
            "status": "MATCH",
            "description": SANCTIONED_ADDRESSES[address],
            "warning": "This address appears on sanctions lists"
        }
    else:
        result["sanctions_match"] = {"status": "CLEAR"}
    
    # Cache successful results
    if use_cache and result["sources"]:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def analyze_ethereum_address(
    address: str,
    include_transactions: bool = False,
    tx_limit: int = 10,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Analyze an Ethereum address for balance, transactions, and intelligence.
    
    Args:
        address: Ethereum address to analyze
        include_transactions: Whether to include recent transactions
        tx_limit: Maximum number of transactions to return
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with Ethereum address analysis
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_ethereum_address(address):
        return {
            "status": "error",
            "message": "Invalid Ethereum address format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("ethereum_address", address=address, include_transactions=include_transactions)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "address": address,
        "balance_eth": 0.0,
        "balance_usd": 0.0,
        "transaction_count": 0,
        "contract_address": False,
        "transactions": [],
        "sources": []
    }
    
    # Use free Ethereum APIs
    try:
        # Try Etherscan API (free tier)
        _rate_limit()
        
        # Get balance
        balance_url = "https://api.etherscan.io/api"
        balance_params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest"
        }
        
        balance_response = requests.get(balance_url, params=balance_params, timeout=15)
        balance_response.raise_for_status()
        
        balance_data = balance_response.json()
        if balance_data.get("status") == "1":
            # Convert from wei to ETH
            wei_balance = int(balance_data.get("result", "0"))
            result["balance_eth"] = wei_balance / 1e18
        
        # Get transaction count
        txcount_params = {
            "module": "proxy",
            "action": "eth_getTransactionCount",
            "address": address,
            "tag": "latest"
        }
        
        txcount_response = requests.get(balance_url, params=txcount_params, timeout=15)
        if txcount_response.status_code == 200:
            txcount_data = txcount_response.json()
            if txcount_data.get("result"):
                result["transaction_count"] = int(txcount_data["result"], 16)
        
        # Check if it's a contract
        code_params = {
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": "latest"
        }
        
        code_response = requests.get(balance_url, params=code_params, timeout=15)
        if code_response.status_code == 200:
            code_data = code_response.json()
            code = code_data.get("result", "0x")
            result["contract_address"] = len(code) > 2  # More than just "0x"
        
        # Get recent transactions if requested
        if include_transactions:
            tx_params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": tx_limit,
                "sort": "desc"
            }
            
            tx_response = requests.get(balance_url, params=tx_params, timeout=15)
            if tx_response.status_code == 200:
                tx_data = tx_response.json()
                if tx_data.get("status") == "1":
                    transactions = []
                    for tx in tx_data.get("result", []):
                        tx_info = {
                            "hash": tx.get("hash"),
                            "block_number": tx.get("blockNumber"),
                            "timestamp": int(tx.get("timeStamp", 0)),
                            "from": tx.get("from"),
                            "to": tx.get("to"),
                            "value_eth": int(tx.get("value", "0")) / 1e18,
                            "gas_used": int(tx.get("gasUsed", "0")),
                            "gas_price": int(tx.get("gasPrice", "0")),
                            "status": "success" if tx.get("txreceipt_status") == "1" else "failed"
                        }
                        transactions.append(tx_info)
                    
                    result["transactions"] = transactions
        
        result["sources"].append("Etherscan")
        
    except Exception as e:
        logger.warning(f"Ethereum analysis failed: {e}")
        return {
            "status": "error",
            "message": f"Failed to analyze Ethereum address: {str(e)}"
        }
    
    # Get current ETH/USD rate
    try:
        _rate_limit()
        
        rate_response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd", timeout=10)
        if rate_response.status_code == 200:
            rate_data = rate_response.json()
            usd_rate = rate_data["ethereum"]["usd"]
            result["balance_usd"] = result["balance_eth"] * usd_rate
            result["eth_usd_rate"] = usd_rate
    except:
        pass
    
    # Cache successful results
    if use_cache and result["sources"]:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def check_crypto_sanctions(
    address: str,
    cryptocurrency: str = "bitcoin",
    check_ofac: bool = True
) -> Dict[str, Any]:
    """
    Check if a cryptocurrency address appears on sanctions lists.
    
    Args:
        address: Cryptocurrency address to check
        cryptocurrency: Type of cryptocurrency ("bitcoin", "ethereum")
        check_ofac: Whether to check OFAC sanctions
        
    Returns:
        Dict with sanctions check results
    """
    result = {
        "status": "success",
        "address": address,
        "cryptocurrency": cryptocurrency,
        "sanctions_status": "CLEAR",
        "matches": [],
        "sources_checked": []
    }
    
    # Check internal sanctions list
    if address in SANCTIONED_ADDRESSES:
        result["sanctions_status"] = "MATCH"
        result["matches"].append({
            "source": "Internal Database",
            "description": SANCTIONED_ADDRESSES[address],
            "confidence": "high"
        })
    
    result["sources_checked"].append("Internal Database")
    
    # In a production environment, you would integrate with:
    # - OFAC SDN List API
    # - Chainalysis sanctions screening
    # - Elliptic sanctions database
    # - TRM Labs compliance data
    
    # For now, we'll simulate OFAC check
    if check_ofac:
        # This would be replaced with actual OFAC API call
        result["sources_checked"].append("OFAC SDN List (simulated)")
        
        # Add warning about limitations
        result["disclaimer"] = "This is a basic sanctions check. For compliance purposes, use official OFAC tools and professional compliance services."
    
    return result


@mcp.tool()
def trace_bitcoin_transactions(
    txid: str,
    depth: int = 1,
    use_cache: bool = True,
    cache_max_age: int = 7200  # 2 hours
) -> Dict[str, Any]:
    """
    Trace Bitcoin transactions to analyze flow of funds.
    
    Args:
        txid: Bitcoin transaction ID to trace
        depth: How many hops to trace (1 = direct connections)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with transaction tracing results
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Validate transaction ID format (64 hex characters)
    if not re.match(r'^[a-fA-F0-9]{64}$', txid):
        return {
            "status": "error",
            "message": "Invalid Bitcoin transaction ID format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("bitcoin_trace", txid=txid, depth=depth)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "txid": txid,
        "depth": depth,
        "transaction": {},
        "input_analysis": [],
        "output_analysis": [],
        "trace_graph": {},
        "sources": []
    }
    
    try:
        _rate_limit()
        
        # Get transaction details from Blockchain.info
        url = f"{BLOCKCHAIN_INFO_BASE}/rawtx/{txid}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        tx_data = response.json()
        
        # Basic transaction info
        result["transaction"] = {
            "hash": tx_data.get("hash"),
            "block_height": tx_data.get("block_height"),
            "time": tx_data.get("time"),
            "size": tx_data.get("size"),
            "fee": tx_data.get("fee", 0) / 100000000,
            "input_count": len(tx_data.get("inputs", [])),
            "output_count": len(tx_data.get("out", []))
        }
        
        # Analyze inputs
        total_input = 0
        for inp in tx_data.get("inputs", []):
            prev_out = inp.get("prev_out", {})
            input_info = {
                "address": prev_out.get("addr"),
                "value_btc": prev_out.get("value", 0) / 100000000,
                "script_type": prev_out.get("type")
            }
            total_input += prev_out.get("value", 0)
            result["input_analysis"].append(input_info)
        
        # Analyze outputs
        total_output = 0
        for out in tx_data.get("out", []):
            output_info = {
                "address": out.get("addr"),
                "value_btc": out.get("value", 0) / 100000000,
                "script_type": out.get("type"),
                "spent": out.get("spent", False)
            }
            total_output += out.get("value", 0)
            result["output_analysis"].append(output_info)
        
        result["transaction"]["total_input_btc"] = total_input / 100000000
        result["transaction"]["total_output_btc"] = total_output / 100000000
        
        # Build trace graph (simplified for depth=1)
        if depth >= 1:
            trace_nodes = []
            trace_edges = []
            
            # Add input nodes
            for i, inp in enumerate(result["input_analysis"]):
                if inp["address"]:
                    trace_nodes.append({
                        "id": inp["address"],
                        "type": "input",
                        "label": f"Input {i+1}",
                        "value": inp["value_btc"]
                    })
                    trace_edges.append({
                        "from": inp["address"],
                        "to": txid,
                        "value": inp["value_btc"]
                    })
            
            # Add output nodes
            for i, out in enumerate(result["output_analysis"]):
                if out["address"]:
                    trace_nodes.append({
                        "id": out["address"],
                        "type": "output",
                        "label": f"Output {i+1}",
                        "value": out["value_btc"]
                    })
                    trace_edges.append({
                        "from": txid,
                        "to": out["address"],
                        "value": out["value_btc"]
                    })
            
            result["trace_graph"] = {
                "nodes": trace_nodes,
                "edges": trace_edges,
                "center_tx": txid
            }
        
        result["sources"].append("Blockchain.info")
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Transaction tracing failed: {str(e)}"
        }


@mcp.tool()
def crypto_intelligence_summary(
    addresses: List[str],
    cryptocurrencies: List[str] = ["bitcoin"],
    include_risk_analysis: bool = True
) -> Dict[str, Any]:
    """
    Generate comprehensive intelligence summary for multiple crypto addresses.
    
    Args:
        addresses: List of cryptocurrency addresses to analyze
        cryptocurrencies: Types of cryptocurrencies (bitcoin, ethereum)
        include_risk_analysis: Whether to include risk analysis
        
    Returns:
        Dict with comprehensive intelligence summary
    """
    if not addresses:
        return {
            "status": "error",
            "message": "No addresses provided"
        }
    
    result = {
        "status": "success",
        "total_addresses": len(addresses),
        "analysis_results": {},
        "overall_summary": {
            "total_balance_btc": 0.0,
            "total_balance_eth": 0.0,
            "total_transactions": 0,
            "high_risk_addresses": [],
            "sanctioned_addresses": []
        }
    }
    
    for address in addresses[:10]:  # Limit to 10 addresses to avoid rate limits
        logger.info(f"Analyzing address: {address}")
        
        # Determine cryptocurrency type
        crypto_type = "bitcoin"
        if _validate_ethereum_address(address):
            crypto_type = "ethereum"
        elif not _validate_bitcoin_address(address):
            result["analysis_results"][address] = {
                "status": "error",
                "message": "Invalid address format"
            }
            continue
        
        # Analyze the address
        if crypto_type == "bitcoin":
            analysis = analyze_bitcoin_address(address, use_cache=True)
        else:
            analysis = analyze_ethereum_address(address, use_cache=True)
        
        result["analysis_results"][address] = analysis
        
        # Update summary
        if analysis.get("status") == "success":
            if crypto_type == "bitcoin":
                result["overall_summary"]["total_balance_btc"] += analysis.get("balance_btc", 0)
            else:
                result["overall_summary"]["total_balance_eth"] += analysis.get("balance_eth", 0)
            
            result["overall_summary"]["total_transactions"] += analysis.get("transaction_count", 0)
            
            # Check for high risk
            if include_risk_analysis and analysis.get("risk_analysis", {}).get("risk_level") in ["high", "critical"]:
                result["overall_summary"]["high_risk_addresses"].append(address)
            
            # Check for sanctions
            if analysis.get("sanctions_match", {}).get("status") == "MATCH":
                result["overall_summary"]["sanctioned_addresses"].append(address)
        
        # Add delay to respect rate limits
        time.sleep(1)
    
    # Generate recommendations
    recommendations = []
    if result["overall_summary"]["high_risk_addresses"]:
        recommendations.append("Review high-risk addresses for compliance")
    if result["overall_summary"]["sanctioned_addresses"]:
        recommendations.append("URGENT: Sanctioned addresses detected - report to compliance")
    if result["overall_summary"]["total_balance_btc"] > 100:
        recommendations.append("Large Bitcoin holdings detected - consider enhanced monitoring")
    
    result["recommendations"] = recommendations
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")