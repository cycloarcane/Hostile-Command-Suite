#!/usr/bin/env python3
"""
image_analysis_osint.py — FastMCP tool for image analysis using local VLLM (Qwen2-VL via Ollama)

FastMCP tools
────────────
    analyze_image(image_path, analysis_type="comprehensive", ...)
    extract_text_from_image(image_path, ...)
    identify_objects_and_people(image_path, ...)
    analyze_document_image(image_path, ...)
    geolocate_image(image_path, ...)
    detect_surveillance_equipment(image_path, ...)

Returns
───────
    {
      "status": "success",
      "image_path": "/path/to/image.jpg",
      "analysis_results": {...},
      "extracted_text": "...",
      "objects_detected": [...],
      "osint_findings": {...}
    }

Dependencies
────────────
    pip install requests pillow base64

Setup
─────
    1. Install Ollama: https://ollama.com/
    2. Pull Qwen2-VL model: ollama pull qwen2-vl
    3. Ensure Ollama is running: ollama serve
    
    Environment variables (optional):
    - OLLAMA_BASE_URL (default: http://localhost:11434)
    - OLLAMA_MODEL (default: qwen2-vl)
"""

import json
import os
import time
import logging
import hashlib
import base64
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("image_analysis_osint")

mcp = FastMCP("image_analysis")  # MCP route → /image_analysis
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Ollama configuration
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2-vl")

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for local model calls"""
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


def _encode_image_to_base64(image_path: str) -> str:
    """Encode image to base64 for Ollama API"""
    try:
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encode image: {e}")
        return ""


def _validate_image_file(image_path: str) -> bool:
    """Validate image file exists and is readable"""
    if not os.path.exists(image_path):
        return False
    
    if PIL_AVAILABLE:
        try:
            with Image.open(image_path) as img:
                img.verify()
            return True
        except Exception:
            return False
    else:
        # Basic file extension check
        valid_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        return Path(image_path).suffix.lower() in valid_extensions


def _call_ollama_vision(image_base64: str, prompt: str, model: str = None) -> Dict[str, Any]:
    """Make a call to Ollama vision model"""
    if not model:
        model = OLLAMA_MODEL
    
    try:
        _rate_limit()
        
        url = f"{OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "images": [image_base64],
            "stream": False,
            "options": {
                "temperature": 0.1,  # Lower temperature for more consistent analysis
                "top_p": 0.9
            }
        }
        
        response = requests.post(url, json=payload, timeout=120)  # Longer timeout for vision models
        response.raise_for_status()
        
        result = response.json()
        return {
            "status": "success",
            "response": result.get("response", ""),
            "model_used": model,
            "done": result.get("done", False)
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama API error: {e}")
        return {
            "status": "error",
            "message": f"Ollama API request failed: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


def _extract_osint_insights(analysis_text: str) -> Dict[str, Any]:
    """Extract OSINT-relevant information from analysis text"""
    insights = {
        "potential_locations": [],
        "identifiable_text": [],
        "technical_equipment": [],
        "vehicles": [],
        "people_indicators": [],
        "documents": [],
        "surveillance_indicators": [],
        "timestamps": [],
        "brands_logos": [],
        "infrastructure": []
    }
    
    analysis_lower = analysis_text.lower()
    
    # Location indicators
    location_keywords = ['street', 'road', 'building', 'sign', 'landmark', 'city', 'country', 'address']
    for keyword in location_keywords:
        if keyword in analysis_lower:
            insights["potential_locations"].append(f"Contains {keyword} references")
    
    # Technical equipment
    tech_keywords = ['camera', 'server', 'computer', 'phone', 'device', 'screen', 'monitor', 'equipment']
    for keyword in tech_keywords:
        if keyword in analysis_lower:
            insights["technical_equipment"].append(f"Detected {keyword}")
    
    # Vehicle indicators
    vehicle_keywords = ['car', 'vehicle', 'license plate', 'truck', 'motorcycle', 'van']
    for keyword in vehicle_keywords:
        if keyword in analysis_lower:
            insights["vehicles"].append(f"Vehicle indicator: {keyword}")
    
    # Document indicators
    doc_keywords = ['document', 'paper', 'form', 'certificate', 'id', 'passport', 'license']
    for keyword in doc_keywords:
        if keyword in analysis_lower:
            insights["documents"].append(f"Document type: {keyword}")
    
    # Surveillance indicators
    surveillance_keywords = ['surveillance', 'security camera', 'cctv', 'monitoring', 'sensor']
    for keyword in surveillance_keywords:
        if keyword in analysis_lower:
            insights["surveillance_indicators"].append(f"Surveillance: {keyword}")
    
    return insights


@mcp.tool()
def check_image_analysis_setup() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check if image analysis dependencies and Ollama are properly configured.
    
    Returns:
        A dictionary with setup status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "pillow": PIL_AVAILABLE,
        "ollama_available": False,
        "qwen2_vl_available": False
    }
    
    # Test Ollama connection
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=10)
        if response.status_code == 200:
            deps["ollama_available"] = True
            
            # Check if Qwen2-VL model is available
            models = response.json().get("models", [])
            for model in models:
                if "qwen2-vl" in model.get("name", "").lower():
                    deps["qwen2_vl_available"] = True
                    break
    except:
        pass
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["pillow"]:
        missing.append("pillow: pip install pillow")
    if not deps["ollama_available"]:
        missing.append("Ollama: Install from https://ollama.com/")
    if not deps["qwen2_vl_available"]:
        missing.append("Qwen2-VL model: Run 'ollama pull qwen2-vl'")
    
    return {
        "status": "ok" if all(deps.values()) else "missing_dependencies",
        "dependencies": deps,
        "ollama_url": OLLAMA_BASE_URL,
        "model": OLLAMA_MODEL,
        "installation_instructions": missing
    }


@mcp.tool()
def analyze_image(
    image_path: str,
    analysis_type: str = "comprehensive",
    custom_prompt: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Comprehensive image analysis using local VLLM.
    
    Args:
        image_path: Path to the image file
        analysis_type: Type of analysis ("comprehensive", "text_extraction", "object_detection", "osint_focused")
        custom_prompt: Custom analysis prompt
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with image analysis results
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_image_file(image_path):
        return {
            "status": "error",
            "message": f"Invalid or unreadable image file: {image_path}"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("analyze_image", image_path=image_path, analysis_type=analysis_type, custom_prompt=custom_prompt)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    # Encode image
    image_base64 = _encode_image_to_base64(image_path)
    if not image_base64:
        return {
            "status": "error",
            "message": "Failed to encode image"
        }
    
    # Prepare analysis prompt based on type
    if custom_prompt:
        prompt = custom_prompt
    elif analysis_type == "comprehensive":
        prompt = """Analyze this image comprehensively for OSINT purposes. Provide detailed information about:

1. VISIBLE TEXT: Extract all readable text, signs, documents, license plates, etc.
2. OBJECTS: Identify all significant objects, equipment, vehicles, and items
3. PEOPLE: Describe any people visible (clothing, activities, but no identification)
4. LOCATION CLUES: Any geographical, architectural, or environmental indicators
5. TECHNICAL DETAILS: Equipment, devices, infrastructure visible
6. TEMPORAL INDICATORS: Any dates, times, or time-period indicators
7. BRAND/LOGO IDENTIFICATION: Any visible brands, logos, or company identifiers
8. SECURITY CONCERNS: Surveillance equipment, security measures, sensitive information

Format your response as structured analysis with clear categories. Be thorough but concise."""

    elif analysis_type == "text_extraction":
        prompt = """Extract ALL visible text from this image. Include:
- Street signs and road signs
- Building names and addresses  
- License plates and vehicle text
- Documents and papers
- Digital displays and screens
- Handwritten text
- Brand names and logos
- Any other readable text

Provide the extracted text exactly as it appears, organized by location in the image."""

    elif analysis_type == "object_detection":
        prompt = """Identify and catalog all objects visible in this image:
- Vehicles (type, color, distinctive features)
- Electronic equipment and devices
- Infrastructure and buildings
- Personal items and accessories
- Tools and equipment
- Furniture and fixtures
- Natural elements

Provide a detailed inventory with descriptions."""

    elif analysis_type == "osint_focused":
        prompt = """Analyze this image specifically for OSINT intelligence gathering:

PRIORITY INFORMATION:
- Any identifying text, numbers, or codes
- Geographic location indicators
- Time/date stamps or temporal clues
- Technical equipment that could indicate capabilities
- Vehicle information and identifiers
- Infrastructure that suggests location type
- Security measures and surveillance equipment
- Any sensitive or classified information visible

OPERATIONAL CONSIDERATIONS:
- What does this image reveal about the subject/location?
- What additional information could be gathered from this context?
- Are there any privacy or security implications?
- What follow-up investigations does this suggest?

Provide actionable intelligence assessment."""

    else:
        prompt = "Describe this image in detail, focusing on all visible elements and their significance."
    
    # Make the analysis call
    logger.info(f"Analyzing image: {image_path}")
    analysis_result = _call_ollama_vision(image_base64, prompt)
    
    if analysis_result.get("status") != "success":
        return analysis_result
    
    analysis_text = analysis_result.get("response", "")
    
    # Extract OSINT insights
    osint_insights = _extract_osint_insights(analysis_text)
    
    # Get image metadata if PIL is available
    image_metadata = {}
    if PIL_AVAILABLE:
        try:
            with Image.open(image_path) as img:
                image_metadata = {
                    "format": img.format,
                    "mode": img.mode,
                    "size": img.size,
                    "filename": os.path.basename(image_path),
                    "file_size": os.path.getsize(image_path)
                }
                
                # Extract EXIF data if available
                if hasattr(img, '_getexif') and img._getexif():
                    image_metadata["has_exif"] = True
                else:
                    image_metadata["has_exif"] = False
        except Exception as e:
            logger.warning(f"Failed to extract image metadata: {e}")
    
    result = {
        "status": "success",
        "image_path": image_path,
        "analysis_type": analysis_type,
        "model_used": analysis_result.get("model_used"),
        "analysis_results": {
            "full_analysis": analysis_text,
            "summary": analysis_text[:500] + "..." if len(analysis_text) > 500 else analysis_text
        },
        "osint_insights": osint_insights,
        "image_metadata": image_metadata,
        "timestamp": time.time()
    }
    
    # Cache successful results
    if use_cache:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def extract_text_from_image(
    image_path: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Extract all visible text from an image using vision model.
    
    Args:
        image_path: Path to the image file
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with extracted text
    """
    return analyze_image(
        image_path=image_path,
        analysis_type="text_extraction",
        use_cache=use_cache,
        cache_max_age=cache_max_age
    )


@mcp.tool()
def identify_objects_and_people(
    image_path: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Identify objects and people in an image.
    
    Args:
        image_path: Path to the image file
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with object and people detection results
    """
    return analyze_image(
        image_path=image_path,
        analysis_type="object_detection",
        use_cache=use_cache,
        cache_max_age=cache_max_age
    )


@mcp.tool()
def analyze_document_image(
    image_path: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Analyze an image of a document for OSINT purposes.
    
    Args:
        image_path: Path to the document image
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with document analysis results
    """
    custom_prompt = """Analyze this document image for OSINT purposes:

DOCUMENT ANALYSIS:
- Document type and purpose
- All visible text content (transcribe exactly)
- Names, dates, addresses, and identifiers
- Official stamps, seals, or signatures
- Letterheads, logos, and branding
- Document numbers, reference codes
- Classification markings or sensitivity indicators

INTELLIGENCE VALUE:
- What information can be extracted?
- What does this document reveal about the subject?
- Are there any redacted or partially visible sections?
- What additional context clues are present?

VERIFICATION INDICATORS:
- Signs of authenticity or forgery
- Print quality and paper type observations  
- Any anomalies or suspicious elements

Provide a complete transcription and intelligence assessment."""

    return analyze_image(
        image_path=image_path,
        analysis_type="comprehensive",
        custom_prompt=custom_prompt,
        use_cache=use_cache,
        cache_max_age=cache_max_age
    )


@mcp.tool()
def geolocate_image(
    image_path: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Analyze an image for geographical location clues.
    
    Args:
        image_path: Path to the image file
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with geolocation analysis
    """
    custom_prompt = """Analyze this image for geographical location and geolocation clues:

GEOGRAPHIC INDICATORS:
- Architecture style and building characteristics
- Street signs, road signs, and traffic signals
- License plates and vehicle types/models
- Language on signs and text
- Vegetation and landscape features
- Climate and weather indicators
- Infrastructure and utility systems

LOCATION CLUES:
- Business names and chain stores
- Street names and addresses visible
- Postal codes or area codes
- Government or municipal identifiers
- Cultural and regional indicators
- Time zone clues (shadows, lighting)

ASSESSMENT:
- Possible country or region
- Urban vs rural environment
- Approximate time of day/season
- Confidence level in location assessment
- Additional research suggestions

Focus on observable details that could help pinpoint or narrow down the geographic location."""

    return analyze_image(
        image_path=image_path,
        analysis_type="comprehensive",
        custom_prompt=custom_prompt,
        use_cache=use_cache,
        cache_max_age=cache_max_age
    )


@mcp.tool()
def detect_surveillance_equipment(
    image_path: str,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Detect surveillance and security equipment in an image.
    
    Args:
        image_path: Path to the image file
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with surveillance equipment detection results
    """
    custom_prompt = """Analyze this image specifically for surveillance and security equipment:

SURVEILLANCE EQUIPMENT:
- Security cameras (types, positions, coverage angles)
- CCTV systems and monitoring equipment
- Motion sensors and detection devices
- Alarm systems and control panels
- Access control systems (card readers, keypads)
- Recording equipment and storage devices

SECURITY MEASURES:
- Physical barriers and fencing
- Security lighting and illumination
- Warning signs and notices
- Guard posts or security stations
- Vehicle barriers and checkpoints
- Restricted access indicators

TECHNICAL ASSESSMENT:
- Equipment manufacturers and models if visible
- Installation quality and positioning
- Coverage areas and blind spots
- Integration with other systems
- Operational status indicators

INTELLIGENCE VALUE:
- Security posture assessment
- Surveillance capability evaluation
- Potential vulnerabilities or gaps
- Recommendations for further analysis

Provide detailed technical assessment of all security and surveillance elements."""

    return analyze_image(
        image_path=image_path,
        analysis_type="comprehensive", 
        custom_prompt=custom_prompt,
        use_cache=use_cache,
        cache_max_age=cache_max_age
    )


@mcp.tool()
def batch_analyze_images(
    image_paths: List[str],
    analysis_type: str = "comprehensive",
    max_images: int = 10,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Analyze multiple images in batch for efficiency.
    
    Args:
        image_paths: List of image file paths
        analysis_type: Type of analysis to perform
        max_images: Maximum number of images to process
        use_cache: Whether to use caching
        
    Returns:
        Dict with batch analysis results
    """
    if not image_paths:
        return {
            "status": "error",
            "message": "No image paths provided"
        }
    
    # Limit number of images
    images_to_process = image_paths[:max_images]
    
    result = {
        "status": "success",
        "total_images": len(image_paths),
        "processed_images": len(images_to_process),
        "analysis_type": analysis_type,
        "results": {},
        "summary": {
            "successful": 0,
            "failed": 0,
            "total_text_extracted": 0,
            "total_objects_found": 0
        }
    }
    
    for i, image_path in enumerate(images_to_process):
        logger.info(f"Processing image {i+1}/{len(images_to_process)}: {image_path}")
        
        analysis_result = analyze_image(
            image_path=image_path,
            analysis_type=analysis_type,
            use_cache=use_cache
        )
        
        result["results"][image_path] = analysis_result
        
        if analysis_result.get("status") == "success":
            result["summary"]["successful"] += 1
            
            # Count insights
            insights = analysis_result.get("osint_insights", {})
            text_items = len(insights.get("identifiable_text", []))
            object_items = len(insights.get("technical_equipment", []))
            
            result["summary"]["total_text_extracted"] += text_items
            result["summary"]["total_objects_found"] += object_items
        else:
            result["summary"]["failed"] += 1
        
        # Add delay between images to avoid overwhelming the model
        if i < len(images_to_process) - 1:
            time.sleep(2)
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")