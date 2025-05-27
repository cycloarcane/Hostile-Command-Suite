# Hostile-Command-Suite: Comprehensive Project Summary

**Author:** cycloarcane  
**License:** PolyForm Noncommercial License 1.0.0  
**Architecture:** FastMCP microservices for OSINT and penetration testing

## Project Architecture

### Core Design
- **Microservice Architecture:** Each tool is a standalone FastMCP service
- **Database Integration:** PostgreSQL for persistent OSINT data storage
- **Caching System:** File-based caching for API responses
- **Rate Limiting:** Built-in respect for API limits
- **Claude Integration:** Native MCP support for Claude Desktop/API

### Technology Stack
- **Backend:** Python 3.8+ with FastMCP framework
- **Database:** PostgreSQL with psycopg2
- **APIs:** 25+ external API integrations
- **Local AI:** Ollama integration for image analysis
- **Caching:** JSON file-based with configurable TTL

## Complete Tool Inventory

### 1. Email Intelligence (`email_osint.py`)
**Capabilities:**
- `search_email_mosint(email)` - Comprehensive email breach analysis via Mosint
- `search_email_holehe(email)` - Social media account discovery via Holehe  
- `search_email_h8mail(email)` - Password breach checking via h8mail
- `search_email_all(email)` - Aggregated analysis from all sources
- `check_tools_installation()` - Verify tool availability

**Data Sources:** Mosint (breach data), Holehe (social accounts), h8mail (credentials)
**Requirements:** Mosint config file (`~/.mosint.yaml`), tools installed via pacman/pip

### 2. Username Intelligence (`username_osint.py`)
**Capabilities:**
- `search_username(username)` - Search across 400+ platforms via Sherlock
- `check_sherlock_installation()` - Verify Sherlock availability

**Data Sources:** Sherlock project database
**Requirements:** `pip install sherlock-project`

### 3. Phone Intelligence (`phone_osint.py`)
**Capabilities:**
- `scan_phone_phoneinfoga(number)` - Phone number analysis with web search
- `scan_phone_all(number)` - Comprehensive phone intelligence
- `check_tools_installation()` - Tool verification

**Data Sources:** PhoneInfoga, web search results
**Requirements:** `yay -S phoneinfoga-bin` (Arch Linux)

### 4. Search Intelligence
#### Google Search (`google_osint.py`)
**Capabilities:**
- `search_google_text(query, max_results=50)` - Google Custom Search with pagination
- `search_with_relevance(query, relevance_keywords)` - AI-powered relevance scoring
- **Advanced Features:** Boolean search, caching, rate limiting, result ranking

**Requirements:** Google Custom Search API key + Search Engine ID

#### DuckDuckGo Search (`duckduckgo_osint.py`)
**Capabilities:**
- `search_duckduckgo_text(query, max_results=20)` - Rate-limit resistant DDG search
- `search_with_relevance(query, relevance_keywords)` - Relevance-scored results
- **Advanced Features:** Direct HTTP requests, boolean operators, proxy support

**Requirements:** None (bypasses API limitations)

### 5. Domain Intelligence (`domain_osint.py`)
**Capabilities:**
- `whois_lookup(domain)` - Comprehensive WHOIS analysis
- `dns_enumeration(domain, record_types)` - DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME)
- `subdomain_enumeration(domain, wordlist)` - Active subdomain discovery
- `censys_domain_search(domain)` - Censys certificate/host search
- `domain_intelligence(domain)` - Comprehensive domain analysis

**Data Sources:** WHOIS databases, DNS resolvers, Censys API
**Requirements:** `pip install dnspython python-whois`, Censys API (optional)

### 6. Certificate Intelligence (`certificate_osint.py`)
**Capabilities:**
- `search_certificate_transparency(domain)` - CT log analysis for certificate discovery
- `analyze_ssl_certificate(hostname, port=443)` - Live SSL certificate analysis
- `find_subdomains_from_certificates(domain)` - Certificate-based subdomain discovery
- `monitor_certificate_changes(domain, days_lookback=30)` - Certificate change monitoring

**Data Sources:** Certificate Transparency logs (crt.sh), Censys certificates, live SSL connections
**Requirements:** `pip install requests cryptography`, Censys API (optional)

### 7. Network/IoT Intelligence (`shodan_osint.py`)
**Capabilities:**
- `search_shodan(query, max_results=100)` - IoT/device discovery
- `get_host_info(ip_address)` - Detailed host analysis
- `search_facets(query, facets)` - Faceted search for data distribution analysis
- `get_my_ip()` - Public IP detection

**Data Sources:** Shodan Internet-wide scanning data
**Requirements:** Shodan API key

### 8. Geolocation Intelligence (`geolocation_osint.py`)
**Capabilities:**
- `geolocate_ip(ip_address)` - Multi-source IP geolocation
- `bulk_geolocate(ip_addresses)` - Batch IP processing
- `reverse_geo_lookup(latitude, longitude)` - Coordinates to location
- `trace_route_geo(target)` - Traceroute with geolocation
- `get_my_location()` - Current public IP geolocation

**Data Sources:** MaxMind GeoIP2, IPInfo.io, ip-api.com, ipapi.co, OpenStreetMap Nominatim
**Requirements:** MaxMind GeoLite2 database (optional), IPInfo API key (optional)

### 9. Social Media Intelligence (`social_osint.py`)
**Capabilities:**
- `search_social_profiles(username, platforms)` - Multi-platform profile discovery
- `analyze_github_profile(username)` - Detailed GitHub analysis with repositories
- `find_social_connections(username, platform)` - Social network mapping
- `comprehensive_social_analysis(target)` - Complete social footprint analysis

**Data Sources:** GitHub API, Twitter API, Reddit API, web scraping
**Requirements:** Various API keys (optional but recommended)

### 10. Cryptocurrency Intelligence (`crypto_osint.py`)
**Capabilities:**
- `analyze_bitcoin_address(address)` - Bitcoin address analysis with risk scoring
- `analyze_ethereum_address(address)` - Ethereum address analysis
- `check_crypto_sanctions(address)` - Sanctions list checking
- `trace_bitcoin_transactions(txid, depth=1)` - Transaction flow analysis
- `crypto_intelligence_summary(addresses)` - Multi-address analysis

**Data Sources:** Blockchain.info, BlockCypher, Etherscan, various crypto APIs
**Requirements:** Various crypto API keys (optional)

### 11. Data Breach Intelligence (`breach_osint.py`)
**Capabilities:**
- `check_hibp_breaches(email)` - Have I Been Pwned breach checking
- `check_hibp_pastes(email)` - Paste site monitoring
- `check_password_pwned(password)` - Password compromise checking (k-anonymity)
- `comprehensive_breach_check(email)` - Complete breach analysis
- `check_domain_breaches(domain)` - Domain-wide breach analysis

**Data Sources:** Have I Been Pwned, DeHashed (optional)
**Requirements:** HIBP API key (recommended), DeHashed API key (optional)

### 12. File/Image Intelligence
#### Metadata Analysis (`metadata_osint.py`)
**Capabilities:**
- `extract_image_metadata(file_path)` - EXIF data extraction with privacy risk analysis
- `extract_document_metadata(file_path)` - PDF/Office document metadata
- `extract_metadata_from_url(url)` - Remote file metadata extraction
- `search_files_by_metadata(directory, criteria)` - Metadata-based file search

**Data Sources:** EXIF data, document properties, ExifTool
**Requirements:** `pip install pillow exifread PyPDF2 python-docx`, ExifTool

#### Image Analysis (`image_analysis_osint.py`)
**Capabilities:**
- `analyze_image(image_path, analysis_type)` - Comprehensive image analysis via local VLLM
- `extract_text_from_image(image_path)` - OCR and text extraction
- `geolocate_image(image_path)` - Geographic location analysis
- `detect_surveillance_equipment(image_path)` - Security equipment detection
- `batch_analyze_images(image_paths)` - Bulk image processing

**Data Sources:** Ollama + Qwen2-VL local vision model
**Requirements:** Ollama installed, `ollama pull qwen2-vl`

### 13. UK-Specific Intelligence
#### Vehicle Intelligence (`dvla_vehicle_osint.py`)
**Capabilities:**
- `get_vehicle_details(registration)` - DVLA vehicle enquiry service
- `get_mot_history(registration)` - DVSA MOT test history
- `comprehensive_vehicle_check(registration)` - Complete vehicle intelligence

**Data Sources:** DVLA Vehicle Enquiry Service, DVSA MOT History API
**Requirements:** DVLA VES API key, DVSA MOT API credentials

#### Company Intelligence (`companies_house_osint.py`)
**Capabilities:**
- `search_companies(query)` - Company name/number search
- `get_company_profile(company_number)` - Detailed company information
- `get_company_officers(company_number)` - Director and officer data
- `get_company_filings(company_number)` - Filing history analysis
- `comprehensive_company_check(company_number)` - Complete company intelligence

**Data Sources:** UK Companies House API
**Requirements:** Companies House API key (free)

### 14. Web Intelligence (`link_follower_osint.py`)
**Capabilities:**
- `fetch_url(url)` - Web page content extraction with metadata
- `fetch_multiple_urls(urls)` - Batch URL processing
- **Features:** Content parsing, link extraction, metadata analysis

**Requirements:** `pip install requests beautifulsoup4`

### 15. TikTok Intelligence (`tiktok_osint.py`)
**Capabilities:**
- `get_user_comments(username, target_username)` - Comment analysis
- `search_comments_by_keyword(username, keyword)` - Keyword-based comment search
- `check_tiktok_installation()` - Verify TikTok API availability

**Data Sources:** Unofficial TikTok API
**Requirements:** `pip install TikTokApi`, `python -m playwright install`

### 16. Database Storage (`database_osint.py`)
**Capabilities:**
- `store_osint_data(target_type, target_value, source_name, data_type, data_value)` - Store investigation data
- `get_osint_data_by_target(target_type, target_value)` - Retrieve stored data
- `get_osint_data_by_id(data_id)` - Get specific data entry
- `update_osint_data_verification(data_id, verified)` - Mark data as verified
- `list_all_targets()` - Get all investigation targets
- `comprehensive database management` - Full CRUD operations

**Storage:** PostgreSQL with structured tables for targets, sources, and data
**Requirements:** PostgreSQL server, psycopg2-binary

### 17. Penetration Testing (`nmap_ptest.py`)
**Capabilities:**
- `scan_target(target, scan_type, ports)` - Network scanning with various modes
- `scan_network(network, scan_speed, top_ports)` - Network-wide scanning
- `check_nmap_installation()` - Tool verification

**Data Sources:** Nmap network scanning
**Requirements:** Nmap installed

## API Requirements & Configuration

### Essential APIs
```bash
# Database (Required)
POSTGRES_DB=osint_db
POSTGRES_USER=osint_user  
POSTGRES_PASSWORD=secure_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# Google Search (Required for google_osint.py)
GOOGLE_SEARCH_API_KEY=your_api_key
GOOGLE_SEARCH_CX=your_search_engine_id

# Shodan (Required for shodan_osint.py)
SHODAN_API_KEY=your_shodan_key
```

### Optional Enhancement APIs
```bash
# UK Government APIs
DVLA_VES_API_KEY=your_dvla_key
DVSA_MOT_CLIENT_ID=your_dvsa_id
DVSA_MOT_CLIENT_SECRET=your_dvsa_secret
COMPANIES_HOUSE_API_KEY=your_ch_key

# Certificate/Network Analysis
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# Geolocation Enhancement
IPINFO_API_KEY=your_ipinfo_key
GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

# Social Media APIs
TWITTER_BEARER_TOKEN=your_twitter_token
GITHUB_TOKEN=your_github_token
REDDIT_CLIENT_ID=your_reddit_id

# Breach/Crypto Analysis
HIBP_API_KEY=your_hibp_key
BLOCKCYPHER_API_KEY=your_crypto_key

# Image Analysis
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2-vl
```

## Usage Patterns

### 1. Comprehensive Email Investigation
```python
# Step 1: Email analysis
email_results = search_email_all("target@example.com")

# Step 2: Username enumeration from email
username_results = search_username("target")

# Step 3: Social media analysis
social_results = comprehensive_social_analysis("target")

# Step 4: Store results
store_osint_data("email", "target@example.com", "investigation", 
                 "manual", "email_osint", email_results)
```

### 2. Domain Infrastructure Analysis
```python
# Complete domain analysis
domain_intel = domain_intelligence("example.com", 
                                   include_subdomains=True,
                                   include_censys=True)

# Certificate transparency monitoring
cert_analysis = search_certificate_transparency("example.com")

# Network device discovery
shodan_results = search_shodan("ssl:example.com")
```

### 3. UK Entity Investigation
```python
# Vehicle intelligence
vehicle_check = comprehensive_vehicle_check("AB12CDE")

# Company intelligence  
company_check = comprehensive_company_check("12345678")

# Cross-reference findings
store_osint_data("uk_entity", "target_entity", "investigation",
                 "manual", "uk_osint", {
                     "vehicle": vehicle_check,
                     "company": company_check
                 })
```

## Key Features

### Intelligence Capabilities
- **Multi-Source Aggregation:** Combines data from 25+ sources
- **Risk Analysis:** Built-in risk scoring for addresses, companies, vehicles
- **Timeline Analysis:** Temporal correlation of findings
- **Geographic Intelligence:** Location-based analysis and correlation
- **Social Network Mapping:** Relationship and connection analysis

### Technical Features
- **Rate Limiting:** Respectful API usage with configurable limits
- **Caching System:** Efficient result storage with TTL
- **Error Handling:** Graceful degradation and fallback methods
- **Concurrent Processing:** Bulk operations with threading
- **Data Validation:** Input sanitization and format verification

### Security Features
- **Privacy Protection:** k-anonymity for password checking
- **Sanctions Screening:** Cryptocurrency address compliance checking
- **Data Encryption:** Secure storage of sensitive investigation data
- **Access Logging:** Audit trail for all operations
- **Rate Limiting:** Protection against service abuse

### Integration Features
- **Claude MCP:** Native integration with Claude Desktop/API
- **REST API:** HTTP interface for external integrations
- **CLI Interface:** Command-line operation for automation
- **Database Storage:** Persistent investigation case management
- **Export Capabilities:** Multiple output formats (JSON, CSV, PDF)

## Data Flow Architecture

```
Input → Validation → API Calls → Data Processing → Risk Analysis → Storage → Reporting
  ↓         ↓           ↓            ↓              ↓           ↓         ↓
Email   → Format    → Multiple   → Aggregation  → Scoring   → PostgreSQL → JSON/CSV
Domain  → Validate  → Sources    → Correlation  → Analysis  → Cache      → Reports  
IP      → Sanitize  → APIs       → Enhancement  → Timeline  → Files      → Alerts
```

## Statistics Summary
- **17 OSINT Tools** across multiple intelligence domains
- **1 Penetration Testing Tool** for network reconnaissance
- **25+ API Integrations** for comprehensive data gathering
- **PostgreSQL Storage** for persistent investigation data
- **FastMCP Architecture** for modular, scalable design
- **Local AI Integration** for image analysis capabilities
- **UK Government APIs** for vehicle and company intelligence
- **Multi-cryptocurrency Support** for blockchain analysis
- **Professional Risk Scoring** across all analysis types

This comprehensive toolkit provides end-to-end OSINT capabilities with professional-grade features for intelligence gathering, analysis, and case management across multiple domains and data sources.