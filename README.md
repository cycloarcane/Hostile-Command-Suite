```
██   ██  ██████ ███████ 
██   ██ ██      ██      
███████ ██      ███████ 
██   ██ ██           ██ 
██   ██  ██████ ███████ 
                        
                        
```

# Hostile‑Command‑Suite

*Author:* **cycloarcane**  
*Contact:* [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)  
*License:* PolyForm Noncommercial License 1.0.0

**A comprehensive OSINT and penetration testing toolkit built as FastMCP micro-services**

---

## 🔥 Quick‑start

### One-command install (Arch Linux)

```bash
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
chmod +x install_hcs.sh
./install_hcs.sh          # grab coffee ☕
source .venv/bin/activate
```

### Manual Install

```bash
# 1. Clone + create virtualenv
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
python -m venv .venv && source .venv/bin/activate && pip install --upgrade pip

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install system tools (Arch Linux)
yay -S spiderfoot recon-ng phoneinfoga-bin mosint holehe sherlock-git nmap

# 4. Initialize database (optional)
bash scripts/database_init.sh

# 5. Configure API keys (see API Keys section below)
```

---

## 🛠️ Available Tools

### OSINT Tools

| Tool | Description | Status | API Keys Required |
|------|-------------|---------|-------------------|
| **`database_osint.py`** | PostgreSQL storage for OSINT results | ✅ | PostgreSQL credentials |
| **`email_osint.py`** | Email OSINT (Mosint + Holehe + h8mail) | ✅ | Mosint config file |
| **`username_osint.py`** | Username search across platforms (Sherlock) | ✅ | None |
| **`phone_osint.py`** | Phone number intelligence (PhoneInfoga) | ✅ | None |
| **`google_osint.py`** | Google Custom Search with relevance scoring | ✅ | Google API + Search Engine ID |
| **`duckduckgo_osint.py`** | DuckDuckGo search with rate-limit resistance | ✅ | None |
| **`shodan_osint.py`** | IoT/device discovery and analysis | ✅ | Shodan API key |
| **`domain_osint.py`** | Domain and DNS reconnaissance | ✅ | Censys API (optional) |
| **`certificate_osint.py`** | SSL/TLS certificate analysis + CT monitoring | ✅ | Censys API (optional) |
| **`geolocation_osint.py`** | IP geolocation and geographical intelligence | ✅ | IPInfo API (optional) |
| **`social_osint.py`** | Social media intelligence gathering | ✅ | Multiple APIs (optional) |
| **`crypto_osint.py`** | Cryptocurrency address analysis | ✅ | Multiple APIs (optional) |
| **`breach_osint.py`** | Data breach and password compromise checking | ✅ | HIBP API (optional) |
| **`metadata_osint.py`** | File and image metadata extraction | ✅ | None |
| **`link_follower_osint.py`** | Web page content fetcher and parser | ✅ | None |
| **`tiktok_osint.py`** | TikTok comment and user analysis | ✅ | None |

### PEN-TEST Tools

| Tool | Description | Status | Requirements |
|------|-------------|---------|--------------|
| **`nmap_ptest.py`** | Network scanning and port discovery | ✅ | Nmap installed |

---

## 🔑 API Keys & Configuration

### Required API Keys

**Essential for core functionality:**

```bash
# Database (Required for data storage)
export POSTGRES_DB=osint_db
export POSTGRES_USER=osint_user
export POSTGRES_PASSWORD=your_secure_password
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432

# Google Search API (Required for google_osint.py)
export GOOGLE_SEARCH_API_KEY=your_google_api_key
export GOOGLE_SEARCH_CX=your_search_engine_id

# Shodan API (Required for shodan_osint.py)
export SHODAN_API_KEY=your_shodan_api_key
```

### Optional API Keys (Enhance functionality)

```bash
# Certificate/Domain Analysis
export CENSYS_API_ID=your_censys_id
export CENSYS_API_SECRET=your_censys_secret

# Geolocation
export IPINFO_API_KEY=your_ipinfo_key
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

# Social Media Intelligence
export TWITTER_BEARER_TOKEN=your_twitter_token
export REDDIT_CLIENT_ID=your_reddit_id
export REDDIT_CLIENT_SECRET=your_reddit_secret
export GITHUB_TOKEN=your_github_token

# Cryptocurrency Analysis
export BLOCKCYPHER_API_KEY=your_blockcypher_key
export BLOCKCHAIN_INFO_API_KEY=your_blockchain_info_key
export OXT_API_KEY=your_oxt_key

# Breach Analysis
export HIBP_API_KEY=your_hibp_key
export DEHASHED_API_KEY=your_dehashed_key
```

### Configuration Files

**Mosint** (`~/.mosint.yaml`):
```yaml
apikeys:
  dehashed: "your_dehashed_api_key"
  emailrep: "your_emailrep_key"
  hunter: "your_hunter_key"
  intelx: "your_intelx_key"
  twitter:
    consumer_key: "your_twitter_consumer_key"
    consumer_secret: "your_twitter_consumer_secret"
    bearer_token: "your_twitter_bearer_token"
```

**Complete configuration details:** See `needed_variables.md`

---

## 🚀 Usage Examples

### As MCP Services (Claude Desktop/API)

Add to your Claude Desktop config or MCP client:

```json
{
  "mcpServers": {
    "email": {
      "command": ".venv/bin/python",
      "args": ["-u", "OSINT/email_osint.py"]
    },
    "shodan": {
      "command": ".venv/bin/python", 
      "args": ["-u", "OSINT/shodan_osint.py"]
    }
  }
}
```

### Direct Command Line

```bash
# Email OSINT
python OSINT/email_osint.py

# Network reconnaissance  
python OSINT/shodan_osint.py

# Social media intelligence
python OSINT/social_osint.py

# Certificate analysis
python OSINT/certificate_osint.py
```

### Comprehensive Investigation Workflow

```bash
# 1. Start with email analysis
echo '{"method":"search_email_all","params":["target@example.com"]}' | python OSINT/email_osint.py

# 2. Username enumeration
echo '{"method":"search_username","params":["targetuser"]}' | python OSINT/username_osint.py

# 3. Domain reconnaissance
echo '{"method":"domain_intelligence","params":["example.com"]}' | python OSINT/domain_osint.py

# 4. Social media intelligence
echo '{"method":"comprehensive_social_analysis","params":["targetuser"]}' | python OSINT/social_osint.py

# 5. Store results in database
echo '{"method":"store_osint_data","params":["email","target@example.com","investigation","manual","findings",{"data":"results"}]}' | python OSINT/database_osint.py
```

---

## 🏗️ Architecture

### Micro-service Design
Each tool is a standalone FastMCP service that can be:
- Used independently via command line
- Integrated with Claude Desktop/API
- Chained together for complex investigations
- Stored and retrieved via the database service

### Data Flow
```
Target Input → OSINT Tools → Database Storage → Analysis & Reporting
     ↓              ↓              ↓              ↓
  • Email       • Email OSINT   • PostgreSQL   • Risk Analysis
  • Username    • Social OSINT  • JSON Store   • Timeline
  • Domain      • Domain OSINT  • Metadata     • Correlation
  • IP Address  • Breach Check  • Cache        • Export
```

---

## 🎯 Tool Capabilities

### Email Intelligence (`email_osint.py`)
- **Breach Detection:** Mosint integration for comprehensive breach data
- **Account Discovery:** Holehe for social media account enumeration  
- **Password Analysis:** h8mail for credential exposure
- **Multi-source:** Aggregates data from multiple OSINT sources

### Username Intelligence (`username_osint.py`)
- **Platform Coverage:** 400+ social media platforms via Sherlock
- **Account Verification:** Live verification of profile existence
- **Bulk Processing:** Efficient multi-username analysis

### Phone Intelligence (`phone_osint.py`)
- **Carrier Information:** PhoneInfoga integration
- **Geographic Data:** Location and region analysis
- **Web Presence:** Automated web search for phone mentions
- **Concurrent Processing:** Fast multi-source data gathering

### Domain Intelligence (`domain_osint.py`)
- **WHOIS Analysis:** Comprehensive domain registration data
- **DNS Enumeration:** A, AAAA, MX, NS, TXT, CNAME records
- **Subdomain Discovery:** Active and passive subdomain enumeration
- **Certificate Transparency:** SSL certificate history via CT logs

### Certificate Intelligence (`certificate_osint.py`)
- **CT Log Monitoring:** Real-time certificate transparency analysis
- **SSL Analysis:** Comprehensive certificate security assessment
- **Subdomain Discovery:** Certificate-based subdomain enumeration
- **Change Detection:** Monitor for new certificate issuances

### Social Intelligence (`social_osint.py`)
- **Multi-platform:** GitHub, Twitter, Reddit, Instagram, LinkedIn
- **Profile Analysis:** Automated data extraction and correlation
- **Connection Mapping:** Social network relationship analysis
- **Activity Timeline:** Historical activity pattern analysis

### Cryptocurrency Intelligence (`crypto_osint.py`)
- **Address Analysis:** Bitcoin and Ethereum address investigation
- **Transaction Tracing:** Money flow analysis and visualization
- **Risk Assessment:** Sanctions screening and risk scoring
- **Blockchain Data:** Real-time and historical transaction data

### Search Intelligence (`google_osint.py` + `duckduckgo_osint.py`)
- **Relevance Scoring:** AI-powered result ranking
- **Rate Limit Bypass:** Advanced techniques for sustained searching
- **Caching System:** Efficient result storage and retrieval
- **Boolean Operators:** Advanced search query construction

---

## 🔧 Development

### Adding New Tools

1. **Create new tool:** `OSINT/newtool_osint.py`
2. **Inherit from FastMCP:** Use the established pattern
3. **Add to config:** Update `config.json`
4. **Document:** Update README and create usage examples

### Tool Template

```python
#!/usr/bin/env python3
from fastmcp import FastMCP

mcp = FastMCP("newtool")

@mcp.tool()
def your_function(param: str) -> dict:
    return {"status": "success", "data": param}

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

---

## 🛡️ Security & Ethics

### Responsible Use
- **Legal Compliance:** Ensure all activities comply with local laws
- **Rate Limiting:** Respect API limits and website ToS
- **Data Protection:** Secure storage of collected intelligence
- **Permission:** Only investigate targets you have authorization for

### Privacy Considerations
- **Data Minimization:** Collect only necessary information
- **Secure Storage:** Use encrypted databases in production
- **Access Control:** Implement proper authentication
- **Audit Logging:** Track all investigative activities

---

## 🗂️ Repository Structure

```
Hostile-Command-Suite/
├── OSINT/                     # OSINT micro-services
│   ├── breach_osint.py        # Data breach checking (HIBP)
│   ├── certificate_osint.py   # SSL/TLS certificate analysis
│   ├── crypto_osint.py        # Cryptocurrency intelligence
│   ├── database_osint.py      # PostgreSQL data storage
│   ├── domain_osint.py        # Domain reconnaissance
│   ├── duckduckgo_osint.py    # DuckDuckGo search engine
│   ├── email_osint.py         # Email intelligence (Mosint/Holehe)
│   ├── geolocation_osint.py   # IP geolocation intelligence
│   ├── google_osint.py        # Google Custom Search
│   ├── link_follower_osint.py # Web content analysis
│   ├── metadata_osint.py      # File metadata extraction
│   ├── phone_osint.py         # Phone number intelligence
│   ├── shodan_osint.py        # IoT/device discovery
│   ├── social_osint.py        # Social media intelligence
│   ├── tiktok_osint.py        # TikTok analysis
│   └── username_osint.py      # Username enumeration
├── PEN-TEST/                  # Penetration testing tools
│   └── nmap_ptest.py          # Network scanning
├── scripts/                   # Setup and utility scripts
│   └── database_init.sh       # Database initialization
├── knowledge_base/            # Documentation and references
├── config.json                # MCP server configuration
├── requirements.txt           # Python dependencies
├── install_hcs.sh             # Automated installer
├── needed_variables.md        # Complete API key guide
└── README.md                  # This file
```

---

## 🤝 Contributing

1. **Fork** → hack → **pull request**
2. Follow [`pre-commit`](https://pre-commit.com/) standards (`black`, `isort`, `flake8`)
3. Add tests in `tests/` for new functionality
4. **Sign commits:** `git commit -s`
5. **Documentation:** Update README for new tools

**Bug reports or feature ideas?** Open an issue or email [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)

---

## 🗺️ Roadmap

### Phase 1: Core OSINT (✅ Complete)
- [x] Email intelligence (Mosint, Holehe, h8mail)
- [x] Username enumeration (Sherlock)
- [x] Phone number analysis (PhoneInfoga)
- [x] Search engines (Google, DuckDuckGo)
- [x] Database storage (PostgreSQL)

### Phase 2: Advanced Intelligence (✅ Complete)
- [x] Domain reconnaissance and DNS analysis
- [x] Certificate transparency monitoring
- [x] IP geolocation and network intelligence
- [x] Social media analysis and profiling
- [x] Cryptocurrency address analysis
- [x] Data breach and password compromise checking
- [x] File and image metadata extraction

### Phase 3: Automation & Integration (🚧 In Progress)
- [ ] Automated investigation workflows
- [ ] Cross-tool data correlation
- [ ] Timeline analysis and visualization
- [ ] Report generation (PDF/HTML)
- [ ] REST API wrapper
- [ ] Web dashboard interface

### Phase 4: Advanced Features (📋 Planned)
- [ ] Machine learning for pattern recognition
- [ ] Dark web monitoring capabilities
- [ ] Threat intelligence feed integration
- [ ] Mobile app analysis tools
- [ ] Container-based deployment (Docker)
- [ ] Distributed scanning capabilities

---

## 📊 Statistics

- **15 OSINT Tools** across multiple intelligence domains
- **1 PEN-TEST Tool** for network reconnaissance  
- **25+ API Integrations** for comprehensive data gathering
- **PostgreSQL Storage** for persistent investigation data
- **FastMCP Architecture** for modular, scalable design

---

**Weaponise knowledge** — *ethically, of course.*

*For questions, feature requests, or commercial licensing inquiries, contact [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)*