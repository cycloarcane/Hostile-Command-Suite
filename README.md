# Hostile Command Suite - OSINT Package

*Author:* **cycloarcane**  
*Contact:* [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)  
*License:* PolyForm Noncommercial License 1.0.0

**Intelligent Open Source Intelligence Investigation System**

A terminal-based OSINT investigation framework with AI-powered analysis and intelligent agent decision-making. Features automated profile scraping, multi-platform username investigation, and local LLM integration for enhanced intelligence gathering.

---

## 🚀 Quick Start

### Prerequisites

1. **Install ollama** (for AI analysis):
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen3:8b  # recommended model
```

2. **Install OSINT tools**:
```bash
# Arch Linux
yay -S sherlock-git mosint

# Ubuntu/Debian  
pip install sherlock-project
# For mosint, download from: https://github.com/alpkeskin/mosint
```

### Installation

```bash
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### Usage

**Interactive comprehensive investigation:**
```bash
python3 HCSO.py --interactive
# Then provide ALL target information: names, usernames, emails, addresses, etc.
```

**Command line investigation:**
```bash
# Single targets (backward compatibility)
python3 HCSO.py cycloarcane
python3 HCSO.py user@example.com

# Comprehensive targets (multiple data points)
python3 HCSO.py "John Smith, @johnsmith123, john@example.com, works at Acme Corp"
python3 HCSO.py --model llama3.2 "Jane Doe jane.doe@company.com https://linkedin.com/in/janedoe"
```

---

## 🛠️ Features

### Core Capabilities

- **🔍 Username Investigation**: Sherlock integration across 400+ social media platforms
- **📧 Email Investigation**: Mosint integration for email intelligence and breach analysis  
- **🌐 Profile Scraping**: Automated extraction of profile details from discovered accounts
- **🔍 Web Search Intelligence**: DuckDuckGo search integration for comprehensive OSINT gathering
- **🤖 AI Agent**: Local ollama integration for intelligent decision-making and analysis
- **⚡ Intelligent Workflow**: Automatic tool chaining and investigation pivoting
- **🎨 Rich Terminal**: Professional red/black themed interface with progress indicators

### Supported Targets

| Target Type | Primary Tool | Secondary Tools | AI Analysis |
|-------------|--------------|-----------------|-------------|
| **Username** | Sherlock → Profile Scraper | DuckDuckGo Search, Link Analyzer | ✅ Full Analysis |
| **Email** | Mosint | DuckDuckGo Search | ✅ Full Analysis |
| **Any Target** | DuckDuckGo Search | Context-dependent pivoting | ✅ Full Analysis |

### MCP Tool Architecture

The system uses Model Context Protocol (MCP) based tool servers:

- **`sherlock_server.py`**: Username investigation across platforms
- **`mosint_server.py`**: Email enumeration and breach investigation  
- **`profile_scraper_server.py`**: Intelligent profile content extraction
- **`duckduckgo_server.py`**: Web search for comprehensive intelligence gathering
- **`link_analyzer_server.py`**: Deep analysis of URLs and GitHub profiles

### AI-Powered Intelligence

The AI agent provides:
- **Comprehensive Data Extraction**: Uses LLM to parse and categorize all provided target information
- **Intelligent Tool Selection**: Automatically chooses appropriate tools based on data types:
  - **Names** → DuckDuckGo web search for public records and news
  - **Usernames** → Sherlock for social media platform discovery
  - **Emails** → Mosint for breach data and domain analysis
  - **Organizations** → Web search for corporate intelligence
  - **URLs** → Link analyzer for deep content analysis
- **Investigation Pivoting**: Discovers new leads and suggests follow-up actions
- **Security Risk Assessment**: Evaluates exposure levels and security implications
- **Pattern Recognition**: Identifies connections across platforms and data sources
- **Decision Making**: Determines when investigations are complete vs need continuation

---

## 🏗️ Architecture

### Intelligent Agent Design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HCSO Agent    │──▶│  Ollama AI       │───▶│ Investigation   │
│                 │    │  Decision Engine │    │ Recommendations │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ MCP Tool        │──▶│  Tool Results    │───▶│ Profile Scraper │
│ Manager         │    │  Analysis        │    │ Auto-Trigger    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Sherlock        │    │ Mosint           │    │ Profile         │
│ Username Search │    │ Email Intel      │    │ Scraper         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Investigation Workflow

1. **Comprehensive Input**: User provides ALL available target information (names, usernames, emails, addresses, organizations, URLs, etc.)
2. **AI Data Extraction**: LLM parses and categorizes information into structured data types
3. **Intelligent Tool Selection**: System automatically selects appropriate tools for each data type:
   - Names → Web search for public intelligence
   - Usernames → Social media platform discovery
   - Emails → Breach analysis and domain intelligence
   - Organizations → Corporate and public records search
   - URLs → Deep content and profile analysis
4. **Parallel Investigation**: Multiple tools execute simultaneously based on extracted data
5. **AI Analysis**: Intelligent analysis of all findings and cross-reference discovery
6. **Decision Point**: AI recommends additional investigations or marks complete
7. **Iterative Enhancement**: Follow-up investigations based on discovered leads

---

## 📊 Example Output

```
  ╔═════════════════════════════════════════════════════════════════════════╗
  ║  ██   ██ ███████ ██████         ███████ ███████  ██ ███    ██ ████████  ║
  ║  ██   ██ ██      ██             ██   ██ ██       ██ ████   ██    ██     ║
  ║  ███████ ███████ ██      █████  ██   ██ ███████  ██ ██ ██  ██    ██     ║
  ║  ██   ██      ██ ██             ██   ██      ██  ██ ██  ██ ██    ██     ║
  ║  ██   ██ ███████ ██████         ███████ ███████  ██ ██   ████    ██     ║
  ╚═════════════════════════════════════════════════════════════════════════╝

      Hostile Command Suite - OSINT Package
      Intelligent Open Source Intelligence Investigation System

  Using AI Model: qwen3:8b
  Available Tools: sherlock, mosint, profile_scraper, duckduckgo_search, link_analyzer

  ──────────────────────────────────────────────────────────────────────────────

  ═══ COMPREHENSIVE TARGET INFORMATION ═══
  Provide ALL available information about your target for intelligent analysis
  Include: names, usernames, emails, addresses, organizations, social profiles, etc.

  Enter ALL target information: John Smith, @johnsmith123, john.smith@techcorp.com, works at TechCorp

  Analyzing Provided Information
  ──────────────────────────────────────────────────────────────────────────────

   Extracted Target Intelligence 
  ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ Data Type      ┃ Extracted Values                                                  ┃
  ┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
  │ Names          │ John Smith                                                        │
  │ Usernames      │ johnsmith123                                                      │
  │ Emails         │ john.smith@techcorp.com                                           │
  │ Organizations  │ TechCorp                                                          │
  └────────────────┴───────────────────────────────────────────────────────────────────┘
  ────────────────────────────────────────────────────────────────

  Investigating Name: John Smith

   SHERLOCK Investigation Results 
  ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
  ┃ Metric         ┃ Value       ┃
  ┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
  │ Target         │ cycloarcane │
  │ Accounts Found │ 17          │
  │ Status         │ Success     │
  └────────────────┴─────────────┘
  ────────────────────────────────────────────────────────────

  Found 17 profiles, scraping for additional intelligence...
  PROFILE_SCRAPER Investigation Results
  ┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
  ┃ Metric           ┃ Value   ┃
  ┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
  │ Total Scraped    │ 5       │
  │ Successful       │ 4       │
  │ With Useful Info │ 4       │
  │ Status           │ Success │
  └──────────────────┴─────────┘
  ────────────────────────────────────────────────────────────

  AI Agent Analyzing...
  ╭─ AI Investigation Analysis ──────────────────────────────────────────────╮
  │ ANALYSIS: Investigation revealed GitHub profile with security research    │
  │ interests (LLMs + red team). High-value intelligence gathered from        │
  │ multiple platforms. Profile scraping provided sufficient context.        │
  │                                                                           │
  │ RECOMMENDATION: Investigation complete - sufficient intelligence gathered │
  │ TOOL: NONE                                                                │
  │ TARGET: N/A                                                               │
  │ REASONING: Profile analysis reveals technical expertise and security      │
  │ focus. No additional tools needed for current investigation scope.        │
  ╰───────────────────────────────────────────────────────────────────────────╯
```

---

## 🛡️ Security & Ethics

### Responsible Use

- **Legal Compliance**: All investigations must comply with applicable laws
- **Authorization**: Only investigate targets you have permission to research
- **Rate Limiting**: Respects platform rate limits and implements delays
- **Local Processing**: All AI analysis happens locally via ollama (no cloud)

### Privacy & Security

- **No Data Persistence**: Investigation results are not stored long-term
- **Local LLM**: AI analysis never leaves your machine
- **Tool Isolation**: Each OSINT tool runs independently
- **Professional Focus**: Designed for defensive security and legitimate research

---

## 🔧 Configuration

### AI Model Selection

```bash
# Use different ollama models
python3 HCSO.py --model llama3.2 target
python3 HCSO.py --model qwen3:8b target
python3 HCSO.py --model mixtral target
```

### Configurable Prompts

Agent behavior is configurable via YAML files:
- `prompts/agent_system.yaml`: Core agent instructions and tool selection logic
- `prompts/tool_prompts.yaml`: Tool-specific analysis templates

### Tool Capabilities

| Tool | Input | Capabilities | Auto-Trigger |
|------|--------|--------------|--------------|
| **DuckDuckGo Search** | Names, Organizations | Web intelligence, news, public records | Auto for names |
| **Sherlock** | Username | 400+ platform search | Auto for usernames |
| **Mosint** | Email | Breach data, domain intel | Auto for emails |
| **Link Analyzer** | URLs | GitHub profiles, web content analysis | Auto for URLs |
| **Profile Scraper** | URLs | Bio, followers, verification | After Sherlock |

---

## 🚧 Development

### Adding New OSINT Tools

1. Create MCP server in `mcp_tools/new_tool_server.py`
2. Add tool detection in `MCPToolManager.check_available_tools()`
3. Implement tool calling in `MCPToolManager.call_tool()`
4. Add result display in `display_investigation_result()`
5. Update agent prompts for tool selection logic

### Architecture Benefits

**Previous Complex Architecture:**
- 15+ microservices with FastMCP
- PostgreSQL database requirement
- Web UI and API complexity
- Multiple authentication layers

**Current Intelligent Agent Architecture:**
- Single intelligent agent with MCP tools
- No database required
- Pure terminal interface with AI
- Local ollama for decision-making
- Automatic tool chaining and pivoting

---

## 📈 Roadmap

### Phase 1: Core Intelligence ✅
- [x] Sherlock username investigation with AI analysis
- [x] Mosint email investigation with AI analysis
- [x] Intelligent profile scraping from social media
- [x] AI-powered investigation decision making
- [x] MCP-based tool architecture

### Phase 2: Enhanced Analysis 🚧
- [ ] Link analyzer for deep GitHub/social media analysis
- [ ] Domain investigation capabilities
- [ ] Phone number OSINT integration
- [ ] Correlation analysis across findings

### Phase 3: Advanced Intelligence 📋
- [ ] Investigation session management
- [ ] Custom tool integration framework
- [ ] Automated investigation workflows
- [ ] Advanced AI reasoning and pivoting

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Add your MCP tool server following existing patterns
4. Update agent prompts for tool integration
5. Test with various target types
6. Submit a pull request

### Development Setup

```bash
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 HCSO.py --interactive
```

---

## 📄 License

This project is licensed under the PolyForm Noncommercial License 1.0.0 - see the LICENSE file for details.

Copyright © cycloarcane (cycloarkane@gmail.com)

---

**Intelligent. Terminal. Effective.**

*Advanced OSINT investigation with AI-powered decision making*

*For questions or feature requests, contact [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)*