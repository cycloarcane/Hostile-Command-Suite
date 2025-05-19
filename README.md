```
██╗  ██╗ ██████╗███████╗
██║  ██║██╔════╝██╔════╝
███████║██║     ███████╗
██╔══██║██║     ╚════██║
██║  ██║╚██████╗███████║
╚═╝  ╚═╝ ╚═════╝╚══════╝
```

# Hostile‑Command‑Suite

*Author:* **cycloarcane**
*Contact:* [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)
*License:* PolyForm Noncommercial License 1.0.0

---

## Repo Layout

```
Hostile-Command-Suite/
├── OSINT/                 # OSINT micro‑services + config
│   ├── database_osint.py  # PostgreSQL storage for OSINT results
│   ├── duckduckgo_osint.py # DuckDuckGo search wrapper
│   ├── email_osint.py     # Mosint / Holehe / h8mail aggregator
│   ├── google_osint.py    # Google Custom Search API wrapper
│   ├── link_follower_osint.py # Web page content fetcher and parser
│   ├── phone_osint.py     # PhoneInfoga wrapper
│   ├── tiktok_osint.py    # TikTok API unofficial wrapper
│   └── username_osint.py  # Sherlock wrapper
├── PEN-TEST/              # Penetration testing tools
│   └── nmap_ptest.py      # Network scanning using Nmap
├── scripts/               # Helper scripts for setup and management
│   └── database_init.sh   # Initialize PostgreSQL database
├── config.json            # MCP server configuration
├── install_hcs.sh         # Installer script
└── README.md              # you are here
```

---

## Quick‑start

*For email_osint you need to make a .mosint.yaml file in your home directory with mosint's config (see [Mosint docs](https://github.com/alpkeskin/mosint)).*

### 🔥 One-command install

If you just want everything set up in one go, clone the repo and run the bundling script:

```bash
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
chmod +x install_hcs.sh   # already in the repo root
./install_hcs.sh          # grab coffee ☕
```

`install_hcs.sh` will:

1. Update the system and install core build/runtime packages.
2. Install **yay** if missing, then pull every AUR tool HCS needs.
4. Set up a project-local Python virtualenv with all pip dependencies.
5. Clone **GHunt** and install its requirements.

```bash
source .venv/bin/activate
```

You're now ready to launch any MCP wrapper (e.g. `python OSINT/email_osint.py`) or plug the suite straight into your chatbot.

### Manual Install

```bash
# 0. Arch prerequisites (base + yay assumed)

# 1. Clone + create virtualenv
 git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
 cd Hostile-Command-Suite
 python -m venv .venv && source .venv/bin/activate && pip install --upgrade pip

# 3. Grab toolchain (AUR helpers shown; swap for paru/pikaur if you like)
 yay -S spiderfoot recon-ng-git phoneinfoga-bin h8mail mosint holehe sherlock-git osintgram twint
 pip install h8mail instaloader social-analyzer
 git clone https://github.com/mxrch/GHunt ~/GHunt && pip install -r ~/GHunt/requirements.txt

# 5. Launch a tool (stdin JSON‑RPC)
echo '{"method":"mosint","params":["alice@example.com"]}' | \
      .venv/bin/python OSINT/email_osint.py
```

---

## API‑Key Matrix

| Tool                | Key **required** to run? | Key file / env var                        | What you miss without it |
| ------------------- | ------------------------ | ----------------------------------------- | ------------------------ |
| **Twint**           | No                       | —                                         | Nothing; full scrape     |
| **SpiderFoot**      | Optional per‑module      | `~/.spiderfoot.conf`                      | Extra data sources       |
| **Recon‑ng**        | Optional per‑module      | `keys add <module> <key>`                 | Extra data modules       |
| **PhoneInfoga**     | Optional                 | `~/.config/phoneinfoga/config.yaml`       | Carrier & spam enrich    |
| **theHarvester**    | Optional                 | `~/.theHarvester/api-keys.yaml`           | Bing/Hunter results      |
| **Mosint**          | **Yes** (full run)       | `~/.mosint.yaml`                          | Breach/social lookups    |
| **Holehe**          | No                       | —                                         | —                        |
| **h8mail**          | Optional                 | `h8mail_config.ini` or `-k` env           | Deep breach content      |
| **Sherlock**        | No                       | —                                         | —                        |
| **Social‑Analyzer** | Optional                 | `--google_key` / REST settings endpoint   | OCR + AI ranking         |
| **Instaloader**     | No                       | Instagram login only for private profiles | —                        |
| **Osintgram**       | IG creds (no API key)    | `credentials.ini`                         | Needs login at all       |
| **GHunt**           | Google cookies           | `config` file with SID, LSID, HSID        | Script won't run         |
| **Google Search**   | **Yes**                  | `GOOGLE_SEARCH_API_KEY`, `GOOGLE_SEARCH_CX` | Entire functionality   |
| **Database**        | **Yes**                  | `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Storage functionality |
| **TikTok API**      | Optional                 | `ms_token` parameter                      | Authentication bypass    |

> **Tip:** keep secrets in 600‑perm dot‑files or systemd `LoadCredential=` so wrappers never embed them in code. See `needed_variables.md` for complete setup instructions.

---

## Implemented vs TODO

| Wrapper script       | Status                                           |
| -------------------- | ------------------------------------------------ |
| `database_osint.py`  | ✅ ready (PostgreSQL storage for OSINT results)   |
| `duckduckgo_osint.py`| ✅ ready (DuckDuckGo search with rate-limiting resistance) |
| `email_osint.py`     | ✅ ready (Mosint + Holehe + h8mail)               |
| `google_osint.py`    | ✅ ready (Google Custom Search with relevance scoring) |
| `link_follower_osint.py` | ✅ ready (Web page content fetcher and parser) |
| `phone_osint.py`     | ✅ ready (PhoneInfoga)                            |
| `tiktok_osint.py`    | ✅ ready (Unofficial TikTok API wrapper)          |
| `username_osint.py`  | ✅ ready (Sherlock)                               |
| `nmap_ptest.py`      | ✅ ready (Network scanning with Nmap)             |
| `twitter_osint.py`   | ❌ *planned* (Twint timeline + followers)         |
| `social_osint.py`    | ❌ *planned* (Osintgram + Instaloader)            |
| `ghunt_osint.py`     | ❌ *planned* (GHunt wrapper)                      |
| `footprint_osint.py` | ❌ *planned* (SpiderFoot / Recon‑ng orchestrator) |
| `PEN-TEST/*`         | 🚧 (Metasploit, Nuclei, etc. to be added)        |

PRs welcome—*especially* if you add a new wrapper with tests + DB storage!

---

## Contributing

1. Fork  ▸ hack ▸ **pull request**.
2. Stick to [`pre-commit`](https://pre-commit.com/) lint rules (`black`, `isort`, `flake8`).
3. Add a unit‑test in `tests/` if you add logic.
4. Sign off your commits (`git commit -s`).

Bug reports or feature ideas?  Open an issue or mail [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com).

---

## Roadmap

* [x] Implement core OSINT wrappers (email, username, phone)
* [x] Add more data sources (Google, DuckDuckGo, TikTok)
* [x] Add database storage functionality
* [x] Add initial PEN-TEST tools (nmap)
* [ ] Finish wrappers marked ❌ (Twitter, Social, GHunt, Footprint)
* [ ] Add more PEN-TEST micro‑services (nuclei, feroxbuster, etc.)
* [ ] Docker‑compose for one‑command bring‑up.
* [ ] Web dashboard (React + FastAPI) to browse stored OSINT artefacts.

---

**weaponise knowledge** - *ethically, of course.*