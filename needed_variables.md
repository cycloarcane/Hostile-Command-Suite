# Hostile-Command-Suite: API Keys & Environment Setup

This guide contains all required API keys and environment variables needed by the Hostile-Command-Suite, with instructions for setting them up in both Bash and Fish shells.

## Quick Reference

| Tool | Key/Variable | Required? | Storage |
|------|-------------|-----------|---------|
| Database | `POSTGRES_*` vars | Yes | Environment variables |
| Google Search | `GOOGLE_SEARCH_API_KEY`, `GOOGLE_SEARCH_CX` | Yes for Google OSINT | Environment variables |
| Mosint | `~/.mosint.yaml` | Yes for full email OSINT | Config file |
| PhoneInfoga | `~/.config/phoneinfoga/config.yaml` | Optional | Config file |
| SpiderFoot | `~/.spiderfoot.conf` | Optional | Config file |
| theHarvester | `~/.theHarvester/api-keys.yaml` | Optional | Config file |
| h8mail | `h8mail_config.ini` | Optional | Config file |
| Social-Analyzer | `--google_key` | Optional | Command parameter |
| Osintgram | `credentials.ini` | Required | Config file |
| GHunt | Config with SID, LSID, HSID cookies | Required | Config file |
| TikTok | `ms_token` | Optional | Command parameter |

## 1. Database Environment Variables

Required for `database_osint.py`:

```
POSTGRES_DB=osint_db
POSTGRES_USER=osint_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
```

## 2. Google Search API

Required for `google_osint.py`:

```
GOOGLE_SEARCH_API_KEY=your_google_api_key
GOOGLE_SEARCH_CX=your_search_engine_id
```

To get these:
1. Create a Google Custom Search Engine: https://programmablesearchengine.google.com/
2. Create a Google API key: https://console.developers.google.com/

## 3. Tool-Specific Configuration Files

### Mosint (`~/.mosint.yaml`)

```yaml
apikeys:
  dehashed: "your_dehashed_api_key"
  emailrep: "your_emailrep_key"
  hunter: "your_hunter_key"
  intelx: "your_intelx_key"
  psbdmp: "your_psbdmp_key"
  twitter:
    consumer_key: "your_twitter_consumer_key"
    consumer_secret: "your_twitter_consumer_secret"
    bearer_token: "your_twitter_bearer_token"
```

### PhoneInfoga (`~/.config/phoneinfoga/config.yaml`)

```yaml
api:
  key: "your_phoneinfoga_api_key"
scanners:
  numverify:
    enabled: true
    api_key: "your_numverify_api_key"
  googlesearch:
    enabled: true
```

### SpiderFoot (`~/.spiderfoot.conf`)

Too large to include fully. Run SpiderFoot once to generate a template, then edit.

```
sfp_example_module_api_key=your_key_here
```

### theHarvester (`~/.theHarvester/api-keys.yaml`)

```yaml
apikeys:
  bing:
    key: your_bing_api_key
  hunter:
    key: your_hunter_api_key
  shodan:
    key: your_shodan_api_key
```

### h8mail (`h8mail_config.ini`)

```ini
[h8mail]
dehashed_email = your_email@example.com
dehashed_key = your_dehashed_api_key
hibp_key = your_haveibeenpwned_api_key
```

### Osintgram (`credentials.ini`)

```ini
[Credentials]
username = your_instagram_username
password = your_instagram_password
```

### GHunt (Cookie-based)

You need to extract these cookies from a logged-in Google session:
- SID
- LSID
- HSID

## 4. Setting Environment Variables

### Bash Shell

#### Temporary (Current Session)
```bash
# Database
export POSTGRES_DB=osint_db
export POSTGRES_USER=osint_user
export POSTGRES_PASSWORD=your_secure_password
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432

# Google Search
export GOOGLE_SEARCH_API_KEY=your_google_api_key
export GOOGLE_SEARCH_CX=your_search_engine_id
```

#### Permanent
Add to your `~/.bashrc` or `~/.bash_profile`:

```bash
# Hostile-Command-Suite Environment
export POSTGRES_DB=osint_db
export POSTGRES_USER=osint_user
export POSTGRES_PASSWORD=your_secure_password
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432

export GOOGLE_SEARCH_API_KEY=your_google_api_key
export GOOGLE_SEARCH_CX=your_search_engine_id
```

Then run: `source ~/.bashrc` (or reopen your terminal)

### Fish Shell

#### Temporary (Current Session)
```fish
# Database
set -x POSTGRES_DB osint_db
set -x POSTGRES_USER osint_user
set -x POSTGRES_PASSWORD your_secure_password
set -x POSTGRES_HOST localhost
set -x POSTGRES_PORT 5432

# Google Search
set -x GOOGLE_SEARCH_API_KEY your_google_api_key
set -x GOOGLE_SEARCH_CX your_search_engine_id
```

#### Permanent
To make variables permanent in Fish, use the `set -U` (universal) option:

```fish
# Database
set -U POSTGRES_DB osint_db
set -U POSTGRES_USER osint_user
set -U POSTGRES_PASSWORD your_secure_password
set -U POSTGRES_HOST localhost
set -U POSTGRES_PORT 5432

# Google Search
set -U GOOGLE_SEARCH_API_KEY your_google_api_key
set -U GOOGLE_SEARCH_CX your_search_engine_id
```

Alternatively, add to your `~/.config/fish/config.fish`:

```fish
# Hostile-Command-Suite Environment 
set -x POSTGRES_DB osint_db
set -x POSTGRES_USER osint_user
set -x POSTGRES_PASSWORD your_secure_password
set -x POSTGRES_HOST localhost
set -x POSTGRES_PORT 5432

set -x GOOGLE_SEARCH_API_KEY your_google_api_key
set -x GOOGLE_SEARCH_CX your_search_engine_id
```

## 5. Setting Up Configuration Files

Create the necessary directories and files:

```bash
# Bash
mkdir -p ~/.config/phoneinfoga
touch ~/.mosint.yaml
touch ~/.config/phoneinfoga/config.yaml

# Edit them with your preferred editor
nano ~/.mosint.yaml
```

```fish
# Fish
mkdir -p ~/.config/phoneinfoga
touch ~/.mosint.yaml
touch ~/.config/phoneinfoga/config.yaml

# Edit them with your preferred editor
nano ~/.mosint.yaml
```

## 6. Testing Your Configuration

Test database connection:
```bash
python3 -c "import psycopg2; conn = psycopg2.connect(dbname=os.environ['POSTGRES_DB'], user=os.environ['POSTGRES_USER'], password=os.environ['POSTGRES_PASSWORD'], host=os.environ['POSTGRES_HOST'], port=os.environ['POSTGRES_PORT']); print('Connection successful!')"
```

Test Google API:
```bash
curl "https://www.googleapis.com/customsearch/v1?key=$GOOGLE_SEARCH_API_KEY&cx=$GOOGLE_SEARCH_CX&q=test"
```

Run tool checks:
```bash
# Inside the project directory with virtualenv activated
python OSINT/email_osint.py check
python OSINT/google_osint.py check
```

## 7. Security Recommendations

- Never commit API keys to Git repositories
- Use environment variables instead of hardcoding
- Consider using a secrets manager for production
- Set restrictive permissions on config files: `chmod 600 ~/.mosint.yaml`
- For sensitive environments, use systemd's `LoadCredential=` feature