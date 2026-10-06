# cert-pulse

A lightweight SSL certificate expiry monitor with automated Slack alerts and a web dashboard.

- Checks SSL certs across all your domains twice daily
- Sends Slack alerts for certificates expiring within 30 days (or already expired)
- Groups alerts by domain owner — one message per person, with @mention
- Deduplicates: each alert fires once per am/pm slot, not repeatedly
- Web dashboard for manual checks and live status

## Screenshot

| Dashboard | Manual check |
|---|---|
| Domains table with expiry status | Type any domain, see its cert info instantly |

## Setup

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Run the app**
```bash
python app.py
```

Open `http://localhost:5051` in your browser.

**3. Configure via the Settings tab**

| Field | Description |
|---|---|
| Slack Webhook URL | Incoming webhook for your alerts channel |
| Slack Bot Token | `xoxb-…` token — used to @mention owners |
| Domain Owners | One line per domain: `github.com: alice@yourcompany.com` |

Config is saved locally to `config.json` (excluded from git).

## How it works

### Scheduling

```python
SCAN_TIMES = ((7, 35), (19, 35))  # scan 25 min early so alerts land by 8am and 8pm
```

A background thread wakes at 7:35 AM and 7:35 PM, checks every configured domain,
and sends Slack alerts for certs that are expiring or expired.

### Alert deduplication

`alerts_sent.json` (local, not committed) tracks which alerts fired:
- Key: domain name
- Value: `"YYYY-MM-DD-am"` or `"YYYY-MM-DD-pm"`

Each daily slot (am/pm) fires independently, so you get at most 2 alerts per domain per day.
Once an alert fires for the pm slot, it won't fire again until the next day.

To force a re-send (e.g. for testing):
```bash
echo '{}' > alerts_sent.json
```

### Cert check

Uses Python's built-in `ssl` + `socket` modules — no external dependencies for the check itself:

```python
def check_cert(domain, port=443):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.create_connection((domain, port), timeout=10),
                         server_hostname=domain) as s:
        cert = s.getpeercert()
    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days   = (expiry - datetime.utcnow()).days
    return expiry.strftime("%Y-%m-%d"), days, None
```

### Slack alert format

```
🔴 SSL Certificate Alert | @alice

  • *github.com* — expires in 12 days
  • *api.example.com* — certificate EXPIRED

🤖 Automated Cert Report | Generated: 2025-01-15 08:00 AM
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web dashboard |
| `/domains` | GET | JSON list of all domains with cert status |
| `/check` | POST | Check a single domain (`domain=github.com`) |
| `/scan_now` | POST | Trigger a full scan immediately |
| `/monitor_status` | GET | Last scan time and duration |
| `/save_settings` | POST | Save configuration |

## Adjusting the warn threshold

In `app.py`:
```python
WARN_DAYS = 30  # alert when cert expires within this many days
```

## Project structure

```
cert-pulse/
├── app.py              # Flask app + background scheduler + Slack alerts
├── requirements.txt
├── .gitignore
├── domains.json.example
└── templates/
    └── index.html      # Web dashboard
```

## License

MIT
