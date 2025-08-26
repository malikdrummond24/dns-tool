# dnswatch (macOS) — DNS cache monitor with VirusTotal + Alerts

Collect recent DNS lookups from macOS logs, store them in SQLite, check each IP on VirusTotal, and alert via Slack/Discord.

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env: set VT_API_KEY=...
# optional: SLACK_WEBHOOK_URL / DISCORD_WEBHOOK_URL

# one-off run
dnswatch once

# continuous run (every 5min)
dnswatch run --interval 300
