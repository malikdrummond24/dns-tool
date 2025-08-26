from pathlib import Path
import os
from dotenv import load_dotenv

# load .env explicitly from this folder
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

flagged = [("203.0.113.66", 4, 1), ("198.51.100.23", 0, 3)]  # (ip, malicious, suspicious)

slack = os.getenv("SLACK_WEBHOOK_URL")
discord = os.getenv("DISCORD_WEBHOOK_URL")

if not slack and not discord:
    print("❌ No webhook found in .env (SLACK_WEBHOOK_URL / DISCORD_WEBHOOK_URL).")
    raise SystemExit(1)

try:
    if slack:
        from dnswatch.alerts.slack import send_slack_alert
        send_slack_alert(slack, flagged)
        print("✅ Sent Slack test alert")
except Exception as e:
    print("Slack alert error:", e)

try:
    if discord:
        from dnswatch.alerts.discord import send_discord_alert
        send_discord_alert(discord, flagged)
        print("✅ Sent Discord test alert")
except Exception as e:
    print("Discord alert error:", e)
