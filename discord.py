import requests # type: ignore
from typing import List, Tuple

def send_discord_alert(webhook_url: str, flagged: List[Tuple[str, int, int]]):
    """
    flagged items are tuples: (ip, malicious, suspicious)
    """
    if not webhook_url:
        return

    lines = []
    for ip, mal, susp in flagged:
        verdict = "MALICIOUS" if mal > 0 else "suspicious"
        lines.append(f"**{ip}** → {verdict}  (malicious={mal}, suspicious={susp})")

    content = "**DNSWatch alert:** Potential threats detected\n" + "\n".join(lines)

    payload = {"content": content}
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[discord] send failed: {e}")
