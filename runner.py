# dnswatch/runner.py
import os
import re
import time
import threading
import subprocess
import ipaddress
from pathlib import Path
from colorama import Fore, Style, init as colorama_init

# Load .env from CWD and repo root (works in Terminal, VS Code, launchd)
try:
    from dotenv import load_dotenv
    load_dotenv(Path.cwd() / ".env")
    load_dotenv((Path(__file__).resolve().parent.parent / ".env"), override=False)
except Exception:
    pass

from dnswatch.parsers.macos_cache import collect_dns_cache
from dnswatch.storage.db import (
    init_db, upsert_sighting, fetch_recent,
    needs_recheck, cache_intel, get_cached_intel
)
from dnswatch.intel.virustotal import vt_lookup_ip, VTError

# Optional alert senders (safe fallbacks if not configured)
try:
    from dnswatch.alerts.slack import send_slack_alert
except Exception:
    def send_slack_alert(*_, **__): pass
try:
    from dnswatch.alerts.discord import send_discord_alert
except Exception:
    def send_discord_alert(*_, **__): pass


# ---------- helpers ----------
def _compile_allowlist(pattern_csv: str):
    pats = []
    for part in (pattern_csv or "").split(","):
        p = part.strip()
        if not p:
            continue
        try:
            pats.append(re.compile(p))
        except re.error:
            pats.append(re.compile(re.escape(p)))
    return pats

def _is_allowed(val: str, patterns):
    if not val or not patterns:
        return False
    return any(p.search(val) for p in patterns)

def _sudo_keepalive(stop_event: threading.Event, period_sec: int = 60):
    while not stop_event.is_set():
        try:
            subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        stop_event.wait(period_sec)

def is_valid_ip(ip: str) -> bool:
    """Return True only for real IPv4/IPv6; filters out junk like '10:20:34' or mDNS placeholders."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------- single verbose pass ----------
def once():
    colorama_init()
    print(f"{Style.BRIGHT}Initializing DB…{Style.RESET_ALL}")
    init_db()

    print(f"{Style.BRIGHT}Collecting macOS DNS cache…{Style.RESET_ALL}")
    records = collect_dns_cache()
    print(f"Parser returned {len(records)} record(s)")

    # Upsert all sightings (we can filter later for VT)
    ins = 0
    for rec in records:
        upsert_sighting(
            rec.get("domain", ""),
            rec.get("record_type", ""),
            rec.get("ip", ""),
            rec.get("source", ""),
        )
        ins += 1
    print(f"Upserted {ins} record(s) into DB")

    recent = fetch_recent(10)
    print(f"Recent rows in DB: {len(recent)}")
    for domain, rtype, ip, last_seen in recent:
        print(f"  {domain:40} {rtype:4} {ip:39} {last_seen}")

    # --- VirusTotal phase ---
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        print(f"{Fore.YELLOW}VT_API_KEY not set (.env). Skipping VirusTotal checks & alerts.{Style.RESET_ALL}")
        return

    allow_ips = _compile_allowlist(os.getenv("WHITELIST_IPS", ""))
    allow_domains = _compile_allowlist(os.getenv("WHITELIST_DOMAINS", ""))
    cooldown_hours = int(os.getenv("IP_RECHECK_COOLDOWN_HOURS", "24"))
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    discord_webhook = os.getenv("DISCORD_WEBHOOK_URL", "")

    # Map IP -> domains seen (for allowlist checks)
    ip_to_domains = {}
    for r in records:
        ip = r.get("ip")
        if ip:
            ip_to_domains.setdefault(ip, set()).add(r.get("domain", ""))

    # Filter: valid IPs only, respect allowlists
    candidate_ips = []
    for ip, domains in ip_to_domains.items():
        if not is_valid_ip(ip):
            print(f"{Style.DIM}Skipping invalid IP: {ip}{Style.RESET_ALL}")
            continue
        if _is_allowed(ip, allow_ips) or any(_is_allowed(d, allow_domains) for d in domains):
            print(f"{Style.DIM}Skipping allowlisted IP: {ip}{Style.RESET_ALL}")
            continue
        candidate_ips.append(ip)

    candidate_ips = sorted(set(candidate_ips))
    print(f"Unique IPs to consider for VT: {len(candidate_ips)}")

    flagged = []
    for ip in candidate_ips:
        try:
            if needs_recheck(ip, cooldown_hours):
                intel = vt_lookup_ip(ip, api_key)
                cache_intel(ip, intel)
                time.sleep(0.6)  # gentle throttle for free VT tier
            else:
                intel = get_cached_intel(ip)
        except VTError as e:
            print(f"{Fore.YELLOW}VT lookup skipped for {ip}: {e}{Style.RESET_ALL}")
            continue

        mal = int(intel.get("malicious", 0))
        susp = int(intel.get("suspicious", 0))
        print(f"VT {ip:<39} → malicious={mal} suspicious={susp}")
        if mal > 0 or susp > 0:
            flagged.append((ip, mal, susp))

    if flagged:
        print(f"{Style.BRIGHT}⚠️  Flagged: {len(flagged)}{Style.RESET_ALL}")
        if slack_webhook:
            send_slack_alert(slack_webhook, flagged)
        if discord_webhook:
            send_discord_alert(discord_webhook, flagged)
    else:
        print(f"{Fore.GREEN}No malicious/suspicious IPs detected by VT.{Style.RESET_ALL}")


# ---------- continuous mode (used by CLI 'run' / 'loop') ----------
def run_loop(interval_secs: int):
    colorama_init()
    print(f"{Style.BRIGHT}Initializing DB…{Style.RESET_ALL}")
    init_db()

    stop = threading.Event()
    t = threading.Thread(target=_sudo_keepalive, args=(stop,), daemon=True)
    t.start()

    try:
        n = 0
        while True:
            n += 1
            print(f"\n{Style.BRIGHT}== Pass {n} == (every {interval_secs}s){Style.RESET_ALL}")
            try:
                once()
            except Exception as e:
                print(f"{Fore.YELLOW}[run] pass failed: {e}{Style.RESET_ALL}")
            print(f"{Style.DIM}Sleeping {interval_secs}s…{Style.RESET_ALL}")
            time.sleep(interval_secs)
    except KeyboardInterrupt:
        print(f"\n{Style.DIM}Stopping…{Style.RESET_ALL}")
    finally:
        stop.set()

