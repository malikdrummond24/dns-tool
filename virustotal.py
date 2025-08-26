import time
import requests # type: ignore

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

class VTError(Exception):
    pass

def vt_lookup_ip(ip: str, api_key: str) -> dict:
    """
    Look up IP reputation on VirusTotal.
    Returns: {"malicious": int, "suspicious": int, "harmless": int, "undetected": int, "raw": dict}
    """
    if not api_key:
        raise VTError("Missing VirusTotal API key")

    headers = {"x-apikey": api_key}
    url = VT_URL.format(ip=ip)

    for attempt in range(3):
        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            if attempt == 2:
                raise VTError(f"Request failed after retries: {e}") from e
            time.sleep(2 * (attempt + 1))
            continue

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "raw": data,
            }

        if resp.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "raw": {"status": 404}}

        if resp.status_code == 401:
            raise VTError("Unauthorized: invalid API key")

        if resp.status_code == 429:
            if attempt == 2:
                raise VTError("Rate limited by VirusTotal (HTTP 429); try again later.")
            time.sleep(4 * (attempt + 1))
            continue

        if attempt == 2:
            raise VTError(f"Unexpected VT status {resp.status_code}: {resp.text[:200]}")
        time.sleep(2 * (attempt + 1))

    raise VTError("Unexpected VT lookup termination")
