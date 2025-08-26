import subprocess
import re

_ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ipv6_re = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b")

def collect_dns_cache():
    """
    Triggers macOS mDNSResponder to dump recent DNS queries into the system log,
    then reads them for the last minute. Requires 'sudo' for killall command.
    """
    try:
        # Tell mDNSResponder to log its cache
        subprocess.run(["sudo", "killall", "-INFO", "mDNSResponder"])
    except Exception as e:
        print(f"Error triggering mDNSResponder: {e}")
        return []

    try:
        log_output = subprocess.run(
            [
                "log", "show", "--last", "1m",
                "--predicate", 'subsystem == "com.apple.mDNSResponder"'
            ],
            capture_output=True, text=True
        ).stdout
    except Exception as e:
        print(f"Error reading logs: {e}")
        return []

    results = []
    for line in log_output.splitlines():
        # Example log entry might have: "... example.com. ..."
        domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-z]{2,})\.", line)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower()

        for ip in _ipv4_re.findall(line):
            results.append({"domain": domain, "record_type": "A", "ip": ip, "source": "macos_log"})

        for ip in _ipv6_re.findall(line):
            results.append({"domain": domain, "record_type": "AAAA", "ip": ip, "source": "macos_log"})

    return results
