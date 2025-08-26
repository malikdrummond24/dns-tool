import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json

DB_PATH = Path("dnswatch.sqlite3")

DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_sightings_domain_ip
    ON sightings(domain, ip);

CREATE TABLE IF NOT EXISTS intel_cache (
    ip TEXT PRIMARY KEY,
    last_checked TEXT NOT NULL,
    malicious INTEGER NOT NULL,
    suspicious INTEGER NOT NULL,
    harmless INTEGER NOT NULL,
    undetected INTEGER NOT NULL,
    raw_json TEXT NOT NULL
);
"""

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def open_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = open_db()
    for stmt in filter(None, DDL.split(";")):
        conn.execute(stmt)
    conn.commit()
    conn.close()

def upsert_sighting(domain, record_type, ip, source):
    conn = open_db()
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO sightings(domain, record_type, ip, first_seen, last_seen, source)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(domain, ip) DO UPDATE SET last_seen=excluded.last_seen
        """,
        (domain, record_type, ip, now, now, source),
    )
    conn.commit()
    conn.close()

def fetch_recent(limit=10):
    conn = open_db()
    rows = conn.execute(
        "SELECT domain, record_type, ip, last_seen FROM sightings ORDER BY last_seen DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows

# ---- VirusTotal cache helpers ----

def cache_intel(ip: str, stats: dict):
    conn = open_db()
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO intel_cache(ip, last_checked, malicious, suspicious, harmless, undetected, raw_json)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          last_checked=excluded.last_checked,
          malicious=excluded.malicious,
          suspicious=excluded.suspicious,
          harmless=excluded.harmless,
          undetected=excluded.undetected,
          raw_json=excluded.raw_json
        """,
        (
            ip, now,
            int(stats.get("malicious", 0)),
            int(stats.get("suspicious", 0)),
            int(stats.get("harmless", 0)),
            int(stats.get("undetected", 0)),
            json.dumps(stats.get("raw", {}))[:500_000],
        )
    )
    conn.commit()
    conn.close()

def get_cached_intel(ip: str):
    conn = open_db()
    row = conn.execute(
        "SELECT ip, last_checked, malicious, suspicious, harmless, undetected, raw_json FROM intel_cache WHERE ip=?",
        (ip,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "ip": row[0],
        "last_checked": row[1],
        "malicious": int(row[2]),
        "suspicious": int(row[3]),
        "harmless": int(row[4]),
        "undetected": int(row[5]),
        "raw": json.loads(row[6]) if row[6] else {},
    }

def needs_recheck(ip: str, cooldown_hours: int) -> bool:
    cached = get_cached_intel(ip)
    if not cached:
        return True
    try:
        last = datetime.fromisoformat(cached["last_checked"])
    except Exception:
        return True
    age = datetime.now(timezone.utc) - last
    return age > timedelta(hours=cooldown_hours)
from datetime import timedelta  # (already imported datetime above)

def fetch_report(since_hours: int = 24, only_flagged: bool = False):
    """
    Returns rows: (domain, record_type, ip, last_seen, malicious, suspicious)
    Joins sightings with intel_cache on IP. Filters by time window and (optional) flagged only.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat(timespec="seconds")
    conn = open_db()
    try:
        base_sql = """
        SELECT s.domain, s.record_type, s.ip, s.last_seen,
               COALESCE(i.malicious, 0) AS malicious,
               COALESCE(i.suspicious, 0) AS suspicious
        FROM sightings s
        LEFT JOIN intel_cache i ON i.ip = s.ip
        WHERE s.last_seen >= ?
        """
        params = [cutoff]
        if only_flagged:
            base_sql += " AND (COALESCE(i.malicious,0) > 0 OR COALESCE(i.suspicious,0) > 0)"
        base_sql += " ORDER BY s.last_seen DESC"
        cur = conn.execute(base_sql, params)
        return cur.fetchall()
    finally:
        conn.close()

