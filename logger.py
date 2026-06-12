"""
logger.py — Thread-safe CSV logger for traffic events.

FIXES APPLIED:
  - recent_events default n raised to 500 (was 100)
  - summary() now counts over the entire file (not just last 100k rows)
    and returns structured blocked_ips list correctly
  - Added get_all_events() helper for full-file reads (used by summary)
"""

import csv, os, threading
from datetime import datetime

LOG_FILE   = "traffic_log.csv"
LOG_FIELDS = ["time", "ip", "path", "label", "confidence", "is_attack", "features"]

_lock = threading.Lock()


def _ensure_header():
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        with open(LOG_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=LOG_FIELDS).writeheader()


def log_event(ip: str, path: str, label: str,
              confidence: float, is_attack: bool, features: dict = None):
    """Append one event row to traffic_log.csv (thread-safe)."""
    row = {
        "time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":         ip,
        "path":       path,
        "label":      label,
        "confidence": round(confidence, 4),
        "is_attack":  int(is_attack),
        "features":   str(features) if features else "",
    }
    with _lock:
        _ensure_header()
        with open(LOG_FILE, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=LOG_FIELDS).writerow(row)


def recent_events(n: int = 500) -> list:
    """Return the last n rows from the CSV as a list of dicts.
    Default raised from 100 → 500 so the dashboard shows more traffic.
    """
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        try:
            with open(LOG_FILE, "r", newline="") as f:
                rows = list(csv.DictReader(f))
            return rows[-n:]
        except Exception:
            return []


def get_all_events() -> list:
    """Read every row in the log (used by summary — no cap)."""
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        try:
            with open(LOG_FILE, "r", newline="") as f:
                return list(csv.DictReader(f))
        except Exception:
            return []


def summary() -> dict:
    """Stats over the ENTIRE log file — not capped at n rows."""
    events      = get_all_events()
    total       = len(events)
    attacks     = sum(1 for e in events if str(e.get("is_attack")) == "1")
    blocked_ips = list({e["ip"] for e in events if str(e.get("is_attack")) == "1"})
    return {
        "total":       total,
        "attacks":     attacks,
        "normal":      total - attacks,
        "blocked_ips": blocked_ips,
    }
