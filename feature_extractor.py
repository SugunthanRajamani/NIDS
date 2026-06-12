"""
feature_extractor.py — Extract 14 ML features from a live Flask request.
All state is in-memory (per-IP counters), reset on restart.

FIXES APPLIED:
  - Added threading.Lock() around all shared per-IP state mutations
    so concurrent Flask requests don't corrupt counters.
"""

import time, threading
from collections import defaultdict
from config import FEATURE_COLUMNS

# ── Per-IP state ───────────────────────────────────────────────────────────────
_state_lock = threading.Lock()
_last_time  = {}
_pkt_count  = defaultdict(int)    # spkts (cumulative)
_byte_count = defaultdict(int)    # sbytes (cumulative)
_endpoints  = defaultdict(set)    # for ct_srv_dst

# ── Encoding helpers ───────────────────────────────────────────────────────────
_PROTO_MAP   = {'http': 0, 'https': 0, 'tcp': 0, 'udp': 1}
_SERVICE_MAP = {'/login': 1, '/api': 2, '/dashboard': 3}
_STATE_VAL   = 4   # CON — established HTTP connection


def extract_features(request) -> dict:
    """Return a dict keyed by FEATURE_COLUMNS for one incoming request."""
    ip   = request.remote_addr
    now  = time.time()
    path = request.path

    with _state_lock:
        # dur — inter-arrival time since last request from this IP
        dur = now - _last_time[ip] if ip in _last_time else 0.0
        _last_time[ip] = now

        # protocol (0=tcp/http, 1=udp)
        proto = _PROTO_MAP.get(request.scheme, 0)

        # service — which area of the app is being hit
        service = next(
            (v for k, v in _SERVICE_MAP.items() if k in path), 0
        )

        # cumulative packets & bytes
        _pkt_count[ip]  += 1
        req_size         = request.content_length or 0
        _byte_count[ip] += req_size

        spkts  = _pkt_count[ip]
        sbytes = _byte_count[ip]

        # ct_srv_dst — unique endpoints visited by this IP
        _endpoints[ip].add(path)
        ct_srv_dst = len(_endpoints[ip])

    # Derived values (no shared state — computed after releasing lock)
    dpkts  = 1
    dbytes = 200          # approximate response size
    rate   = spkts / (dur + 1e-5)
    sinpkt = dur
    smean  = sbytes / (spkts or 1)
    dmean  = dbytes
    ct_src_ltm = spkts

    return {
        'dur':        dur,
        'proto':      proto,
        'service':    service,
        'state':      _STATE_VAL,
        'spkts':      spkts,
        'dpkts':      dpkts,
        'sbytes':     sbytes,
        'dbytes':     dbytes,
        'rate':       rate,
        'sinpkt':     sinpkt,
        'smean':      smean,
        'dmean':      dmean,
        'ct_src_ltm': ct_src_ltm,
        'ct_srv_dst': ct_srv_dst,
    }


def reset_ip(ip: str):
    """Clear per-IP state (call after blocking)."""
    with _state_lock:
        _last_time.pop(ip, None)
        _pkt_count.pop(ip, None)
        _byte_count.pop(ip, None)
        _endpoints.pop(ip, None)
