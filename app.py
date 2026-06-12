"""
app.py — IDS with Dual Detection: Raw Packets + HTTP Layer
============================================================
Detection Layer 1 — packet_sniffer.py
  Raw socket captures every IP packet.
  Evaluates ML features every 3 seconds per source IP.
  Logs both Normal AND Attack rows every window.

Detection Layer 2 — before_request middleware
  Every complete HTTP request -> feature extraction -> ML predict.
  Catches application-layer attacks (slow HTTP, API abuse).

Both layers write to traffic_log.csv and push SSE alerts.

FIXES APPLIED:
  - recent_events cap raised 50 → 500
  - SKIP_PATHS no longer skips page routes (/home, /dashboard, /login)
    so browser visits ARE logged as Normal traffic — previously those
    routes were in SKIP_PATHS which meant the dashboard never showed
    any Normal rows at all.
  - Only high-frequency internal polling paths are skipped (/api/traffic,
    /api/stream, /api/metrics, /static, /favicon.ico).
"""

import os, sys, time, random, threading, json
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response

from config import RATE_BLOCK_THRESHOLD, ATTACK_CONFIDENCE_THRESHOLD
from feature_extractor import extract_features, reset_ip
from predict import DoSDetector
from logger import log_event, recent_events, summary
import packet_sniffer

app = Flask(__name__)
app.secret_key = "ids-research-secret"

# ── Shared state ───────────────────────────────────────────────────────────────
blocked_ips:     set         = set()
request_counter: defaultdict = defaultdict(int)
attack_queue:    list        = []
_queue_lock                  = threading.Lock()

# Only skip high-frequency internal polling + static assets.
# PAGE ROUTES (/home, /dashboard, /login) are intentionally NOT skipped
# so that browser visits appear as Normal traffic in the dashboard.
SKIP_PATHS = {
    "/api/traffic", "/api/stream", "/api/metrics",
    "/api/block", "/api/unblock", "/api/simulate",
    "/static", "/favicon.ico",
}

# IPs that will never be blocked
WHITELIST_IPS = {"127.0.0.1", "::1", "localhost"}

# ── Load ML model ──────────────────────────────────────────────────────────────
detector = DoSDetector()
detector.load()

# ── Discover network IP ────────────────────────────────────────────────────────
def _get_network_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"

NETWORK_IP = _get_network_ip()

# ── Start packet sniffer (Layer 1) ────────────────────────────────────────────
packet_sniffer.start_sniffer(detector, attack_queue, _queue_lock, blocked_ips)


# ── Layer 2: HTTP middleware ───────────────────────────────────────────────────
@app.before_request
def inspect_http():
    ip   = request.remote_addr
    path = request.path

    # Skip only polling APIs and static files — NOT page routes
    if any(path.startswith(p) for p in SKIP_PATHS):
        return

    # Never block whitelisted IPs
    if ip in WHITELIST_IPS:
        # Still log whitelisted IPs as Normal so the dashboard isn't empty
        features = extract_features(request)
        log_event(ip=ip, path=path, label="Normal", confidence=0.0,
                  is_attack=False, features=features)
        return

    if ip in blocked_ips:
        log_event(ip, path, "Blocked", 1.0, True)
        return "blocked by IDS", 403

    request_counter[ip] += 1
    features = extract_features(request)
    result   = detector.predict(features)

    # Rate-based pre-block for very aggressive HTTP floods
    if request_counter[ip] > 300:
        result["is_attack"]  = True
        result["label"]      = "DoS Attack (HTTP Rate)"
        result["confidence"] = max(result["confidence"], 0.95)

    # Log every request — Normal and Attack alike
    log_event(ip=ip, path=path, label=result["label"],
              confidence=result["confidence"], is_attack=result["is_attack"],
              features=features)

    if result["is_attack"]:
        blocked_ips.add(ip)
        reset_ip(ip)
        request_counter[ip] = 0
        _push_alert(ip, result["label"], result["confidence"])
        print(f"[BLOCKED HTTP] {ip}  conf={result['confidence']:.2f}")


def _push_alert(ip, label, confidence):
    with _queue_lock:
        attack_queue.append({
            "time":       datetime.now().strftime("%H:%M:%S"),
            "ip":         ip,
            "label":      label,
            "confidence": confidence,
        })


# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index(): return redirect(url_for("login"))

@app.route("/login")
def login(): return render_template("login.html")

@app.route("/home")
def home(): return render_template("home.html")

@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html")


# ── APIs ───────────────────────────────────────────────────────────────────────
@app.route("/api/traffic")
def api_traffic():
    events = recent_events(500)   # was 50
    stats  = summary()
    return jsonify({
        "total":       stats["total"],
        "normal":      stats["normal"],
        "attacks":     stats["attacks"],
        "blocked_ips": stats["blocked_ips"],
        "status":      "ATTACK" if stats["attacks"] > 0 else "SAFE",
        "events":      events,
    })


@app.route("/api/stream")
def api_stream():
    def generate():
        yield 'data: {"type":"connected"}\n\n'
        sent = 0
        while True:
            with _queue_lock:
                pending = attack_queue[sent:]
                sent    = len(attack_queue)
            for alert in pending:
                yield f"data: {json.dumps(alert)}\n\n"
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/metrics")
def api_metrics():
    from packet_sniffer import get_live_metrics
    return jsonify(get_live_metrics())


@app.route("/api/block", methods=["POST"])
def api_block():
    ip = (request.json or {}).get("ip", "")
    if ip:
        blocked_ips.add(ip)
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"error": "no ip"}), 400


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = (request.json or {}).get("ip", "")
    blocked_ips.discard(ip)
    reset_ip(ip)
    request_counter[ip] = 0
    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    body     = request.json or {}
    sim_type = body.get("type", "syn")
    count    = int(body.get("count", 300))
    threading.Thread(target=_simulate_attack, args=(sim_type, count), daemon=True).start()
    return jsonify({"status": "started", "type": sim_type, "count": count})


# ── Attack simulator ───────────────────────────────────────────────────────────
_SIM_PROFILES = {
    "syn":  {"rate": 2000, "label": "SYN Flood",  "proto": 0, "state": 0},
    "udp":  {"rate": 3000, "label": "UDP Flood",  "proto": 1, "state": 4},
    "icmp": {"rate": 1500, "label": "ICMP Flood", "proto": 2, "state": 0},
    "http": {"rate": 600,  "label": "HTTP Flood", "proto": 0, "state": 4},
}

def _simulate_attack(sim_type="syn", n=300):
    p        = _SIM_PROFILES.get(sim_type, _SIM_PROFILES["syn"])
    attacker = (f"10.{random.randint(0,255)}."
                f"{random.randint(0,255)}.{random.randint(2,254)}")
    print(f"[SIM] {p['label']} from {attacker}")

    features = {
        "dur":        n / max(p["rate"], 1),
        "proto":      p["proto"],
        "service":    0,
        "state":      p["state"],
        "spkts":      n,
        "dpkts":      0,
        "sbytes":     n * 512,
        "dbytes":     0,
        "rate":       p["rate"],
        "sinpkt":     1 / p["rate"],
        "smean":      512,
        "dmean":      0,
        "ct_src_ltm": n,
        "ct_srv_dst": 1,
    }
    result = detector.predict(features)
    result["is_attack"]  = True
    result["label"]      = f"DoS Attack ({p['label']}) [SIM]"
    result["confidence"] = max(result["confidence"], 0.98)

    log_event(ip=attacker, path=f"[SIM:{p['label']}]",
              label=result["label"], confidence=result["confidence"],
              is_attack=True, features=features)
    blocked_ips.add(attacker)
    _push_alert(attacker, result["label"], result["confidence"])
    print(f"[SIM BLOCKED] {attacker}")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(" IDS DUAL-LAYER SYSTEM")
    print("  Layer 1: Raw packet sniffer (Scapy / Npcap)")
    print("  Layer 2: HTTP middleware (application-layer)")
    print()
    print(f"  Local dashboard  → http://127.0.0.1:5000/dashboard")
    print(f"  Network access   → http://{NETWORK_IP}:5000/dashboard")
    print()
    print("  ── Attack test commands ─────────────────────────────")
    print(f"  hping3 SYN : sudo hping3 -S --flood -p 5000 {NETWORK_IP}")
    print(f"  hping3 UDP : sudo hping3 --udp --flood -p 5000 {NETWORK_IP}")
    print(f"  HTTP flood : ab -n 5000 -c 50 http://{NETWORK_IP}:5000/home")
    print(f"  curl flood : for i in $(seq 500); do curl -s http://{NETWORK_IP}:5000/home & done")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
