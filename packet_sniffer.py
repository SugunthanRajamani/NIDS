"""
packet_sniffer.py — Windows IDS (Scapy + Npcap)
=================================================
ALL FIXES APPLIED:

  Fix 1 — Separate _pkt_lock so flood packets are never dropped
           while the evaluator is running.

  Fix 2 — Snapshot-then-reset (two separate passes inside the lock)
           IP stats are never wiped before being evaluated.

  Fix 3 — MIN_PKTS_TO_EVAL lowered 100 → 20
           Catches burst attacks, not just perfectly steady floods.

  Fix 4 — RATE_PPS_THRESHOLD lowered 150 → 50 pps
           Detection fires earlier.

  Fix 5 — log_event() is called BEFORE the blocked_ips check.
           *** THIS IS THE ROOT CAUSE OF "ONLY 1 LOG PER ATTACKER" ***
           Previously: once blocked_ips.add(ip) ran in window 1, every
           subsequent 3-second window hit `if ip in blocked_ips: continue`
           which skipped log_event() entirely — so a 60-second flood still
           only ever produced 1 CSV row.
           Now: log first, then decide whether to add to blocked_ips.

  Fix 6 — Normal traffic is also logged.
           Every evaluated window (attack OR normal) writes a row so the
           dashboard shows both labels, not just attacks.

Requires:
  pip install scapy
  Npcap from https://npcap.com  (tick WinPcap-compatible mode)
  Run PowerShell as Administrator
"""

import time, threading, socket, warnings
warnings.filterwarnings("ignore")

from collections import defaultdict
from datetime import datetime
from logger import log_event

# ── Thresholds ─────────────────────────────────────────────────────────────────
WINDOW_SECONDS     = 2     # evaluation cadence (seconds)
MIN_PKTS_TO_EVAL   = 10    # was 100
RATE_PPS_THRESHOLD = 50    # was 150
ML_CONF_THRESHOLD  = 0.85
MIN_RATE_FOR_ML    = 20    # was 50

# ── IPs never evaluated ────────────────────────────────────────────────────────
def _build_whitelist():
    w = {"127.0.0.1", "::1", "0.0.0.0",
         "224.0.0.1", "224.0.0.22", "224.0.0.251", "224.0.0.252",
         "239.255.255.250", "255.255.255.255",
         "8.8.8.8", "8.8.4.4", "1.1.1.1"}
    try:
        w.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return w

WHITELIST_IPS = _build_whitelist()

# ── Per-IP state ───────────────────────────────────────────────────────────────
_pkt_lock = threading.Lock()   # guards _ip_stats only — short hold time

def _new_stats():
    t = time.time()
    return {"pkt_count": 0, "byte_count": 0,
            "syn_count": 0, "udp_count": 0, "icmp_count": 0,
            "first_seen": t, "last_seen": t, "dst_ports": set()}

_ip_stats = defaultdict(_new_stats)

# ── Live metrics ───────────────────────────────────────────────────────────────
_met_lock    = threading.Lock()
live_metrics = {"pps": 0.0, "top_attacker": "",
                "attack_types": defaultdict(int), "total_pkts": 0}


def _build_features(s):
    now    = time.time()
    dur    = max(now - s["first_seen"], 1e-5)
    spkts  = s["pkt_count"]
    sbytes = s["byte_count"]
    rate   = spkts / dur
    return {
        "dur":     dur,
        "proto":   1 if s["udp_count"]  > spkts * 0.5 else
                   (2 if s["icmp_count"] > spkts * 0.3 else 0),
        "service": 1 if s["dst_ports"] & {80, 443, 5000, 8080} else 0,
        "state":   0 if s["syn_count"] / max(spkts, 1) > 0.4 else 4,
        "spkts":   spkts, "dpkts": 0,
        "sbytes":  sbytes, "dbytes": 0,
        "rate":    rate,
        "sinpkt":  dur / max(spkts, 1),
        "smean":   sbytes / max(spkts, 1), "dmean": 0,
        "ct_src_ltm": spkts,
        "ct_srv_dst": len(s["dst_ports"]),
    }


def _attack_label(s):
    p = max(s["pkt_count"], 1)
    if s["syn_count"]  / p > 0.5: return "SYN-Flood"
    if s["udp_count"]  / p > 0.5: return "UDP-Flood"
    if s["icmp_count"] / p > 0.3: return "ICMP-Flood"
    return "HTTP-Flood"


# ── Scapy packet callback ──────────────────────────────────────────────────────
def _process_packet(pkt):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        if src in WHITELIST_IPS:
            return
        now = time.time()
        with _pkt_lock:
            s = _ip_stats[src]
            s["pkt_count"]  += 1
            s["byte_count"] += len(pkt)
            s["last_seen"]   = now
            if s["pkt_count"] == 1:
                s["first_seen"] = now
            if pkt.haslayer(TCP):
                flags = str(pkt[TCP].flags)
                s["dst_ports"].add(pkt[TCP].dport)
                if "S" in flags and "A" not in flags:
                    s["syn_count"] += 1
            elif pkt.haslayer(UDP):
                s["udp_count"] += 1
                s["dst_ports"].add(pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                s["icmp_count"] += 1
    except Exception:
        pass


# ── Evaluator — fires every WINDOW_SECONDS ────────────────────────────────────
def _evaluate_loop(detector, attack_queue, queue_lock, blocked_ips):
    t_prev     = time.time()
    prev_total = 0

    while True:
        time.sleep(WINDOW_SECONDS)
        now = time.time()

        # STEP 1: grab snapshot + reset stats — hold lock as briefly as possible
        with _pkt_lock:
            snapshot     = []
            total_pkts   = 0
            ips_to_reset = list(_ip_stats.keys())

            for ip, s in list(_ip_stats.items()):
                total_pkts += s["pkt_count"]
                if (s["pkt_count"] >= MIN_PKTS_TO_EVAL and
                        (now - s["last_seen"]) < WINDOW_SECONDS * 2):
                    snapshot.append((ip, {**s, "dst_ports": set(s["dst_ports"])}))

            # FIX 2: reset only AFTER full snapshot is built
            for ip in ips_to_reset:
                _ip_stats[ip] = _new_stats()
                _ip_stats[ip]["first_seen"] = now

        # Update PPS gauge
        dt = max(now - t_prev, 1e-5)
        with _met_lock:
            live_metrics["pps"]        = round(max(total_pkts - prev_total, 0) / dt, 1)
            live_metrics["total_pkts"] = total_pkts
        prev_total = total_pkts
        t_prev     = now

        # STEP 2: classify each IP (ML runs outside the lock)
        for ip, stats in snapshot:
            features = _build_features(stats)
            rate     = features["rate"]
            atk_lbl  = _attack_label(stats)

            is_attack  = False
            label      = "Normal"
            confidence = 0.0

            if rate > RATE_PPS_THRESHOLD:
                is_attack  = True
                label      = f"DoS ({atk_lbl})"
                confidence = 0.99
            elif rate > MIN_RATE_FOR_ML:
                result     = detector.predict(features)
                confidence = result["confidence"]
                if result["is_attack"] and confidence >= ML_CONF_THRESHOLD:
                    is_attack = True
                    label     = f"DoS ({atk_lbl}) — ML"
                else:
                    label      = "Normal"
                    confidence = result["confidence"]

            # ----------------------------------------------------------------
            # FIX 5 + FIX 6: log EVERY window for EVERY evaluated IP, and do
            # it BEFORE the blocked_ips guard so already-blocked attackers
            # still produce a log row each window.
            # ----------------------------------------------------------------
            log_event(ip=ip, path=f"[PKT:{atk_lbl}]",
                      label=label, confidence=confidence,
                      is_attack=is_attack, features=features)

            if is_attack:
                with _met_lock:
                    live_metrics["attack_types"][atk_lbl] += 1
                    live_metrics["top_attacker"] = ip

                if ip not in blocked_ips:
                    # First time we see this attacker — block + push SSE alert
                    blocked_ips.add(ip)
                    with queue_lock:
                        attack_queue.append({
                            "time":       datetime.now().strftime("%H:%M:%S"),
                            "ip":         ip,
                            "label":      label,
                            "confidence": confidence,
                            "type":       atk_lbl,
                            "rate_pps":   round(rate, 1),
                        })
                    print(f"[🔥 BLOCKED ] {ip}  {atk_lbl}  pps={rate:.0f}  conf={confidence:.2f}")
                else:
                    # Already blocked — still logged above, just no duplicate alert
                    print(f"[⚠️  ONGOING ] {ip}  {atk_lbl}  pps={rate:.0f}  (already blocked)")
            else:
                print(f"[📊 NORMAL  ] {ip}  pps={rate:.0f}  pkts={stats['pkt_count']}")


# ── Scapy capture thread ───────────────────────────────────────────────────────
def _capture_loop():
    try:
        from scapy.all import sniff, conf
        conf.verb = 0
        print("[📡 SNIFFER] Active — capturing all IP traffic")
        sniff(filter="ip", prn=_process_packet, store=False, iface=None)
    except ImportError:
        print("[❌ SNIFFER] scapy not installed → pip install scapy")
    except PermissionError:
        print("[❌ SNIFFER] Run PowerShell as Administrator for packet capture")
        print("            HTTP-layer detection still active")
    except Exception as e:
        print(f"[⚠️  SNIFFER] {e}")


def get_live_metrics():
    with _met_lock:
        return {
            "pps":          live_metrics["pps"],
            "top_attacker": live_metrics["top_attacker"],
            "attack_types": dict(live_metrics["attack_types"]),
            "total_pkts":   live_metrics["total_pkts"],
        }


def start_sniffer(detector, attack_queue, queue_lock, blocked_ips):
    threading.Thread(target=_capture_loop,  daemon=True, name="scapy-capture").start()
    threading.Thread(target=_evaluate_loop,
                     args=(detector, attack_queue, queue_lock, blocked_ips),
                     daemon=True, name="pkt-evaluator").start()
    print(f"[📡 SNIFFER] Window={WINDOW_SECONDS}s | MinPkts={MIN_PKTS_TO_EVAL} | "
          f"RateThreshold={RATE_PPS_THRESHOLD}pps | MLThreshold={ML_CONF_THRESHOLD}")
