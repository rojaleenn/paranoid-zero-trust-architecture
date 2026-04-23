import time
import requests
import json
import os
from datetime import datetime
from collections import defaultdict

# ------------------------------
# CONFIGURATION
# ------------------------------
GATEWAY_URL         = "http://localhost:8080/heartbeat_status"
GATEWAY_ISOLATE_URL = "http://localhost:8080/isolate_node"
GATEWAY_DASHBOARD   = "http://localhost:8080/dashboard_data"
CHECK_INTERVAL      = 5
HEARTBEAT_THRESHOLD = 10
FORENSICS_FOLDER    = "forensics"

# ------------------------------
# STATE
# ------------------------------
isolated_nodes     = set()
reported_malicious = set()
consecutive_delays = defaultdict(int)
lurk_counter       = defaultdict(int)
previous_seconds   = {}

os.makedirs(FORENSICS_FOLDER, exist_ok=True)
print("🟢 Behavior Monitor started...")

# ------------------------------
# HELPERS
# ------------------------------
def log_forensic_event(node_id, event):
    filename = os.path.join(FORENSICS_FOLDER, f"{node_id}.json")
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event"    : event
    }
    with open(filename, "a") as f:
        f.write(json.dumps(data) + "\n")

def isolate_node(node_id, reason):
    if node_id in isolated_nodes:
        return
    isolated_nodes.add(node_id)
    log_forensic_event(node_id, f"⛔ ISOLATED — {reason}")
    print(f"🚨 Node {node_id[:8]}... ISOLATED — {reason}")
    try:
        r = requests.post(
            GATEWAY_ISOLATE_URL,
            json={"node_id": node_id},
            timeout=3
        )
        print(f"🔴 Gateway notified → {r.json().get('message')}")
    except Exception as e:
        print(f"⚠️ Could not notify gateway: {e}")

def detect_dead_node(node_id, current_seconds):
    """
    seconds_since_last exceeds threshold
    consistently across 2 checks = dead node
    """
    if current_seconds > HEARTBEAT_THRESHOLD:
        consecutive_delays[node_id] += 1
        lurk_counter[node_id] = 0  # reset lurk — this is dead
    else:
        consecutive_delays[node_id] = 0
    return consecutive_delays[node_id] >= 2

def detect_lurk(node_id, current_seconds):
    """
    STRICT rules — can never fire on dead node:
    1. current_seconds MUST be below threshold
    2. Must drift slowly across 3+ consecutive checks
    3. Drift must be gradual not sudden
    """
    # ✅ Hard gate — if over threshold this is dead node
    if current_seconds >= HEARTBEAT_THRESHOLD:
        lurk_counter[node_id] = 0
        previous_seconds[node_id] = current_seconds
        return False, 0

    prev = previous_seconds.get(node_id, None)
    previous_seconds[node_id] = current_seconds

    if prev is None:
        return False, 0

    drift = current_seconds - prev

    # Node got faster or same — reset
    if drift <= 1.0:
        lurk_counter[node_id] = 0
        return False, 0

    # Getting slower but still below threshold
    if 1.0 < drift < 6.0:
        lurk_counter[node_id] += 1

    # ✅ Only confirm after 3 consecutive slow checks
    if lurk_counter[node_id] >= 3:
        return True, drift

    return False, drift

def check_malicious_nodes():
    try:
        r = requests.get(GATEWAY_DASHBOARD, timeout=5)
        data = r.json()
        nodes = data.get("nodes", {})
        for node_id, info in nodes.items():
            if info.get("status") == "malicious":
                attempts = info.get("attempts", 1)
                if node_id not in isolated_nodes and attempts >= 3:
                    print(
                        f"🔴 MALICIOUS NODE {node_id[:8]}... "
                        f"— {attempts} attempts — ISOLATING"
                    )
                    log_forensic_event(
                        node_id,
                        f"Malicious node isolated — {attempts} forged attempts"
                    )
                    isolate_node(
                        node_id,
                        f"Forged identity — {attempts} attempts"
                    )
                    continue
                report_key = f"{node_id}_{attempts}"
                if report_key not in reported_malicious:
                    reported_malicious.add(report_key)
                    print(
                        f"🔴 MALICIOUS: {node_id[:8]}... "
                        f"— {attempts} attempt(s) blocked"
                    )
                    log_forensic_event(
                        node_id,
                        f"Malicious — {attempts} attempt(s)"
                    )
    except Exception as e:
        print(f"⚠️ Could not check malicious nodes: {e}")

# ------------------------------
# MAIN MONITOR LOOP
# ------------------------------
def monitor_nodes():
    while True:
        try:
            check_malicious_nodes()

            try:
                response = requests.get(GATEWAY_URL, timeout=5)
                data = response.json()
            except Exception as e:
                print(f"[Error] Gateway unreachable: {e}")
                time.sleep(CHECK_INTERVAL)
                continue

            for node_id, status in data.items():

                if node_id in isolated_nodes:
                    continue

                time_since_last = status.get("seconds_since_last")
                last_heartbeat  = status.get("last_heartbeat")

                if last_heartbeat is None:
                    print(f"⚠️ Node {node_id[:8]}... never sent heartbeat")
                    log_forensic_event(node_id, "Heartbeat never received")
                    isolate_node(node_id, "Never sent heartbeat")
                    continue

                if time_since_last is None:
                    print(f"⚠️ Node {node_id[:8]}... info missing")
                    log_forensic_event(node_id, "Heartbeat info missing")
                    isolate_node(node_id, "Info missing")
                    continue

                # ── Dead node check first
                is_dead = detect_dead_node(node_id, time_since_last)
                if is_dead:
                    print(
                        f"💀 DEAD NODE — {node_id[:8]}... "
                        f"— silent {time_since_last:.1f}s"
                    )
                    log_forensic_event(
                        node_id,
                        f"Dead node — silent {time_since_last:.1f}s"
                    )
                    isolate_node(
                        node_id,
                        f"Dead — {time_since_last:.1f}s silence"
                    )
                    continue

                # ── Lurk check — only below threshold
                is_lurking, drift = detect_lurk(node_id, time_since_last)
                if is_lurking:
                    print(
                        f"🐢 LURK ATTACK — {node_id[:8]}... "
                        f"— drift {drift:.1f}s over 3 checks"
                    )
                    log_forensic_event(
                        node_id,
                        f"Slow lurk — drift {drift:.1f}s"
                    )
                    isolate_node(node_id, f"Slow lurk — {drift:.1f}s drift")
                    continue

                print(
                    f"✅ Node {node_id[:8]}... healthy "
                    f"— {time_since_last:.1f}s ago"
                )

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n🟠 Behavior Monitor stopped")
            break

# ------------------------------
# ENTRY POINT
# ------------------------------
if __name__ == "__main__":
    monitor_nodes()
