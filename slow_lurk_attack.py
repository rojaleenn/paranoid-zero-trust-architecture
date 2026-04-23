import requests
import time
import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------------------
# CONFIGURATION
# ----------------------------------------
GATEWAY     = "http://localhost:8080"
KEYS_FOLDER = "heartbeat_keys"

# ----------------------------------------
# HELPERS
# ----------------------------------------
def log(msg, level="INFO"):
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    icons = {
        "INFO"   : "⬜",
        "GOOD"   : "✅",
        "WARN"   : "⚠️ ",
        "ATTACK" : "🔴",
        "DETECT" : "🛡️ ",
        "LURK"   : "🐢"
    }
    icon = icons.get(level, "⬜")
    print(f"[{timestamp}] {icon}  {msg}")

def get_registered_nodes():
    if not os.path.exists(KEYS_FOLDER):
        return []
    files = os.listdir(KEYS_FOLDER)
    node_ids = list(set(
        f.replace("_private.pem", "").replace("_public.pem", "")
        for f in files
        if f.endswith("_private.pem")
    ))
    return node_ids

def load_private_key(node_id):
    path = os.path.join(KEYS_FOLDER, f"{node_id}_private.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign(private_key, node_id):
    return private_key.sign(
        node_id.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()

def send_heartbeat(node_id, private_key):
    try:
        signature = sign(private_key, node_id)
        r = requests.post(f"{GATEWAY}/heartbeat", json={
            "node_id"  : node_id,
            "signature": signature
        }, timeout=5)
        return r.status_code, r.json()
    except Exception as e:
        return 0, {"message": str(e)}

def check_my_status(node_id):
    try:
        r = requests.get(f"{GATEWAY}/dashboard_data", timeout=5)
        data = r.json()
        node_data = data.get("nodes", {}).get(node_id, {})
        return node_data.get("status", "unknown")
    except Exception:
        return "unknown"

# ----------------------------------------
# SLOW LURK ATTACK
# ----------------------------------------
if __name__ == "__main__":

    print()
    print("🔴 ATTACK SIMULATION — SLOW LURKING ATTACK")
    print("=" * 55)
    print("Strategy: Node degrades heartbeat interval slowly")
    print("          Trying to avoid detection by being subtle")
    print("          Each round interval increases by 1 second")
    print("=" * 55)
    print()
    time.sleep(2)

    # ── Find a real node to compromise
    nodes = get_registered_nodes()
    if not nodes:
        log("No registered nodes found in heartbeat_keys/", "WARN")
        log("Start heartbeat_generator.py first", "WARN")
        exit(1)

    target_id  = nodes[0]
    target_key = load_private_key(target_id)

    log(f"Compromised node: {target_id[:8]}...", "ATTACK")
    log("Attacker now controls this node's heartbeat timing", "ATTACK")
    log("Starting slow degradation...", "LURK")
    print()
    time.sleep(2)

    # ── Lurking phases
    # Start at normal interval then slowly increase
    phases = [
        {"interval": 2,  "label": "Normal behaviour — blending in",        "rounds": 4},
        {"interval": 4,  "label": "Slightly slower — still under radar",    "rounds": 4},
        {"interval": 6,  "label": "Getting slower — pushing the limit",     "rounds": 3},
        {"interval": 8,  "label": "Near threshold — almost detectable",     "rounds": 3},
        {"interval": 11, "label": "OVER threshold — behavior monitor alert","rounds": 3},
        {"interval": 15, "label": "Deep delay — isolation imminent",        "rounds": 3},
    ]

    round_number = 0

    for phase in phases:
        interval = phase["interval"]
        label    = phase["label"]
        rounds   = phase["rounds"]

        print(f"\n{'─' * 55}")
        log(f"Phase: {label}", "LURK")
        log(f"Heartbeat interval: {interval}s  (normal = 5s)", "LURK")
        print(f"{'─' * 55}")

        for i in range(rounds):
            round_number += 1

            # Check if already isolated
            status = check_my_status(target_id)

            if status == "isolated":
                print()
                log(f"SYSTEM DETECTED THE LURKING ATTACK!", "DETECT")
                log(f"Node {target_id[:8]}... has been ISOLATED", "DETECT")
                log(f"Slow degradation detected after {round_number} rounds", "DETECT")
                log(f"Final interval was {interval}s vs normal 5s", "DETECT")
                print()
                print("=" * 55)
                log("BEHAVIOR BASELINE MONITORING WORKED", "DETECT")
                log("Stealthy attack failed — system wins 🛡️", "DETECT")
                print("=" * 55)
                exit(0)

            # Send heartbeat
            code, result = send_heartbeat(target_id, target_key)

            if code == 200:
                log(
                    f"[Round {round_number}] "
                    f"Heartbeat sent (interval={interval}s) → "
                    f"{result.get('message')} | "
                    f"Node status: {status}",
                    "LURK"
                )
            elif code == 403:
                log(
                    f"[Round {round_number}] "
                    f"BLOCKED → {result.get('message')}",
                    "DETECT"
                )
                log("Node was already isolated before this round", "DETECT")
                exit(0)
            else:
                log(f"[Round {round_number}] No response from gateway", "WARN")

            # Wait the degraded interval
            time.sleep(interval)

    # If we get here system did not catch it — needs behavior monitor tuning
    print()
    print("=" * 55)
    log("WARNING: Attack completed without detection", "WARN")
    log("Behavior monitor threshold may need tuning", "WARN")
    log("Reduce HEARTBEAT_THRESHOLD in behavior_monitor.py", "WARN")
    print("=" * 55)
