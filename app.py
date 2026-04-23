from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import os
import json
from collections import defaultdict
import boto3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# -------------------------------
# CONFIGURATION
# -------------------------------
app = Flask(__name__)

HEARTBEAT_THRESHOLD  = 10
REPLAY_WINDOW        = 10   # seconds
REPLAY_MAX_COUNT     = 5    # max heartbeats allowed in window
KEYS_FOLDER          = "heartbeat_keys"
FORENSICS_FOLDER     = "forensics"
# ✅ S3 CONFIG
BUCKET_NAME = "paranoid-zero-trust-forensics"
s3 = boto3.client("s3", region_name="us-east-1")

# ✅ SNS CONFIG
sns = boto3.client("sns", region_name="us-east-1")
TOPIC_ARN = "arn:aws:sns:us-east-1:579302405084:paranoid-alerts"

os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(FORENSICS_FOLDER, exist_ok=True)

# -------------------------------
# GLOBAL STATE
# -------------------------------
last_heartbeat  = {}              # node_id -> datetime
isolated_nodes  = {}              # node_id -> isolated_at (permanent)
rejected_nodes  = {}              # node_id -> attempt info
heartbeat_times = defaultdict(list)  # ✅ node_id -> list of arrival timestamps

# -------------------------------
# UTILITY FUNCTIONS
# -------------------------------
def load_public_key(node_id):
    pub_path = os.path.join(KEYS_FOLDER, f"{node_id}_public.pem")
    if not os.path.exists(pub_path):
        return None
    with open(pub_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_identity(node_id, signature_hex):
    pub_key = load_public_key(node_id)
    if not pub_key:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
        pub_key.verify(
            signature,
            node_id.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def log_forensic_event(node_id, event):
    filename = os.path.join(FORENSICS_FOLDER, f"{node_id}.json")
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event"    : event
    }

    # ✅ Local logging (unchanged)
    with open(filename, "a") as f:
        f.write(json.dumps(data) + "\n")

    # ✅ S3 logging (NEW ADDITION ONLY)
    try:
        file_name = f"{node_id}_{int(datetime.utcnow().timestamp())}.json"

        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=file_name,
            Body=json.dumps(data),
            ContentType="application/json"
        )

        print(f"☁️ Uploaded to S3: {file_name}")

    except Exception as e:
        print(f"❌ S3 upload failed: {e}")

def send_alert(message):
    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Message=message,
            Subject="🚨 Zero Trust Security Alert"
        )
        print("📧 Alert sent!")
    except Exception as e:
        print(f"❌ SNS failed: {e}")

def check_node_health():
    now = datetime.utcnow()
    suspicious = []
    for node_id, last_time in last_heartbeat.items():
        delta = (now - last_time).total_seconds()
        if delta > HEARTBEAT_THRESHOLD:
            suspicious.append(node_id)
            log_forensic_event(node_id, f"Missed heartbeat ({delta:.1f}s)")
            print(f"⚠ Node {node_id[:8]}... missed heartbeat!")
    return suspicious

# ✅ Replay detection inside gateway
def detect_replay(node_id):
    now = datetime.utcnow().timestamp()

    # Add current arrival time
    heartbeat_times[node_id].append(now)

    # Clean entries outside window
    heartbeat_times[node_id] = [
        t for t in heartbeat_times[node_id]
        if now - t <= REPLAY_WINDOW
    ]

    count = len(heartbeat_times[node_id])

    if count >= REPLAY_MAX_COUNT:
        return True, count
    return False, count

# -------------------------------
# ROUTES
# -------------------------------

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data      = request.json
    node_id   = data.get("node_id")
    signature = data.get("signature")

    if not node_id or not signature:
        return jsonify({"status": "error",
                        "message": "Missing fields"}), 400

    # ✅ Permanently blocked
    if node_id in isolated_nodes:
        print(f"⛔ Blocked: {node_id[:8]}...")
        log_forensic_event(node_id, "Blocked — permanently isolated")
        return jsonify({"status": "error",
                        "message": "Node permanently isolated"}), 403

    if verify_identity(node_id, signature):

        # ✅ Replay detection happens HERE — inside gateway
        # because gateway sees every single heartbeat
        is_replay, count = detect_replay(node_id)
        if is_replay:
            print(
                f"🔴 REPLAY ATTACK detected: {node_id[:8]}... "
                f"— {count} heartbeats in {REPLAY_WINDOW}s"
            )
            log_forensic_event(
                node_id,
                f"Replay attack — {count} heartbeats in {REPLAY_WINDOW}s"
            )
            send_alert(f"🚨 Replay attack detected on node {node_id}")
            # ✅ Auto isolate immediately at gateway level
            if node_id not in isolated_nodes:
                isolated_nodes[node_id] = datetime.utcnow().isoformat()
                log_forensic_event(
                    node_id,
                    "⛔ Auto isolated — replay attack detected at gateway"
                )
                print(f"⛔ Node {node_id[:8]}... AUTO ISOLATED by gateway")
            return jsonify({"status": "error",
                            "message": "Replay attack detected"}), 403

        last_heartbeat[node_id] = datetime.utcnow()
        rejected_nodes.pop(node_id, None)
        print(f"✔ Heartbeat verified: {node_id[:8]}...")
        return jsonify({"status": "ok", "message": "Heartbeat accepted"})

    else:
        prev = rejected_nodes.get(node_id, {})
        rejected_nodes[node_id] = {
            "last_attempt": datetime.utcnow().isoformat(),
            "status"      : "malicious",
            "attempts"    : prev.get("attempts", 0) + 1
        }
        attempts = rejected_nodes[node_id]["attempts"]
        print(f"✖ Rejected: {node_id[:8]}... attempts={attempts}")
        log_forensic_event(
            node_id,
            f"Invalid signature attempt #{attempts}"
        )
        send_alert(f"🚨 Fake node detected: {node_id}")
        return jsonify({"status": "error",
                        "message": "Invalid node"}), 403

@app.route("/heartbeat_status", methods=["GET"])
def heartbeat_status():
    now    = datetime.utcnow()
    status = {}
    for node_id, last_time in last_heartbeat.items():
        delta = (now - last_time).total_seconds()
        status[node_id] = {
            "last_heartbeat"    : last_time.isoformat(),
            "seconds_since_last": delta,
            "status"            : "healthy" if delta <= HEARTBEAT_THRESHOLD
                                  else "delayed"
        }
    return jsonify(status)

@app.route("/check_suspicious_nodes", methods=["GET"])
def suspicious_nodes():
    nodes = check_node_health()
    return jsonify({"suspicious_nodes": nodes})

@app.route("/isolate_node", methods=["POST"])
def isolate_node():
    data    = request.json
    node_id = data.get("node_id")
    if not node_id:
        return jsonify({"status": "error",
                        "message": "Missing node_id"}), 400
    if node_id not in isolated_nodes:
        isolated_nodes[node_id] = datetime.utcnow().isoformat()
        log_forensic_event(node_id, "⛔ Permanently isolated")
        send_alert(f"⛔ Node isolated: {node_id}")
        print(f"⛔ Node {node_id[:8]}... PERMANENTLY ISOLATED")
    return jsonify({"status": "ok",
                    "message": f"{node_id} permanently isolated"})

@app.route("/clear_decommissioned", methods=["POST"])
def clear_decommissioned():
    data    = request.json
    node_id = data.get("node_id")
    if not node_id:
        return jsonify({"status": "error",
                        "message": "Missing node_id"}), 400
    isolated_nodes.pop(node_id, None)
    last_heartbeat.pop(node_id, None)
    rejected_nodes.pop(node_id, None)
    heartbeat_times.pop(node_id, None)
    log_forensic_event(node_id, "Old identity cleared — new identity required")
    print(f"🗑 Old identity {node_id[:8]}... cleared")
    return jsonify({"status": "ok",
                    "message": "Old identity cleared."})

@app.route("/is_isolated/<node_id>", methods=["GET"])
def is_isolated(node_id):
    return jsonify({
        "isolated"   : node_id in isolated_nodes,
        "isolated_at": isolated_nodes.get(node_id, None)
    })

@app.route("/security_status", methods=["GET"])
def security_status():
    active_isolated  = len(isolated_nodes)
    active_malicious = len(rejected_nodes)
    alert = "CLEAR"
    if active_isolated > 0 or active_malicious > 0:
        alert = "COMPROMISED"
    return jsonify({
        "security_alert" : alert,
        "isolated_count" : active_isolated,
        "malicious_count": active_malicious
    })

# -------------------------------
# DASHBOARD API
# -------------------------------
@app.route("/dashboard_data")
def dashboard_data():
    result         = {}
    delayed_count  = 0
    isolated_count = 0

    for node_id, last_time in last_heartbeat.items():
        seconds = (datetime.utcnow() - last_time).total_seconds()
        if node_id in isolated_nodes:
            status = "isolated"
            isolated_count += 1
        elif seconds > HEARTBEAT_THRESHOLD:
            status = "delayed"
            delayed_count += 1
        else:
            status = "healthy"
        result[node_id] = {
            "seconds_since_last": seconds,
            "status"            : status,
            "isolated_at"       : isolated_nodes.get(node_id, None)
        }

    for node_id, info in rejected_nodes.items():
        if node_id not in result:
            result[node_id] = {
                "seconds_since_last": 0,
                "status"            : "malicious",
                "isolated_at"       : None,
                "attempts"          : info.get("attempts", 1),
                "last_attempt"      : info.get("last_attempt")
            }

    network_threat = "LOW"
    if delayed_count > 0 or len(rejected_nodes) > 0:
        network_threat = "MEDIUM"
    if delayed_count > 2 or isolated_count > 0:
        network_threat = "CRITICAL"

    security_alert = "CLEAR"
    if isolated_count > 0 or len(rejected_nodes) > 0:
        security_alert = "COMPROMISED"

    return jsonify({
        "nodes"          : result,
        "network_threat" : network_threat,
        "security_alert" : security_alert,
        "total_nodes"    : len(last_heartbeat),
        "isolated_count" : isolated_count,
        "malicious_count": len(rejected_nodes)
    })

@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "dashboard.html")

# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    print("🚀 Zero-Trust Gateway running...")
    app.run(host="0.0.0.0", port=8080)
