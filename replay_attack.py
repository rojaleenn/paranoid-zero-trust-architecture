import requests
import time
import argparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

GATEWAY = "http://localhost:8080"
KEYS_FOLDER = "heartbeat_keys"

print("🔴 ATTACK SIMULATION — REPLAY ATTACK")
print("=" * 50)

# ── Step 1: Find a real node ID to impersonate
def get_registered_nodes():
    files = os.listdir(KEYS_FOLDER)
    node_ids = list(set(
        f.replace("_private.pem", "").replace("_public.pem", "")
        for f in files
        if f.endswith("_private.pem")
    ))
    return node_ids

nodes = get_registered_nodes()

if not nodes:
    print("❌ No registered nodes found in heartbeat_keys/")
    print("Start heartbeat_generator.py first then run this")
    exit(1)

# Pick first node to attack
target_node_id = nodes[0]
print(f"🎯 Target node identified: {target_node_id[:8]}...")
print(f"📦 Attacker captured a valid heartbeat packet")
print(f"🔁 Replaying captured packet repeatedly...")
print("=" * 50)
time.sleep(2)

# ── Step 2: Load the real private key
# In real attack, attacker would have captured the SIGNED PACKET
# Here we simulate by loading key (pretending packet was captured)
priv_path = os.path.join(KEYS_FOLDER, f"{target_node_id}_private.pem")
with open(priv_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# ── Step 3: Generate ONE signature (the "captured" packet)
captured_signature = private_key.sign(
    target_node_id.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
).hex()

print(f"📦 Captured signature: {captured_signature[:32]}...")
print("🔁 Starting replay flood...")
print("=" * 50)
time.sleep(1)

# ── Step 4: Replay same signature rapidly
attempt = 0
while True:
    attempt += 1

    try:
        r = requests.post(f"{GATEWAY}/heartbeat", json={
            "node_id"  : target_node_id,
            "signature": captured_signature  # same packet every time
        })

        status = r.status_code
        result = r.json()

        if status == 200:
            print(f"[Replay {attempt}] ⚠️  ACCEPTED → Replay not yet detected")
        elif status == 403:
            print(f"[Replay {attempt}] 🛡️  BLOCKED → {result['message']}")
        else:
            print(f"[Replay {attempt}] ❓ Status {status} → {result}")

    except Exception as e:
        print(f"[Replay {attempt}] Error: {e}")

    # Rapid fire — this is what behavior monitor detects
    time.sleep(0.5)
