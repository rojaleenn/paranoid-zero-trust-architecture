import time
import requests
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import uuid

# Config
IDENTITY_AUTHORITY_URL = "http://localhost:5000/register"
GATEWAY_URL = "http://localhost:6000/heartbeat"
HEARTBEAT_INTERVAL = 5
KEY_FOLDER = "heartbeat_keys"
os.makedirs(KEY_FOLDER, exist_ok=True)

# Step 1: Auto-register with Identity Authority
response = requests.get(IDENTITY_AUTHORITY_URL).json()
node_id = response["node_id"]
print(f"✅ Registered with Identity Authority: {node_id}")

# Step 2: Keep public key in identities, copy private key for local use
private_key_file = os.path.join(KEY_FOLDER, f"{node_id}_private.pem")
if not os.path.exists(private_key_file):
    # Copy only private key to heartbeat_keys
    os.system(f"cp identities/{node_id}_private.pem {private_key_file}")

# Load private key
with open(private_key_file, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

print("💓 Heartbeat generator started...")

# Step 3: Send signed heartbeat continuously
while True:
    try:
        signature = private_key.sign(
            node_id.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        payload = {"node_id": node_id, "signature": signature.hex()}

        try:
            r = requests.post(GATEWAY_URL, json=payload)
            print(f"[Gateway Response] {r.json()}")
        except Exception as e:
            print(f"[Error] Gateway unreachable: {e}")

        time.sleep(HEARTBEAT_INTERVAL)
    except KeyboardInterrupt:
        print("🛑 Heartbeat stopped by user")
        break

