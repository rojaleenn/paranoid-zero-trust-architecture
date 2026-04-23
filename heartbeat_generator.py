import os
import requests
import uuid
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# -----------------------
# CONFIGURATION
# -----------------------
IDENTITY_AUTHORITY_URL = "http://localhost:5000/register"
GATEWAY_URL = "http://localhost:8080/heartbeat"
HEARTBEAT_INTERVAL = 5  # seconds

IDENTITIES_FOLDER = "identities"
KEYS_FOLDER = "heartbeat_keys"
os.makedirs(KEYS_FOLDER, exist_ok=True)

# -----------------------
# FUNCTION TO LOAD OR MOVE KEYS
# -----------------------
def load_or_move_keys(node_id):
    private_key_file = os.path.join(KEYS_FOLDER, f"{node_id}_private.pem")
    public_key_file = os.path.join(KEYS_FOLDER, f"{node_id}_public.pem")

    # If keys already exist in heartbeat_keys, just return
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        return private_key_file, public_key_file

    # Look for keys in identities folder
    identity_private = os.path.join(IDENTITIES_FOLDER, f"{node_id}_private.pem")
    identity_public = os.path.join(IDENTITIES_FOLDER, f"{node_id}_public.pem")

    if os.path.exists(identity_private) and os.path.exists(identity_public):
        # Move keys to heartbeat_keys folder
        os.rename(identity_private, private_key_file)
        os.rename(identity_public, public_key_file)
        print(f"✅ Keys for node {node_id} moved from identities/ to heartbeat_keys/")
        return private_key_file, public_key_file

    # If keys not found anywhere
    raise FileNotFoundError(f"Missing keys for node {node_id}! Place them in {IDENTITIES_FOLDER}/")

# -----------------------
# REGISTER NODE
# -----------------------
response = requests.get(IDENTITY_AUTHORITY_URL).json()
node_id = response["node_id"]
print(f"🆔 Node registered with ID: {node_id}")

# Load or move keys
private_file, public_file = load_or_move_keys(node_id)

# Load private key for signing
with open(private_file, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# -----------------------
# SEND HEARTBEAT LOOP
# -----------------------
print("💓 Heartbeat generator started...")

while True:
    try:
        message = node_id.encode()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
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

