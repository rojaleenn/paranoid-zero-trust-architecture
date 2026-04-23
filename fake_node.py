import requests
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

GATEWAY = "http://localhost:8080"
FAKE_NODE_ID = "FAKE_NODE_01"

print("🔴 ATTACK SIMULATION — NODE SPOOFING")
print("=" * 50)
print(f"Attacker using fake node ID: {FAKE_NODE_ID}")
print("Generating forged RSA key (NOT registered with authority)...")
time.sleep(1)

# Attacker generates their OWN key — not registered
fake_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

print("Attempting to send forged heartbeat to gateway...")
print("=" * 50)

attempt = 0
while True:
    attempt += 1

    # Sign with FAKE key — gateway has no public key for this
    fake_signature = fake_key.sign(
        FAKE_NODE_ID.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()

    try:
        r = requests.post(f"{GATEWAY}/heartbeat", json={
            "node_id"  : FAKE_NODE_ID,
            "signature": fake_signature
        })

        status = r.status_code
        result = r.json()

        if status == 403:
            print(f"[Attempt {attempt}] ❌ REJECTED → {result['message']}")
        elif status == 200:
            print(f"[Attempt {attempt}] ⚠️  ACCEPTED → {result['message']}")
        else:
            print(f"[Attempt {attempt}] ❓ Status {status} → {result}")

    except Exception as e:
        print(f"[Attempt {attempt}] Gateway unreachable: {e}")

    time.sleep(3)
