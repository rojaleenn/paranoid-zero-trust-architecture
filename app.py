import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
IDENTITY_FOLDER = "identities"

def verify_identity(node_id, signature_hex):
    pub_key_file = os.path.join(IDENTITY_FOLDER, f"{node_id}_public.pem")
    if not os.path.exists(pub_key_file):
        return False

    with open(pub_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    signature = bytes.fromhex(signature_hex)

    try:
        public_key.verify(
            signature,
            node_id.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"❌ Signature verification failed for {node_id}: {e}")
        return False

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.json
    node_id = data.get("node_id")
    signature = data.get("signature")

    if not node_id or not signature:
        return jsonify({"status": "error", "message": "Missing node_id or signature"}), 400

    if verify_identity(node_id, signature):
        print(f"✅ Heartbeat verified from node: {node_id}")
        return jsonify({"status": "ok", "message": "Heartbeat accepted"})
    else:
        print(f"❌ Heartbeat rejected from node: {node_id}")
        return jsonify({"status": "error", "message": "Unknown or invalid node"}), 403

if __name__ == "__main__":
    # Use port 6000 or any free port
    app.run(host="0.0.0.0", port=6000)

