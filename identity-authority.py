from flask import Flask, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uuid
import os

app = Flask(__name__)

IDENTITY_FOLDER = "identities"
os.makedirs(IDENTITY_FOLDER, exist_ok=True)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

@app.route("/register", methods=["GET"])
def register():
    node_id = str(uuid.uuid4())

    private_key, public_key = generate_keys()

    with open(f"{IDENTITY_FOLDER}/{node_id}_private.pem", "wb") as f:
        f.write(private_key)

    with open(f"{IDENTITY_FOLDER}/{node_id}_public.pem", "wb") as f:
        f.write(public_key)

    return jsonify({
        "node_id": node_id,
        "message": "Identity issued successfully"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

