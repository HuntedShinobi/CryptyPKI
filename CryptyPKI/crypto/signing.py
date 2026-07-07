import os
import json
import time
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from pki.user import load_user_private_key
from pki.validation import validate_certificate
from attacks.replay_attack import register_nonce

def sign_file(file_path, username, password, ROOT_DIR):
    key = load_user_private_key(username, password, ROOT_DIR)

    with open(file_path, "rb") as f:
        data = f.read()

    metadata = {
        "nonce": os.urandom(16).hex(),
        "timestamp": time.time(),
        "filename": os.path.basename(file_path),
        "signer": username,
    }
    metadata_bytes = json.dumps(metadata).encode()

    payload = metadata_bytes + data
    signature = key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = f"{file_path}.sig"
    with open(sig_path, "wb") as f:
        f.write(struct.pack(">I", len(metadata_bytes)))
        f.write(metadata_bytes)
        f.write(struct.pack(">I", len(signature)))
        f.write(signature)

def verify_signature(file_path, username, ROOT_DIR):
    cert_path = os.path.join(ROOT_DIR, "users", f"{username}_cert.pem")
    valid, msg = validate_certificate(cert_path, ROOT_DIR)
    if not valid:
        return False, msg

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    sig_path = f"{file_path}.sig"
    if not os.path.exists(sig_path):
        return False, "Signature file not found"

    with open(sig_path, "rb") as f:
        meta_len = struct.unpack(">I", f.read(4))[0]
        metadata_bytes = f.read(meta_len)
        sig_len = struct.unpack(">I", f.read(4))[0]
        signature = f.read(sig_len)

    try:
        metadata = json.loads(metadata_bytes.decode())
    except Exception:
        return False, "Corrupted signature metadata"

    nonce = metadata.get("nonce", "")
    if not register_nonce(nonce):
        return False, "Replay detected: nonce already used"

    age = time.time() - metadata.get("timestamp", 0)
    if age > 300:
        return False, f"Signature too old ({int(age)}s). Possible replay."

    with open(file_path, "rb") as f:
        data = f.read()

    payload = metadata_bytes + data
    try:
        cert.public_key().verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, f"Signature valid (signed by '{metadata.get('signer')}' at {time.ctime(metadata.get('timestamp'))})"
    except InvalidSignature:
        return False, "Invalid Signature"