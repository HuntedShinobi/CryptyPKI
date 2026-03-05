import os
import json
import time
import struct
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from attacks.replay_attack import register_nonce

def encrypt_file(file_path, receiver_username, ROOT_DIR):
    cert_path = os.path.join(ROOT_DIR, "users", f"{receiver_username}_cert.pem")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()

    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path, "rb") as f:
        plaintext = f.read()

    metadata = {
        "nonce": secrets.token_hex(16),
        "timestamp": time.time(),
        "filename": os.path.basename(file_path),
        "receiver": receiver_username,
    }
    metadata_bytes = json.dumps(metadata).encode()

    inner = struct.pack(">I", len(metadata_bytes)) + metadata_bytes + plaintext

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, inner, None)

    out_path = f"{file_path}.enc"
    with open(out_path, "wb") as f:
        f.write(struct.pack(">I", len(encrypted_key)))
        f.write(encrypted_key)
        f.write(iv)
        f.write(ciphertext)

def decrypt_file(file_path, receiver_username, password, ROOT_DIR):
    key_path = os.path.join(ROOT_DIR, "users", f"{receiver_username}_key.pem")
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=password.encode())

    with open(file_path, "rb") as f:
        key_len = struct.unpack(">I", f.read(4))[0]
        encrypted_key = f.read(key_len)
        iv = f.read(12)
        ciphertext = f.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    inner = aesgcm.decrypt(iv, ciphertext, None)

    meta_len = struct.unpack(">I", inner[:4])[0]
    metadata_bytes = inner[4:4 + meta_len]
    plaintext = inner[4 + meta_len:]

    try:
        metadata = json.loads(metadata_bytes.decode())
    except Exception:
        raise ValueError("Corrupted encryption metadata")

    nonce = metadata.get("nonce", "")
    if not register_nonce(nonce):
        raise ValueError("Replay detected: this encrypted message has already been decrypted")

    age = time.time() - metadata.get("timestamp", 0)
    if age > 300:
        raise ValueError(f"Encrypted message too old ({int(age)}s). Possible replay.")

    out_path = file_path.replace(".enc", ".dec")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path