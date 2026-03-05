import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def create_user_key_and_csr(username, password, ROOT_DIR):
    users_dir = os.path.join(ROOT_DIR, "users")
    os.makedirs(users_dir, exist_ok=True)
    key_path = os.path.join(users_dir, f"{username}_key.pem")
    csr_path = os.path.join(users_dir, f"{username}_csr.pem")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ))
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)]))
        .sign(key, hashes.SHA256())
    )
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return key_path, csr_path

def load_user_private_key(username, password, ROOT_DIR):
    key_path = os.path.join(ROOT_DIR, "users", f"{username}_key.pem")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Private key for user '{username}' not found.")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(key_path, "rb") as f:
        key = load_pem_private_key(f.read(), password=password.encode())
    return key