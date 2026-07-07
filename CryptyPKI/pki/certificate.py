from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
import datetime
import os

def issue_certificate(username, ROOT_DIR, ca_cert_path=None, ca_key_path=None, ca_password="capassword"):
    users_dir = os.path.join(ROOT_DIR, "users")
    csr_path = os.path.join(users_dir, f"{username}_csr.pem")
    cert_path = os.path.join(users_dir, f"{username}_cert.pem")
    if not ca_cert_path:
        ca_cert_path = os.path.join(ROOT_DIR, "root_ca", "root_ca_cert.pem")
    if not ca_key_path:
        ca_key_path = os.path.join(ROOT_DIR, "root_ca", "root_ca_key.pem")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=ca_password.encode())
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path