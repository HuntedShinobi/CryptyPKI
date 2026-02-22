from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime, os

def create_ca(ROOT_DIR, ca_name="root_ca", password="capassword"):
    ca_dir = os.path.join(ROOT_DIR, "root_ca")
    os.makedirs(ca_dir, exist_ok=True)
    key_path = os.path.join(ca_dir, f"{ca_name}_key.pem")
    cert_path = os.path.join(ca_dir, f"{ca_name}_cert.pem")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ))
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path

def load_ca_certificate(ROOT_DIR, ca_cert_path=None):
    if not ca_cert_path:
        ca_cert_path = os.path.join(ROOT_DIR, "root_ca", "root_ca_cert.pem")
    with open(ca_cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert