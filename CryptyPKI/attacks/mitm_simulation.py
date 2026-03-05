import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from pki.validation import validate_certificate

def simulate_mitm_attack_demo(ROOT_DIR=None):
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"FakeUser")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"FakeCA")]))
        .public_key(fake_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(fake_key, hashes.SHA256())
    )
    temp_cert_path = os.path.join(ROOT_DIR or "", "temp_fake_cert.pem")
    with open(temp_cert_path, "wb") as f:
        f.write(fake_cert.public_bytes(serialization.Encoding.PEM))
    log_messages = [
        "MITM Attack Simulation Started",
        f"Fake Certificate Generated for: {fake_cert.subject.rfc4514_string()}",
        f"Issuer: {fake_cert.issuer.rfc4514_string()}",
        f"Serial Number: {fake_cert.serial_number}"
    ]
    valid, msg = validate_certificate(temp_cert_path, ROOT_DIR)
    if valid:
        log_messages.append("Validation Result: SUCCESS (Unexpected!)")
    else:
        log_messages.append(f"Validation Result: FAILED as expected → {msg}")
    log_messages.append("MITM Simulation Complete\n")
    if os.path.exists(temp_cert_path):
        os.remove(temp_cert_path)
    return "\n".join(log_messages)