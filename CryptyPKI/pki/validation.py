from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from pki.ca import load_ca_certificate
from pki.crl import is_revoked
import datetime

def validate_certificate(cert_path, ROOT_DIR):
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    ca_cert = load_ca_certificate(ROOT_DIR)
    if is_revoked(cert.serial_number, ROOT_DIR):
        return False, "Certificate Revoked"
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_before_utc > now:
        return False, "Certificate Not Yet Valid"
    if cert.not_valid_after_utc < now:
        return False, "Certificate Expired"
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if basic.value.ca:
            return False, "End-user certificate cannot be CA"
    except Exception:
        return False, "Missing BasicConstraints"
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "Invalid Signature"
    return True, "Valid Certificate"