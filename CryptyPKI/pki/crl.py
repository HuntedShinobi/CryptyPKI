import os, json, datetime

CRL_FILE_NAME = "crl.json"

def init_crl(ROOT_DIR):
    crl_dir = os.path.join(ROOT_DIR, "crl")
    os.makedirs(crl_dir, exist_ok=True)
    crl_path = os.path.join(crl_dir, CRL_FILE_NAME)
    if not os.path.exists(crl_path):
        with open(crl_path, "w") as f:
            json.dump({}, f)

def revoke_certificate(username, ROOT_DIR):
    crl_path = os.path.join(ROOT_DIR, "crl", CRL_FILE_NAME)
    cert_path = os.path.join(ROOT_DIR, "users", f"{username}_cert.pem")
    if not os.path.exists(cert_path):
        return False
    from cryptography import x509
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    serial = str(cert.serial_number)
    with open(crl_path, "r") as f:
        data = json.load(f)
    data[serial] = datetime.datetime.utcnow().isoformat()
    with open(crl_path, "w") as f:
        json.dump(data, f, indent=4)
    return True

def is_revoked(serial, ROOT_DIR):
    crl_path = os.path.join(ROOT_DIR, "crl", CRL_FILE_NAME)
    with open(crl_path, "r") as f:
        data = json.load(f)
    return str(serial) in data