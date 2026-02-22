import os
from gui import start_gui
from pki.crl import init_crl

ROOT_DIR = "AppData"

def initialize_environment():
    os.makedirs(os.path.join(ROOT_DIR, "users"), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, "root_ca"), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, "crl"), exist_ok=True)
    init_crl(ROOT_DIR)
    log_file = os.path.join(ROOT_DIR, "security_log.txt")
    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write("CryptyPKI Security Log\n")
            f.write("=" * 40 + "\n")

def main():
    initialize_environment()
    start_gui(ROOT_DIR)

if __name__ == "__main__":
    main()