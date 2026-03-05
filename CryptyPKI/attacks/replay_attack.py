import os
import json
import time

NONCE_FILE = "AppData/crl/used_nonces.json"

def _load_nonces():
    if os.path.exists(NONCE_FILE):
        with open(NONCE_FILE, "r") as f:
            return json.load(f)
    return {}

def _save_nonces(nonces):
    os.makedirs(os.path.dirname(NONCE_FILE), exist_ok=True)
    with open(NONCE_FILE, "w") as f:
        json.dump(nonces, f, indent=2)

def register_nonce(nonce_hex: str) -> bool:
    nonces = _load_nonces()
    now = time.time()

    nonces = {k: v for k, v in nonces.items() if now - v < 86400}

    if nonce_hex in nonces:
        _save_nonces(nonces)
        return False

    nonces[nonce_hex] = now
    _save_nonces(nonces)
    return True

def simulate_replay_demo():
    nonce = os.urandom(16).hex()
    log_messages = ["Replay Attack Simulation Started"]

    if register_nonce(nonce):
        log_messages.append(f"Generated nonce: {nonce} → First message accepted.")
    else:
        log_messages.append(f"Generated nonce: {nonce} → Unexpected: nonce already exists!")

    if not register_nonce(nonce):
        log_messages.append(f"Replaying nonce: {nonce} → Replay detected! Message blocked.")
    else:
        log_messages.append(f"Replaying nonce: {nonce} → Replay allowed (should not happen).")

    log_messages.append("Replay Attack Simulation Complete\n")
    return "\n".join(log_messages)