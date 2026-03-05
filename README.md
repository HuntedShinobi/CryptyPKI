# CryptyPKI

**CryptyPKI** is a modern Python GUI application that demonstrates core Public Key Infrastructure (PKI) operations, hybrid encryption, digital signatures, and simulated cryptographic attacks.

---

## 🚀 Features

- Full PKI lifecycle: create CAs, issue, validate, and revoke certificates
- Hybrid file encryption using AES-256-GCM + RSA-OAEP
- Digital file signing and verification with RSA-PSS
- Built-in MITM and Replay Attack simulations
- Clean, modern Tkinter GUI with real-time activity log
- Replay protection via nonce tracking and timestamp validation

---

## 🏛 PKI Management

- Create a Root Certificate Authority (CA)
- Generate user key pairs and Certificate Signing Requests (CSRs)
- Issue end-user certificates
- Validate certificates
- Revoke certificates
- Maintain a lightweight Certificate Revocation List (CRL)

---

## 🔐 Cryptographic Operations

- Hybrid file encryption using:
  - AES-256-GCM (symmetric encryption)
  - RSA-OAEP (asymmetric key exchange)
- Secure file decryption
- Digital file signing using RSA-PSS
- Signature verification

---

## ⚠️ Security Attack Simulations

CryptyPKI includes built-in demonstrations of common cryptographic attack scenarios:

- **MITM (Man-in-the-Middle) Simulation**  
  Demonstrates the risks of unverified or spoofed certificates

- **Replay Attack Simulation**  
  Shows vulnerabilities that arise without replay protection mechanisms

---

## 🖥 GUI Interface

<img width="1255" height="810" alt="image" src="https://github.com/user-attachments/assets/b25252ab-761f-49ac-89a2-4d2e5b58aa69" />

- Clean and modern Tkinter-based interface
- Sidebar navigation for:
  - PKI operations
  - Cryptographic tools
  - Attack simulations
- Real-time, color-coded activity log
- Secure dialogs for username and password input

---

## 🛠 Installation

### Prerequisites

- Python 3.8+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/CryptyPKI.git
cd CryptyPKI

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py
```

---

## 📁 File Structure

```
CryptyPKI/
├── main.py                  # Entry point, initializes environment and launches GUI
├── gui.py                   # Tkinter GUI — layout, sidebar, activity log
├── requirements.txt
│
├── pki/
│   ├── ca.py                # Root CA creation and loading
│   ├── user.py              # User key pair and CSR generation
│   ├── certificate.py       # Certificate issuance
│   ├── validation.py        # Certificate validation
│   └── crl.py               # Certificate Revocation List
│
├── crypto/
│   ├── hybrid.py            # AES-256-GCM + RSA-OAEP encrypt/decrypt
│   └── signing.py           # RSA-PSS file signing and verification
│
├── attacks/
│   ├── mitm_simulation.py   # MITM attack demo
│   └── replay_attack.py     # Replay attack demo + nonce tracking
│
└── AppData/                 # Auto-generated at runtime
    ├── root_ca/             # CA key and certificate
    ├── users/               # User keys, CSRs, certificates
    └── crl/                 # Revocation list and used nonces
```

---

## 📅 Development Timeline

```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "primaryColor": "#2563eb",
    "primaryTextColor": "#ffffff",
    "primaryBorderColor": "#1d4ed8",
    "secondaryColor": "#1d4ed8",
    "tertiaryColor": "#1e40af",
    "sectionBkgColor": "#1e3a5f",
    "altSectionBkgColor": "#162032",
    "taskBkgColor": "#2563eb",
    "taskBorderColor": "#1d4ed8",
    "taskTextColor": "#ffffff",
    "activeTaskBkgColor": "#3b82f6",
    "activeTaskBorderColor": "#60a5fa",
    "gridColor": "#30363d",
    "todayLineColor": "#60a5fa",
    "fontFamily": "Segoe UI, sans-serif"
  }
}}%%
gantt
    title CryptyPKI Development Timeline
    dateFormat  YYYY-MM-DD
    section Project Setup
    Environment & dependencies       :a1, 2026-02-01, 3d
    Project structure & main.py      :a2, after a1, 2d

    section PKI Core
    Root CA (ca.py)                  :b1, after a2, 3d
    User keys & CSR (user.py)        :b2, after b1, 2d
    Certificate issuance (cert.py)   :b3, after b2, 2d
    Validation (validation.py)       :b4, after b3, 2d
    CRL & revocation (crl.py)        :b5, after b4, 1d

    section Cryptography
    Hybrid encryption (hybrid.py)    :c1, after b3, 3d
    Digital signing (signing.py)     :c2, after c1, 2d

    section Attack Simulations
    Replay attack (replay_attack.py) :d1, after c1, 2d
    MITM simulation (mitm_sim.py)    :d2, after d1, 2d

    section GUI
    Tkinter layout & sidebar (gui.py):e1, after b5, 3d
    PKI buttons integration          :e2, after e1, 2d
    Crypto buttons integration       :e3, after e2, 2d
    Attack sim integration           :e4, after e3, 1d
    Polish & DPI/log styling         :e5, after e4, 2d

    section Finalization
    Testing & bug fixes              :f1, after e5, 3d
    README & documentation           :f2, after f1, 2026-03-05
```

---

## ⚙️ Technologies Used

- Python
- Tkinter (GUI)
- Cryptography libraries (RSA, AES, PKI operations)

---

## 📌 Disclaimer

CryptyPKI is intended for educational and demonstration purposes only.  
It should not be used as a production-grade security system.
