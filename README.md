# CryptyPKI

**CryptyPKI** is a modern Python GUI application that demonstrates core Public Key Infrastructure (PKI) operations, hybrid encryption, digital signatures, and simulated cryptographic attacks.

---

## 🚀 Features

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

- MITM (Man-in-the-Middle) Simulation  
  Demonstrates the risks of unverified or spoofed certificates

- Replay Attack Simulation  
  Shows vulnerabilities that arise without replay protection mechanisms

---

## 🖥 GUI Interface

<img width="1255" height="810" alt="image" src="https://github.com/user-attachments/assets/3932d023-f63a-407d-9064-f2c3cda1a24a" />

- Clean and modern Tkinter-based interface
- Sidebar navigation for:
  - PKI operations
  - Cryptographic tools
  - Attack simulations
- Real-time, color-coded activity log
- Secure dialogs for username and password input

---

## ⚙️ Technologies Used

- Python
- Tkinter (GUI)
- Cryptography libraries (RSA, AES, PKI operations)

---

## 📌 Disclaimer

CryptyPKI is intended for educational and demonstration purposes only.  
It should not be used as a production-grade security system.
