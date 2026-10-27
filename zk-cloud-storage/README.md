# ZK-CloudVault — Zero-Knowledge Cloud Storage with Client-Side Encryption

> A cybersecurity demonstration project for college faculty  
> **All encryption and decryption happens in the browser. The server never sees your password or encryption key.**

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        BROWSER                               │
│                                                              │
│  ┌──────────┐   password+salt   ┌─────────────────────────┐ │
│  │  User    │ ──────────────▶   │  PBKDF2-SHA-256         │ │
│  │ Password │                   │  310,000 iterations     │ │
│  └──────────┘                   │  → 256-bit AES key      │ │
│                                 └──────────┬──────────────┘ │
│  ┌──────────┐   plaintext                  │ key            │
│  │  File    │ ─────────────────────────────▼──────────────┐ │
│  │ (input)  │              AES-256-GCM encrypt             │ │
│  └──────────┘              random 96-bit nonce             │ │
│                            ─────────────────               │ │
│                            ciphertext + auth tag            │ │
│                                 └──────────────────────────┘ │
│                                           │                  │
│                        password NEVER ────X──▶ network       │
└───────────────────────────────────────────┼──────────────────┘
                                            │ (ciphertext + salt + iv only)
                                            ▼
┌──────────────────────────────────────────────────────────────┐
│                   FLASK SERVER                               │
│                                                              │
│   POST /api/upload   ──▶  stores encrypted blob to disk     │
│   GET  /api/files    ──▶  returns metadata list             │
│   GET  /api/files/ID ──▶  returns encrypted blob (base64)   │
│   DELETE /api/files/ID ▶  removes file                      │
│                                                              │
│   The server is BLIND to file contents — zero knowledge.    │
└──────────────────────────────────────────────────────────────┘
```

### Cryptographic Primitives

| Property          | Value                                    |
|-------------------|------------------------------------------|
| Encryption        | AES-256-GCM (authenticated encryption)   |
| Key derivation    | PBKDF2-SHA-256                           |
| KDF iterations    | 310,000 (OWASP 2023 recommendation)      |
| Salt              | 128-bit random (unique per file)         |
| Nonce / IV        | 96-bit random (unique per encryption)    |
| Authentication    | 128-bit GCM tag (tamper detection)       |
| Key storage       | Never stored — derived on demand         |
| Browser API       | `window.crypto.subtle` (Web Crypto API)  |

### Why AES-GCM?

AES-GCM is an *authenticated* encryption scheme. It produces a 128-bit authentication tag along with the ciphertext. When decrypting, the tag is verified before any plaintext is returned. This means:

- A **wrong password** → wrong key → tag mismatch → `DOMException: OperationError`  
- **Tampered ciphertext** → tag mismatch → same error  
- No partial plaintext is ever exposed on failure

---

## Prerequisites

- Python 3.10 or later
- pip

---

## Installation

```bash
# 1. Go to the project directory
cd "zk-cloud-storage"

# 2. (Recommended) Create a virtual environment
python -m venv venv

# 3. Activate it
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# macOS / Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

```bash
python app.py
```

Then open your browser at: **http://127.0.0.1:5000**

---

## Running Tests

```bash
pytest tests/ -v
```

Expected output: all tests pass (26 tests).

---

## Usage Walkthrough

### Encrypt & Upload a File

1. Click **"Drop a file here"** or drag any file onto the drop zone.
2. Enter a strong password in the **Encryption Password** field.
3. Click **"Encrypt & Upload"**.
4. The browser derives an AES-256 key using PBKDF2, encrypts the file with AES-256-GCM, then uploads the ciphertext to the server.
5. The **Cryptographic Details** panel shows the algorithm, KDF parameters, hex salt, and hex IV for the upload.

### Decrypt & Download a File

1. Find the file in the **Encrypted Files on Server** panel.
2. Click **Decrypt**.
3. Enter the password used during encryption.
4. The browser downloads the ciphertext, re-derives the key, decrypts, and triggers a file download.

### Demonstrating Wrong Password Failure

1. Click **Decrypt** on any file.
2. Enter an **incorrect** password.
3. Observe the red error: *"Decryption failed! The GCM authentication tag did not match."*
4. The info box explains that the wrong password produces the wrong AES key, causing the GCM authentication tag to fail before any plaintext is released.

---

## Project Structure

```
zk-cloud-storage/
├── app.py                  # Flask backend (zero-knowledge server)
├── requirements.txt        # Python dependencies
├── README.md
├── uploads/                # Encrypted blobs stored here (auto-created)
├── templates/
│   └── index.html          # Full dashboard (HTML + Jinja2)
├── static/
│   ├── css/
│   │   └── style.css       # Cybersecurity-themed dark dashboard
│   └── js/
│       ├── crypto.js       # Web Crypto API module (encrypt/decrypt)
│       └── app.js          # UI controller
└── tests/
    └── test_app.py         # pytest backend tests
```

---

## Security Notes & Limitations

| Topic | Detail |
|-------|--------|
| Transport | This demo uses HTTP locally. In production, **always use HTTPS (TLS)** to protect the ciphertext and metadata in transit. |
| Key management | The derived key lives only in `CryptoKey` objects inside the browser's WebCrypto context and is marked non-extractable. |
| Salt & IV | Not secret — stored alongside ciphertext as is standard for all authenticated encryption schemes. |
| Password in memory | The password string lives in a JS variable during the operation. The browser GC collects it. For higher assurance, zero the string after use. |
| File size limit | 64 MB configured; increase `MAX_CONTENT_LENGTH` in `app.py` if needed. |
| Storage | Local disk (demo). Replace with cloud blob storage (S3, GCS, Azure Blob) for production. |
| Authentication | No user login system — any browser can upload/delete. Add Flask-Login or OAuth for multi-user scenarios. |
| Rate limiting | Not implemented. Add `Flask-Limiter` for production. |

---

## Tech Stack

- **Frontend**: HTML5, CSS3, vanilla JavaScript, Web Crypto API  
- **Backend**: Python 3, Flask 3  
- **Encryption**: AES-256-GCM via `window.crypto.subtle`  
- **KDF**: PBKDF2-SHA-256 via `window.crypto.subtle`  
- **Testing**: pytest, pytest-flask  
