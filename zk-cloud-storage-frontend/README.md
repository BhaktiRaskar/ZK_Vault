# ZK-CloudVault — Frontend

> Zero-Knowledge Cloud Storage · AES-256-GCM · Client-Side Encryption  
> All encryption and decryption happen **entirely in the browser**. The server never sees your password or key.

---

## What this repository contains

```
zk-cloud-storage-frontend/
├── index.html               Main dashboard UI
├── static/
│   ├── css/
│   │   └── style.css        Cybersecurity-themed dark dashboard
│   └── js/
│       ├── config.js        ← API base URL — edit this for production
│       ├── crypto.js        Web Crypto API module (AES-256-GCM + PBKDF2)
│       └── app.js           UI controller
└── README.md
```

---

## Quick start (local development)

The backend and this static frontend are separate projects. Start both servers in separate PowerShell terminals. For the recommended setup, open the static frontend at `http://127.0.0.1:8080`. When both project folders are side by side as shown below, the backend's `http://127.0.0.1:5000/` page also serves the dashboard and its CSS/JavaScript from this frontend folder.

### 1. Start the backend

In a PowerShell terminal:

```powershell
Set-Location "C:\Users\bhakt\Crypto Project\zk-cloud-storage-backend"
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

The API starts at `http://127.0.0.1:5000`. The backend's default CORS origins allow both `http://127.0.0.1:8080` and `http://localhost:8080`.

### 2. Serve the frontend

In a second PowerShell terminal:

```powershell
Set-Location "C:\Users\bhakt\Crypto Project\zk-cloud-storage-frontend"
py -m http.server 8080 --bind 127.0.0.1
```

Open **http://127.0.0.1:8080**. Serving from the frontend directory ensures its CSS and JavaScript modules resolve correctly. The backend root page is also available locally at **http://127.0.0.1:5000/**.

The API base URL is configured in `static/js/config.js`. Keep it set to the backend's public URL when deploying; it is a URL, not a secret. If the frontend origin changes, configure the backend's `ALLOWED_ORIGINS` to include that exact origin.

### 3. Connecting to a deployed backend

Change `API_BASE_URL` in `static/js/config.js`:

```js
const CONFIG = {
  API_BASE_URL: "https://your-backend-domain.com",
};
```

Make sure the backend has CORS configured to allow your frontend's origin.

---

## Cryptographic design

| Property        | Value                                      |
|-----------------|--------------------------------------------|
| Encryption      | AES-256-GCM (authenticated encryption)     |
| Key derivation  | PBKDF2-SHA-256, 310 000 iterations          |
| Salt            | 128-bit random per file                    |
| Nonce / IV      | 96-bit random per encryption               |
| Auth tag        | 128-bit GCM tag (tamper detection)         |
| Browser API     | `window.crypto.subtle` (Web Crypto API)    |

The password **never leaves the browser**. The backend stores only encrypted blobs.

---

## Backend

The separate `zk-cloud-storage-backend` project provides the Flask API. The frontend uses its existing `/api/upload`, `/api/files`, `/api/files/<id>`, `/api/files/<id>/download`, and `/api/files/<id>` DELETE endpoints.
