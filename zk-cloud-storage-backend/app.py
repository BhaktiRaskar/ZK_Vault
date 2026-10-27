"""
Zero-Knowledge Cloud Storage - Flask Backend
============================================
The server stores ONLY encrypted blobs. It never sees passwords or keys.
All encryption/decryption happens in the browser via the Web Crypto API.

Environment variables (create a .env file locally, or set in your host):
  SECRET_KEY        – Flask session signing key (generate with: python -c "import secrets; print(secrets.token_hex(32))")
  ALLOWED_ORIGINS   – Comma-separated list of allowed CORS origins
                      e.g. "http://localhost:8080,https://your-frontend.com"
                      Defaults to localhost and 127.0.0.1 on port 8080 (local dev only)
  UPLOAD_FOLDER     – Optional path override for the uploads directory
  MAX_UPLOAD_MB     – Optional max upload size in MB (default: 64)
"""

import os
import json
import uuid
import base64
import struct
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template, abort, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER",
    os.path.join(os.path.dirname(__file__), "uploads")
)
METADATA_FILE = os.path.join(UPLOAD_FOLDER, "_metadata.json")
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", 64)) * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"]       = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"]  = MAX_CONTENT_LENGTH
# SECRET_KEY must be set in the environment for production.
# Falls back to a random key for local dev (sessions won't persist across restarts).
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Read allowed origins from the environment.
# NEVER allow "*" in production — that would let any website call your API.
_raw_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://127.0.0.1:8080,http://localhost:8080"
)
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=False)

# ---------------------------------------------------------------------------
# Metadata helpers  (stored in uploads/_metadata.json)
# ---------------------------------------------------------------------------

def _load_metadata() -> dict:
    if not os.path.exists(METADATA_FILE):
        return {}
    with open(METADATA_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_metadata(data: dict) -> None:
    with open(METADATA_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """
    Receive an encrypted file blob from the browser.

    Expected multipart fields:
      - file           : the encrypted binary blob (raw AES-GCM ciphertext, no container header)
      - filename       : original filename  e.g. "photo.jpg"
      - mime_type      : original MIME type e.g. "image/jpeg"  (optional, defaults to octet-stream)
      - encrypted_size : byte length of the encrypted blob (informational)
      - salt           : hex-encoded PBKDF2 salt  (NOT secret – needed to re-derive key)
      - iv             : hex-encoded AES-GCM nonce (NOT secret)
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    blob = request.files["file"]
    original_name = request.form.get("filename", blob.filename or "unknown")
    mime_type     = request.form.get("mime_type", "application/octet-stream")
    salt_hex      = request.form.get("salt", "")
    iv_hex        = request.form.get("iv", "")

    if not salt_hex or not iv_hex:
        return jsonify({"error": "Encryption metadata (salt / iv) missing"}), 400

    # Store the raw original name for display; also keep a sanitised name for disk use.
    raw_name  = original_name                              # preserved exactly
    safe_name = secure_filename(original_name) or "encrypted_file"

    file_id     = str(uuid.uuid4())
    stored_name = f"{file_id}.enc"
    dest_path   = os.path.join(UPLOAD_FOLDER, stored_name)

    blob.save(dest_path)
    encrypted_size = os.path.getsize(dest_path)

    metadata = _load_metadata()
    metadata[file_id] = {
        "id":               file_id,
        "original_name":    safe_name,   # sanitised (safe for Content-Disposition)
        "original_name_raw": raw_name,   # exact name the user uploaded (for display & decrypt)
        "mime_type":        mime_type,   # preserved for correct Blob reconstruction on decrypt
        "stored_name":      stored_name,
        "salt":             salt_hex,
        "iv":               iv_hex,
        "encrypted_size":   encrypted_size,
        "uploaded_at":      datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    _save_metadata(metadata)

    return jsonify({
        "success":      True,
        "file_id":      file_id,
        "original_name": safe_name,
        "original_name_raw": raw_name,
        "mime_type":    mime_type,
        "encrypted_size": encrypted_size,
    }), 201


@app.route("/api/files", methods=["GET"])
def list_files():
    """Return metadata for all stored (encrypted) files."""
    metadata = _load_metadata()
    files = list(metadata.values())
    # Sort newest first
    files.sort(key=lambda f: f.get("uploaded_at", ""), reverse=True)
    return jsonify({"files": files})


@app.route("/api/files/<file_id>", methods=["GET"])
def download_file(file_id: str):
    """
    Return metadata + base64-encoded ciphertext (RAW, no container header).
    Used by the in-browser Decrypt & Download modal (server supplies all metadata).
    Now includes mime_type and original_name_raw so the browser can reconstruct
    the exact original file with the correct name and MIME type.
    """
    metadata = _load_metadata()
    if file_id not in metadata:
        abort(404)

    info = metadata[file_id]
    stored_path = os.path.join(UPLOAD_FOLDER, info["stored_name"])
    if not os.path.exists(stored_path):
        abort(404)

    with open(stored_path, "rb") as fh:
        encrypted_data = fh.read()

    return jsonify({
        "file_id":           file_id,
        "original_name":     info.get("original_name_raw") or info["original_name"],
        "mime_type":         info.get("mime_type", "application/octet-stream"),
        "salt":              info["salt"],
        "iv":                info["iv"],
        "encrypted_size":    info["encrypted_size"],
        "data":              base64.b64encode(encrypted_data).decode("ascii"),
    })


@app.route("/api/files/<file_id>/download", methods=["GET"])
def download_enc_container(file_id: str):
    """
    Stream a self-contained ZKCV v2 .enc container to the browser.

    v2 header layout:
      Bytes  0- 3 : magic "ZKCV"
      Bytes  4- 5 : version = 2  (little-endian uint16)
      Bytes  6-21 : PBKDF2 salt  (16 bytes)
      Bytes 22-33 : AES-GCM IV   (12 bytes)
      Bytes 34-35 : filename length L_name (LE uint16)
      Bytes 36    : original filename in UTF-8 (L_name bytes)
      Bytes 36+L_name .. 37+L_name : MIME length L_mime (LE uint16)
      Bytes 38+L_name              : MIME type in UTF-8 (L_mime bytes)
      Bytes 38+L_name+L_mime       : AES-256-GCM ciphertext + 16-byte GCM tag

    The file is completely self-contained — the browser can decrypt it
    offline and will restore the original filename and MIME type exactly.
    """
    import struct

    metadata = _load_metadata()
    if file_id not in metadata:
        abort(404)

    info = metadata[file_id]
    stored_path = os.path.join(UPLOAD_FOLDER, info["stored_name"])
    if not os.path.exists(stored_path):
        abort(404)

    with open(stored_path, "rb") as fh:
        cipher_bytes = fh.read()

    # Use the raw (unmodified) original name if available, else fall back to sanitised
    orig_name = info.get("original_name_raw") or info["original_name"]
    mime_type = info.get("mime_type", "application/octet-stream")

    name_bytes = orig_name.encode("utf-8")
    mime_bytes = mime_type.encode("utf-8")
    salt       = bytes.fromhex(info["salt"])   # 16 bytes
    iv         = bytes.fromhex(info["iv"])     # 12 bytes

    container = (
        b"ZKCV"
        + struct.pack("<H", 2)                          # version 2
        + salt                                          # 16 bytes
        + iv                                            # 12 bytes
        + struct.pack("<H", len(name_bytes))            # filename length
        + name_bytes                                    # filename UTF-8
        + struct.pack("<H", len(mime_bytes))            # MIME length
        + mime_bytes                                    # MIME UTF-8
        + cipher_bytes                                  # ciphertext + GCM tag
    )

    # Safe ASCII filename for Content-Disposition (browsers are picky about non-ASCII)
    base_name = os.path.splitext(secure_filename(orig_name))[0] or "encrypted"
    dl_name   = base_name + ".enc"

    return Response(
        container,
        status=200,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{dl_name}"',
            "Content-Length":      str(len(container)),
            "X-Original-Filename": orig_name,
            "X-Original-Mime":     mime_type,
        },
    )


@app.route("/api/files/<file_id>", methods=["DELETE"])
def delete_file(file_id: str):
    """Delete an encrypted file and its metadata."""
    metadata = _load_metadata()
    if file_id not in metadata:
        abort(404)

    info = metadata.pop(file_id)
    stored_path = os.path.join(UPLOAD_FOLDER, info["stored_name"])
    if os.path.exists(stored_path):
        os.remove(stored_path)

    _save_metadata(metadata)
    return jsonify({"success": True, "deleted": file_id})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  Zero-Knowledge Cloud Storage  –  Flask Dev Server")
    print("  http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
