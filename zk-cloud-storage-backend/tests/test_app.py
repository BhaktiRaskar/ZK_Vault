"""
tests/test_app.py
=================
Backend tests for ZK-CloudVault Flask API.

Run with:
    pytest tests/ -v

Coverage:
  - Index route
  - Upload (success, missing fields, multiple files)
  - List files (empty, populated, field presence, newest-first)
  - Download JSON endpoint (base64 round-trip, 404)
  - Download .enc container (v2 header structure, byte-exact ciphertext)
  - Delete
  - Zero-knowledge server properties
  - MIME type and original filename preservation
  - Crypto round-trip: AES-256-GCM encrypt→decrypt with correct bytes
  - Wrong password fails (GCM tag mismatch)
  - Tampered ciphertext fails decryption
  - Container v2 byte-exact structure for PDF, JPEG, and text payloads
"""

import os
import json
import base64
import struct
import hashlib
import pytest
from io import BytesIO

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app as flask_app


# ─── Fixtures ────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr("app.METADATA_FILE", str(tmp_path / "_metadata.json"))
    flask_app.config["TESTING"] = True
    flask_app.config["UPLOAD_FOLDER"] = str(tmp_path)
    with flask_app.test_client() as c:
        yield c


def _make_upload(client, *,
                 filename      = "test.txt",
                 content       = b"fake-encrypted-data",
                 salt          = "aabbccddeeff00112233445566778899",
                 iv            = "001122334455667788990011",
                 mime_type     = "text/plain"):
    """POST a fake encrypted blob to /api/upload and return the response."""
    data = {
        "file":           (BytesIO(content), filename),
        "filename":       filename,
        "mime_type":      mime_type,
        "encrypted_size": str(len(content)),
        "salt":           salt,
        "iv":             iv,
    }
    return client.post("/api/upload", data=data, content_type="multipart/form-data")


# ─── Synthetic file payloads ─────────────────────────────────
# Real magic bytes so tests are realistic

PDF_PAYLOAD  = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n" + bytes(range(50))
JPEG_PAYLOAD = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" \
               + b"\xff\xd9" + bytes(range(80))
TEXT_PAYLOAD = b"Hello, world!\nThis is a plain text file.\nLine 3.\n"

# ─── Index route ─────────────────────────────────────────────

class TestIndex:
    def test_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"ZK-CloudVault" in r.data or b"Zero-Knowledge" in r.data

    def test_content_type_html(self, client):
        r = client.get("/")
        assert "text/html" in r.content_type


# ─── Upload ──────────────────────────────────────────────────

class TestUpload:
    def test_upload_success(self, client):
        r = _make_upload(client)
        assert r.status_code == 201
        body = r.get_json()
        assert body["success"] is True
        assert "file_id" in body
        assert body["original_name"] == "test.txt"

    def test_upload_creates_file_on_disk(self, client, tmp_path):
        r = _make_upload(client)
        fid = r.get_json()["file_id"]
        assert (tmp_path / f"{fid}.enc").exists()

    def test_upload_stores_all_metadata(self, client, tmp_path):
        r = _make_upload(
            client,
            filename="photo.jpg",
            salt="deadbeef" * 4,
            iv="cafebabe" * 3,
            mime_type="image/jpeg",
        )
        fid = r.get_json()["file_id"]
        meta = json.loads((tmp_path / "_metadata.json").read_text())
        entry = meta[fid]
        assert entry["salt"]      == "deadbeef" * 4
        assert entry["iv"]        == "cafebabe" * 3
        assert entry["mime_type"] == "image/jpeg"
        assert entry["original_name_raw"] == "photo.jpg"

    def test_upload_missing_file_field(self, client):
        r = client.post("/api/upload",
                        data={"salt": "aa", "iv": "bb"},
                        content_type="multipart/form-data")
        assert r.status_code == 400

    def test_upload_missing_salt(self, client):
        data = {"file": (BytesIO(b"x"), "f.txt"), "filename": "f.txt",
                "encrypted_size": "1", "iv": "001122334455667788990011"}
        r = client.post("/api/upload", data=data,
                        content_type="multipart/form-data")
        assert r.status_code == 400

    def test_upload_missing_iv(self, client):
        data = {"file": (BytesIO(b"x"), "f.txt"), "filename": "f.txt",
                "encrypted_size": "1", "salt": "aabbccddeeff00112233445566778899"}
        r = client.post("/api/upload", data=data,
                        content_type="multipart/form-data")
        assert r.status_code == 400

    def test_upload_multiple_unique_ids(self, client):
        ids = {_make_upload(client, filename=f"f{i}.bin").get_json()["file_id"]
               for i in range(4)}
        assert len(ids) == 4


# ─── List files ──────────────────────────────────────────────

class TestListFiles:
    def test_empty_list(self, client):
        assert client.get("/api/files").get_json()["files"] == []

    def test_lists_uploaded_file(self, client):
        _make_upload(client, filename="hello.txt")
        files = client.get("/api/files").get_json()["files"]
        assert len(files) == 1
        assert files[0]["original_name"] == "hello.txt"

    def test_required_fields_present(self, client):
        _make_upload(client)
        f = client.get("/api/files").get_json()["files"][0]
        for field in {"id", "original_name", "salt", "iv",
                      "encrypted_size", "uploaded_at"}:
            assert field in f, f"Missing field: {field}"

    def test_does_not_expose_file_content(self, client):
        _make_upload(client, content=b"top-secret-plaintext")
        assert b"top-secret-plaintext" not in client.get("/api/files").data

    def test_newest_first(self, client):
        _make_upload(client, filename="first.txt")
        _make_upload(client, filename="second.txt")
        files = client.get("/api/files").get_json()["files"]
        assert files[0]["original_name"] == "second.txt"


# ─── Download JSON endpoint ───────────────────────────────────

class TestDownloadJSON:
    def test_returns_required_fields(self, client):
        fid = _make_upload(client).get_json()["file_id"]
        body = client.get(f"/api/files/{fid}").get_json()
        for f in {"file_id", "original_name", "mime_type", "salt", "iv", "data"}:
            assert f in body, f"Missing: {f}"

    def test_mime_type_returned(self, client):
        fid = _make_upload(client, mime_type="application/pdf",
                           filename="doc.pdf").get_json()["file_id"]
        body = client.get(f"/api/files/{fid}").get_json()
        assert body["mime_type"] == "application/pdf"

    def test_original_name_returned(self, client):
        fid = _make_upload(client, filename="report.xlsx").get_json()["file_id"]
        body = client.get(f"/api/files/{fid}").get_json()
        assert body["original_name"] == "report.xlsx"

    def test_data_is_valid_base64(self, client):
        payload = b"\x01\x02\x03\x04" * 4
        fid = _make_upload(client, content=payload).get_json()["file_id"]
        decoded = base64.b64decode(client.get(f"/api/files/{fid}").get_json()["data"])
        assert decoded == payload

    def test_bytes_round_trip_exact(self, client):
        original = bytes(range(256))
        fid = _make_upload(client, content=original).get_json()["file_id"]
        decoded = base64.b64decode(client.get(f"/api/files/{fid}").get_json()["data"])
        assert decoded == original

    def test_not_found(self, client):
        assert client.get("/api/files/no-such-id").status_code == 404


# ─── Download .enc container (v2) ────────────────────────────

SALT_HEX = "aabbccddeeff00112233445566778899"
IV_HEX   = "001122334455667788990011"
SALT_B   = bytes.fromhex(SALT_HEX)   # 16 bytes
IV_B     = bytes.fromhex(IV_HEX)     # 12 bytes


class TestDownloadContainer:

    def _upload_and_get_container(self, client, *, filename, content,
                                  mime_type="application/octet-stream"):
        fid = _make_upload(client, filename=filename, content=content,
                           salt=SALT_HEX, iv=IV_HEX,
                           mime_type=mime_type).get_json()["file_id"]
        r = client.get(f"/api/files/{fid}/download")
        return fid, r

    def _parse_v2_container(self, data: bytes):
        """Parse a v2 ZKCV container and return its fields."""
        assert data[:4] == b"ZKCV"
        ver = struct.unpack_from("<H", data, 4)[0]
        assert ver == 2, f"Expected version 2, got {ver}"
        salt_b  = data[6:22]
        iv_b    = data[22:34]
        off     = 34
        name_len = struct.unpack_from("<H", data, off)[0]; off += 2
        name    = data[off : off + name_len].decode("utf-8"); off += name_len
        mime_len = struct.unpack_from("<H", data, off)[0]; off += 2
        mime    = data[off : off + mime_len].decode("utf-8"); off += mime_len
        cipher  = data[off:]
        return dict(salt=salt_b, iv=iv_b, name=name, mime=mime, cipher=cipher)

    # ── Status and headers ──

    def test_status_200(self, client):
        _, r = self._upload_and_get_container(client, filename="a.txt", content=b"x")
        assert r.status_code == 200

    def test_content_type_octet_stream(self, client):
        _, r = self._upload_and_get_container(client, filename="a.txt", content=b"x")
        assert "octet-stream" in r.content_type

    def test_content_disposition_attachment(self, client):
        _, r = self._upload_and_get_container(client, filename="report.pdf", content=b"x")
        cd = r.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert ".enc" in cd

    def test_not_found(self, client):
        assert client.get("/api/files/no-such-id/download").status_code == 404

    # ── Header structure ──

    def test_magic_bytes(self, client):
        _, r = self._upload_and_get_container(client, filename="f.bin", content=b"abc")
        assert r.data[:4] == b"ZKCV"

    def test_version_is_2(self, client):
        _, r = self._upload_and_get_container(client, filename="f.bin", content=b"abc")
        assert struct.unpack_from("<H", r.data, 4)[0] == 2

    def test_salt_correct(self, client):
        _, r = self._upload_and_get_container(client, filename="f.bin", content=b"abc")
        assert r.data[6:22] == SALT_B

    def test_iv_correct(self, client):
        _, r = self._upload_and_get_container(client, filename="f.bin", content=b"abc")
        assert r.data[22:34] == IV_B

    def test_filename_embedded(self, client):
        _, r = self._upload_and_get_container(client, filename="photo.jpg", content=b"abc")
        parsed = self._parse_v2_container(r.data)
        assert parsed["name"] == "photo.jpg"

    def test_mime_type_embedded(self, client):
        _, r = self._upload_and_get_container(client, filename="doc.pdf", content=b"abc",
                                              mime_type="application/pdf")
        parsed = self._parse_v2_container(r.data)
        assert parsed["mime"] == "application/pdf"

    def test_ciphertext_correct(self, client):
        payload = b"the-raw-ciphertext-bytes"
        _, r = self._upload_and_get_container(client, filename="f.bin", content=payload)
        parsed = self._parse_v2_container(r.data)
        assert parsed["cipher"] == payload

    def test_total_length_correct(self, client):
        payload = b"A" * 100
        name_b  = b"test_file.txt"
        mime_b  = b"text/plain"
        _, r = self._upload_and_get_container(client, filename="test_file.txt",
                                              content=payload, mime_type="text/plain")
        # 4+2+16+12+2+len(name)+2+len(mime)+100
        expected = 4+2+16+12 + 2+len(name_b) + 2+len(mime_b) + 100
        assert len(r.data) == expected

    # ── Byte-exact round-trips for real file types ──

    def _verify_round_trip(self, client, filename, content, mime_type):
        """Upload content, download container, parse, confirm ciphertext exact."""
        fid = _make_upload(client, filename=filename, content=content,
                           salt=SALT_HEX, iv=IV_HEX,
                           mime_type=mime_type).get_json()["file_id"]
        data = client.get(f"/api/files/{fid}/download").data
        parsed = self._parse_v2_container(data)
        # Filename preserved
        assert parsed["name"] == filename, \
            f"Filename mismatch: stored {parsed['name']!r}, expected {filename!r}"
        # MIME type preserved
        assert parsed["mime"] == mime_type, \
            f"MIME mismatch: stored {parsed['mime']!r}, expected {mime_type!r}"
        # Salt and IV correct
        assert parsed["salt"] == SALT_B
        assert parsed["iv"]   == IV_B
        # Ciphertext bytes are byte-for-byte identical
        assert parsed["cipher"] == content, \
            f"Ciphertext mismatch: {len(parsed['cipher'])} vs {len(content)} bytes"
        # SHA-256 double-check
        assert hashlib.sha256(parsed["cipher"]).digest() == hashlib.sha256(content).digest()

    def test_pdf_round_trip(self, client):
        self._verify_round_trip(client, "document.pdf", PDF_PAYLOAD, "application/pdf")

    def test_jpeg_round_trip(self, client):
        self._verify_round_trip(client, "photo.jpg", JPEG_PAYLOAD, "image/jpeg")

    def test_text_round_trip(self, client):
        self._verify_round_trip(client, "notes.txt", TEXT_PAYLOAD, "text/plain")

    def test_binary_round_trip(self, client):
        """Arbitrary binary data (all 256 byte values) must survive unchanged."""
        payload = bytes(range(256)) * 4   # 1024 bytes, all byte values
        self._verify_round_trip(client, "binary.bin", payload,
                                "application/octet-stream")

    def test_original_name_preserved_in_json_endpoint(self, client):
        """Server-decrypt modal path: JSON endpoint returns the raw original name
        exactly as uploaded so the browser can restore the correct filename."""
        fid = _make_upload(client, filename="My Report.pdf",
                           mime_type="application/pdf",
                           content=b"fake").get_json()["file_id"]
        body = client.get(f"/api/files/{fid}").get_json()
        # original_name_raw is returned — spaces and all, so the restored file
        # downloads as "My Report.pdf" not "My_Report.pdf"
        assert body["original_name"] == "My Report.pdf"
        assert body["mime_type"]     == "application/pdf"

    def test_full_structure_round_trip(self, client):
        """Comprehensive parse: upload → container → parse every field."""
        payload  = bytes(range(50))
        filename = "archive.tar.gz"
        mime     = "application/gzip"
        fid = _make_upload(client, filename=filename, content=payload,
                           salt=SALT_HEX, iv=IV_HEX,
                           mime_type=mime).get_json()["file_id"]
        data = client.get(f"/api/files/{fid}/download").data
        assert data[:4]    == b"ZKCV"
        assert struct.unpack_from("<H", data, 4)[0] == 2
        assert data[6:22]  == SALT_B
        assert data[22:34] == IV_B
        parsed = self._parse_v2_container(data)
        assert parsed["name"]   == filename
        assert parsed["mime"]   == mime
        assert parsed["cipher"] == payload


# ─── Delete ──────────────────────────────────────────────────

class TestDelete:
    def test_delete_removes_file(self, client):
        fid = _make_upload(client).get_json()["file_id"]
        assert client.delete(f"/api/files/{fid}").get_json()["success"] is True
        assert client.get(f"/api/files/{fid}").status_code == 404

    def test_delete_removes_from_list(self, client):
        fid = _make_upload(client).get_json()["file_id"]
        client.delete(f"/api/files/{fid}")
        ids = [f["id"] for f in client.get("/api/files").get_json()["files"]]
        assert fid not in ids

    def test_delete_not_found(self, client):
        assert client.delete("/api/files/no-such-id").status_code == 404


# ─── Zero-knowledge server properties ────────────────────────

class TestZeroKnowledge:

    def test_password_never_stored(self, client):
        """Server must ignore any 'password' field in the upload."""
        data = {
            "file":           (BytesIO(b"cipher"), "secret.txt"),
            "filename":       "secret.txt",
            "mime_type":      "text/plain",
            "encrypted_size": "6",
            "salt":           "aabb" * 8,
            "iv":             "ccdd" * 6,
            "password":       "supersecret",   # must be silently ignored
        }
        r = client.post("/api/upload", data=data, content_type="multipart/form-data")
        assert r.status_code == 201
        fid  = r.get_json()["file_id"]
        body = client.get(f"/api/files/{fid}").get_json()
        assert "password" not in body

    def test_server_stores_only_what_was_uploaded(self, client):
        """
        The server is a transparent pass-through.
        Downloaded bytes must equal uploaded bytes exactly.
        If the server attempted to decrypt or re-encode the data,
        this assertion would fail.
        """
        plaintext = b"the-quick-brown-fox"  # caller treats this as ciphertext
        fid   = _make_upload(client, content=plaintext).get_json()["file_id"]
        body  = client.get(f"/api/files/{fid}").get_json()
        assert base64.b64decode(body["data"]) == plaintext

    def test_listing_does_not_expose_content(self, client):
        _make_upload(client, content=b"top-secret-plaintext-bytes")
        assert b"top-secret-plaintext-bytes" not in client.get("/api/files").data


# ─── Crypto correctness (Python-side AES-256-GCM simulation) ─

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _hashes
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@pytest.mark.skipif(not _CRYPTO_AVAILABLE,
                    reason="cryptography package not installed")
class TestCryptoRoundTrip:
    """
    These tests use the 'cryptography' library to perform the SAME operations
    as the browser's Web Crypto API (PBKDF2-SHA256 + AES-256-GCM) and verify
    that:
      1. Encrypting then decrypting produces byte-identical plaintext.
      2. The correct password always succeeds.
      3. A wrong password raises an authentication failure (GCM tag mismatch).
      4. A tampered ciphertext raises an authentication failure.
      5. All three file types (PDF, JPEG, text) round-trip exactly.
    """

    ITERATIONS = 310_000

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(password)

    def _encrypt(self, plaintext: bytes, password: str):
        import os
        salt = os.urandom(16)
        iv   = os.urandom(12)
        key  = self._derive_key(password.encode(), salt)
        aesgcm     = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)  # no AAD
        return ciphertext, salt, iv

    def _decrypt(self, ciphertext: bytes, password: str, salt: bytes, iv: bytes):
        key    = self._derive_key(password.encode(), salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, None)

    # ── Round-trip ──

    def _roundtrip(self, plaintext: bytes, password: str):
        ciphertext, salt, iv = self._encrypt(plaintext, password)
        # Ciphertext must not equal plaintext
        assert ciphertext[:len(plaintext)] != plaintext
        # Decrypted bytes must be byte-for-byte identical
        recovered = self._decrypt(ciphertext, password, salt, iv)
        assert recovered == plaintext, \
            f"Round-trip failed: {len(recovered)} vs {len(plaintext)} bytes"
        # SHA-256 hash of original and recovered must match
        assert hashlib.sha256(recovered).digest() == hashlib.sha256(plaintext).digest()
        return recovered

    def test_text_file_round_trip(self):
        self._roundtrip(TEXT_PAYLOAD, "StrongPass123!")

    def test_pdf_file_round_trip(self):
        self._roundtrip(PDF_PAYLOAD, "P@ssw0rd#2024")

    def test_jpeg_file_round_trip(self):
        self._roundtrip(JPEG_PAYLOAD, "my_secret_key")

    def test_binary_all_bytes_round_trip(self):
        """All 256 byte values in the plaintext must survive unchanged."""
        data = bytes(range(256)) * 8   # 2048 bytes
        self._roundtrip(data, "AnotherPassword99")

    def test_original_bytes_not_modified(self):
        """Recovered bytes must be identical to original, not ciphertext."""
        original = b"This is original content. Do not corrupt me."
        ciphertext, salt, iv = self._encrypt(original, "pass")
        recovered = self._decrypt(ciphertext, "pass", salt, iv)
        # Byte-level identity check
        assert recovered == original
        # Make sure it's not the ciphertext being returned
        assert recovered != ciphertext[:len(original)]

    # ── Wrong password must fail ──

    def test_wrong_password_fails(self):
        """
        PBKDF2 with wrong password → wrong AES key → GCM tag mismatch.
        cryptography raises InvalidTag; Web Crypto raises DOMException(OperationError).
        No plaintext must be released.
        """
        from cryptography.exceptions import InvalidTag
        ciphertext, salt, iv = self._encrypt(TEXT_PAYLOAD, "correct-password")
        with pytest.raises(InvalidTag):
            self._decrypt(ciphertext, "WRONG-password", salt, iv)

    def test_empty_password_fails_with_correct_nonempty(self):
        from cryptography.exceptions import InvalidTag
        ciphertext, salt, iv = self._encrypt(TEXT_PAYLOAD, "somepassword")
        with pytest.raises(InvalidTag):
            self._decrypt(ciphertext, "", salt, iv)

    def test_password_with_unicode_round_trips(self):
        """Unicode passwords must work consistently."""
        self._roundtrip(TEXT_PAYLOAD, "pässwört_日本語_123")

    # ── Tampered ciphertext must fail ──

    def test_tampered_ciphertext_fails(self):
        """
        Flipping a single bit in the ciphertext must cause GCM auth failure.
        This verifies the integrity guarantee of authenticated encryption.
        """
        from cryptography.exceptions import InvalidTag
        ciphertext, salt, iv = self._encrypt(PDF_PAYLOAD, "integrity-test")
        # Flip byte in the middle of the ciphertext (not in the tag at the end)
        mid = len(ciphertext) // 2
        tampered = bytearray(ciphertext)
        tampered[mid] ^= 0xFF   # flip all bits
        with pytest.raises(InvalidTag):
            self._decrypt(bytes(tampered), "integrity-test", salt, iv)

    def test_tampered_auth_tag_fails(self):
        """Flipping a bit in the GCM auth tag (last 16 bytes) must also fail."""
        from cryptography.exceptions import InvalidTag
        ciphertext, salt, iv = self._encrypt(TEXT_PAYLOAD, "auth-tag-test")
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01   # flip last byte of 16-byte GCM tag
        with pytest.raises(InvalidTag):
            self._decrypt(bytes(tampered), "auth-tag-test", salt, iv)

    def test_tampered_iv_fails(self):
        """Using a different IV during decryption must cause auth failure."""
        from cryptography.exceptions import InvalidTag
        import os
        ciphertext, salt, iv = self._encrypt(JPEG_PAYLOAD, "iv-test")
        wrong_iv = os.urandom(12)
        # Ensure it's actually different
        while wrong_iv == iv:
            wrong_iv = os.urandom(12)
        with pytest.raises(InvalidTag):
            self._decrypt(ciphertext, "iv-test", salt, wrong_iv)

    def test_correct_password_always_succeeds(self):
        """Same password, same salt, same IV → always succeeds deterministically."""
        import os
        password   = "deterministic-test-password"
        salt       = os.urandom(16)
        iv         = os.urandom(12)
        key        = self._derive_key(password.encode(), salt)
        aesgcm     = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, TEXT_PAYLOAD, None)
        # Decrypt three times — must always produce identical plaintext
        for _ in range(3):
            recovered = aesgcm.decrypt(iv, ciphertext, None)
            assert recovered == TEXT_PAYLOAD
