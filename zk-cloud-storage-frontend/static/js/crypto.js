/**
 * crypto.js  –  Zero-Knowledge Client-Side Encryption
 * =====================================================
 * Uses the browser's native Web Crypto API (SubtleCrypto).
 *
 * Algorithm : AES-256-GCM  (authenticated encryption)
 * KDF       : PBKDF2-SHA-256  (310,000 iterations – OWASP 2023 recommendation)
 * Salt      : 128-bit random  (unique per file)
 * IV/Nonce  : 96-bit random   (unique per encryption, as per NIST SP 800-38D)
 *
 * ─── Container format v2 (self-contained binary) ────────────────────────────
 *
 *  Offset  Length  Field
 *  ──────  ──────  ──────────────────────────────────────────────────────────
 *       0       4  Magic: ASCII "ZKCV"
 *       4       2  Version: 2 (little-endian uint16)
 *       6      16  PBKDF2 salt (random, 128-bit)
 *      22      12  AES-GCM IV / nonce (random, 96-bit)
 *      34       2  Filename length in bytes L_name (little-endian uint16)
 *      36    L_name Original filename, UTF-8 encoded (e.g. "photo.jpg")
 *   36+L_name  2  MIME type length in bytes L_mime (little-endian uint16)
 *   38+L_name L_mime MIME type, UTF-8 encoded (e.g. "image/jpeg")
 *   38+L_name+L_mime  … AES-256-GCM ciphertext + 16-byte GCM auth tag
 *
 * Total fixed header = 38 bytes + L_name + L_mime (both variable-length).
 * The file is completely self-contained — no server metadata needed to decrypt.
 *
 * ─── v1 backward compatibility ───────────────────────────────────────────────
 * v1 containers (version=1, fixed 34-byte header) are still readable.
 * The decrypted filename falls back to stripping ".enc" from the container
 * filename, and the MIME type falls back to "application/octet-stream".
 */

"use strict";

const ZKCrypto = (() => {

  // ─── Constants ───────────────────────────────────────────
  const ALGO       = "AES-GCM";
  const KEY_BITS   = 256;
  const PBKDF2_ALG = "PBKDF2";
  const HASH       = "SHA-256";
  const ITERATIONS = 310_000;   // OWASP 2023 recommendation
  const SALT_BYTES = 16;        // 128-bit salt
  const IV_BYTES   = 12;        // 96-bit nonce (NIST recommended for GCM)

  // Container magic and current version
  const MAGIC   = new Uint8Array([0x5A, 0x4B, 0x43, 0x56]); // "ZKCV"
  const VERSION = 2;

  // Fixed-size portion of v2 header (before variable fields)
  // magic(4) + version(2) + salt(16) + iv(12) + name_len(2) = 36 bytes
  // then mime_len(2) after the name bytes

  // ─── Utility: ArrayBuffer ↔ hex string ───────────────────

  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexToBuf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, 2 + i), 16);
    }
    return bytes.buffer;
  }

  const _te = new TextEncoder();
  const _td = new TextDecoder();

  // ─── Container encode (v2) ───────────────────────────────

  /**
   * Pack salt + iv + originalName + mimeType + ciphertext into one ArrayBuffer.
   *
   * @param {Uint8Array} saltBytes
   * @param {Uint8Array} ivBytes
   * @param {ArrayBuffer} cipherBuf
   * @param {string} originalName  – e.g. "photo.jpg"  (preserved across disk)
   * @param {string} mimeType      – e.g. "image/jpeg" (preserved across disk)
   * @returns {ArrayBuffer}
   */
  function encodeContainer(saltBytes, ivBytes, cipherBuf, originalName, mimeType) {
    const nameBytes = _te.encode(originalName || "");
    const mimeBytes = _te.encode(mimeType    || "application/octet-stream");

    // Total = 4+2+16+12+2+L_name+2+L_mime+N_cipher
    const totalLen = 4 + 2 + SALT_BYTES + IV_BYTES
                   + 2 + nameBytes.byteLength
                   + 2 + mimeBytes.byteLength
                   + cipherBuf.byteLength;

    const out = new Uint8Array(totalLen);
    const dv  = new DataView(out.buffer);
    let off = 0;

    // Magic
    out.set(MAGIC, off);                          off += 4;
    // Version (LE uint16)
    dv.setUint16(off, VERSION, /*LE=*/true);       off += 2;
    // Salt
    out.set(saltBytes, off);                       off += SALT_BYTES;
    // IV
    out.set(ivBytes, off);                         off += IV_BYTES;
    // Filename length + bytes
    dv.setUint16(off, nameBytes.byteLength, true); off += 2;
    out.set(nameBytes, off);                       off += nameBytes.byteLength;
    // MIME length + bytes
    dv.setUint16(off, mimeBytes.byteLength, true); off += 2;
    out.set(mimeBytes, off);                       off += mimeBytes.byteLength;
    // Ciphertext
    out.set(new Uint8Array(cipherBuf), off);

    return out.buffer;
  }

  // ─── Container decode (v1 + v2) ─────────────────────────

  /**
   * Decode a ZKCV container buffer.
   * Supports v1 (fixed 34-byte header, no filename/mime) and v2 (variable header).
   *
   * @param {ArrayBuffer} buf
   * @returns {{ saltHex, ivHex, cipherBuf, originalName, mimeType }}
   * @throws if magic invalid or version unsupported
   */
  function decodeContainer(buf) {
    const bytes = new Uint8Array(buf);
    const dv    = new DataView(buf);

    // Minimum size check (v1 fixed header + at least 1 ciphertext byte)
    if (bytes.byteLength < 35) {
      throw new Error("File is too small to be a valid .enc container.");
    }

    // Verify magic "ZKCV"
    if (bytes[0] !== MAGIC[0] || bytes[1] !== MAGIC[1] ||
        bytes[2] !== MAGIC[2] || bytes[3] !== MAGIC[3]) {
      throw new Error(
        "Not a ZKCV-format .enc file. This file was not encrypted by ZK-CloudVault, " +
        "or it was not downloaded as a self-contained .enc container from this app."
      );
    }

    const ver = dv.getUint16(4, /*LE=*/true);
    let off = 6;

    // Salt (16 bytes) — same in v1 and v2
    const saltHex = bufToHex(bytes.slice(off, off + SALT_BYTES).buffer);
    off += SALT_BYTES;

    // IV (12 bytes) — same in v1 and v2
    const ivHex = bufToHex(bytes.slice(off, off + IV_BYTES).buffer);
    off += IV_BYTES;
    // off is now 34 for both versions

    let originalName = "";
    let mimeType     = "application/octet-stream";

    if (ver === 1) {
      // v1: no filename/mime fields — ciphertext starts at byte 34
      // (no change to off)
    } else if (ver === 2) {
      // v2: variable-length filename then mime
      if (bytes.byteLength < off + 4) {
        throw new Error("Container header truncated (v2 name/mime fields missing).");
      }
      const nameLen = dv.getUint16(off, true); off += 2;
      if (bytes.byteLength < off + nameLen + 2) {
        throw new Error("Container header truncated (filename field incomplete).");
      }
      originalName = _td.decode(bytes.slice(off, off + nameLen)); off += nameLen;

      const mimeLen = dv.getUint16(off, true); off += 2;
      if (bytes.byteLength < off + mimeLen) {
        throw new Error("Container header truncated (MIME field incomplete).");
      }
      mimeType = _td.decode(bytes.slice(off, off + mimeLen)); off += mimeLen;
    } else {
      throw new Error(
        `Unsupported .enc container version ${ver}. ` +
        `This file requires a newer version of ZK-CloudVault.`
      );
    }

    // Everything from `off` onwards is the AES-GCM ciphertext + 16-byte tag
    if (off >= bytes.byteLength) {
      throw new Error("Container has no ciphertext — file may be truncated.");
    }
    // Use slice() not subarray() so the cipherBuf owns its own ArrayBuffer
    const cipherBuf = bytes.slice(off).buffer;

    return { saltHex, ivHex, cipherBuf, originalName, mimeType };
  }

  // ─── Derive a CryptoKey from a password + salt ───────────

  async function deriveKey(password, saltBuf) {
    const rawKey = await crypto.subtle.importKey(
      "raw",
      _te.encode(password),
      { name: PBKDF2_ALG },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name:       PBKDF2_ALG,
        salt:       saltBuf,    // must be the exact 16-byte ArrayBuffer, not a view offset
        iterations: ITERATIONS,
        hash:       HASH,
      },
      rawKey,
      { name: ALGO, length: KEY_BITS },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // ─── Encrypt ─────────────────────────────────────────────

  /**
   * Encrypts a file's raw bytes using a password.
   *
   * @param {ArrayBuffer} plainBuf      – raw file bytes (from FileReader)
   * @param {string}      password      – user-supplied passphrase
   * @param {string}      [originalName] – original filename e.g. "photo.jpg"
   * @param {string}      [mimeType]     – file MIME type e.g. "image/jpeg"
   * @returns {Promise<{
   *   cipherBuf:     ArrayBuffer,   raw ciphertext (no header) – for server upload
   *   containerBuf:  ArrayBuffer,   ZKCV v2 container – for .enc file download
   *   saltHex:       string,
   *   ivHex:         string,
   *   originalSize:  number,
   * }>}
   */
  async function encrypt(plainBuf, password, originalName = "", mimeType = "application/octet-stream") {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key  = await deriveKey(password, salt.buffer);

    const cipherBuf = await crypto.subtle.encrypt(
      { name: ALGO, iv },
      key,
      plainBuf
    );
    // cipherBuf = ciphertext ∥ 128-bit GCM auth tag (appended by SubtleCrypto)

    const containerBuf = encodeContainer(salt, iv, cipherBuf, originalName, mimeType);

    return {
      cipherBuf,
      containerBuf,
      saltHex:      bufToHex(salt.buffer),
      ivHex:        bufToHex(iv.buffer),
      originalSize: plainBuf.byteLength,
    };
  }

  // ─── Decrypt (server-metadata path) ──────────────────────

  /**
   * Decrypts a raw ciphertext using salt+iv supplied as hex strings.
   * Used by the "Decrypt from server" modal flow where metadata comes from the API.
   *
   * @param {ArrayBuffer} cipherBuf  – raw ciphertext + GCM tag (no container header)
   * @param {string}      password
   * @param {string}      saltHex    – 32 hex chars (16 bytes)
   * @param {string}      ivHex      – 24 hex chars (12 bytes)
   * @returns {Promise<ArrayBuffer>} – plaintext bytes
   * @throws DOMException("OperationError") on wrong password or tampered data
   */
  async function decrypt(cipherBuf, password, saltHex, ivHex) {
    // hexToBuf creates a fresh ArrayBuffer each time — no shared-buffer aliasing
    const saltBuf = hexToBuf(saltHex);  // 16-byte ArrayBuffer
    const ivArr   = new Uint8Array(hexToBuf(ivHex));  // 12-byte view
    const key     = await deriveKey(password, saltBuf);
    // GCM tag verification happens inside SubtleCrypto — throws OperationError on failure
    return crypto.subtle.decrypt({ name: ALGO, iv: ivArr }, key, cipherBuf);
  }

  // ─── Decrypt (local .enc container path) ─────────────────

  /**
   * Decrypts a self-contained ZKCV .enc container file loaded from disk.
   * Reads all parameters (salt, IV, filename, MIME) from the container header.
   * No server connection needed.
   *
   * @param {ArrayBuffer} containerBuf  – full bytes of the .enc file
   * @param {string}      password
   * @returns {Promise<{
   *   plainBuf:     ArrayBuffer,  – restored original file bytes
   *   originalName: string,       – original filename (e.g. "photo.jpg")
   *   mimeType:     string,       – original MIME type (e.g. "image/jpeg")
   *   saltHex:      string,
   *   ivHex:        string,
   * }>}
   * @throws if format invalid, version unsupported, or GCM tag fails (wrong password)
   */
  async function decryptContainer(containerBuf, password) {
    const { saltHex, ivHex, cipherBuf, originalName, mimeType } =
      decodeContainer(containerBuf);
    const plainBuf = await decrypt(cipherBuf, password, saltHex, ivHex);
    return { plainBuf, originalName, mimeType, saltHex, ivHex };
  }

  // ─── File helpers ─────────────────────────────────────────

  /** Read a File/Blob as an ArrayBuffer. */
  function readFileAsBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = e => resolve(e.target.result);
      reader.onerror = () => reject(new Error("FileReader error"));
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Compute SHA-256 of an ArrayBuffer using Web Crypto.
   * Returns a lowercase hex string.
   */
  async function sha256Hex(buf) {
    const hashBuf = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Trigger a browser file-save download.
   * Always uses a Blob — never converts binary data to a string.
   *
   * @param {ArrayBuffer|Blob} buf
   * @param {string}  filename  – name including correct extension, e.g. "photo.jpg"
   * @param {string}  [mimeType]
   */
  function downloadBuffer(buf, filename, mimeType = "application/octet-stream") {
    const blob = buf instanceof Blob ? buf : new Blob([buf], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.style.display = "none";
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
  }

  /** Format bytes as human-readable string. */
  function formatBytes(bytes) {
    if (bytes < 1024)       return bytes + " B";
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
  }

  /** Estimate password strength 0–4 for visual indicator. */
  function passwordStrength(pw) {
    if (!pw) return 0;
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw))   score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(4, score);
  }

  // ─── Public API ────────────────────────────────────────────
  return {
    encrypt,
    decrypt,
    decryptContainer,
    encodeContainer,
    decodeContainer,
    readFileAsBuffer,
    sha256Hex,
    downloadBuffer,
    formatBytes,
    passwordStrength,
    ALGO,
    KEY_BITS,
    ITERATIONS,
    PBKDF2_ALG,
    HASH,
    SALT_BYTES,
    IV_BYTES,
    VERSION,
  };

})();
