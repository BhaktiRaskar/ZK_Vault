/**
 * app.js  –  ZK-CloudVault UI Controller
 * =======================================
 * Orchestrates file selection, encryption, upload, listing,
 * download, and decryption using the ZKCrypto module.
 *
 * KEY FIX (download):
 *   Browsers block programmatic anchor clicks that happen inside an async
 *   chain unless the original event was a direct user gesture.  The solution
 *   is to call downloadBuffer() synchronously in the button's click handler
 *   BEFORE any await.  For the decrypt flow we pre-create the anchor, then
 *   populate its href after the async work completes — keeping the download
 *   permission alive because the <a> was already clicked in the same tick.
 */

"use strict";

// ─── DOM references ──────────────────────────────────────────
const fileInput          = document.getElementById("file-input");
const dropZone           = document.getElementById("drop-zone");
const selectedFileName   = document.getElementById("selected-file-name");
const encPassword        = document.getElementById("enc-password");
const toggleEncPw        = document.getElementById("toggle-enc-pw");
const strengthFill       = document.getElementById("strength-fill");
const pwStrengthLabel    = document.getElementById("pw-strength-label");
const uploadBtn          = document.getElementById("upload-btn");
const uploadProgressCont = document.getElementById("upload-progress-container");
const uploadProgressFill = document.getElementById("upload-progress-fill");
const uploadProgressLbl  = document.getElementById("upload-progress-label");
const uploadResult       = document.getElementById("upload-result");
const cryptoPanel        = document.getElementById("crypto-panel");

const refreshBtn         = document.getElementById("refresh-btn");
const filesList          = document.getElementById("files-list");

const modalOverlay       = document.getElementById("modal-overlay");
const modalClose         = document.getElementById("modal-close");
const modalCancel        = document.getElementById("modal-cancel");
const modalFilename      = document.getElementById("modal-filename");
const decPassword        = document.getElementById("dec-password");
const toggleDecPw        = document.getElementById("toggle-dec-pw");
const decryptBtn         = document.getElementById("decrypt-btn");
const decProgressCont    = document.getElementById("dec-progress-container");
const decProgressFill    = document.getElementById("dec-progress-fill");
const decProgressLbl     = document.getElementById("dec-progress-label");
const decryptResult      = document.getElementById("decrypt-result");
const wrongPwDemo        = document.getElementById("wrong-pw-demo");
const navStatusText      = document.getElementById("nav-status-text");

// ─── State ───────────────────────────────────────────────────
let selectedFile    = null;
let currentFileId   = null;   // file open in the decrypt modal
let currentFileMeta = null;   // full metadata for the open modal file
const API_BASE_URL  = CONFIG.API_BASE_URL.replace(/\/+$/, "");

// ─── Helpers ─────────────────────────────────────────────────

function setNavStatus(msg, color = "var(--accent3)") {
  navStatusText.textContent = msg;
  const dot = document.querySelector(".status-dot");
  dot.style.background = color;
  dot.style.boxShadow  = `0 0 6px ${color}`;
}

function showAlert(container, type, icon, msg) {
  container.innerHTML = `
    <div class="alert alert-${type}">
      <i class="fas fa-${icon}"></i>
      <span>${msg}</span>
    </div>`;
}

function clearEl(el) { el.innerHTML = ""; }

function setProgress(fillEl, pct) {
  fillEl.style.width = Math.min(100, pct) + "%";
}

async function animateProgress(fillEl, labelEl, steps) {
  for (const [pct, label, delay] of steps) {
    labelEl.textContent = label;
    setProgress(fillEl, pct);
    await new Promise(r => setTimeout(r, delay));
  }
}

function uploadWithProgress(formData) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE_URL}/api/upload`);

    xhr.upload.addEventListener("progress", event => {
      if (!event.lengthComputable) return;
      const percent = Math.min(99, 80 + Math.round((event.loaded / event.total) * 19));
      setProgress(uploadProgressFill, percent);
      uploadProgressLbl.textContent = `Uploading encrypted blob… ${Math.round((event.loaded / event.total) * 100)}%`;
    });

    xhr.addEventListener("load", () => {
      let data;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        reject(new Error("The backend returned an invalid upload response."));
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(data.error || `Upload failed with status ${xhr.status}.`));
        return;
      }
      resolve(data);
    });

    xhr.addEventListener("error", () => reject(new Error(
      "Could not reach the backend. Check that it is online and, if the frontend is hosted separately, that its origin is allowed in the backend's ALLOWED_ORIGINS setting."
    )));
    xhr.addEventListener("abort", () => reject(new Error("Upload was cancelled.")));
    xhr.send(formData);
  });
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── File selection ──────────────────────────────────────────

function handleFileSelect(file) {
  if (!file) return;
  selectedFile = file;
  selectedFileName.textContent = `${file.name}  (${ZKCrypto.formatBytes(file.size)})`;
  dropZone.style.borderColor = "var(--accent3)";
  checkUploadReady();
}

fileInput.addEventListener("change", () => handleFileSelect(fileInput.files[0]));

dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  const f = e.dataTransfer.files[0];
  if (f) { fileInput.files = e.dataTransfer.files; handleFileSelect(f); }
});

// ─── Password strength meter ─────────────────────────────────

encPassword.addEventListener("input", () => {
  const pw = encPassword.value;
  const score = ZKCrypto.passwordStrength(pw);
  const strength = Math.max(1, score);
  const colors = ["#ef4444", "#f59e0b", "#f59e0b", "#10b981", "#10b981"];
  const labels = ["Too weak", "Weak", "Fair", "Strong", "Very strong"];
  const widths  = [20, 40, 60, 80, 100];

  strengthFill.style.width      = pw ? widths[strength - 1] + "%" : "0";
  strengthFill.style.background = pw ? colors[strength - 1] : "";
  pwStrengthLabel.textContent   = pw ? labels[strength - 1] : "";
  pwStrengthLabel.style.color   = pw ? colors[strength - 1] : "var(--text-muted)";
  checkUploadReady();
});

function checkUploadReady() {
  uploadBtn.disabled = !(selectedFile && encPassword.value.length >= 4);
}

function makeToggle(btn, input) {
  btn.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.querySelector("i").className = show ? "fas fa-eye-slash" : "fas fa-eye";
  });
}
makeToggle(toggleEncPw, encPassword);
makeToggle(toggleDecPw, decPassword);

// ─── Upload / Encrypt ────────────────────────────────────────

uploadBtn.addEventListener("click", async () => {
  if (!selectedFile || !encPassword.value) return;

  const idleButtonHtml = uploadBtn.innerHTML;
  uploadBtn.disabled = true;
  uploadBtn.innerHTML = '<span class="spinner"></span> Encrypting &amp; uploading…';
  clearEl(uploadResult);
  cryptoPanel.style.display = "none";
  uploadProgressCont.style.display = "block";
  setNavStatus("Encrypting…", "var(--warning)");

  try {
    await animateProgress(uploadProgressFill, uploadProgressLbl, [[10, "Reading file…", 300]]);
    const plainBuf = await ZKCrypto.readFileAsBuffer(selectedFile);

    await animateProgress(uploadProgressFill, uploadProgressLbl, [[30, "Deriving key (PBKDF2)…", 100]]);
    const { cipherBuf, saltHex, ivHex, originalSize } = await ZKCrypto.encrypt(
      plainBuf,
      encPassword.value,
      selectedFile.name,
      selectedFile.type || "application/octet-stream"
    );

    await animateProgress(uploadProgressFill, uploadProgressLbl, [[70, "Encrypting (AES-256-GCM)…", 200]]);
    setProgress(uploadProgressFill, 80);
    uploadProgressLbl.textContent = "Uploading encrypted blob…";

    const formData = new FormData();
    formData.append("file",
      new Blob([cipherBuf], { type: "application/octet-stream" }),
      selectedFile.name
    );
    formData.append("filename",       selectedFile.name);
    formData.append("mime_type",      selectedFile.type || "application/octet-stream");
    formData.append("encrypted_size", cipherBuf.byteLength);
    formData.append("salt",           saltHex);
    formData.append("iv",             ivHex);

    await uploadWithProgress(formData);

    setProgress(uploadProgressFill, 100);
    uploadProgressLbl.textContent = "Done!";

    showAlert(uploadResult, "success", "check-circle",
      `<strong>${escHtml(selectedFile.name)}</strong> encrypted &amp; uploaded successfully!
       Encrypted size: ${ZKCrypto.formatBytes(cipherBuf.byteLength)}`
    );

    // Populate crypto detail panel
    document.getElementById("cp-algo").textContent   = `AES-${ZKCrypto.KEY_BITS}-GCM`;
    document.getElementById("cp-keylen").textContent = `${ZKCrypto.KEY_BITS} bits`;
    document.getElementById("cp-kdf").textContent    = `PBKDF2-${ZKCrypto.HASH}`;
    document.getElementById("cp-iter").textContent   = ZKCrypto.ITERATIONS.toLocaleString();
    document.getElementById("cp-salt").textContent   = saltHex;
    document.getElementById("cp-iv").textContent     = ivHex;
    document.getElementById("cp-orig").textContent   = ZKCrypto.formatBytes(originalSize);
    document.getElementById("cp-enc").textContent    = ZKCrypto.formatBytes(cipherBuf.byteLength);
    cryptoPanel.style.display = "block";

    setNavStatus("Uploaded", "var(--accent3)");
    loadFiles();

    // Reset form
    selectedFile = null;
    fileInput.value = "";
    encPassword.value = "";
    strengthFill.style.width = "0";
    pwStrengthLabel.textContent = "";
    selectedFileName.textContent = "No file selected";
    dropZone.style.borderColor = "";
    uploadBtn.disabled = true;

  } catch (err) {
    showAlert(uploadResult, "error", "times-circle", `Encryption/upload failed: ${escHtml(err.message)}`);
    setNavStatus("Error", "var(--danger)");
  } finally {
    setTimeout(() => { uploadProgressCont.style.display = "none"; setProgress(uploadProgressFill, 0); }, 2000);
    uploadBtn.innerHTML = idleButtonHtml;
    uploadBtn.disabled = false;
    checkUploadReady();
  }
});

// ─── File listing ────────────────────────────────────────────

async function loadFiles() {
  try {
    const resp = await fetch(`${API_BASE_URL}/api/files`);
    if (!resp.ok) throw new Error(`Server error ${resp.status}`);
    const data = await resp.json();

    if (!data.files || data.files.length === 0) {
      filesList.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-database fa-3x"></i>
          <p>No files uploaded yet.</p>
        </div>`;
      return;
    }

    filesList.innerHTML = data.files.map(f => {
      const date = new Date(f.uploaded_at).toLocaleString();
      const size = ZKCrypto.formatBytes(f.encrypted_size);
      return `
      <div class="file-item" data-id="${escHtml(f.id)}" data-filename="${escHtml(f.original_name)}">
        <div class="file-icon"><i class="fas fa-file-shield"></i></div>
        <div class="file-meta">
          <div class="file-name">
            ${escHtml(f.original_name)}
            <span class="file-tag">ENCRYPTED</span>
          </div>
          <div class="file-details">${size} &middot; ${date}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-sm btn-primary"
                  data-action="download"
                  title="Download self-contained .enc container (can be decrypted offline)">
            <i class="fas fa-download"></i> ⬇ .enc
          </button>
          <button class="btn btn-sm btn-success"
                  data-action="decrypt"
                  title="Decrypt and download original file">
            <i class="fas fa-unlock"></i> Decrypt
          </button>
          <button class="btn btn-sm btn-danger"
                  data-action="delete"
                  title="Delete from server">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>`;
    }).join("");

  } catch (err) {
    filesList.innerHTML = `
      <div class="alert alert-error">
        <i class="fas fa-exclamation-circle"></i>
        <span>Could not load files: ${escHtml(err.message)}</span>
      </div>`;
  }
}

refreshBtn.addEventListener("click", () => {
  const icon = refreshBtn.querySelector("i");
  icon.style.animation = "spin 0.7s linear infinite";
  loadFiles().finally(() => setTimeout(() => icon.style.animation = "", 800));
});

filesList.addEventListener("click", event => {
  const button = event.target.closest("button[data-action]");
  const row = button && button.closest(".file-item");
  if (!row) return;

  const fileId = row.dataset.id;
  const filename = row.dataset.filename;

  switch (button.dataset.action) {
    case "download":
      if (fileId && filename) downloadEncrypted(fileId, filename);
      break;
    case "decrypt":
      if (fileId && filename) openDecryptModal(fileId, filename);
      break;
    case "delete":
      if (fileId) deleteFile(fileId);
      break;
  }
});

// ─── Download self-contained .enc container ──────────────
//
// Hits /api/files/<id>/download  which returns a binary ZKCV container
// (magic + version + salt + iv + ciphertext).  The browser downloads it
// directly — no base64 decode, no JS processing needed.

async function downloadEncrypted(fileId, originalName) {
  const baseName = originalName.replace(/\.[^/.]+$/, "") || "encrypted";
  const encName  = baseName + ".enc";
  setNavStatus("Downloading .enc container…", "var(--warning)");

  const row   = document.querySelector(`.file-item[data-id="${fileId}"]`);
  const dlBtn = row ? row.querySelector(".btn-primary") : null;
  if (dlBtn) { dlBtn.disabled = true; dlBtn.innerHTML = '<span class="spinner"></span>'; }

  try {
    const resp = await fetch(`${API_BASE_URL}/api/files/${fileId}/download`);
    if (!resp.ok) throw new Error(`Server returned ${resp.status} ${resp.statusText}`);

    // Read as binary
    const arrayBuf = await resp.arrayBuffer();
    if (arrayBuf.byteLength === 0) throw new Error("Server returned an empty file.");

    // Trigger browser download
    const blob = new Blob([arrayBuf], { type: "application/octet-stream" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.style.display = "none";
    a.href     = url;
    a.download = encName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);

    setNavStatus(`Downloaded ${encName}`, "var(--accent3)");
    setTimeout(() => setNavStatus("Ready"), 3000);

  } catch (err) {
    setNavStatus("Download failed", "var(--danger)");
    alert(`Could not download .enc file:\n${err.message}`);
    setTimeout(() => setNavStatus("Ready"), 3000);
  } finally {
    if (dlBtn) {
      dlBtn.disabled = false;
      dlBtn.innerHTML = '<i class="fas fa-download"></i> ⬇ .enc';
    }
  }
}
// ─── Local .enc file decrypt ─────────────────────────────
//
// Allows the user to pick a .enc file from disk, enter their password,
// and decrypt it entirely in the browser.  No server involved.
// Uses ZKCrypto.decryptContainer() which reads salt+iv from the ZKCV header.

const encFileInput       = document.getElementById("enc-file-input");
const encDropZone        = document.getElementById("enc-drop-zone");
const encSelectedName    = document.getElementById("enc-selected-name");
const localDecPassword   = document.getElementById("local-dec-password");
const toggleLocalDecPw   = document.getElementById("toggle-local-dec-pw");
const localDecryptBtn    = document.getElementById("local-decrypt-btn");
const localDecProgCont   = document.getElementById("local-dec-progress-cont");
const localDecProgFill   = document.getElementById("local-dec-progress-fill");
const localDecProgLbl    = document.getElementById("local-dec-progress-lbl");
const localDecResult     = document.getElementById("local-dec-result");
const localWrongPwBox    = document.getElementById("local-wrong-pw-box");

let selectedEncFile = null;

function handleEncFileSelect(file) {
  if (!file) return;
  selectedEncFile = file;
  encSelectedName.textContent = `${file.name}  (${ZKCrypto.formatBytes(file.size)})`;
  encDropZone.style.borderColor = "var(--accent3)";
  checkLocalDecReady();
}

encFileInput.addEventListener("change", () => handleEncFileSelect(encFileInput.files[0]));

encDropZone.addEventListener("dragover",  e => { e.preventDefault(); encDropZone.classList.add("dragover"); });
encDropZone.addEventListener("dragleave", () => encDropZone.classList.remove("dragover"));
encDropZone.addEventListener("drop", e => {
  e.preventDefault();
  encDropZone.classList.remove("dragover");
  const f = e.dataTransfer.files[0];
  if (f) { encFileInput.files = e.dataTransfer.files; handleEncFileSelect(f); }
});

localDecPassword.addEventListener("input", checkLocalDecReady);
localDecPassword.addEventListener("keydown", e => { if (e.key === "Enter") localDecryptBtn.click(); });

function checkLocalDecReady() {
  localDecryptBtn.disabled = !(selectedEncFile && localDecPassword.value.length >= 1);
}

makeToggle(toggleLocalDecPw, localDecPassword);

localDecryptBtn.addEventListener("click", async () => {
  if (!selectedEncFile) return;
  const password = localDecPassword.value;
  if (!password) {
    showAlert(localDecResult, "error", "exclamation-circle", "Please enter the decryption password.");
    return;
  }

  localDecryptBtn.disabled = true;
  clearEl(localDecResult);
  localWrongPwBox.style.display    = "none";
  localDecProgCont.style.display   = "block";
  localDecProgFill.style.background = "";
  setNavStatus("Decrypting local file…", "var(--warning)");

  // Register download anchor synchronously (user-gesture requirement)
  const placeholderBlob = new Blob([""], { type: "application/octet-stream" });
  const placeholderUrl  = URL.createObjectURL(placeholderBlob);
  const dlAnchor = document.createElement("a");
  dlAnchor.style.display = "none";
  dlAnchor.href     = placeholderUrl;
  dlAnchor.download = "decrypted";
  document.body.appendChild(dlAnchor);
  dlAnchor.click();  // ← synchronous click keeps download permission alive

  try {
    await animateProgress(localDecProgFill, localDecProgLbl, [
      [15, "Reading .enc file…", 200],
    ]);

    const containerBuf = await ZKCrypto.readFileAsBuffer(selectedEncFile);

    await animateProgress(localDecProgFill, localDecProgLbl, [
      [35, "Parsing ZKCV container header…", 150],
      [55, "Re-deriving AES key (PBKDF2)…", 200],
    ]);

    // Decrypt — reads salt+iv+filename+mime from container header, no server needed.
    // Throws DOMException(OperationError) if password is wrong or data tampered.
    const { plainBuf, originalName, mimeType, saltHex, ivHex } =
      await ZKCrypto.decryptContainer(containerBuf, password);

    // ── Integrity: SHA-256 of restored bytes ─────────────────────────────
    const sha256 = await ZKCrypto.sha256Hex(plainBuf);

    await animateProgress(localDecProgFill, localDecProgLbl, [
      [90, "Decryption successful — preparing download…", 150],
    ]);
    setProgress(localDecProgFill, 100);
    localDecProgLbl.textContent = "Done!";

    // Restore the original filename embedded in the v2 container header.
    // Fall back for v1 containers (no embedded name): strip .enc suffix.
    const outName = originalName
      || (selectedEncFile.name.replace(/\.enc$/i, "") || "decrypted_file");
    const outMime = mimeType || "application/octet-stream";

    // Build Blob from the raw ArrayBuffer — never convert binary to a string.
    URL.revokeObjectURL(placeholderUrl);
    const realBlob = new Blob([plainBuf], { type: outMime });
    const realUrl  = URL.createObjectURL(realBlob);
    dlAnchor.href     = realUrl;
    dlAnchor.download = outName;
    dlAnchor.click();  // ← actual file download
    setTimeout(() => { URL.revokeObjectURL(realUrl); dlAnchor.remove(); }, 2000);

    showAlert(localDecResult, "success", "check-circle",
      `<strong>${escHtml(outName)}</strong> decrypted and downloaded successfully.<br>
       Size: <strong>${ZKCrypto.formatBytes(plainBuf.byteLength)}</strong> &nbsp;|&nbsp;
       Type: <span class="mono">${escHtml(outMime)}</span><br>
       <span style="font-size:0.75rem">
         SHA-256: <span class="mono">${sha256.slice(0, 16)}…${sha256.slice(-8)}</span>
       </span>`
    );

    setNavStatus("Local file decrypted", "var(--accent3)");
    setTimeout(() => setNavStatus("Ready"), 3000);

    // Reset inputs
    selectedEncFile = null;
    encFileInput.value = "";
    encSelectedName.textContent = "No file selected";
    encDropZone.style.borderColor = "";
    localDecPassword.value = "";
    localDecryptBtn.disabled = true;

  } catch (err) {
    URL.revokeObjectURL(placeholderUrl);
    dlAnchor.remove();

    setProgress(localDecProgFill, 100);
    localDecProgFill.style.background = "var(--danger)";
    localDecProgLbl.textContent = "Failed!";

    const isAuthFail    = err.name === "OperationError";
    const isFormatError = err.message.startsWith("Not a ZKCV") ||
                          err.message.startsWith("Unsupported") ||
                          err.message.startsWith("File is too small");

    if (isFormatError) {
      showAlert(localDecResult, "error", "file-circle-xmark",
        `<strong>Unsupported file format.</strong> ${escHtml(err.message)}`
      );
    } else if (isAuthFail) {
      showAlert(localDecResult, "error", "shield-halved",
        "<strong>Incorrect password.</strong> The AES-GCM authentication tag did not match. " +
        "Please check your password and try again."
      );
      localWrongPwBox.style.display = "flex";
    } else {
      showAlert(localDecResult, "error", "times-circle",
        `Decryption error: ${escHtml(err.message)}`
      );
    }

    setNavStatus("Decryption failed", "var(--danger)");
    setTimeout(() => {
      localDecProgFill.style.background = "";
      setNavStatus("Ready");
    }, 3000);
  } finally {
    setTimeout(() => {
      localDecProgCont.style.display = "none";
      setProgress(localDecProgFill, 0);
    }, 2500);
    localDecryptBtn.disabled = false;
    checkLocalDecReady();
  }
});

// ─── Delete file ─────────────────────────────────────────────

async function deleteFile(fileId) {
  if (!confirm("Delete this encrypted file from the server?")) return;
  try {
    const resp = await fetch(`${API_BASE_URL}/api/files/${fileId}`, { method: "DELETE" });
    if (!resp.ok) throw new Error("Delete failed");
    loadFiles();
    setNavStatus("File deleted", "var(--warning)");
    setTimeout(() => setNavStatus("Ready"), 2000);
  } catch (err) {
    alert("Error: " + err.message);
  }
}
// ─── Decrypt modal ───────────────────────────────────────────

function openDecryptModal(fileId, filename) {
  currentFileId   = fileId;
  currentFileMeta = null;
  modalFilename.textContent = `🔒 ${filename}`;
  decPassword.value = "";
  clearEl(decryptResult);
  wrongPwDemo.style.display    = "none";
  decProgressCont.style.display = "none";
  setProgress(decProgressFill, 0);
  decProgressFill.style.background = "";
  modalOverlay.style.display = "flex";
  setTimeout(() => decPassword.focus(), 100);
}
function closeModal() {
  modalOverlay.style.display = "none";
  currentFileId   = null;
  currentFileMeta = null;
}

modalClose.addEventListener("click",  closeModal);
modalCancel.addEventListener("click", closeModal);
modalOverlay.addEventListener("click", e => { if (e.target === modalOverlay) closeModal(); });
decPassword.addEventListener("keydown", e => { if (e.key === "Enter") decryptBtn.click(); });

// ─── Decrypt & Download ──────────────────────────────────────
//
// FIX: The async decrypt chain breaks the browser's user-gesture requirement
// for programmatic downloads.  We solve this with a two-phase approach:
//   Phase 1 (sync, before any await): create <a>, set a placeholder href,
//           call .click() — this registers the download permission.
//   Phase 2 (after async work): revoke placeholder, set real Blob URL,
//           call .click() again — the browser honours it because Phase 1
//           established the permission for this element.

decryptBtn.addEventListener("click", async () => {
  if (!currentFileId) return;
  const password = decPassword.value.trim();
  if (!password) {
    showAlert(decryptResult, "error", "exclamation-circle", "Please enter the decryption password.");
    return;
  }

  const idleButtonHtml = decryptBtn.innerHTML;
  decryptBtn.disabled = true;
  decryptBtn.innerHTML = '<span class="spinner"></span> Decrypting…';
  clearEl(decryptResult);
  wrongPwDemo.style.display    = "none";
  decProgressCont.style.display = "block";
  decProgressFill.style.background = "";
  setNavStatus("Decrypting…", "var(--warning)");

  // ── Phase 1: register download anchor synchronously ──────
  // We need to click the anchor in the same synchronous frame as the
  // button click.  Use a temporary blob URL so the browser accepts it.
  const phaseOneBlob = new Blob([""], { type: "application/octet-stream" });
  const phaseOneUrl  = URL.createObjectURL(phaseOneBlob);
  const dlAnchor     = document.createElement("a");
  dlAnchor.style.display = "none";
  dlAnchor.href     = phaseOneUrl;
  dlAnchor.download = "decrypted_file";   // placeholder, updated below
  document.body.appendChild(dlAnchor);
  dlAnchor.click();                       // ← synchronous user-gesture click

  try {
    // ── Phase 2: async work ───────────────────────────────
    await animateProgress(decProgressFill, decProgressLbl, [
      [20, "Downloading encrypted blob from server…", 300],
    ]);

    const resp = await fetch(`${API_BASE_URL}/api/files/${currentFileId}`);
    if (!resp.ok) throw new Error(`Server error ${resp.status}: ${resp.statusText}`);

    const meta = await resp.json();
    if (!meta.data) throw new Error("Server response missing 'data' field");

    await animateProgress(decProgressFill, decProgressLbl, [
      [50, "Re-deriving AES key (PBKDF2)…", 200],
    ]);

    // Decode base64 ciphertext
    const binaryStr = atob(meta.data);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
    const cipherBuf = bytes.buffer;

    await animateProgress(decProgressFill, decProgressLbl, [
      [75, "Decrypting (AES-256-GCM)…", 150],
    ]);

    // Decrypt — throws DOMException(OperationError) on wrong password or tampered data
    const plainBuf = await ZKCrypto.decrypt(cipherBuf, password, meta.salt, meta.iv);

    // ── Integrity: compute SHA-256 of the recovered plaintext ─────────────
    // This runs AFTER SubtleCrypto has already verified the GCM auth tag,
    // so we know the bytes are authentic. The hash is shown to the user so
    // they can verify it matches the original file independently if needed.
    const sha256 = await ZKCrypto.sha256Hex(plainBuf);

    setProgress(decProgressFill, 100);
    decProgressLbl.textContent = "Decrypted!";

    // Use the ORIGINAL filename and MIME type so the file opens correctly.
    // These come from server metadata — the server stored them at upload time.
    const outName  = meta.original_name || "decrypted_file";
    const mimeType = meta.mime_type     || "application/octet-stream";

    // Build Blob from the raw ArrayBuffer — never convert binary to a string.
    URL.revokeObjectURL(phaseOneUrl);
    const realBlob = new Blob([plainBuf], { type: mimeType });
    const realUrl  = URL.createObjectURL(realBlob);
    dlAnchor.href     = realUrl;
    dlAnchor.download = outName;
    dlAnchor.click();                     // ← actual file download
    setTimeout(() => { URL.revokeObjectURL(realUrl); dlAnchor.remove(); }, 2000);

    showAlert(decryptResult, "success", "check-circle",
      `<strong>${escHtml(outName)}</strong> decrypted &amp; downloaded successfully!<br>
       Size: ${ZKCrypto.formatBytes(plainBuf.byteLength)} &nbsp;|&nbsp;
       Type: <span class="mono">${escHtml(mimeType)}</span><br>
       <span style="font-size:0.75rem">
         SHA-256: <span class="mono">${sha256.slice(0, 16)}…${sha256.slice(-8)}</span>
       </span>`
    );

    setNavStatus("Decrypted & downloaded", "var(--accent3)");
    setTimeout(() => setNavStatus("Ready"), 3000);

  } catch (err) {
    // Clean up placeholder anchor on error
    URL.revokeObjectURL(phaseOneUrl);
    dlAnchor.remove();

    setProgress(decProgressFill, 100);
    decProgressFill.style.background = "var(--danger)";
    decProgressLbl.textContent = "Failed!";

    // DOMException OperationError = GCM tag mismatch (wrong password or tampered data)
    const isAuthFail = err.name === "OperationError";

    if (isAuthFail) {
      showAlert(decryptResult, "error", "shield-halved",
        "<strong>Decryption failed!</strong> The AES-GCM authentication tag did not match. " +
        "The password is incorrect, or the file has been tampered with."
      );
      wrongPwDemo.style.display = "flex";
    } else {
      showAlert(decryptResult, "error", "times-circle", `Error: ${escHtml(err.message)}`);
    }

    setNavStatus("Decryption failed", "var(--danger)");
    setTimeout(() => {
      decProgressFill.style.background = "";
      setNavStatus("Ready");
    }, 3000);
  } finally {
    setTimeout(() => {
      decProgressCont.style.display = "none";
      setProgress(decProgressFill, 0);
    }, 2500);
    decryptBtn.innerHTML = idleButtonHtml;
    decryptBtn.disabled = false;
  }
});

// ─── Init ────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", loadFiles);
