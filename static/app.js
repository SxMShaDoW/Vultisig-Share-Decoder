import { parseVaultContainer, parseVault } from "./vault_pb.js";
import { decryptWithAesGcm, fromBase64 } from "./aes_gcm.js";

let goWasmReady = false;
let dklsWasmModule = null;
let schnorrWasmModule = null;

const go = new Go();

const initGoWasm = (async () => {
  const response = await fetch("main.wasm.gz");
  if (!response.ok) throw new Error(`Failed to fetch main.wasm.gz: ${response.status}`);
  const ds = new DecompressionStream("gzip");
  const decompressed = response.body.pipeThrough(ds);
  const wasmBytes = await new Response(decompressed).arrayBuffer();
  const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
  go.run(result.instance);
  goWasmReady = true;
  return result;
})();

const initDklsWasm = (async () => {
  try {
    const mod = await import("./vs_wasm.js");
    await mod.default("./vs_wasm_bg.wasm");
    if (!mod.Keyshare || !mod.KeyExportSession) return null;
    dklsWasmModule = { Keyshare: mod.Keyshare, KeyExportSession: mod.KeyExportSession };
    return dklsWasmModule;
  } catch {
    return null;
  }
})();

const initSchnorrWasm = (async () => {
  try {
    const mod = await import("./vs_schnorr_wasm.js");
    await mod.default("./vs_schnorr_wasm_bg.wasm");
    if (!mod.Keyshare || !mod.KeyExportSession) return null;
    schnorrWasmModule = {
      Keyshare: mod.Keyshare,
      KeyExportSession: mod.KeyExportSession,
    };
    return schnorrWasmModule;
  } catch {
    return null;
  }
})();

Promise.all([initGoWasm, initDklsWasm, initSchnorrWasm])
  .then(() => {
    document.getElementById("loader").style.display = "none";
    document.getElementById("app").style.display = "block";
  })
  .catch(() => {
    initGoWasm
      .then(() => {
        document.getElementById("loader").style.display = "none";
        document.getElementById("app").style.display = "block";
      })
      .catch((e) => {
        document.getElementById("loader").innerHTML =
          `<div class="loader-error">Failed to load: ${e.message}</div>`;
      });
  });

async function parseVaultFile(fileData, password) {
  let containerData = fileData;
  try {
    const b64 = new TextDecoder().decode(fileData);
    const decoded = fromBase64(b64);
    if (decoded.length > 100) containerData = decoded;
  } catch {}

  const container = parseVaultContainer(containerData);
  let vaultBytes;
  if (container.isEncrypted) {
    if (!password) throw new Error("Vault is encrypted — password required");
    const encBytes = fromBase64(container.vault);
    vaultBytes = await decryptWithAesGcm({ key: password, value: encBytes });
  } else {
    vaultBytes = fromBase64(container.vault);
  }
  return parseVault(vaultBytes);
}

function detectScheme(vault) {
  if (!vault.keyShares || vault.keyShares.length === 0) return "gg20";
  const ks = vault.keyShares[0].keyshare;
  if (!ks) return "gg20";
  try {
    JSON.parse(ks);
    return "gg20";
  } catch {
    return "dkls";
  }
}

function decodeKeyshare(ksString) {
  const trimmed = ksString.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length > 200) {
    return new Uint8Array(trimmed.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  }
  try {
    const decoded = fromBase64(trimmed);
    if (decoded.length > 100) return decoded;
  } catch {}
  throw new Error("Could not decode keyshare data");
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function exportKeyWithWasm(wasmMod, keyshareDataList, partyIds) {
  const { Keyshare, KeyExportSession } = wasmMod;
  const keyshares = keyshareDataList.map((data) => Keyshare.fromBytes(data));

  const session = KeyExportSession.new(keyshares[0], partyIds);
  const setupMsg = session.setup;

  for (let i = 1; i < keyshares.length; i++) {
    const msg = KeyExportSession.exportShare(setupMsg, partyIds[i], keyshares[i]);
    const done = session.inputMessage(msg.body);
    if (done) break;
  }

  const privateKeyBytes = session.finish();
  const publicKeyBytes = keyshares[0].publicKey();
  return { privateKeyBytes, publicKeyBytes };
}

async function recoverDKLS(files, passwords, fileNames) {
  if (!dklsWasmModule) throw new Error("DKLS WASM module not available");
  if (files.length < 2) throw new Error("DKLS requires at least 2 keyshare files");

  const vaults = [];
  const partyIds = [];
  const ecdsaKeyshareData = [];
  const eddsaKeyshareData = [];

  for (let i = 0; i < files.length; i++) {
    const vault = await parseVaultFile(files[i], passwords[i] || "");
    vaults.push(vault);
    partyIds.push(vault.localPartyId || `party${i + 1}`);

    ecdsaKeyshareData.push(decodeKeyshare(vault.keyShares[0].keyshare));

    if (vault.keyShares.length > 1 && vault.keyShares[1].keyshare) {
      eddsaKeyshareData.push(decodeKeyshare(vault.keyShares[1].keyshare));
    }
  }

  const ecdsa = exportKeyWithWasm(dklsWasmModule, ecdsaKeyshareData, partyIds);
  const pubKeyHex = bytesToHex(ecdsa.publicKeyBytes);
  const privKeyHex = bytesToHex(ecdsa.privateKeyBytes);
  const chainCodeHex = bytesToHex(
    dklsWasmModule.Keyshare.fromBytes(ecdsaKeyshareData[0]).rootChainCode(),
  );

  let result = {
    success: true,
    scheme: "dkls",
    publicKeys: { ecdsa: pubKeyHex },
    rootKeyInfo: {
      hexPubKeyECDSA: pubKeyHex,
      hexPrivKeyECDSA: privKeyHex,
      chainCode: chainCodeHex,
    },
    shareDetails: partyIds.map((id, i) => ({
      backupName: fileNames[i],
      thisShare: id,
      allShares: partyIds,
    })),
    ecdsaKeys: [],
    eddsaKeys: [],
  };

  if (goWasmReady && window.DeriveAddresses) {
    try {
      const derived = JSON.parse(window.DeriveAddresses(privKeyHex, chainCodeHex));
      if (derived.success && derived.ecdsaKeys) {
        result.ecdsaKeys = derived.ecdsaKeys;
      }
    } catch {}
  }

  if (schnorrWasmModule && eddsaKeyshareData.length >= 2) {
    try {
      const eddsa = exportKeyWithWasm(schnorrWasmModule, eddsaKeyshareData, partyIds);
      const eddsaPubHex = bytesToHex(eddsa.publicKeyBytes);
      const eddsaPrivHex = bytesToHex(eddsa.privateKeyBytes);
      result.publicKeys.eddsa = eddsaPubHex;

      if (goWasmReady && window.DeriveEdDSAAddresses) {
        try {
          const derived = JSON.parse(window.DeriveEdDSAAddresses(eddsaPrivHex, eddsaPubHex));
          if (derived.success && derived.eddsaKeys) {
            result.eddsaKeys = derived.eddsaKeys;
          }
        } catch {}
      }
    } catch {}
  }

  return result;
}

async function recoverGG20(files, passwords) {
  if (!goWasmReady) throw new Error("Go WASM not ready");

  const jsFiles = files;
  const jsPw = passwords;
  const jsonStr = window.RecoverGG20(jsFiles, jsPw);
  return JSON.parse(jsonStr);
}

async function handleRecover() {
  const fileGroups = document.querySelectorAll(".file-group");
  const files = [];
  const passwords = [];
  const fileNames = [];

  for (const group of fileGroups) {
    const fileInput = group.querySelector(".file-input");
    const pwInput = group.querySelector(".password-input");
    if (fileInput.files.length > 0) {
      const f = fileInput.files[0];
      const data = new Uint8Array(await f.arrayBuffer());
      files.push(data);
      passwords.push(pwInput.value || "");
      fileNames.push(f.name);
    }
  }

  if (files.length === 0) {
    showError("Please select at least one vault file.");
    return;
  }

  const btn = document.getElementById("recoverBtn");
  btn.disabled = true;
  btn.textContent = "Recovering...";
  clearResults();

  try {
    const firstVault = await parseVaultFile(files[0], passwords[0] || "");
    const scheme = detectScheme(firstVault);
    let result;

    if (scheme === "dkls") {
      result = await recoverDKLS(files, passwords, fileNames);
    } else {
      result = await recoverGG20(files, passwords);
    }

    if (!result.success) {
      showError(result.error || "Recovery failed");
      return;
    }

    displayResults(result);
  } catch (err) {
    showError(err.message || "Recovery failed");
  } finally {
    btn.disabled = false;
    btn.textContent = "Recover Keys";
  }
}

function clearResults() {
  document.getElementById("results").innerHTML = "";
  document.getElementById("results").classList.remove("visible");
}

function showError(msg) {
  const results = document.getElementById("results");
  results.innerHTML = `<div class="error-card"><h3>Error</h3><p>${escapeHtml(msg)}</p></div>`;
  results.classList.add("visible");
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function displayResults(result) {
  const container = document.getElementById("results");
  container.classList.add("visible");
  let html = "";

  html += `<div class="result-badge">${result.scheme.toUpperCase()} Recovery</div>`;

  if (result.shareDetails && result.shareDetails.length > 0) {
    html += `<div class="result-card">
            <h3>Share Details</h3>
            <div class="share-details">`;
    for (const s of result.shareDetails) {
      html += `<div class="share-item">
                <span class="share-label">File:</span> <span class="share-value">${escapeHtml(s.backupName)}</span>
                <span class="share-label">Party:</span> <span class="share-value mono">${escapeHtml(s.thisShare)}</span>
            </div>`;
    }
    html += `</div></div>`;
  }

  if (result.publicKeys) {
    html += `<div class="result-card">
            <h3>Public Keys</h3>`;
    if (result.publicKeys.ecdsa) {
      html += keyRow("ECDSA", result.publicKeys.ecdsa);
    }
    if (result.publicKeys.eddsa) {
      html += keyRow("EdDSA", result.publicKeys.eddsa);
    }
    html += `</div>`;
  }

  if (result.ecdsaKeys && result.ecdsaKeys.length > 0) {
    html += `<div class="result-card">
            <h3>ECDSA Coins</h3>
            <div class="coin-grid">`;
    for (const coin of result.ecdsaKeys) {
      html += coinCard(coin);
    }
    html += `</div></div>`;
  }

  if (result.eddsaKeys && result.eddsaKeys.length > 0) {
    html += `<div class="result-card">
            <h3>EdDSA Coins</h3>
            <div class="coin-grid">`;
    for (const coin of result.eddsaKeys) {
      html += coinCard(coin);
    }
    html += `</div></div>`;
  }

  if (result.rootKeyInfo) {
    html += `<div class="result-card collapsible">
            <h3 class="collapsible-header" onclick="toggleCollapsible(this)">
                Root Key Info <span class="arrow">+</span>
            </h3>
            <div class="collapsible-body">`;
    if (result.rootKeyInfo.hexPubKeyECDSA) {
      html += keyRow("ECDSA Public Key", result.rootKeyInfo.hexPubKeyECDSA);
    }
    if (result.rootKeyInfo.hexPrivKeyECDSA) {
      html += keyRow("ECDSA Private Key", result.rootKeyInfo.hexPrivKeyECDSA, true);
    }
    if (result.rootKeyInfo.chainCode) {
      html += keyRow("Chain Code", result.rootKeyInfo.chainCode);
    }
    if (result.rootKeyInfo.extendedPrivateKey) {
      html += keyRow("Extended Private Key", result.rootKeyInfo.extendedPrivateKey, true);
    }
    html += `</div></div>`;
  }

  container.innerHTML = html;
}

function keyRow(label, value, sensitive = false) {
  const cls = sensitive ? "key-row sensitive" : "key-row";
  return `<div class="${cls}">
        <span class="key-label">${escapeHtml(label)}</span>
        <div class="key-value-wrap">
            <code class="key-value">${escapeHtml(value)}</code>
            <button class="copy-btn" onclick="copyValue(this, '${value.replace(/'/g, "\\'")}')">Copy</button>
        </div>
    </div>`;
}

function coinCard(coin) {
  const name = coin.name || coin.Name || "";
  const path = coin.derivePath || coin.DerivePath || "";
  const addr = coin.address || coin.Address || "";
  const privKey = coin.hexPrivateKey || coin.HexPrivateKey || "";
  const pubKey = coin.hexPublicKey || coin.HexPublicKey || "";
  const wif = coin.wifPrivateKey || coin.WIFPrivateKey || "";

  let html = `<div class="coin-card">
        <div class="coin-header">
            <span class="coin-name">${escapeHtml(name)}</span>
            <span class="coin-path">${escapeHtml(path)}</span>
        </div>`;

  if (addr) {
    html += `<div class="coin-field">
            <span class="coin-field-label">Address</span>
            <div class="coin-field-value-wrap">
                <code class="coin-field-value">${escapeHtml(addr)}</code>
                <button class="copy-btn" onclick="copyValue(this, '${addr.replace(/'/g, "\\'")}')">Copy</button>
            </div>
        </div>`;
  }

  html += `<div class="coin-secrets" style="display:none">`;
  if (privKey) {
    html += `<div class="coin-field">
            <span class="coin-field-label">Private Key</span>
            <div class="coin-field-value-wrap">
                <code class="coin-field-value">${escapeHtml(privKey)}</code>
                <button class="copy-btn" onclick="copyValue(this, '${privKey.replace(/'/g, "\\'")}')">Copy</button>
            </div>
        </div>`;
  }
  if (wif) {
    html += `<div class="coin-field">
            <span class="coin-field-label">WIF</span>
            <div class="coin-field-value-wrap">
                <code class="coin-field-value">${escapeHtml(wif)}</code>
                <button class="copy-btn" onclick="copyValue(this, '${wif.replace(/'/g, "\\'")}')">Copy</button>
            </div>
        </div>`;
  }
  if (pubKey) {
    html += `<div class="coin-field">
            <span class="coin-field-label">Public Key</span>
            <div class="coin-field-value-wrap">
                <code class="coin-field-value">${escapeHtml(pubKey)}</code>
                <button class="copy-btn" onclick="copyValue(this, '${pubKey.replace(/'/g, "\\'")}')">Copy</button>
            </div>
        </div>`;
  }
  html += `</div>`;
  html += `<button class="show-secrets-btn" onclick="toggleSecrets(this)">Show Private Keys</button>`;
  html += `</div>`;
  return html;
}

let fileGroupCounter = 1;

function addFileInput() {
  const container = document.getElementById("fileInputs");
  const div = document.createElement("div");
  div.className = "file-group";
  div.id = `fileGroup${fileGroupCounter}`;
  div.innerHTML = `
        <div class="input-wrapper">
            <label class="file-drop-label">
                <input type="file" accept=".bak,.vult" class="file-input" />
                <span class="file-drop-text">Choose file or drop here</span>
            </label>
            <input type="password" placeholder="Password (optional)" class="password-input" />
        </div>
        <button class="btn-icon-only remove-btn" onclick="removeFileInput('fileGroup${fileGroupCounter}')">
            &times;
        </button>`;
  container.appendChild(div);
  setupDropZone(div.querySelector(".file-drop-label"));
  fileGroupCounter++;
}

function removeFileInput(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function setupDropZone(label) {
  label.addEventListener("dragover", (e) => {
    e.preventDefault();
    label.classList.add("drag-over");
  });
  label.addEventListener("dragleave", () => label.classList.remove("drag-over"));
  label.addEventListener("drop", (e) => {
    e.preventDefault();
    label.classList.remove("drag-over");
    const input = label.querySelector(".file-input");
    if (e.dataTransfer.files.length > 0) {
      input.files = e.dataTransfer.files;
      label.querySelector(".file-drop-text").textContent = e.dataTransfer.files[0].name;
    }
  });
  const input = label.querySelector(".file-input");
  input.addEventListener("change", () => {
    if (input.files.length > 0) {
      label.querySelector(".file-drop-text").textContent = input.files[0].name;
    }
  });
}

window.copyValue = function (btn, value) {
  navigator.clipboard.writeText(value).then(() => {
    const orig = btn.textContent;
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("copied");
    }, 1200);
  });
};

window.toggleSecrets = function (btn) {
  const secrets = btn.previousElementSibling;
  if (secrets.style.display === "none") {
    secrets.style.display = "block";
    btn.textContent = "Hide Private Keys";
  } else {
    secrets.style.display = "none";
    btn.textContent = "Show Private Keys";
  }
};

window.toggleCollapsible = function (header) {
  const body = header.nextElementSibling;
  const arrow = header.querySelector(".arrow");
  if (body.style.display === "block") {
    body.style.display = "none";
    arrow.textContent = "+";
  } else {
    body.style.display = "block";
    arrow.textContent = "-";
  }
};

window.addFileInput = addFileInput;
window.removeFileInput = removeFileInput;
window.handleRecover = handleRecover;

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".file-drop-label").forEach(setupDropZone);
});
