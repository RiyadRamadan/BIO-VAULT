/***********************************************************************
 * main.js — Single Vault + Device Key + Simple Biometric Check + 
 *            Passphrase Modals + Multi-Tab Concurrency
 * 
 * KEY POINTS:
 * 1. Uses a "light" WebAuthn call to navigator.credentials.create() on 
 *    vault creation or unlock, with no stored credentialId or assertion.
 * 2. If user denies or fails, we fallback to "No Biometric".
 * 3. We keep passphrase modals, chain hashing, single device key,
 *    local backup restore, concurrency lock (txInProgress), etc.
 ***********************************************************************/

const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

const EXCHANGE_RATE = 12;  
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720;  // 12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;     // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const THREE_MONTHS_SECONDS = 7776000;      // 3 months
const MAX_ANNUAL_INTERVALS = 4;
const BIO_LINE_INCREMENT_AMOUNT = 15000;   // 15,000 TVM per interval

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;     // 5 minutes

const vaultSyncChannel = new BroadcastChannel('vault-sync');

// ephemeral
let vaultUnlocked = false;
let derivedKey = null;
let bioLineInterval = null;

let vaultData = {
  bioIBAN: null,
  initialBalanceTVM: 15000,
  balanceTVM: 0,
  balanceUSD: 0,
  bioConstant: INITIAL_BIO_CONSTANT,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  joinTimestamp: 0,
  incrementsUsed: 0,
  lastTransactionHash: '',
  finalChainHash: '',
  // We no longer store credentialId (we do a one-shot check each time).
  deviceKey: null
};

/* ------------------------------------------------------------------
   1) Utility / Common
------------------------------------------------------------------ */
function formatWithCommas(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  return date.toISOString().slice(0, 19).replace('T', ' ');
}
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}
function bufferToBase64(buffer) {
  if (buffer instanceof ArrayBuffer) buffer = new Uint8Array(buffer);
  return btoa(String.fromCharCode(...buffer));
}
function base64ToBuffer(base64) {
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}
function validateBioIBAN(bioIBAN) {
  if (typeof bioIBAN !== 'string') return false;
  if (!bioIBAN.startsWith('BIO')) return false;
  const numericPart = parseInt(bioIBAN.slice(3), 10);
  return Number.isFinite(numericPart) && numericPart > 0;
}

/* ------------------------------------------------------------------
   2) UI For Passphrase (Modal-based) 
------------------------------------------------------------------ */
async function getPassphraseFromModal({ confirmNeeded = false, modalTitle = 'Enter Passphrase' }) {
  return new Promise((resolve) => {
    const passModal = document.getElementById('passModal');
    const passTitle = document.getElementById('passModalTitle');
    const passInput = document.getElementById('passModalInput');
    const passConfirmLabel = document.getElementById('passModalConfirmLabel');
    const passConfirmInput = document.getElementById('passModalConfirmInput');
    const passCancelBtn = document.getElementById('passModalCancelBtn');
    const passSaveBtn = document.getElementById('passModalSaveBtn');

    passTitle.textContent = modalTitle;
    passInput.value = '';
    passConfirmInput.value = '';
    passConfirmLabel.style.display = confirmNeeded ? 'block' : 'none';
    passConfirmInput.style.display = confirmNeeded ? 'block' : 'none';

    function cleanup() {
      passCancelBtn.removeEventListener('click', onCancel);
      passSaveBtn.removeEventListener('click', onSave);
      passModal.style.display = 'none';
    }
    function onCancel() {
      cleanup();
      resolve({ pin: null });
    }
    function onSave() {
      const pinVal = passInput.value.trim();
      if (!pinVal || pinVal.length < 8) {
        alert("⚠️ Passphrase must be >= 8 chars.");
        return;
      }
      if (confirmNeeded) {
        const confVal = passConfirmInput.value.trim();
        if (pinVal !== confVal) {
          alert("❌ Passphrases do not match!");
          return;
        }
      }
      cleanup();
      resolve({ pin: pinVal, confirmed: true });
    }
    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);

    passModal.style.display = 'block';
  });
}

/* ------------------------------------------------------------------
   3) Device Key, Simple Biometric
------------------------------------------------------------------ */

/**
 * If you want a simpler approach: calls navigator.credentials.create()
 * but does NOT store a credentialId or re-assert. 
 * It's effectively a one-shot "human present" check.
 */
async function performSimpleBiometricCheck() {
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Bio‑Vault" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "bio-user",
        displayName: "Bio User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 } // typically ES256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required"
      },
      timeout: 60000,
      attestation: "none"
    };
    const credential = await navigator.credentials.create({ publicKey });
    // If user says "Cancel" or device times out => error is thrown => returns null
    return credential ? true : false;
  } catch (err) {
    console.error("Simple Biometric check error:", err);
    return false;
  }
}

/**
 * getOrCreateDeviceKey for single vault on device
 */
async function getOrCreateDeviceKey() {
  let storedKey = localStorage.getItem('deviceKey');
  if (storedKey) {
    return JSON.parse(storedKey);
  }
  try {
    let keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
    let exportedKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    localStorage.setItem('deviceKey', JSON.stringify(exportedKey));
    return exportedKey;
  } catch (err) {
    console.error("Error generating device key:", err);
    return null;
  }
}
async function deriveKeyFromPIN(pin, salt) {
  try {
    const encoder = new TextEncoder();
    const pinBuffer = encoder.encode(pin);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      pinBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return derivedKey;
  } catch (err) {
    console.error("Error deriving key from PIN:", err);
    return null;
  }
}

/* ------------------------------------------------------------------
   4) Encryption / Decryption, plus DB
------------------------------------------------------------------ */
async function encryptData(key, dataObj) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}
async function decryptData(key, iv, ciphertext) {
  const dec = new TextDecoder();
  const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(plainBuffer));
}
async function encryptBioCatchNumber(plainText) {
  try { return btoa(plainText); }
  catch (err) {
    console.error("Error obfuscating BioCatchNumber:", err);
    return plainText; 
  }
}
async function decryptBioCatchNumber(encryptedString) {
  try { return atob(encryptedString); }
  catch (err) {
    console.error("Error deobfuscating BioCatchNumber:", err);
    return null;
  }
}

/* ------------------------------------------------------------------
   IndexedDB
------------------------------------------------------------------ */
function openVaultDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = (event) => resolve(event.target.result);
    request.onerror = (event) => reject(event.target.error);
  });
}
async function saveVaultDataToDB(iv, ciphertext, saltBase64) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    const ciphertextUint8 = new Uint8Array(ciphertext);
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertextUint8),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp || null,
      authAttempts: vaultData.authAttempts || 0
    });
    tx.oncomplete = () => resolve();
    tx.onerror = (err) => reject(err);
  });
}
async function loadVaultDataFromDB() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const getReq = store.get('vaultData');
    getReq.onsuccess = () => {
      if (getReq.result) {
        try {
          const iv = base64ToBuffer(getReq.result.iv);
          const ciphertext = base64ToBuffer(getReq.result.ciphertext);
          const salt = getReq.result.salt ? base64ToBuffer(getReq.result.salt) : null;
          resolve({
            iv,
            ciphertext,
            salt,
            lockoutTimestamp: getReq.result.lockoutTimestamp || null,
            authAttempts: getReq.result.authAttempts || 0
          });
        } catch (error) {
          console.error('Error decoding stored data:', error);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror = (err) => reject(err);
  });
}

/* ------------------------------------------------------------------
   5) Transaction Hashing & Full-Chain Validation
------------------------------------------------------------------ */
async function computeTransactionHash(previousHash, txObject) {
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}
async function computeFullChainHash(transactions) {
  let runningHash = '';
  const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
  for (let tx of sortedTx) {
    const txObjForHash = {
      type: tx.type,
      amount: tx.amount,
      timestamp: tx.timestamp,
      status: tx.status,
      bioCatch: tx.bioCatch,
      previousHash: runningHash
    };
    runningHash = await computeTransactionHash(runningHash, txObjForHash);
  }
  return runningHash;
}
async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  try {
    const { joinTimestamp, initialBioConstant, transactions, finalChainHash } = senderVaultSnapshot;
    const recomputedHash = await computeFullChainHash(transactions);
    if (recomputedHash !== finalChainHash) {
      return { success: false, reason: 'Chain Hash mismatch' };
    }
    const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    let simulatedBioConstant = initialBioConstant;
    let prevTimestamp = joinTimestamp;
    for (let tx of sortedTx) {
      const delta = tx.timestamp - prevTimestamp;
      if (delta < 0) return { success: false, reason: 'Transaction timestamps are out of order' };
      simulatedBioConstant += delta;
      if (tx.bioConstantAtGeneration !== undefined && tx.bioConstantAtGeneration !== simulatedBioConstant) {
        return { success: false, reason: `BioConstant mismatch on TX at timestamp ${tx.timestamp}` };
      }
      prevTimestamp = tx.timestamp;
    }
    return { success: true };
  } catch (err) {
    return { success: false, reason: err.message };
  }
}

/* ------------------------------------------------------------------
   6) Vault Persistence
------------------------------------------------------------------ */
async function persistVaultData(salt = null) {
  if (!derivedKey) {
    console.error("No encryption key available for persistVaultData.");
    return;
  }
  const { iv, ciphertext } = await encryptData(derivedKey, vaultData);
  let saltBase64;
  if (salt) {
    saltBase64 = bufferToBase64(salt);
  } else {
    const stored = await loadVaultDataFromDB();
    if (stored && stored.salt) {
      saltBase64 = bufferToBase64(stored.salt);
    } else {
      console.error("Salt not found in DB. Skipping persistence to avoid corruption.");
      return;
    }
  }
  await saveVaultDataToDB(iv, ciphertext, saltBase64);
  const backupPayload = {
    iv: bufferToBase64(iv),
    data: bufferToBase64(ciphertext),
    salt: saltBase64,
    timestamp: Date.now()
  };
  localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
  vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: backupPayload });
  console.log('💾 Vault data persisted successfully.');
}
async function promptAndSaveVault() {
  if (!derivedKey) return;
  await persistVaultData();
}

/* ------------------------------------------------------------------
   7) Local Backup Restore (Modal-based)
------------------------------------------------------------------ */
async function tryLocalBackupRestore() {
  const backupStr = localStorage.getItem(VAULT_BACKUP_KEY);
  if (!backupStr) {
    console.log("No local backup found in localStorage. Cannot restore.");
    return false;
  }
  try {
    const backup = JSON.parse(backupStr);
    const { pin } = await getPassphraseFromModal({
      confirmNeeded: false,
      modalTitle: "Restore Backup: Enter Old Passphrase"
    });
    if (!pin) {
      console.log("User canceled backup restore.");
      return false;
    }
    const saltBuf = base64ToBuffer(backup.salt);
    const attemptKey = await deriveKeyFromPIN(pin, saltBuf);
    if (!attemptKey) {
      alert("❌ Could not derive key from backup passphrase.");
      return false;
    }
    const ivBuf = base64ToBuffer(backup.iv);
    const cipherBuf = base64ToBuffer(backup.data);
    const decryptedData = await decryptData(attemptKey, ivBuf, cipherBuf);
    vaultData = decryptedData;
    derivedKey = attemptKey;
    await persistVaultData(saltBuf);
    alert("✅ Local backup restored successfully!");
    return true;
  } catch (err) {
    console.error("Backup restore error:", err);
    alert("❌ Failed to restore from backup. See console for details.");
    return false;
  }
}

/* ------------------------------------------------------------------
   8) Create / Unlock Vault
------------------------------------------------------------------ */
async function ensureSingleVaultOnThisDevice() {
  let devKey = localStorage.getItem('deviceKey');
  const stored = await loadVaultDataFromDB();
  if (stored) {
    console.log("Vault data found in DB. Let user unlock it by pressing 'Enter Vault'.");
    document.getElementById('enterVaultBtn').style.display = 'block';
    document.getElementById('lockedScreen').classList.remove('hidden');
  } else {
    console.log("No valid vault data in DB. Trying local backup...");
    if (devKey) {
      let restored = await tryLocalBackupRestore();
      if (restored) {
        document.getElementById('enterVaultBtn').style.display = 'block';
        document.getElementById('lockedScreen').classList.remove('hidden');
        return;
      }
    }
    console.log("No backup or restore failed. We'll do a new vault on user action.");
    document.getElementById('enterVaultBtn').style.display = 'block';
    document.getElementById('lockedScreen').classList.remove('hidden');
  }
}

async function createNewVault() {
  const devKey = await getOrCreateDeviceKey();
  const { pin } = await getPassphraseFromModal({
    confirmNeeded: true,
    modalTitle: "Create Vault: Enter Passphrase"
  });
  if (!pin) {
    alert("❌ Vault creation aborted. No passphrase provided.");
    return;
  }
  // Attempt simple biometric
  let ok = await performSimpleBiometricCheck();
  if (!ok) {
    const fallback = confirm("Biometric creation check failed or cancelled. Proceed with NO BIOMETRIC?");
    if (!fallback) {
      alert("Vault not created. You must allow or fallback acceptance.");
      return;
    } else {
      console.log("User chose fallback => no biometric used.");
    }
  }

  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = vaultData.bioConstant;
  vaultData.joinTimestamp = nowSec;
  vaultData.bioIBAN = `BIO${vaultData.bioConstant + nowSec}`;
  vaultData.balanceTVM = vaultData.initialBalanceTVM;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.incrementsUsed = 0;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';
  vaultData.deviceKey = devKey;

  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pin, salt);
  if (!derivedKey) {
    alert("Failed to derive encryption key. Vault creation aborted.");
    return;
  }
  await persistVaultData(salt);
  vaultUnlocked = true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked', 'true');
  localStorage.setItem('vaultLock', 'unlocked');
  console.log("✅ New vault created & unlocked successfully (simple biometric or fallback).");
}

async function unlockVault() {
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    alert("No vault data found. Creating new vault now...");
    await createNewVault();
    return;
  }
  if (stored.lockoutTimestamp) {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (currentTimestamp < stored.lockoutTimestamp) {
      const remaining = stored.lockoutTimestamp - currentTimestamp;
      alert(`❌ Vault is locked. Try again in ${Math.ceil(remaining / 60)} minutes.`);
      return;
    } else {
      stored.lockoutTimestamp = null;
      stored.authAttempts = 0;
    }
  }
  // Attempt simple biometric
  let ok = await performSimpleBiometricCheck();
  if (!ok) {
    const fallback = confirm("Biometric check failed or cancelled. Continue unlocking with NO BIOMETRIC?");
    if (!fallback) {
      alert("Unlock aborted. You must allow biometric or fallback acceptance.");
      return handleFailedAuthAttempt(null);
    }
  }

  const { pin } = await getPassphraseFromModal({
    confirmNeeded: false,
    modalTitle: "Unlock Vault: Enter Passphrase"
  });
  if (!pin) {
    alert("❌ Passphrase is required or user canceled.");
    return handleFailedAuthAttempt(null);
  }

  if (!stored.salt) {
    alert("No salt in stored vault data => corrupted? Attempting backup restore or new vault...");
    return handleFailedAuthAttempt(null);
  }
  const attemptKey = await deriveKeyFromPIN(pin, stored.salt);
  if (!attemptKey) {
    alert("❌ Could not derive key from passphrase. Aborting unlock.");
    return handleFailedAuthAttempt(null);
  }
  try {
    const decryptedData = await decryptData(attemptKey, stored.iv, stored.ciphertext);
    vaultData = decryptedData;
    derivedKey = attemptKey;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
    vaultData.authAttempts = stored.authAttempts;

    let devKey = await getOrCreateDeviceKey();
    if (JSON.stringify(vaultData.deviceKey) !== JSON.stringify(devKey)) {
      alert("❌ This vault is not meant for this device (deviceKey mismatch).");
      return;
    }
    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;
    await promptAndSaveVault();
    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
    localStorage.setItem('vaultLock', 'unlocked');
    console.log("🔓 Vault unlocked successfully (simple biometric or fallback).");
  } catch (err) {
    alert(`❌ Unlock failed: ${err.message}`);
    console.error(err);
    return handleFailedAuthAttempt(null);
  }
}

async function handleFailedAuthAttempt(localKey) {
  if (localKey) derivedKey = localKey;
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max attempts exceeded. Locked out for 1 hour.');
    vaultSyncChannel.postMessage({ type: 'lockout', lockoutTimestamp: vaultData.lockoutTimestamp });
  } else {
    alert(`❌ Authentication failed. ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  if (derivedKey) {
    await promptAndSaveVault();
  }
}

function lockVault() {
  if (!vaultUnlocked) return;
  vaultUnlocked = false;
  document.getElementById('vaultUI').classList.add('hidden');
  document.getElementById('lockVaultBtn').classList.add('hidden');
  document.getElementById('lockedScreen').classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  localStorage.setItem('vaultLock', 'locked');
  console.log('🔒 Vault locked by user action.');
}

/* ------------------------------------------------------------------
   9) Periodic Increments, UI
------------------------------------------------------------------ */
function updatePeriodicIncrements() {
  if (!vaultData.joinTimestamp) return;
  const nowSec = Math.floor(Date.now() / 1000);
  const elapsed = nowSec - vaultData.joinTimestamp;
  const intervalsPassed = Math.floor(elapsed / THREE_MONTHS_SECONDS);
  const newIncrements = Math.min(intervalsPassed, MAX_ANNUAL_INTERVALS);
  if (newIncrements > vaultData.incrementsUsed) {
    const difference = newIncrements - vaultData.incrementsUsed;
    const bonus = difference * BIO_LINE_INCREMENT_AMOUNT;
    vaultData.initialBalanceTVM += bonus;
    vaultData.incrementsUsed = newIncrements;
  }
}
function populateWalletUI() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (bioIBANInput) {
    bioIBANInput.value = vaultData.bioIBAN || 'BIO...';
  }
  updatePeriodicIncrements();
  const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((acc, tx) => acc + tx.amount, 0);
  const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((acc, tx) => acc + tx.amount, 0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM - sentTVM;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));
  document.getElementById('tvmBalance').textContent = `💰 Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  const bioLineElement = document.getElementById('bioLineText');
  const utcTimeElement = document.getElementById('utcTime');
  if (bioLineElement && utcTimeElement) {
    bioLineElement.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
    utcTimeElement.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}
function initializeBioConstantAndUTCTime() {
  if (bioLineInterval) clearInterval(bioLineInterval);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsedSeconds = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsedSeconds;
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();
  // every 30s
  bioLineInterval = setInterval(async () => {
    vaultData.bioConstant += 30;
    vaultData.lastUTCTimestamp += 30;
    populateWalletUI();
    await promptAndSaveVault();
  }, 30_000);
}
function showVaultUI() {
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('lockVaultBtn').classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

/* ------------------------------------------------------------------
   10) UI Helpers
------------------------------------------------------------------ */
function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ Error: No Bio‑IBAN found to copy!');
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => alert('✅ Bio‑IBAN copied to clipboard!'))
    .catch(err => {
      console.error('❌ Clipboard copy failed:', err);
      alert('⚠️ Failed to copy Bio‑IBAN. Try again!');
    });
}
function exportTransactionTable() {
  const table = document.getElementById('transactionTable');
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";
  rows.forEach(row => {
    const cols = row.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(col => {
      let data = col.innerText.replace(/"/g, '""');
      if (data.includes(',')) data = `"${data}"`;
      rowData.push(data);
    });
    csvContent += rowData.join(",") + "\r\n";
  });
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "transaction_history.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
function showBioCatchPopup(encryptedBioCatch) {
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const bioCatchNumberText = document.getElementById('bioCatchNumberText');
  bioCatchNumberText.textContent = encryptedBioCatch;
  bioCatchPopup.style.display = 'flex';
}
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  vaultData.transactions
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const row = document.createElement('tr');
      let bioIBANCell = '—';
      if (tx.type === 'sent') {
        bioIBANCell = tx.receiverBioIBAN;
      } else if (tx.type === 'received') {
        bioIBANCell = tx.senderBioIBAN || 'Unknown';
      }
      let bioCatchCell = tx.bioCatch || '—';
      let amountCell = tx.amount;
      let timestampCell = formatDisplayDate(tx.timestamp);
      let statusCell = tx.status;
      let bioIBANCellStyle = '';
      if (tx.type === 'sent') {
        bioIBANCellStyle = 'style="background-color: #FFCCCC;"';
      } else if (tx.type === 'received') {
        bioIBANCellStyle = 'style="background-color: #CCFFCC;"';
      }
      row.innerHTML = `
        <td ${bioIBANCellStyle}>${bioIBANCell}</td>
        <td>${bioCatchCell}</td>
        <td>${amountCell}</td>
        <td>${timestampCell}</td>
        <td>${statusCell}</td>
      `;
      tbody.appendChild(row);
    });
}

/* ------------------------------------------------------------------
   Snapshots for Bio‑Catch Validation
------------------------------------------------------------------ */
function serializeVaultSnapshotForBioCatch(vData) {
  const fieldSep = '|';
  const txSep = '^';
  const txFieldSep = '~';
  const txParts = (vData.transactions || []).map(tx => {
    return [
      tx.type || '',
      tx.receiverBioIBAN || '',
      tx.senderBioIBAN || '',
      tx.amount || 0,
      tx.timestamp || 0,
      tx.status || '',
      tx.bioCatch || '',
      tx.bioConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.incrementsUsed || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    txString
  ].join(fieldSep);
  return btoa(rawString);
}
function deserializeVaultSnapshotFromBioCatch(base64String) {
  const raw = atob(base64String);
  const fieldSep = '|';
  const txSep = '^';
  const txFieldSep = '~';
  const parts = raw.split(fieldSep);
  if (parts.length < 6) throw new Error('Vault snapshot missing fields.');
  const joinTimestamp = parseInt(parts[0], 10);
  const initialBioConstant = parseInt(parts[1], 10);
  const incrementsUsed = parseInt(parts[2], 10);
  const finalChainHash = parts[3];
  const initialBalanceTVM = parseInt(parts[4], 10);
  const txString = parts[5] || '';
  const txChunks = txString.split(txSep).filter(Boolean);
  const transactions = txChunks.map(chunk => {
    const txFields = chunk.split(txFieldSep);
    return {
      type: txFields[0] || '',
      receiverBioIBAN: txFields[1] || '',
      senderBioIBAN: txFields[2] || '',
      amount: parseFloat(txFields[3]) || 0,
      timestamp: parseInt(txFields[4], 10) || 0,
      status: txFields[5] || '',
      bioCatch: txFields[6] || '',
      bioConstantAtGeneration: parseInt(txFields[7], 10) || 0,
      previousHash: txFields[8] || '',
      txHash: txFields[9] || ''
    };
  });
  return {
    joinTimestamp,
    initialBioConstant,
    incrementsUsed,
    finalChainHash,
    initialBalanceTVM,
    transactions
  };
}

/* ------------------------------------------------------------------
   11) Transaction Handlers (with concurrency)
------------------------------------------------------------------ */
async function handleSendTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (localStorage.getItem('txInProgress') === 'true') {
    alert("🔒 Another transaction is in progress (possibly in another tab). Please wait.");
    return;
  }
  localStorage.setItem('txInProgress', 'true');
  try {
    const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
    const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
    if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
      alert('❌ Please enter a valid Receiver Bio‑IBAN and Amount.');
      return;
    }
    if (!validateBioIBAN(receiverBioIBAN)) {
      alert('❌ Invalid Receiver Bio‑IBAN format.');
      return;
    }
    if (receiverBioIBAN === vaultData.bioIBAN) {
      alert('❌ You cannot send to your own Bio‑IBAN.');
      return;
    }
    if (vaultData.balanceTVM < amount) {
      alert('❌ Insufficient TVM balance.');
      return;
    }
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    const currentTimestamp = vaultData.lastUTCTimestamp;
    const plainBioCatchNumber = generateBioCatchNumber(
      vaultData.bioIBAN,
      receiverBioIBAN,
      amount,
      currentTimestamp,
      vaultData.balanceTVM,
      vaultData.finalChainHash
    );
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plainBioCatchNumber) {
          alert('❌ This BioCatch number already exists. Try again.');
          return;
        }
      }
    }
    const obfuscatedCatch = await encryptBioCatchNumber(plainBioCatchNumber);
    const newTx = {
      type: 'sent',
      receiverBioIBAN,
      amount,
      timestamp: currentTimestamp,
      status: 'Completed',
      bioCatch: obfuscatedCatch,
      bioConstantAtGeneration: vaultData.bioConstant,
      previousHash: vaultData.lastTransactionHash
    };
    newTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash = newTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Transaction successful! Amount ${amount} TVM sent to ${receiverBioIBAN}`);
    showBioCatchPopup(obfuscatedCatch);
    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Error processing send transaction:', error);
    alert('❌ An error occurred while processing the transaction. Please try again.');
  } finally {
    localStorage.setItem('txInProgress', 'false');
  }
}

async function handleReceiveTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (localStorage.getItem('txInProgress') === 'true') {
    alert("🔒 Another transaction is in progress (possibly in another tab). Please wait.");
    return;
  }
  localStorage.setItem('txInProgress', 'true');
  try {
    const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
    const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
    if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
      alert('❌ Please enter a valid (base64) BioCatch Number and Amount.');
      return;
    }
    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode the provided BioCatch Number. Please ensure it is correct.');
      return;
    }
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          alert('❌ This BioCatch Number has already been used in a transaction.');
          return;
        }
      }
    }
    const validation = validateBioCatchNumber(bioCatchNumber, amount);
    if (!validation.valid) {
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      return;
    }
    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    const crossCheck = await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if (!crossCheck.success) {
      alert(`❌ Sender chain mismatch: ${crossCheck.reason}`);
      return;
    }
    if (senderVaultSnapshot.finalChainHash !== chainHash) {
      alert('❌ The chainHash in the Bio‑Catch does not match snapshot’s finalChainHash!');
      return;
    }
    const currentTimestamp = vaultData.lastUTCTimestamp;
    const newRx = {
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: currentTimestamp,
      status: 'Valid',
      bioConstantAtGeneration: vaultData.bioConstant,
      previousHash: vaultData.lastTransactionHash
    };
    newRx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newRx);
    vaultData.transactions.push(newRx);
    vaultData.lastTransactionHash = newRx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Transaction received successfully! ${amount} TVM added.`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Error processing receive transaction:', error);
    alert('❌ An error occurred. Please try again.');
  } finally {
    localStorage.setItem('txInProgress', 'false');
  }
}

/* ------------------------------------------------------------------
   12) Multi-Tab & Offline Handling
------------------------------------------------------------------ */
function preventMultipleVaults() {
  window.addEventListener('storage', (event) => {
    if (event.key === 'vaultUnlocked') {
      if (event.newValue === 'true' && !vaultUnlocked) {
        vaultUnlocked = true;
        showVaultUI();
        initializeBioConstantAndUTCTime();
      } else if (event.newValue === 'false' && vaultUnlocked) {
        vaultUnlocked = false;
        lockVault();
      }
    }
    if (event.key === 'vaultLock') {
      if (event.newValue === 'locked' && vaultUnlocked) {
        lockVault();
      }
    }
    if (event.key === 'txInProgress') {
      console.log(`txInProgress changed => ${event.newValue}`);
    }
  });
}
function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log(`🔒 Vault lock status: ${vaultLock}`);
  }
}

/* ------------------------------------------------------------------
   Startup
------------------------------------------------------------------ */
window.addEventListener('DOMContentLoaded', async () => {
  // Minimal check to avoid infinite redirect loops
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && lastURL !== window.location.href) {
    if (!/avoid-loop/.test(window.location.href)) {
      window.location.href = `${lastURL}?avoid-loop=1`;
      return;
    }
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });
  console.log("✅ main.js: Initializing UI...");
  initializeUI();
  await ensureSingleVaultOnThisDevice();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey not available in this tab yet.');
          return;
        }
        const decrypted = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, decrypted);
        populateWalletUI();
        console.log('🔄 Synced vault across tabs');
      } catch (err) {
        console.error('Tab sync failed:', err);
      }
    }
    else if (e.data?.type === 'lockout') {
      vaultData.lockoutTimestamp = e.data.lockoutTimestamp;
      alert(`⚠️ The vault is locked out until ${formatDisplayDate(vaultData.lockoutTimestamp)}!`);
    }
  };
});

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? '🔒 Storage hardened (persist granted)' : '⚠️ Storage not persistent');
  }
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('🚨 Storage usage critical:', estimate);
      alert('❗ Vault storage nearing limit! Please export a backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

function initializeUI() {
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', () => {
      loadVaultDataFromDB().then(stored => {
        if (!stored) {
          createNewVault();
        } else {
          unlockVault();
        }
      });
    });
  }

  const lockVaultBtn = document.getElementById('lockVaultBtn');
  if (lockVaultBtn) lockVaultBtn.addEventListener('click', lockVault);

  const catchInBtn = document.getElementById('catchInBtn');
  if (catchInBtn) catchInBtn.addEventListener('click', handleReceiveTransaction);

  const catchOutBtn = document.getElementById('catchOutBtn');
  if (catchOutBtn) catchOutBtn.addEventListener('click', handleSendTransaction);

  const copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  if (copyBioIBANBtn) copyBioIBANBtn.addEventListener('click', handleCopyBioIBAN);

  const exportBtn = document.getElementById('exportBtn');
  if (exportBtn) exportBtn.addEventListener('click', exportTransactionTable);

  // passModal references
  const passModal = document.getElementById('passModal');
  passModal.style.display = 'none';

  // Bio-Catch popup
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
  if (closeBioCatchPopupBtn) {
    closeBioCatchPopupBtn.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
  }
  const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
  if (copyBioCatchPopupBtn) {
    copyBioCatchPopupBtn.addEventListener('click', () => {
      const bcNum = document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(() => alert('✅ Bio‑Catch Number copied to clipboard!'))
        .catch(err => {
          console.error('❌ Clipboard copy failed:', err);
          alert('⚠️ Failed to copy Bio‑Catch Number. Try again!');
        });
    });
  }
  window.addEventListener('click', (event) => {
    if (event.target === bioCatchPopup) {
      bioCatchPopup.style.display = 'none';
    }
  });

  enforceSingleVault();
}
