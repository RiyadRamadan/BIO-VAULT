/***********************************************************************
 * main.js — Enhanced Version (with chain cross-check + full vault snapshot
 *            embedded in Bio‑Catch) + Device Key Enforcement, PIN Confirmation,
 *            and Transaction Authentication.
 *
 * This version uses a custom, non-JSON serialization to embed the sender’s
 * entire vault data into the Bio‑Catch itself.
 *
 * ADDITIONS/CHANGES:
 * - Generates a device key (stored in localStorage) to ensure only one vault per device.
 *   If a vault already exists on this device, any attempt to create a new one will instead
 *   load the existing vault.
 * - The initial vault creation now asks the user to confirm their passphrase.
 * - Before sending money, the user must authenticate (via biometric if available).
 * - The "Add to Home Screen" code has been removed. Instead, if the device supports auto‑prompting
 *   (via the beforeinstallprompt event), that prompt is fired automatically.
 *
 * NOTE: The 404 errors for icon.png and the manifest warnings are due to missing assets.
 ***********************************************************************/

/* ========= Global Constants & Variables ========= */
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

const EXCHANGE_RATE = 12;  // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // 12 minutes
const LOCKOUT_DURATION_SECONDS = 3600; // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const THREE_MONTHS_SECONDS = 7776000; // Every 3 months
const MAX_ANNUAL_INTERVALS = 4;
const BIO_LINE_INCREMENT_AMOUNT = 15000; // 15,000 TVM per interval

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 minutes

const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;  // Derived from user's passphrase
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
  credentialId: null,
  finalChainHash: '',
  deviceKey: null
};

/* ========= UTILITY FUNCTIONS ========= */
function formatWithCommas(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

/* ========= A2HS AUTO‑PROMPT ========= */
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ 'beforeinstallprompt' event captured.");
  setTimeout(() => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(choiceResult => {
        console.log(`User response to install prompt: ${choiceResult.outcome}`);
        deferredPrompt = null;
      });
    }
  }, 1000);
});

/* ========= DEVICE KEY FUNCTIONS ========= */
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

/* ========= TRANSACTION HASHING ========= */
async function computeTransactionHash(previousHash, txObject) {
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
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

/* ========= CHAIN & BIO‑CONSTANT VALIDATION ========= */
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
      if (delta < 0) {
        return { success: false, reason: 'Transaction timestamps are out of order' };
      }
      simulatedBioConstant += delta;
      if (tx.bioConstantAtGeneration !== undefined &&
          tx.bioConstantAtGeneration !== simulatedBioConstant) {
        return { success: false, reason: `BioConstant mismatch on TX at timestamp ${tx.timestamp}` };
      }
      prevTimestamp = tx.timestamp;
    }
    return { success: true };
  } catch (err) {
    console.error('verifyFullChainAndBioConstant error:', err);
    return { success: false, reason: err.message };
  }
}

/* ========= CRYPTO HELPERS ========= */
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

async function deriveKeyFromPIN(pin, salt) {
  try {
    const encoder = new TextEncoder();
    const pinBuffer = encoder.encode(pin);
    const keyMaterial = await crypto.subtle.importKey('raw', pinBuffer, { name: 'PBKDF2' }, false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
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

/* ========= WEBAUTHN / BIOMETRIC ========= */
async function performBiometricAuthenticationForCreation() {
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
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
      timeout: 60000,
      attestation: "none"
    };
    const credential = await navigator.credentials.create({ publicKey });
    return credential || null;
  } catch (err) {
    console.error("Biometric Credential Creation Error:", err);
    return null;
  }
}

async function performBiometricAssertion(credentialId) {
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: base64ToBuffer(credentialId), type: 'public-key' }],
      userVerification: "required",
      timeout: 60000
    };
    const assertion = await navigator.credentials.get({ publicKey });
    return !!assertion;
  } catch (err) {
    console.error("Biometric Assertion Error:", err);
    return false;
  }
}

/* ========= TRANSACTION AUTHENTICATION ========= */
async function authenticateForTransaction() {
  if (vaultData.credentialId) {
    const ok = await performBiometricAssertion(vaultData.credentialId);
    return ok;
  }
  alert("Transaction authentication failed. Transaction cancelled.");
  return false;
}

/* ========= ENCRYPTION / DECRYPTION ========= */
async function encryptData(key, dataObj) {
  try {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ciphertext };
  } catch (err) {
    console.error("Encryption error:", err);
    throw err;
  }
}

async function decryptData(key, iv, ciphertext) {
  try {
    const dec = new TextDecoder();
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(plainBuffer));
  } catch (err) {
    console.error("Decryption error:", err);
    throw err;
  }
}

async function encryptBioCatchNumber(plainText) {
  try {
    return btoa(plainText);
  } catch (err) {
    console.error("Error obfuscating BioCatchNumber:", err);
    return plainText;
  }
}

async function decryptBioCatchNumber(encryptedString) {
  try {
    return atob(encryptedString);
  } catch (err) {
    console.error("Error deobfuscating BioCatchNumber:", err);
    return null;
  }
}

/* ========= INDEXEDDB CRUD ========= */
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
  try {
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
  } catch (err) {
    console.error("Error saving to DB:", err);
    throw err;
  }
}

async function loadVaultDataFromDB() {
  try {
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
            resolve({ iv, ciphertext, salt, lockoutTimestamp: getReq.result.lockoutTimestamp || null, authAttempts: getReq.result.authAttempts || 0 });
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
  } catch (err) {
    console.error("Error loading from DB:", err);
    return null;
  }
}

/* ========= VAULT CREATION / UNLOCK ========= */
async function createNewVault(pin) {
  // If a vault already exists on this device, load it instead.
  const existingDeviceKey = localStorage.getItem('deviceKey');
  if (existingDeviceKey) {
    alert('A vault has already been created on this device. Opening existing vault.');
    await unlockVault();
    return;
  }
  if (!pin || pin.length < 8) {
    alert('⚠️ Please use a strong passphrase of at least 8 characters!');
    return;
  }
  const pinConfirm = prompt('Confirm your vault passphrase:');
  if (pin !== pinConfirm) {
    alert('Passphrases do not match.');
    return;
  }
  console.log("No existing vault found. Proceeding with NEW vault creation...");
  localStorage.setItem('vaultLock', 'locked');
  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = vaultData.bioConstant;
  vaultData.joinTimestamp = nowSec;
  vaultData.bioIBAN = `BIO${vaultData.bioConstant + nowSec}`;
  vaultData.balanceTVM = 15000;
  vaultData.balanceUSD = parseFloat((15000 / EXCHANGE_RATE).toFixed(2));
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.incrementsUsed = 0;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';
  // Generate or retrieve device key.
  const deviceKey = await getOrCreateDeviceKey();
  vaultData.deviceKey = deviceKey;
  // Create biometric credential.
  let credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric device credential creation failed or was cancelled. Vault cannot be created.');
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);
  console.log('🆕 Creating new vault:', vaultData);
  const salt = generateSalt();
  console.log('🆕 Generated new salt:', salt);
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
}

async function unlockVault() {
  if (vaultData.lockoutTimestamp) {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (currentTimestamp < vaultData.lockoutTimestamp) {
      const remaining = vaultData.lockoutTimestamp - currentTimestamp;
      alert(`❌ Vault is locked. Try again in ${Math.ceil(remaining / 60)} minutes.`);
      return;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }
  const pin = prompt('🔒 Enter your vault passphrase (>=8 chars recommended):');
  if (!pin) {
    alert('❌ Passphrase is required.');
    await handleFailedAuthAttempt();
    return;
  }
  if (pin.length < 8) {
    alert('⚠️ Please use a stronger passphrase of at least 8 characters.');
    await handleFailedAuthAttempt();
    return;
  }
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    if (!confirm('⚠️ No existing vault found. Create a new vault?')) return;
    await createNewVault(pin);
    return;
  }
  try {
    if (!stored.salt) {
      throw new Error('🔴 Salt not found in stored data.');
    }
    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    if (!derivedKey) throw new Error("Failed to derive encryption key.");
    const decryptedData = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData = decryptedData;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
    vaultData.authAttempts = stored.authAttempts;
    // Check device key.
    const currentDeviceKey = await getOrCreateDeviceKey();
    if (JSON.stringify(vaultData.deviceKey) !== JSON.stringify(currentDeviceKey)) {
      alert('❌ This vault is not meant for this device.');
      return;
    }
    if (vaultData.credentialId) {
      const assertionOK = await performBiometricAssertion(vaultData.credentialId);
      if (!assertionOK) {
        alert('❌ This device does not match the vault’s stored credential. Unlock failed.');
        await handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("🔶 No credentialId found in vault, skipping WebAuthn check.");
    }
    console.log('🔓 Vault Decrypted:', vaultData);
    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;
    await promptAndSaveVault();
    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
  } catch (err) {
    alert(`❌ Failed to decrypt: ${err.message}`);
    console.error(err);
    await handleFailedAuthAttempt();
  }
}

async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
  } else {
    alert(`❌ Authentication failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
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
  console.log('🔒 Vault locked.');
  localStorage.setItem('vaultUnlocked', 'false');
}

/* ========= PERSISTENCE ========= */
async function persistVaultData(salt = null) {
  try {
    if (!derivedKey) {
      console.error("No encryption key available.");
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
        console.error("Salt not found. Skipping persistence.");
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
    console.log('💾 Triply-redundant persistence complete');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

async function promptAndSaveVault() {
  if (!derivedKey) return;
  await persistVaultData();
}

/* ========= UI FUNCTIONS ========= */
function showVaultUI() {
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('lockVaultBtn').classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

/* ========= STARTUP & MULTI‑TAB ========= */
window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });
  console.log("✅ Initializing UI...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();
  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey is not available yet.');
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
  };
});

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? '🔒 Storage hardened' : '⚠️ Storage vulnerable');
  }
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('🚨 Storage critical:', estimate);
      alert('❗ Vault storage nearing limit! Export backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

async function loadVaultOnStartup() {
  try {
    let stored = await loadVaultDataFromDB();
    if (!stored) {
      const backup = localStorage.getItem(VAULT_BACKUP_KEY);
      if (backup) {
        const parsed = JSON.parse(backup);
        parsed.iv = base64ToBuffer(parsed.iv);
        parsed.ciphertext = base64ToBuffer(parsed.data);
        console.log('♻️ Restored from localStorage backup');
        stored = parsed;
      }
    }
    if (stored) {
      document.getElementById('enterVaultBtn').style.display = 'block';
      document.getElementById('lockedScreen').classList.remove('hidden');
    } else {
      document.getElementById('enterVaultBtn').style.display = 'block';
      document.getElementById('lockedScreen').classList.remove('hidden');
    }
  } catch (err) {
    console.error('🔥 Backup restoration failed:', err);
    localStorage.removeItem(VAULT_BACKUP_KEY);
  }
}

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
      if (event.newValue === 'locked' && !vaultUnlocked) {
        console.log('🔒 Another tab indicated vault lock is in place.');
      }
    }
  });
  enforceSingleVault();
}

/* ========= WALLET / BALANCE / BIO‑LINE ========= */
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
  const tvmFormatted = formatWithCommas(vaultData.balanceTVM);
  const usdFormatted = formatWithCommas(vaultData.balanceUSD);
  document.getElementById('tvmBalance').textContent = `💰 Balance: ${tvmFormatted} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${usdFormatted} USD`;
  const bioLineElement = document.getElementById('bioLineText');
  const utcTimeElement = document.getElementById('utcTime');
  if (bioLineElement && utcTimeElement) {
    bioLineElement.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
    utcTimeElement.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

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
    console.log(`💥 Gave user ${bonus} TVM in lumpsum increments (3-mo intervals).`);
  }
}

function initializeBioConstantAndUTCTime() {
  if (bioLineInterval) clearInterval(bioLineInterval);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsedSeconds = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsedSeconds;
  vaultData.lastUTCTimestamp = currentTimestamp;
  console.log("✅ Bio-Line initialized with current bioConstant and UTC timestamp.");
  populateWalletUI();
  bioLineInterval = setInterval(async () => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    populateWalletUI();
    await promptAndSaveVault();
  }, 1000);
}

/* ========= COPY / EXPORT ========= */
function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ Error: No Bio-IBAN found to copy!');
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

/* ========= SNAPSHOT SERIALIZATION ========= */
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
  if (parts.length < 6) {
    throw new Error('Vault snapshot missing fields.');
  }
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
  return { joinTimestamp, initialBioConstant, incrementsUsed, finalChainHash, initialBalanceTVM, transactions };
}

/* ========= BIO‑CATCH GENERATION & VALIDATION ========= */
function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  const senderVaultSnapshotEncoded = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  const secondPart = amount + timestamp;
  return `Bio-${firstPart}-${secondPart}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${senderVaultSnapshotEncoded}`;
}

function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 7 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 7 parts with prefix "Bio-".' };
  }
  const [ , firstPartStr, secondPartStr, claimedSenderBalanceStr, claimedSenderIBAN, chainHash, snapshotEncoded ] = parts;
  const firstPart = parseInt(firstPartStr);
  const secondPart = parseInt(secondPartStr);
  const claimedSenderBalance = parseInt(claimedSenderBalanceStr);
  if (isNaN(firstPart) || isNaN(secondPart) || isNaN(claimedSenderBalance)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
  const senderNumeric = firstPart - receiverNumeric;
  if (senderNumeric < 0) {
    return { valid: false, message: 'Negative or invalid sender numeric from Bio-Catch code.' };
  }
  const expectedFirstPart = senderNumeric + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of sender/receiver IBAN numerics.' };
  }
  const extractedTimestamp = secondPart - claimedAmount;
  const currentTimestamp = vaultData.lastUTCTimestamp;
  const timeDiff = Math.abs(currentTimestamp - extractedTimestamp);
  if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp is outside ±12min window.' };
  }
  const expectedSenderIBAN = `BIO${senderNumeric}`;
  if (claimedSenderIBAN !== expectedSenderIBAN) {
    return { valid: false, message: 'Mismatched Sender IBAN in the Bio-Catch code.' };
  }
  if (claimedSenderBalance < claimedAmount) {
    return { valid: false, message: 'Sender’s claimed balance is less than transaction amount.' };
  }
  let senderVaultSnapshot = null;
  try {
    senderVaultSnapshot = deserializeVaultSnapshotFromBioCatch(snapshotEncoded);
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }
  return { valid: true, message: 'OK', chainHash, claimedSenderIBAN, senderVaultSnapshot };
}

function validateBioIBAN(bioIBAN) {
  if (!bioIBAN.startsWith('BIO')) return false;
  const numericPart = parseInt(bioIBAN.slice(3));
  return !isNaN(numericPart) && numericPart > 0;
}

/* ========= TRANSACTION HANDLERS ========= */
let transactionLock = false;

async function handleSendTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    return;
  }
  const authOk = await authenticateForTransaction();
  if (!authOk) return;
  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Please enter a valid Receiver Bio‑IBAN and Amount.');
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Receiver Bio-IBAN format.');
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
  transactionLock = true;
  try {
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
      bioConstantAtGeneration: vaultData.bioConstant
    };
    newTx.previousHash = vaultData.lastTransactionHash;
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
    transactionLock = false;
  }
}

async function handleReceiveTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    return;
  }
  const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
  const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
  if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
    alert('❌ Please enter a valid (base64) BioCatch Number and Amount.');
    return;
  }
  transactionLock = true;
  try {
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
      bioConstantAtGeneration: vaultData.bioConstant
    };
    newRx.previousHash = vaultData.lastTransactionHash;
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
    transactionLock = false;
  }
}

/* ========= TRANSACTION TABLE / POPUPS ========= */
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  tbody.innerHTML = '';
  vaultData.transactions
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const row = document.createElement('tr');
      let bioIBANCell = '—';
      let bioCatchCell = '—';
      let amountCell = tx.amount;
      let timestampCell = formatDisplayDate(tx.timestamp);
      let statusCell = tx.status;
      if (tx.type === 'sent') {
        bioIBANCell = tx.receiverBioIBAN;
      } else if (tx.type === 'received') {
        bioIBANCell = tx.senderBioIBAN || 'Unknown';
      }
      if (tx.bioCatch) {
        bioCatchCell = tx.bioCatch;
      }
      let bioIBANCellStyle = tx.type === 'sent'
        ? 'style="background-color: #FFCCCC;"'
        : tx.type === 'received'
        ? 'style="background-color: #CCFFCC;"'
        : '';
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

function showBioCatchPopup(encryptedBioCatch) {
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const bioCatchNumberText = document.getElementById('bioCatchNumberText');
  bioCatchNumberText.textContent = encryptedBioCatch;
  bioCatchPopup.style.display = 'flex';
}

/* ========= UI INITIALIZATION ========= */
function initializeUI() {
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', unlockVault);
    console.log("✅ Event listener attached to enterVaultBtn!");
  } else {
    console.error("❌ enterVaultBtn NOT FOUND in DOM!");
  }
  const lockVaultBtn = document.getElementById('lockVaultBtn');
  const catchInBtn = document.getElementById('catchInBtn');
  const catchOutBtn = document.getElementById('catchOutBtn');
  const copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  const exportBtn = document.getElementById('exportBtn');
  if (lockVaultBtn) lockVaultBtn.addEventListener('click', lockVault);
  if (catchInBtn) catchInBtn.addEventListener('click', handleReceiveTransaction);
  if (catchOutBtn) catchOutBtn.addEventListener('click', handleSendTransaction);
  if (copyBioIBANBtn) copyBioIBANBtn.addEventListener('click', handleCopyBioIBAN);
  if (exportBtn) exportBtn.addEventListener('click', exportTransactionTable);
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
  const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
  if (closeBioCatchPopupBtn) {
    closeBioCatchPopupBtn.addEventListener('click', () => { bioCatchPopup.style.display = 'none'; });
  }
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
  // "Add to Home Screen" code has been removed.
}

function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

/* ========= WALLET / BALANCE / BIO‑LINE ========= */
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
  const tvmFormatted = formatWithCommas(vaultData.balanceTVM);
  const usdFormatted = formatWithCommas(vaultData.balanceUSD);
  document.getElementById('tvmBalance').textContent = `💰 Balance: ${tvmFormatted} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${usdFormatted} USD`;
  const bioLineElement = document.getElementById('bioLineText');
  const utcTimeElement = document.getElementById('utcTime');
  if (bioLineElement && utcTimeElement) {
    bioLineElement.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
    utcTimeElement.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

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
    console.log(`💥 Gave user ${bonus} TVM in lumpsum increments (3-mo intervals).`);
  }
}

function initializeBioConstantAndUTCTime() {
  if (bioLineInterval) clearInterval(bioLineInterval);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsedSeconds = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsedSeconds;
  vaultData.lastUTCTimestamp = currentTimestamp;
  console.log("✅ Bio-Line initialized with current bioConstant and UTC timestamp.");
  populateWalletUI();
  bioLineInterval = setInterval(async () => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    populateWalletUI();
    await promptAndSaveVault();
  }, 1000);
}

/* ========= COPY / EXPORT ========= */
function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ Error: No Bio-IBAN found to copy!');
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

/* ========= SNAPSHOT SERIALIZATION ========= */
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
  if (parts.length < 6) {
    throw new Error('Vault snapshot missing fields.');
  }
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
  return { joinTimestamp, initialBioConstant, incrementsUsed, finalChainHash, initialBalanceTVM, transactions };
}

/* ========= BIO‑CATCH GENERATION & VALIDATION ========= */
function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  const senderVaultSnapshotEncoded = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  const secondPart = amount + timestamp;
  return `Bio-${firstPart}-${secondPart}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${senderVaultSnapshotEncoded}`;
}

function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 7 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 7 parts with prefix "Bio-".' };
  }
  const [ , firstPartStr, secondPartStr, claimedSenderBalanceStr, claimedSenderIBAN, chainHash, snapshotEncoded ] = parts;
  const firstPart = parseInt(firstPartStr);
  const secondPart = parseInt(secondPartStr);
  const claimedSenderBalance = parseInt(claimedSenderBalanceStr);
  if (isNaN(firstPart) || isNaN(secondPart) || isNaN(claimedSenderBalance)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
  const senderNumeric = firstPart - receiverNumeric;
  if (senderNumeric < 0) {
    return { valid: false, message: 'Negative or invalid sender numeric from Bio-Catch code.' };
  }
  const expectedFirstPart = senderNumeric + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of sender/receiver IBAN numerics.' };
  }
  const extractedTimestamp = secondPart - claimedAmount;
  const currentTimestamp = vaultData.lastUTCTimestamp;
  const timeDiff = Math.abs(currentTimestamp - extractedTimestamp);
  if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp is outside ±12min window.' };
  }
  const expectedSenderIBAN = `BIO${senderNumeric}`;
  if (claimedSenderIBAN !== expectedSenderIBAN) {
    return { valid: false, message: 'Mismatched Sender IBAN in the Bio-Catch code.' };
  }
  if (claimedSenderBalance < claimedAmount) {
    return { valid: false, message: 'Sender’s claimed balance is less than transaction amount.' };
  }
  let senderVaultSnapshot = null;
  try {
    senderVaultSnapshot = deserializeVaultSnapshotFromBioCatch(snapshotEncoded);
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }
  return { valid: true, message: 'OK', chainHash, claimedSenderIBAN, senderVaultSnapshot };
}

function validateBioIBAN(bioIBAN) {
  if (!bioIBAN.startsWith('BIO')) return false;
  const numericPart = parseInt(bioIBAN.slice(3));
  return !isNaN(numericPart) && numericPart > 0;
}

/* ========= TRANSACTION HANDLERS ========= */
let transactionLock = false;

async function handleSendTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    return;
  }
  const authOk = await authenticateForTransaction();
  if (!authOk) return;
  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Please enter a valid Receiver Bio‑IBAN and Amount.');
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Receiver Bio-IBAN format.');
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
  transactionLock = true;
  try {
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
      bioConstantAtGeneration: vaultData.bioConstant
    };
    newTx.previousHash = vaultData.lastTransactionHash;
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
    transactionLock = false;
  }
}

async function handleReceiveTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock the vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 A transaction is already in progress. Please wait.');
    return;
  }
  const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
  const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
  if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
    alert('❌ Please enter a valid (base64) BioCatch Number and Amount.');
    return;
  }
  transactionLock = true;
  try {
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
      bioConstantAtGeneration: vaultData.bioConstant
    };
    newRx.previousHash = vaultData.lastTransactionHash;
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
    transactionLock = false;
  }
}

/* ========= UI / MULTI‑TAB ========= */
window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });
  console.log("✅ Initializing UI...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();
  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey is not available yet.');
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
  };
});

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  const persisted = await navigator.storage.persisted();
  if (!persisted) {
    const granted = await navigator.storage.persist();
    console.log(granted ? '🔒 Storage hardened' : '⚠️ Storage vulnerable');
  }
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('🚨 Storage critical:', estimate);
      alert('❗ Vault storage nearing limit! Export backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

async function loadVaultOnStartup() {
  try {
    let stored = await loadVaultDataFromDB();
    if (!stored) {
      const backup = localStorage.getItem(VAULT_BACKUP_KEY);
      if (backup) {
        const parsed = JSON.parse(backup);
        parsed.iv = base64ToBuffer(parsed.iv);
        parsed.ciphertext = base64ToBuffer(parsed.data);
        console.log('♻️ Restored from localStorage backup');
        stored = parsed;
      }
    }
    if (stored) {
      document.getElementById('enterVaultBtn').style.display = 'block';
      document.getElementById('lockedScreen').classList.remove('hidden');
    } else {
      document.getElementById('enterVaultBtn').style.display = 'block';
      document.getElementById('lockedScreen').classList.remove('hidden');
    }
  } catch (err) {
    console.error('🔥 Backup restoration failed:', err);
    localStorage.removeItem(VAULT_BACKUP_KEY);
  }
}

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
      if (event.newValue === 'locked' && !vaultUnlocked) {
        console.log('🔒 Another tab indicated vault lock is in place.');
      }
    }
  });
  enforceSingleVault();
}
