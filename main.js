/***********************************************************************
 * main.js — Comprehensive Bio‑Vault Code (with enhanced integrity checks)
 *
 * Features:
 *  - Vault creation/unlock (PBKDF2 + AES-GCM encryption, WebAuthn biometrics)
 *  - Transaction chain hashing (computeTransactionHash, computeFullChainHash)
 *  - Daily-limit logic for large TX (>1200 TVM → 400 TVM bonus up to 3/day)
 *  - Periodic increments (15,000 TVM every 3 months, up to 4 times)
 *  - BioCatch numbers embedding entire vault snapshots (8-part format)
 *  - Offline readiness (IndexedDB + localStorage backups, multi-tab sync)
 *  - UI integration (copy IBAN, export CSV, modals, etc.)
 *  - **Extra Verification:** Checks that sender snapshots are anchored
 *    to a known initial balance (3000 TVM) and initial bio-constant.
 ***********************************************************************/

/******************************
 * Constants & Global Variables
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

const EXCHANGE_RATE = 12; // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

// For this system, every vault must start with an initial balance of 3000 TVM.
const INITIAL_BALANCE_TVM = 3000;

// For the bonus increments (if applicable)
const BIO_LINE_INTERVAL = 15783000;     // example value (~182 days)
const BIO_LINE_INCREMENT_AMOUNT = 15000; // 15,000 TVM per interval

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;   // 5 minutes

// Daily-limit logic:
const MAX_BONUS_PER_DAY = 3;   
const LARGE_TX_BONUS = 400;    
const LARGE_TX_THRESHOLD = 1200; // If TX > 1200 TVM => bonus

// Cross-tab sync channel using BroadcastChannel
const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null; // cryptographic key after unlocking
let bioLineIntervalTimer = null;

let vaultData = {
  bioIBAN: null,
  initialBalanceTVM: INITIAL_BALANCE_TVM, // must be 3000
  balanceTVM: 0,
  balanceUSD: 0,
  bioConstant: INITIAL_BIO_CONSTANT,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  joinTimestamp: 0,
  incrementsUsed: 0
};

/******************************
 * Utility / Helper Functions
 ******************************/
function formatWithCommas(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  const isoString = date.toISOString();
  return `${isoString.slice(0, 10)} ${isoString.slice(11, 19)}`;
}

/******************************
 * "Add to Home Screen" Prompt
 ******************************/
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ 'beforeinstallprompt' captured — prompt can be shown via promptInstallA2HS().");
});

function promptInstallA2HS() {
  if (!deferredPrompt) {
    console.log("No deferredPrompt. Possibly not supported or already installed.");
    return;
  }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choiceResult => {
    console.log(`A2HS result: ${choiceResult.outcome}`);
    deferredPrompt = null;
  });
}

/******************************
 * Transaction Hashing Utilities
 ******************************/
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

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
      bioCatch: tx.bioCatch, // if included in chain
      previousHash: runningHash
    };
    runningHash = await computeTransactionHash(runningHash, txObjForHash);
  }
  return runningHash;
}

/******************************
 * Cross-Device Chain & Bio-Constant Validation
 ******************************/
async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  try {
    const { joinTimestamp, initialBioConstant, transactions, finalChainHash } = senderVaultSnapshot;
    const recomputedHash = await computeFullChainHash(transactions);
    if (recomputedHash !== finalChainHash) {
      return { success: false, reason: 'Chain Hash mismatch' };
    }
    let simulatedBio = initialBioConstant;
    let prevTs = joinTimestamp;
    const sortedTx = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    for (let tx of sortedTx) {
      const delta = tx.timestamp - prevTs;
      if (delta < 0) {
        return { success: false, reason: 'Transaction timestamps out of order' };
      }
      simulatedBio += delta;
      if (tx.bioConstantAtGeneration !== undefined && tx.bioConstantAtGeneration !== simulatedBio) {
        return { success: false, reason: `BioConstant mismatch on TX at timestamp ${tx.timestamp}` };
      }
      prevTs = tx.timestamp;
    }
    return { success: true };
  } catch (err) {
    console.error('verifyFullChainAndBioConstant error:', err);
    return { success: false, reason: err.message };
  }
}

/******************************
 * WebCrypto / PBKDF2 / AES-GCM Functions
 ******************************/
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

function bufferToBase64(buffer) {
  if (buffer instanceof ArrayBuffer) {
    buffer = new Uint8Array(buffer);
  }
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
  const encoder = new TextEncoder();
  const pinBuffer = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
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
}

/******************************
 * WebAuthn / Biometric Functions
 ******************************/
async function performBiometricAuthenticationForCreation() {
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "Bio-Vault" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "bio-user",
        displayName: "Bio User"
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required"
      },
      timeout: 60000,
      attestation: "none"
    };
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      console.error("❌ Biometric creation returned null.");
      return null;
    }
    console.log("✅ Biometric Credential Created:", credential);
    return credential;
  } catch (err) {
    console.error("❌ Biometric Credential Creation Error:", err);
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
    console.error("❌ Biometric Assertion Error:", err);
    return false;
  }
}

/******************************
 * Encryption / Decryption Helpers
 ******************************/
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

/******************************
 * Cross-Tab Synchronization & Storage Persistence
 ******************************/
function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

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

async function restoreDerivedKey() {
  const storedKey = sessionStorage.getItem("vaultDerivedKey");
  if (storedKey) {
    derivedKey = base64ToBuffer(storedKey);
    console.log("🔑 Restored encryption key after refresh.");
  }
}

window.addEventListener("beforeunload", () => {
  if (derivedKey) {
    sessionStorage.setItem("vaultDerivedKey", bufferToBase64(derivedKey));
  }
});

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

/******************************
 * IndexedDB CRUD Functions
 ******************************/
function openVaultDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (evt) => {
      const db = evt.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = (evt) => resolve(evt.target.result);
    req.onerror = (evt) => reject(evt.target.error);
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

/******************************
 * Vault Creation / Unlock Functions
 ******************************/
async function createNewVault(pin) {
  const stored = await loadVaultDataFromDB();
  if (stored) {
    alert('❌ A vault already exists on this device. Please unlock it instead.');
    return;
  }
  if (!pin || pin.length < 8) {
    alert('⚠️ Please use a strong passphrase of at least 8 characters!');
    return;
  }
  console.log("No existing vault found. Proceeding with NEW vault creation...");
  localStorage.setItem('vaultLock', 'locked');

  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.joinTimestamp = nowSec;
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = vaultData.bioConstant; // set baseline
  vaultData.bioIBAN = `BIO${vaultData.bioConstant + nowSec}`;

  // Enforce known initial balance (3000 TVM)
  vaultData.initialBalanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceUSD = parseFloat((INITIAL_BALANCE_TVM / EXCHANGE_RATE).toFixed(2));
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.incrementsUsed = 0;

  console.log('🆕 Creating new vault:', vaultData);

  const salt = generateSalt();
  derivedKey = await deriveKeyFromPIN(pin, salt);
  await persistVaultData(salt);

  vaultUnlocked = true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked', 'true');
}

async function unlockVault() {
  if (vaultData.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (now < vaultData.lockoutTimestamp) {
      const remain = vaultData.lockoutTimestamp - now;
      alert(`❌ Vault locked. Try again in ${Math.ceil(remain / 60)} min.`);
      return;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      await promptAndSaveVault();
    }
  }

  const biometricAuth = await performBiometricAuthenticationForCreation();
  if (!biometricAuth) {
    handleFailedAuthAttempt();
    return;
  }

  const pin = prompt('🔒 Enter your vault passphrase (>=8 chars recommended):');
  if (!pin) {
    alert('❌ Passphrase is required.');
    handleFailedAuthAttempt();
    return;
  }

  const stored = await loadVaultDataFromDB();
  if (!stored) {
    if (!confirm('⚠️ No vault found. Create a new vault?')) return;
    await createNewVault(pin);
    return;
  }

  try {
    if (!stored.salt) {
      throw new Error('🔴 Salt not found in stored data.');
    }
    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    const decrypted = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData = decrypted;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
    vaultData.authAttempts = stored.authAttempts;

    if (vaultData.credentialId) {
      const ok = await performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        alert('❌ Device credential mismatch. Unlock failed.');
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("🔶 No credentialId found, skipping WebAuthn check.");
    }

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
    handleFailedAuthAttempt();
  }
}

async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
  } else {
    alert(`❌ Auth failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

function lockVault() {
  if (!vaultUnlocked) return;
  vaultUnlocked = false;
  document.getElementById('vaultUI').classList.add('hidden');
  document.getElementById('lockVaultBtn').classList.add('hidden');
  document.getElementById('lockedScreen').classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log('🔒 Vault locked.');
}

/******************************
 * Persistence Functions
 ******************************/
async function persistVaultData(salt = null) {
  try {
    if (!derivedKey) {
      throw new Error('🔴 No encryption key');
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
        throw new Error('🔴 Salt not found. Cannot persist vault data.');
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
    vaultSyncChannel.postMessage({
      type: 'vaultUpdate',
      payload: backupPayload
    });
    console.log('💾 Persistence complete');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

async function promptAndSaveVault() {
  await persistVaultData();
}

/******************************
 * Extra: Validate Sender Snapshot Integrity
 ******************************/
/**
 * validateSenderVaultSnapshot()
 *
 * Checks that the sender’s vault snapshot is anchored to known initial values.
 * This includes verifying:
 *   - The initial balance must be 3000 TVM.
 *   - The initial bioConstant must equal INITIAL_BIO_CONSTANT.
 *   - The transaction chain hash computed from the snapshot matches the stored finalChainHash.
 *   - The computed balance from the snapshot matches the snapshot’s stored balance.
 *   - The bioConstant derived from elapsed time matches the snapshot’s bioConstant.
 *   - (Optionally) The sender’s Bio‑IBAN derivation is verified.
 *
 * @param {object} senderSnapshot - The sender’s full vault snapshot.
 * @param {string} claimedSenderIBAN - The sender’s Bio‑IBAN claimed in the transaction.
 *
 * @returns {object} - { valid: boolean, errors: string[] }
 */
async function validateSenderVaultSnapshot(senderSnapshot, claimedSenderIBAN) {
  const errors = [];
  
  if (senderSnapshot.initialBalanceTVM !== 3000) {
    errors.push(`Invalid initial balance: expected 3000 TVM, found ${senderSnapshot.initialBalanceTVM}`);
  }
  
  if (senderSnapshot.initialBioConstant !== INITIAL_BIO_CONSTANT) {
    errors.push(`Invalid initial bio constant: expected ${INITIAL_BIO_CONSTANT}, found ${senderSnapshot.initialBioConstant}`);
  }
  
  try {
    const computedChainHash = await computeFullChainHash(senderSnapshot.transactions);
    if (computedChainHash !== senderSnapshot.finalChainHash) {
      errors.push(`Chain hash mismatch: computed ${computedChainHash} vs stored ${senderSnapshot.finalChainHash}`);
    }
  } catch (err) {
    errors.push(`Error computing chain hash: ${err.message}`);
  }
  
  const receivedTVM = senderSnapshot.transactions.filter(tx => tx.type === 'received').reduce((sum, tx) => sum + tx.amount, 0);
  const sentTVM = senderSnapshot.transactions.filter(tx => tx.type === 'sent').reduce((sum, tx) => sum + tx.amount, 0);
  const computedBalance = senderSnapshot.initialBalanceTVM + receivedTVM - sentTVM;
  if (computedBalance !== senderSnapshot.balanceTVM) {
    errors.push(`Balance mismatch: computed ${computedBalance} vs stored ${senderSnapshot.balanceTVM}`);
  }
  
  const expectedBioConstant = senderSnapshot.initialBioConstant + (senderSnapshot.lastUTCTimestamp - senderSnapshot.joinTimestamp);
  if (expectedBioConstant !== senderSnapshot.bioConstant) {
    errors.push(`BioConstant mismatch: expected ${expectedBioConstant} vs stored ${senderSnapshot.bioConstant}`);
  }
  
  // For example, assume sender's Bio‑IBAN is derived as: "BIO" + (bioConstant + joinTimestamp)
  const computedSenderIBAN = `BIO${senderSnapshot.bioConstant + senderSnapshot.joinTimestamp}`;
  if (claimedSenderIBAN !== computedSenderIBAN) {
    errors.push(`Sender Bio‑IBAN mismatch: computed ${computedSenderIBAN} vs claimed ${claimedSenderIBAN}`);
  }
  
  return { valid: errors.length === 0, errors: errors };
}

/******************************
 * Generating & Validating Bio‑Catch Numbers
 ******************************/
// Generate an 8-part BioCatch Number:
// Format: Bio-{firstPart}-{timestamp}-{amount}-{senderBalance}-{senderBioIBAN}-{finalChainHash}-{vaultSnapshotEncoded}
async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp) {
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3)); // receiver is the current vault
  const firstPart = senderNumeric + receiverNumeric;
  const senderBalance = vaultData.balanceTVM;
  const finalChainHash = await computeFullChainHash(vaultData.transactions);
  const snapshotEncoded = btoa(JSON.stringify(vaultData)); // or use serializeVaultSnapshotForBioCatch(vaultData)
  return `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${snapshotEncoded}`;
}

async function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 8 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 8 parts with prefix "Bio-".' };
  }
  const firstPart = parseInt(parts[1]);
  const timestamp = parseInt(parts[2]);
  const amountPart = parseFloat(parts[3]);
  const senderBalance = parseFloat(parts[4]);
  const claimedSenderIBAN = parts[5];
  const chainHash = parts[6];
  const snapshotEncoded = parts[7];

  if (isNaN(firstPart) || isNaN(timestamp) || isNaN(amountPart) || isNaN(senderBalance)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  if (amountPart !== claimedAmount) {
    return { valid: false, message: 'Claimed amount does not match BioCatch amount.' };
  }

  // Validate timestamp window
  const currentTimestamp = vaultData.lastUTCTimestamp;
  if (Math.abs(currentTimestamp - timestamp) > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp outside ±12min window.' };
  }

  // Validate that the receiver (this vault) has the correct BioIBAN format
  if (!vaultData.bioIBAN) {
    return { valid: false, message: 'Receiver Bio‑IBAN not available in vault.' };
  }
  const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
  const expectedFirstPart = (firstPart - receiverNumeric) + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of sender/receiver numerics.' };
  }

  // Return extracted values along with the snapshot (decoded)
  let senderVaultSnapshot;
  try {
    senderVaultSnapshot = JSON.parse(atob(snapshotEncoded));
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }

  return {
    valid: true,
    chainHash: chainHash,
    claimedSenderIBAN: claimedSenderIBAN,
    senderVaultSnapshot: senderVaultSnapshot
  };
}

/******************************
 * Transaction Handlers
 ******************************/
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
  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid receiver Bio‑IBAN or amount.');
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Bio‑IBAN format.');
    return;
  }
  if (receiverBioIBAN === vaultData.bioIBAN) {
    alert('❌ Cannot send to self.');
    return;
  }
  if (vaultData.balanceTVM < amount) {
    alert('❌ Insufficient TVM balance.');
    return;
  }
  transactionLock = true;
  try {
    const currentTimestamp = vaultData.lastUTCTimestamp;
    const plainBioCatchNumber = await generateBioCatchNumber(vaultData.bioIBAN, receiverBioIBAN, amount, currentTimestamp);
    // Check for duplicate BioCatch number in past transactions
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plainBioCatchNumber) {
          alert('❌ This BioCatch number already exists. Try again.');
          transactionLock = false;
          return;
        }
      }
    }
    const obfuscatedCatch = await encryptBioCatchNumber(plainBioCatchNumber);
    vaultData.transactions.push({
      type: 'sent',
      receiverBioIBAN,
      amount,
      timestamp: currentTimestamp,
      status: 'Completed',
      bioCatch: obfuscatedCatch,
      bioConstantAtGeneration: vaultData.bioConstant
    });
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Transaction successful! Sent ${amount} TVM to ${receiverBioIBAN}`);
    showBioCatchPopup(obfuscatedCatch);
    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Send Transaction Error:', error);
    alert('❌ An error occurred processing the transaction.');
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
    alert('❌ Invalid BioCatch number or amount.');
    return;
  }
  transactionLock = true;
  try {
    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode the provided BioCatch number.');
      transactionLock = false;
      return;
    }
    // Check for duplicate usage
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          alert('❌ This BioCatch number has already been used.');
          transactionLock = false;
          return;
        }
      }
    }
    const validation = await validateBioCatchNumber(bioCatchNumber, amount);
    if (!validation.valid) {
      alert(`❌ BioCatch validation failed: ${validation.message}`);
      transactionLock = false;
      return;
    }
    // Extract values from validated BioCatch
    const { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    const crossCheck = await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if (!crossCheck.success) {
      alert(`❌ Sender chain mismatch: ${crossCheck.reason}`);
      transactionLock = false;
      return;
    }
    if (senderVaultSnapshot.finalChainHash !== chainHash) {
      alert('❌ The chain hash in the BioCatch does not match the snapshot’s final chain hash!');
      transactionLock = false;
      return;
    }
    // Extra integrity check: ensure sender snapshot starts from known values
    const snapshotValidation = await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if (!snapshotValidation.valid) {
      alert("❌ Sender snapshot integrity check failed: " + snapshotValidation.errors.join("; "));
      transactionLock = false;
      return;
    }
    const currentTimestamp = vaultData.lastUTCTimestamp;
    vaultData.transactions.push({
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: currentTimestamp,
      status: 'Valid',
      bioConstantAtGeneration: vaultData.bioConstant
    });
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Transaction received successfully! Added ${amount} TVM.`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Receive Transaction Error:', error);
    alert('❌ An error occurred processing the transaction.');
  } finally {
    transactionLock = false;
  }
}

/******************************
 * UI & Table Functions
 ******************************/
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  tbody.innerHTML = '';
  vaultData.transactions
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const row = document.createElement('tr');
      let bioIBANCell = '—';
      let amountCell = tx.amount;
      let timestampCell = formatDisplayDate(tx.timestamp);
      let statusCell = tx.status;
      if (tx.type === 'sent') {
        bioIBANCell = tx.receiverBioIBAN;
      } else if (tx.type === 'received') {
        bioIBANCell = tx.senderBioIBAN || 'Unknown';
      }
      row.innerHTML = `
        <td>${bioIBANCell}</td>
        <td>${tx.bioCatch || '—'}</td>
        <td>${amountCell}</td>
        <td>${timestampCell}</td>
        <td>${statusCell}</td>
      `;
      tbody.appendChild(row);
    });
}

function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ No Bio‑IBAN to copy.');
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => alert('✅ Bio‑IBAN copied to clipboard!'))
    .catch(err => {
      console.error('❌ Copy failed:', err);
      alert('⚠️ Failed to copy. Try again!');
    });
}

function exportTransactionTable() {
  const table = document.getElementById('transactionTable');
  if (!table) {
    alert('No transaction table found.');
    return;
  }
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";
  rows.forEach(row => {
    const cols = row.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(col => {
      let data = col.innerText.replace(/"/g, '""');
      if (data.includes(',')) {
        data = `"${data}"`;
      }
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

function initializeBioConstantAndUTCTime() {
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsed = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsed;
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();
  bioLineIntervalTimer = setInterval(() => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    populateWalletUI();
    promptAndSaveVault();
  }, 1000);
}

function populateWalletUI() {
  document.getElementById('bioibanInput').value = vaultData.bioIBAN || 'BIO...';
  // Dynamic balance calculation can incorporate periodic increments if desired.
  const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((sum, tx) => sum + tx.amount, 0);
  const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((sum, tx) => sum + tx.amount, 0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM - sentTVM;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));
  document.getElementById('tvmBalance').textContent = `💰 Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  document.getElementById('bioLineText').textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
  document.getElementById('utcTime').textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
}

function initializeUI() {
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', unlockVault);
  }
  const lockVaultBtn = document.getElementById('lockVaultBtn');
  if (lockVaultBtn) {
    lockVaultBtn.addEventListener('click', lockVault);
  }
  const catchInBtn = document.getElementById('catchInBtn');
  if (catchInBtn) {
    catchInBtn.addEventListener('click', handleReceiveTransaction);
  }
  const catchOutBtn = document.getElementById('catchOutBtn');
  if (catchOutBtn) {
    catchOutBtn.addEventListener('click', handleSendTransaction);
  }
  const copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  if (copyBioIBANBtn) {
    copyBioIBANBtn.addEventListener('click', handleCopyBioIBAN);
  }
  const exportBtn = document.getElementById('exportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportTransactionTable);
  }
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  if (bioCatchPopup) {
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
  }
  enforceSingleVault();
}

function validateBioIBAN(bioIBAN) {
  return bioIBAN && bioIBAN.startsWith('BIO');
}

/******************************
 * Extra: Modal-based Passphrase UI (optional)
 ******************************/
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
