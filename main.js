/***********************************************************************
 * main.js — Constructively Fixed
 * 
 * - Removes the duplicate snippet in persistVaultData()
 * - Keeps usage of saltBase64 consistent
 * - Corrects dynamicBaseTVM calculation to prevent double-counting initial balance
 * - All other logic remains unchanged
 ***********************************************************************/

const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

const EXCHANGE_RATE = 12;  // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // 12 minutes
const LOCKOUT_DURATION_SECONDS = 3600; // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

// For the advanced balance increments
const BIO_LINE_INTERVAL = 15783000;     // 15,783,000 seconds (~182 days)
const BIO_LINE_INCREMENT_AMOUNT = 15000; // 15,000 TVM per interval

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 minutes
const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;  // cryptographic key after unlocking
let bioLineInterval = null;

let vaultData = {
  bioIBAN: null,
  // For dynamic increment logic
  initialBalanceTVM: 15000,
  // For direct transaction changes
  balanceTVM: 0,
  balanceUSD: 0,
  bioConstant: INITIAL_BIO_CONSTANT,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  initialBioConstant: INITIAL_BIO_CONSTANT
};

function formatWithCommas(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Format a UTC timestamp as "YYYY-MM-DD HH:MM:SS" for UI.
 */
function formatDisplayDate(timestampInSeconds) {
  const date = new Date(timestampInSeconds * 1000);
  const isoString = date.toISOString();  // e.g. "2025-01-28T13:18:55.000Z"
  const datePart = isoString.slice(0, 10);   // "2025-01-28"
  const timePart = isoString.slice(11, 19); // "13:18:55"
  return `${datePart} ${timePart}`;
}

window.addEventListener('DOMContentLoaded', () => {
  // === SESSION RESTORE SNIPPET: Resume the user's last page ===
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }

  // Save the current page (URL) before user leaves/reloads
  window.addEventListener("beforeunload", function() {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Initializing UI...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults(); // inter-tab sync
  enforceStoragePersistence();

  // Cross-tab sync handler
  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data, salt } = e.data.payload;
        // must have derivedKey to decrypt:
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey is not available yet.');
          return;
        }
        const decrypted = await decryptData(
          derivedKey, 
          base64ToBuffer(iv), 
          base64ToBuffer(data)
        );
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

  // Storage health monitor
  setInterval(async () => {
    const estimate = await navigator.storage.estimate();
    if ((estimate.usage / estimate.quota) > 0.85) {
      console.warn('🚨 Storage critical:', estimate);
      alert('❗ Vault storage nearing limit! Export backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
}

function bufferToBase64(buffer) {
  if (buffer instanceof ArrayBuffer) {
    buffer = new Uint8Array(buffer);
  }
  return btoa(String.fromCharCode(...buffer));
}

function base64ToBuffer(base64) {
  try {
    if (typeof base64 !== 'string') {
      throw new TypeError('Input must be a Base64-encoded string.');
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
      throw new Error('Invalid Base64 string.');
    }
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      buffer[i] = binary.charCodeAt(i);
    }
    return buffer;
  } catch (error) {
    console.error('base64ToBuffer Error:', error, 'Input:', base64);
    throw error;
  }
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
}

async function performBiometricAuthentication() {
  try {
    const publicKey = {
      challenge: new Uint8Array(32),
      rp: { name: "Bio-Vault" },
      user: { id: new Uint8Array(16), name: "bio-user", displayName: "Bio User" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
      timeout: 60000,
      attestation: "none"
    };

    const credential = await navigator.credentials.create({ publicKey });
    if (credential) {
      console.log("✅ Biometric Authentication Successful.");
      return true;
    } else {
      console.error("❌ Biometric Authentication Failed.");
      return false;
    }
  } catch (err) {
    console.error("❌ Biometric Authentication Error:", err);
    return false;
  }
}

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
    return plainText; // fallback
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

function openVaultDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = (event) => {
      resolve(event.target.result);
    };
    request.onerror = (event) => {
      reject(event.target.error);
    };
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
          resolve(null); // handle corrupted data
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror = (err) => reject(err);
  });
}

async function clearVaultDB() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    const request = store.clear();
    request.onsuccess = () => resolve();
    request.onerror = (err) => reject(err);
  });
}

async function createNewVault(pin) {
  const stored = await loadVaultDataFromDB();
  if (stored) {
    // Enforce single vault
    alert('❌ A vault already exists on this device. Please unlock it instead with your old PIN.');
    return;
  }

  console.log("No existing vault found. Proceeding with NEW vault creation...");

  if (localStorage.getItem('vaultLock') !== 'locked') {
    localStorage.setItem('vaultLock', 'locked');
  }

  if (!vaultData.lastUTCTimestamp || vaultData.lastUTCTimestamp < 1000000000) {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    vaultData.initialBioConstant = vaultData.bioConstant;
  }

  vaultData.bioIBAN = `BIO${vaultData.bioConstant + vaultData.lastUTCTimestamp}`;

  vaultData = {
    ...vaultData,
    balanceTVM: 15000,
    balanceUSD: parseFloat((15000 / EXCHANGE_RATE).toFixed(2)),
    transactions: [],
    authAttempts: 0,
    lockoutTimestamp: null
  };

  console.log('🆕 Creating new vault:', vaultData);

  const salt = generateSalt();
  console.log('🆕 Generated new salt:', salt);

  derivedKey = await deriveKeyFromPIN(pin, salt);
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

  const biometricAuth = await performBiometricAuthentication();
  if (!biometricAuth) {
    handleFailedAuthAttempt();
    return;
  }

  const pin = prompt('🔒 Enter your vault PIN:');
  if (!pin) {
    alert('❌ PIN is required.');
    handleFailedAuthAttempt();
    return;
  }

  const stored = await loadVaultDataFromDB();
  if (!stored) {
    // no vault => create new if user wants
    if (!confirm('⚠️ No existing vault found. Create a new vault?')) return;
    await createNewVault(pin);
    return;
  }

  try {
    if (!stored.salt) {
      throw new Error('🔴 Salt not found in stored data.');
    }

    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    const decryptedData = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData = decryptedData;

    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
    vaultData.authAttempts = stored.authAttempts;

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
    handleFailedAuthAttempt();
  }
}

async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
  } else {
    alert(`❌ Authentication failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} attempts left.`);
  }
  await promptAndSaveVault();
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

/** 
 * FIXED function: 
 * - Removed the duplicated snippet
 * - Ensured consistent saltBase64 usage
 * - Corrected dynamicBaseTVM calculation to prevent double-counting initial balance
 */
async function persistVaultData(salt = null) {
  try {
    if (!derivedKey) {
      throw new Error('🔴 No encryption key');
    }

    // Encrypt current vault data
    const { iv, ciphertext } = await encryptData(derivedKey, vaultData);

    // Decide which salt we use
    let saltBase64;
    if (salt) {
      // If new salt is provided
      saltBase64 = bufferToBase64(salt);
    } else {
      // Fallback to existing salt in DB
      const stored = await loadVaultDataFromDB();
      if (stored && stored.salt) {
        // stored.salt is a buffer from DB
        saltBase64 = bufferToBase64(stored.salt);
      } else {
        throw new Error('🔴 Salt not found. Cannot persist vault data.');
      }
    }

    // 1) Save to IndexedDB
    await saveVaultDataToDB(iv, ciphertext, saltBase64);

    // 2) Backup in localStorage (still encrypted)
    const backupPayload = {
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext),
      salt: saltBase64,
      timestamp: Date.now()
    };
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));

    // 3) Cross-tab sync
    vaultSyncChannel.postMessage({
      type: 'vaultUpdate',
      payload: backupPayload
    });

    console.log('💾 Triply-redundant persistence complete');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

async function promptAndSaveVault() {
  await persistVaultData();
}

function showVaultUI() {
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('lockVaultBtn').classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

async function loadVaultOnStartup() {
  try {
    // 1. Try primary IndexedDB
    let stored = await loadVaultDataFromDB();

    // 2. Fallback to localStorage backup
    if (!stored) {
      const backup = localStorage.getItem(VAULT_BACKUP_KEY);
      if (backup) {
        const parsed = JSON.parse(backup);
        parsed.iv = base64ToBuffer(parsed.iv);
        parsed.ciphertext = base64ToBuffer(parsed.data);
        console.log('♻️ Restored from localStorage backup');
        stored = parsed; // Now stored has .iv, .ciphertext, .salt
      }
    }

    // Basic logic for showing "enterVaultBtn" or not
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
}

function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

function populateWalletUI() {
  // Set the Bio-IBAN in the input field
  document.getElementById('bioibanInput').value = vaultData.bioIBAN || 'BIO...';

  // Calculate dynamic increments based on BIO-Line intervals
  const bioLineProgress = vaultData.bioConstant - vaultData.initialBioConstant;
  const completedIntervals = Math.floor(bioLineProgress / BIO_LINE_INTERVAL);
  
  // 🔴 **CORRECTION**: Remove initialBalanceTVM from dynamicBaseTVM to prevent double-counting
  const dynamicBaseTVM = completedIntervals * BIO_LINE_INCREMENT_AMOUNT;

  // Calculate total received TVM
  const receivedTVM = vaultData.transactions
    .filter(tx => tx.type === 'received')
    .reduce((acc, tx) => acc + tx.amount, 0);

  // Calculate total sent TVM
  const sentTVM = vaultData.transactions
    .filter(tx => tx.type === 'sent')
    .reduce((acc, tx) => acc + tx.amount, 0);

  // 🔴 **CORRECTION**: Update balanceTVM correctly without double-counting initialBalanceTVM
  vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM - sentTVM + dynamicBaseTVM;

  // Update balanceUSD based on the updated balanceTVM
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  // Format balances with commas for better readability
  const tvmFormatted = formatWithCommas(vaultData.balanceTVM);
  const usdFormatted = formatWithCommas(vaultData.balanceUSD);

  // Update the UI elements with the formatted balances
  document.getElementById('tvmBalance').textContent = `💰 Balance: ${tvmFormatted} TVM`;
  document.getElementById('usdBalance').textContent = `💵 Equivalent to ${usdFormatted} USD`;

  // Update Bio‑Line and UTC Time in the UI
  let bioLineElement = document.getElementById('bioLineText');
  let utcTimeElement = document.getElementById('utcTime');

  if (bioLineElement && utcTimeElement) {
    bioLineElement.textContent = `🔄 Bio‑Line: ${vaultData.bioConstant}`;
    utcTimeElement.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  } else {
    console.warn("⚠️ Bio-Line and UTC elements are missing in the DOM!");
  }
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
        bioCatchCell = tx.bioCatch; // base64 string
      }

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

function initializeBioConstantAndUTCTime() {
  if (bioLineInterval) clearInterval(bioLineInterval);

  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsedSeconds = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.bioConstant += elapsedSeconds;
  vaultData.lastUTCTimestamp = currentTimestamp;

  console.log("✅ Bio-Line initialized with current bioConstant and UTC timestamp.");
  populateWalletUI();

  bioLineInterval = setInterval(() => {
    vaultData.bioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    console.log(`🔄 Bio-Constant Updated: ${vaultData.bioConstant}`);

    populateWalletUI();
    promptAndSaveVault();
  }, 1000);
}

function showBioCatchPopup(encryptedBioCatch) {
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const bioCatchNumberText = document.getElementById('bioCatchNumberText');

  bioCatchNumberText.textContent = encryptedBioCatch; // base64
  bioCatchPopup.style.display = 'flex';
}

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
    closeBioCatchPopupBtn.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
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

  enforceSingleVault(); // ensure single vault on device
}

let transactionLock = false;

function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp) {
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  const secondPart = amount + timestamp;
  // includes sender’s IBAN as final part
  return `Bio-${firstPart}-${secondPart}-${senderBioIBAN}`;
}

/**
 * Validate 4 parts in the Bio-Catch code
 */
function validateBioCatchNumber(bioCatchNumber, amount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 4 || parts[0] !== 'Bio') {
    return { valid: false, message: 'Format must be Bio-<first>-<second>-<senderIBAN>.' };
  }
  const firstPart = parseInt(parts[1]);
  const secondPart = parseInt(parts[2]);
  const claimedSenderIBAN = parts[3];

  if (isNaN(firstPart) || isNaN(secondPart)) {
    return { valid: false, message: 'Both numeric parts must be valid numbers.' };
  }

  const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
  const senderNumeric = firstPart - receiverNumeric;
  const expectedFirstPart = senderNumeric + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of sender/receiver IBAN numerics.' };
  }

  const extractedTimestamp = secondPart - amount;
  const currentTimestamp = vaultData.lastUTCTimestamp;
  const timeDiff = Math.abs(currentTimestamp - extractedTimestamp);
  if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp is outside ±12min window.' };
  }

  const expectedSenderIBAN = `BIO${senderNumeric}`;
  if (claimedSenderIBAN !== expectedSenderIBAN) {
    return { valid: false, message: 'Mismatched Sender IBAN in the Bio-Catch code.' };
  }

  return { valid: true };
}

function validateBioIBAN(bioIBAN) {
  if (!bioIBAN.startsWith('BIO')) return false;
  const numericPart = parseInt(bioIBAN.slice(3));
  if (isNaN(numericPart)) return false;
  const derivedTimestamp = numericPart - vaultData.bioConstant;
  const currentUTCTimestamp = Math.floor(Date.now() / 1000);
  return (derivedTimestamp > 0 && derivedTimestamp <= currentUTCTimestamp);
}

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
    alert('❌ Please enter a valid Receiver Bio‑IBAN and Amount.');
    return;
  }
  if (!validateBioIBAN(receiverBioIBAN)) {
    alert('❌ Invalid Bio-IBAN format.');
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
    const currentTimestamp = vaultData.lastUTCTimestamp;
    const plainBioCatchNumber = generateBioCatchNumber(
      vaultData.bioIBAN,
      receiverBioIBAN,
      amount,
      currentTimestamp
    );

    // check duplication
    for (let tx of vaultData.transactions) {
      if (tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === plainBioCatchNumber) {
          alert('❌ This BioCatch number already exists. Try again.');
          return;
        }
      }
    }

    // Direct modifications of vaultData.balanceTVM and balanceUSD have been removed

    const obfuscatedCatch = await encryptBioCatchNumber(plainBioCatchNumber);

    vaultData.transactions.push({
      type: 'sent',
      receiverBioIBAN,
      amount,
      timestamp: currentTimestamp,
      status: 'Completed', // irreversible
      bioCatch: obfuscatedCatch,
      bioConstantAtGeneration: vaultData.bioConstant
    });

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
      if (tx.type === 'received' && tx.bioCatch) {
        const existingPlain = await decryptBioCatchNumber(tx.bioCatch);
        if (existingPlain === bioCatchNumber) {
          alert('❌ This BioCatch Number has already been used in a received transaction.');
          return;
        }
      }
    }

    const validation = validateBioCatchNumber(bioCatchNumber, amount);
    if (!validation.valid) {
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      return;
    }

    const parts = bioCatchNumber.split('-');
    const firstPart = parseInt(parts[1]);
    const secondPart = parseInt(parts[2]);
    const claimedSenderIBAN = parts[3];

    const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
    const senderNumeric = firstPart - receiverNumeric;
    const senderBioIBAN = `BIO${senderNumeric}`;
    const extractedTimestamp = secondPart - amount;

    if (!validateBioIBAN(senderBioIBAN)) {
      alert('❌ Invalid Sender Bio‑IBAN extracted from BioCatch Number.');
      return;
    }

    const currentTimestamp = vaultData.lastUTCTimestamp;
    const timeDifference = Math.abs(currentTimestamp - extractedTimestamp);
    if (timeDifference > TRANSACTION_VALIDITY_SECONDS) {
      alert('❌ The timestamp in BioCatch Number is outside acceptable window.');
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

    // Direct modifications of vaultData.balanceTVM and balanceUSD have been removed

    const obfuscatedCatch = await encryptBioCatchNumber(bioCatchNumber);
    vaultData.transactions.push({
      type: 'received',
      senderBioIBAN,
      bioCatch: obfuscatedCatch,
      amount,
      timestamp: currentTimestamp,
      status: 'Valid'
    });

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

function isVaultLockedOut() {
  if (vaultData.lockoutTimestamp) {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (currentTimestamp < vaultData.lockoutTimestamp) {
      return true;
    } else {
      vaultData.lockoutTimestamp = null;
      vaultData.authAttempts = 0;
      promptAndSaveVault();
      return false;
    }
  }
  return false;
}
