/***********************************************************************
 * main.js — Final Production with userWallet bridging & onChain stub
 ***********************************************************************/

console.log("[main.js] Offline Vault + On-Chain Integration with userWallet...");

const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// Basic config
const INITIAL_BALANCE_TVM = 1200;
const PER_TX_BONUS = 120; 
const MAX_BONUSES_PER_DAY = 3; 
const MAX_BONUSES_PER_MONTH = 30; 
const MAX_ANNUAL_BONUS_TVM = 10800; 

const EXCHANGE_RATE = 12;  
const INITIAL_BIO_CONSTANT = 1736565605; 
const TRANSACTION_VALIDITY_SECONDS = 720; 
const LOCKOUT_DURATION_SECONDS = 3600;    
const MAX_AUTH_ATTEMPTS = 3;

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;   

const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/**
 * The vaultData structure
 *  - userWallet: user-supplied "0x..." address for on-chain minting
 *  - nextBonusId: increment for each bonus
 */
let vaultData = {
  bioIBAN: null,
  initialBioConstant: 0,
  bonusConstant: 0,
  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM: 0,
  balanceUSD: 0,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  joinTimestamp: 0,
  lastTransactionHash: '',
  credentialId: null,
  finalChainHash: '',
  dailyCashback: { date: '', usedCount: 0 },
  monthlyUsage: { yearMonth: '', usedCount: 0 },
  annualBonusUsed: 0,

  userWallet: "",  
  nextBonusId: 1  
};

/******************************
 * Utility / Formatting
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
 * Biometric / Passphrase
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
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
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
 * Local Encryption / Decryption
 ******************************/
async function deriveKeyFromPIN(pin, salt) {
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinBytes,
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
async function encryptData(key, dataObj) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}
async function decryptData(key, iv, ciphertext) {
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(plainBuf));
}

/******************************
 * IndexedDB Persistence
 ******************************/
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base64ToBuffer(base64) {
  const bin = atob(base64);
  const buffer = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    buffer[i] = bin.charCodeAt(i);
  }
  return buffer;
}
async function openVaultDB() {
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
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
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
async function promptAndSaveVault() {
  await persistVaultData();
}
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
    vaultSyncChannel.postMessage({ type: 'vaultUpdate', payload: backupPayload });
    console.log('💾 Triply-redundant persistence complete');
  } catch (err) {
    console.error('💥 Persistence failed:', err);
    alert('🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!');
  }
}

/******************************
 * Vault Logic (120 TVM / Bonus)
 ******************************/
const transactionLock = false;

// We keep the same daily / monthly / annual logic, plus the 2+1 type rule
function resetDailyUsageIfNeeded(nowSec) {
  const currentDateStr = new Date(nowSec * 1000).toISOString().slice(0, 10);
  if (vaultData.dailyCashback.date !== currentDateStr) {
    vaultData.dailyCashback.date = currentDateStr;
    vaultData.dailyCashback.usedCount = 0;
  }
}
function resetMonthlyUsageIfNeeded(nowSec) {
  const d = new Date(nowSec * 1000);
  const ym = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  if (!vaultData.monthlyUsage) {
    vaultData.monthlyUsage = { yearMonth: '', usedCount: 0 };
  }
  if (vaultData.monthlyUsage.yearMonth !== ym) {
    vaultData.monthlyUsage.yearMonth = ym;
    vaultData.monthlyUsage.usedCount = 0;
  }
}
function bonusDiversityCheck(newTxType) {
  const currentDateStr = vaultData.dailyCashback.date;
  let sentTriggeredCount = 0;
  let receivedTriggeredCount = 0;
  for (const tx of vaultData.transactions) {
    if (tx.type === 'cashback') {
      const dateStr = new Date(tx.timestamp * 1000).toISOString().slice(0, 10);
      if (dateStr === currentDateStr && tx.triggerOrigin) {
        if (tx.triggerOrigin === 'sent') sentTriggeredCount++;
        else if (tx.triggerOrigin === 'received') receivedTriggeredCount++;
      }
    }
  }
  if (newTxType === 'sent' && sentTriggeredCount >= 2) return false;
  if (newTxType === 'received' && receivedTriggeredCount >= 2) return false;
  return true;
}
function canGive120Bonus(nowSec, newTxType, newTxAmount) {
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);
  if (vaultData.dailyCashback.usedCount >= MAX_BONUSES_PER_DAY) return false;
  if (vaultData.monthlyUsage.usedCount >= MAX_BONUSES_PER_MONTH) return false;
  if ((vaultData.annualBonusUsed || 0) >= MAX_ANNUAL_BONUS_TVM) return false;
  if (newTxType === 'sent' && newTxAmount <= 240) return false;
  if (!bonusDiversityCheck(newTxType)) return false;
  return true;
}
function record120BonusUsage(triggerOrigin) {
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed = (vaultData.annualBonusUsed || 0) + PER_TX_BONUS;
}

/******************************
 * Transaction Hashing
 ******************************/
async function computeTransactionHash(previousHash, txObject) {
  const dataString = JSON.stringify({ previousHash, ...txObject });
  const buffer = new TextEncoder().encode(dataString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
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
      bonusConstantAtGeneration: tx.bonusConstantAtGeneration,
      previousHash: runningHash
    };
    runningHash = await computeTransactionHash(runningHash, txObjForHash);
  }
  return runningHash;
}

/******************************
 * BioCatch: generating & validating
 ******************************/
async function encryptBioCatchNumber(plainText) {
  try {
    return btoa(plainText);
  } catch (err) {
    console.error("Error obfuscating:", err);
    return plainText;
  }
}
async function decryptBioCatchNumber(encryptedString) {
  try {
    return atob(encryptedString);
  } catch (err) {
    console.error("Error deobfuscating:", err);
    return null;
  }
}

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
      tx.bonusConstantAtGeneration || 0,
      tx.previousHash || '',
      tx.txHash || ''
    ].join(txFieldSep);
  });
  const txString = txParts.join(txSep);
  const rawString = [
    vData.joinTimestamp || 0,
    vData.initialBioConstant || 0,
    vData.bonusConstant || 0,
    vData.finalChainHash || '',
    vData.initialBalanceTVM || 0,
    vData.balanceTVM || 0,
    vData.lastUTCTimestamp || 0,
    txString
  ].join(fieldSep);
  return btoa(rawString);
}
function deserializeVaultSnapshotFromBioCatch(base64String) {
  const raw = atob(base64String);
  const parts = raw.split('|');
  if (parts.length < 8) throw new Error('Vault snapshot missing fields');
  const joinTimestamp = parseInt(parts[0], 10);
  const initialBioConstant = parseInt(parts[1], 10);
  const bonusConstant = parseInt(parts[2], 10);
  const finalChainHash = parts[3];
  const initialBalanceTVM = parseInt(parts[4], 10);
  const balanceTVM = parseInt(parts[5], 10);
  const lastUTCTimestamp = parseInt(parts[6], 10);
  const txString = parts[7] || '';

  const txSep = '^';
  const txFieldSep = '~';
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
      bonusConstantAtGeneration: parseInt(txFields[7], 10) || 0,
      previousHash: txFields[8] || '',
      txHash: txFields[9] || ''
    };
  });
  return {
    joinTimestamp,
    initialBioConstant,
    bonusConstant,
    finalChainHash,
    initialBalanceTVM,
    balanceTVM,
    lastUTCTimestamp,
    transactions
  };
}

async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
  const encodedVault = serializeVaultSnapshotForBioCatch(vaultData);
  const senderNumeric = parseInt(senderBioIBAN.slice(3));
  const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
  const firstPart = senderNumeric + receiverNumeric;
  return `Bio-${firstPart}-${timestamp}-${amount}-${senderBalance}-${senderBioIBAN}-${finalChainHash}-${encodedVault}`;
}

async function validateBioCatchNumber(bioCatchNumber, claimedAmount) {
  const parts = bioCatchNumber.split('-');
  if (parts.length !== 8 || parts[0] !== 'Bio') {
    return { valid: false, message: 'BioCatch must have 8 parts with prefix "Bio-".' };
  }
  const [ , firstPartStr, timestampStr, amountStr, claimedSenderBalanceStr, claimedSenderIBAN, chainHash, snapshotEncoded] = parts;
  const firstPart = parseInt(firstPartStr);
  const encodedTimestamp = parseInt(timestampStr);
  const encodedAmount = parseFloat(amountStr);
  const claimedSenderBalance = parseFloat(claimedSenderBalanceStr);

  if (isNaN(firstPart) || isNaN(encodedTimestamp) || isNaN(encodedAmount) || isNaN(claimedSenderBalance)) {
    return { valid: false, message: 'Numeric parts must be valid numbers.' };
  }
  const senderNumeric = parseInt(claimedSenderIBAN.slice(3));
  const receiverNumeric = firstPart - senderNumeric;
  if (receiverNumeric < 0) {
    return { valid: false, message: 'Invalid sender numeric in BioCatch.' };
  }
  const expectedFirstPart = senderNumeric + receiverNumeric;
  if (firstPart !== expectedFirstPart) {
    return { valid: false, message: 'Mismatch in sum of IBAN numerics.' };
  }
  if (!vaultData.bioIBAN) {
    return { valid: false, message: 'Receiver IBAN not found in vault.' };
  }
  const receiverNumericFromVault = parseInt(vaultData.bioIBAN.slice(3));
  if (receiverNumeric !== receiverNumericFromVault) {
    return { valid: false, message: 'This BioCatch is not intended for this receiver IBAN.' };
  }
  if (encodedAmount !== claimedAmount) {
    return { valid: false, message: 'Claimed amount does not match BioCatch amount.' };
  }
  const currentTimestamp = vaultData.lastUTCTimestamp;
  const timeDiff = Math.abs(currentTimestamp - encodedTimestamp);
  if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
    return { valid: false, message: 'Timestamp outside ±12min window.' };
  }

  let senderVaultSnapshot;
  try {
    senderVaultSnapshot = deserializeVaultSnapshotFromBioCatch(snapshotEncoded);
  } catch (err) {
    return { valid: false, message: `Snapshot parse error: ${err.message}` };
  }

  if (claimedSenderIBAN.startsWith("BONUS")) {
    const offset = encodedTimestamp - senderVaultSnapshot.joinTimestamp;
    const expected = "BONUS" + (senderVaultSnapshot.bonusConstant + offset);
    if (claimedSenderIBAN !== expected) {
      return { valid: false, message: 'Mismatched Bonus Sender IBAN in BioCatch.' };
    }
  } else {
    const expectedSenderIBAN = `BIO${senderVaultSnapshot.initialBioConstant + senderVaultSnapshot.joinTimestamp}`;
    if (claimedSenderIBAN !== expectedSenderIBAN) {
      return { valid: false, message: 'Mismatched Sender IBAN in BioCatch.' };
    }
  }

  return { valid: true, message: 'OK', chainHash, claimedSenderIBAN, senderVaultSnapshot };
}

/******************************
 * Handling Sent & Received
 ******************************/
let transactionLock = false;
async function handleSendTransaction() {
  if (!vaultUnlocked) {
    alert('❌ Please unlock vault first.');
    return;
  }
  if (transactionLock) {
    alert('🔒 Another transaction in progress.');
    return;
  }

  const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
  const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());
  if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
    alert('❌ Invalid receiver Bio‑IBAN or amount.');
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
    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'sent', amount)) {
      record120BonusUsage('sent');
      bonusGranted = true;
    }

    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    const plainBioCatchNumber = await generateBioCatchNumber(
      vaultData.bioIBAN,
      receiverBioIBAN,
      amount,
      nowSec,
      vaultData.balanceTVM,
      vaultData.finalChainHash
    );

    // uniqueness
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
    const newTx = {
      type: 'sent',
      receiverBioIBAN,
      amount,
      timestamp: nowSec,
      status: 'Completed',
      bioCatch: obfuscatedCatch,
      bonusConstantAtGeneration: vaultData.bonusConstant,
      previousHash: vaultData.lastTransactionHash,
      txHash: ''
    };
    newTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash = newTx.txHash;
    vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);

    if (bonusGranted) {
      const offset = nowSec - vaultData.joinTimestamp;
      const bonusIBAN = "BONUS" + (vaultData.bonusConstant + offset);
      const currentBonusId = vaultData.nextBonusId++;

      const bonusTx = {
        type: 'cashback',
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bonusConstantAtGeneration: vaultData.bonusConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: '',
        senderBioIBAN: bonusIBAN,
        triggerOrigin: 'sent',
        bonusId: currentBonusId
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);

    document.getElementById('receiverBioIBAN').value = '';
    document.getElementById('catchOutAmount').value = '';
    renderTransactionTable();
  } catch (err) {
    console.error('Send Transaction Error:', err);
    alert('❌ Error processing transaction.');
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
    alert('🔒 Another transaction in progress.');
    return;
  }

  transactionLock = true;
  try {
    const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
    const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());
    if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
      alert('❌ Invalid BioCatch number or amount.');
      transactionLock = false;
      return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    vaultData.lastUTCTimestamp = nowSec;

    let bonusGranted = false;
    if (canGive120Bonus(nowSec, 'received', amount)) {
      record120BonusUsage('received');
      bonusGranted = true;
    }

    const bioCatchNumber = await decryptBioCatchNumber(encryptedBioCatchInput);
    if (!bioCatchNumber) {
      alert('❌ Unable to decode BioCatch number.');
      transactionLock = false;
      return;
    }

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
      alert(`❌ BioCatch Validation Failed: ${validation.message}`);
      transactionLock = false;
      return;
    }
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
    const snapshotValidation = await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if (!snapshotValidation.valid) {
      alert("❌ Sender snapshot integrity check failed: " + snapshotValidation.errors.join("; "));
      transactionLock = false;
      return;
    }

    const rxTx = {
      type: 'received',
      senderBioIBAN: claimedSenderIBAN,
      bioCatch: encryptedBioCatchInput,
      amount,
      timestamp: nowSec,
      status: 'Valid',
      bonusConstantAtGeneration: vaultData.bonusConstant
    };
    vaultData.transactions.push(rxTx);

    if (bonusGranted) {
      const offset = nowSec - vaultData.joinTimestamp;
      const bonusIBAN = "BONUS" + (vaultData.bonusConstant + offset);
      const currentBonusId = vaultData.nextBonusId++;

      const bonusTx = {
        type: 'cashback',
        amount: PER_TX_BONUS,
        timestamp: nowSec,
        status: 'Granted',
        bonusConstantAtGeneration: vaultData.bonusConstant,
        previousHash: vaultData.lastTransactionHash,
        txHash: '',
        senderBioIBAN: bonusIBAN,
        triggerOrigin: 'received',
        bonusId: currentBonusId
      };
      bonusTx.txHash = await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await computeFullChainHash(vaultData.transactions);
    }

    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Transaction received successfully! +${amount} TVM. Bonus: ${bonusGranted ? '120 TVM' : 'None'}`);
    document.getElementById('catchInBioCatch').value = '';
    document.getElementById('catchInAmount').value = '';
    renderTransactionTable();
  } catch (error) {
    console.error('Receive Transaction Error:', error);
    alert('❌ Error processing transaction.');
  } finally {
    transactionLock = false;
  }
}

/******************************
 * UI & Rendering
 ******************************/
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  let sorted = [...vaultData.transactions].sort((a, b) => b.timestamp - a.timestamp);
  sorted.forEach(tx => {
    const row = document.createElement('tr');
    let bioIBANCell = '—';
    let bioCatchCell = tx.bioCatch || '—';
    let amountCell = tx.amount;
    let timestampCell = formatDisplayDate(tx.timestamp);
    let statusCell = tx.status;

    if (tx.type === 'sent') {
      bioIBANCell = tx.receiverBioIBAN;
    } else if (tx.type === 'received') {
      bioIBANCell = tx.senderBioIBAN || 'Unknown';
    } else if (tx.type === 'cashback') {
      bioIBANCell = `System/Bonus (ID=${tx.bonusId || ''})`;
    } else if (tx.type === 'increment') {
      bioIBANCell = 'Periodic Increment';
    }

    let styleCell = '';
    if (tx.type === 'sent') {
      styleCell = 'style="background-color: #FFCCCC;"';
    } else if (tx.type === 'received') {
      styleCell = 'style="background-color: #CCFFCC;"';
    } else if (tx.type === 'cashback') {
      styleCell = 'style="background-color: #CCFFFF;"';
    } else if (tx.type === 'increment') {
      styleCell = 'style="background-color: #FFFFCC;"';
    }

    row.innerHTML = `
      <td ${styleCell}>${bioIBANCell}</td>
      <td>${bioCatchCell}</td>
      <td>${amountCell}</td>
      <td>${timestampCell}</td>
      <td>${statusCell}</td>
    `;
    tbody.appendChild(row);
  });
}

function populateWalletUI() {
  const ibanInput = document.getElementById('bioibanInput');
  if (ibanInput) {
    ibanInput.value = vaultData.bioIBAN || 'BIO...';
  }
  const receivedTVM = vaultData.transactions.filter(tx => tx.type === 'received').reduce((s, t) => s + t.amount, 0);
  const sentTVM = vaultData.transactions.filter(tx => tx.type === 'sent').reduce((s, t) => s + t.amount, 0);
  const bonusTVM = vaultData.transactions.filter(tx => tx.type === 'cashback' || tx.type === 'increment')
    .reduce((s, t) => s + t.amount, 0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + receivedTVM + bonusTVM - sentTVM;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  const tvmElem = document.getElementById('tvmBalance');
  if (tvmElem) {
    tvmElem.textContent = `Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  }
  const usdElem = document.getElementById('usdBalance');
  if (usdElem) {
    usdElem.textContent = `Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  }

  const bioLineElem = document.getElementById('bioLineText');
  if (bioLineElem) {
    bioLineElem.textContent = `🔄 BonusConstant: ${vaultData.bonusConstant}`;
  }
  const utcElem = document.getElementById('utcTime');
  if (utcElem) {
    utcElem.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

/******************************
 * Lock/Unlock & Creation
 ******************************/
function lockVault() {
  if (!vaultUnlocked) return;
  vaultUnlocked = false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked', 'false');
  console.log("🔒 Vault locked.");
}
async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
    alert('❌ Max auth attempts exceeded. Vault locked 1 hour.');
  } else {
    alert(`❌ Auth failed. ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

/******************************
 * Passphrase & Modal
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

/******************************
 * Vault Creation / Unlock
 ******************************/
async function checkAndUnlockVault() {
  const stored = await loadVaultDataFromDB();
  if (!stored) {
    if (!confirm('⚠️ No vault found. Create a new one?')) return;
    const { pin } = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    await createNewVault(pin);
  } else {
    await unlockVault();
  }
}
async function createNewVault(pinFromUser = null) {
  if (!pinFromUser) {
    const result = await getPassphraseFromModal({ confirmNeeded: true, modalTitle: 'Create New Vault (Set Passphrase)' });
    pinFromUser = result.pin;
  }
  if (!pinFromUser || pinFromUser.length < 8) {
    alert('⚠️ Passphrase must be >= 8 chars.');
    return;
  }
  console.log("Proceed with new vault creation...");

  localStorage.setItem('vaultLock', 'locked');
  const nowSec = Math.floor(Date.now() / 1000);
  vaultData.joinTimestamp = nowSec;
  vaultData.lastUTCTimestamp = nowSec;
  vaultData.initialBioConstant = INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant = vaultData.joinTimestamp - vaultData.initialBioConstant;
  vaultData.bioIBAN = `BIO${vaultData.initialBioConstant + vaultData.joinTimestamp}`;
  vaultData.initialBalanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceTVM = INITIAL_BALANCE_TVM;
  vaultData.balanceUSD = parseFloat((INITIAL_BALANCE_TVM / EXCHANGE_RATE).toFixed(2));
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;
  vaultData.lastTransactionHash = '';
  vaultData.finalChainHash = '';
  vaultData.nextBonusId = 1;
  vaultData.userWallet = ""; // not set yet

  const credential = await performBiometricAuthenticationForCreation();
  if (!credential || !credential.id) {
    alert('Biometric creation failed. Vault cannot be created.');
    return;
  }
  vaultData.credentialId = bufferToBase64(credential.rawId);

  console.log('🆕 Creating new vault =>', vaultData);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
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

  const { pin } = await getPassphraseFromModal({ confirmNeeded: false, modalTitle: 'Unlock Vault' });
  if (!pin) {
    alert('❌ Passphrase required or canceled.');
    handleFailedAuthAttempt();
    return;
  }
  if (pin.length < 8) {
    alert('⚠️ Passphrase must be >= 8 chars.');
    handleFailedAuthAttempt();
    return;
  }

  const stored = await loadVaultDataFromDB();
  if (!stored) {
    if (!confirm('No vault found. Create new?')) return;
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
        alert('❌ Biometric mismatch. Unlock failed.');
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("No credentialId => skipping WebAuthn check");
    }

    vaultUnlocked = true;
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;
    await promptAndSaveVault();

    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
  } catch (err) {
    alert(`❌ Decrypt failed: ${err.message}`);
    console.error(err);
    handleFailedAuthAttempt();
  }
}

/******************************
 * UI / Initialization
 ******************************/
function initializeBioConstantAndUTCTime() {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = currentTimestamp;
  populateWalletUI();
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer = setInterval(() => {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    populateWalletUI();
  }, 1000);
}

function showVaultUI() {
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

/******************************
 * Multi-Tab Storage
 ******************************/
function preventMultipleVaults() {
  window.addEventListener('storage', (evt) => {
    if (evt.key === 'vaultUnlocked') {
      if (evt.newValue === 'true' && !vaultUnlocked) {
        vaultUnlocked = true;
        showVaultUI();
        initializeBioConstantAndUTCTime();
      } else if (evt.newValue === 'false' && vaultUnlocked) {
        vaultUnlocked = false;
        lockVault();
      }
    }
    if (evt.key === 'vaultLock') {
      if (evt.newValue === 'locked' && !vaultUnlocked) {
        console.log('Another tab indicated vault lock is in place.');
      }
    }
  });
}
function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Single instance enforced.');
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
      console.warn('🚨 Storage near limit:', estimate);
      alert('❗ Vault storage nearing limit! Please backup!');
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * On DOM Loaded
 ******************************/
window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Bio-Vault: UI init...");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        const { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn('🔒 Received vaultUpdate but derivedKey not available');
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
  enforceStoragePersistence();
});

function loadVaultOnStartup() {
  console.log("[loadVaultOnStartup] => no auto unlock by default");
}

function initializeUI() {
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  if (enterVaultBtn) {
    enterVaultBtn.addEventListener('click', checkAndUnlockVault);
    console.log("✅ Event listener on enterVaultBtn");
  } else {
    console.error("❌ no enterVaultBtn!");
  }

  const lockVaultBtn = document.getElementById('lockVaultBtn');
  lockVaultBtn?.addEventListener('click', lockVault);

  const catchInBtn = document.getElementById('catchInBtn');
  catchInBtn?.addEventListener('click', handleReceiveTransaction);

  const catchOutBtn = document.getElementById('catchOutBtn');
  catchOutBtn?.addEventListener('click', handleSendTransaction);

  const copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  copyBioIBANBtn?.addEventListener('click', handleCopyBioIBAN);

  const exportBtn = document.getElementById('exportBtn');
  exportBtn?.addEventListener('click', exportTransactionTable);

  const exportBackupBtn = document.getElementById('exportBackupBtn');
  exportBackupBtn?.addEventListener('click', exportVaultBackup);

  const bioCatchPopup = document.getElementById('bioCatchPopup');
  if (bioCatchPopup) {
    const closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
    const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click', () => {
      const bcNum = document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(() => alert('✅ Bio‑Catch copied!'))
        .catch(err => {
          console.error('❌ Clipboard copy failed:', err);
          alert('⚠️ Copy failed, try again!');
        });
    });
    window.addEventListener('click', (event) => {
      if (event.target === bioCatchPopup) {
        bioCatchPopup.style.display = 'none';
      }
    });
  }

  enforceSingleVault();
}

/******************************
 * Export / Copy
 ******************************/
function handleCopyBioIBAN() {
  const bioIBANInput = document.getElementById('bioibanInput');
  if (!bioIBANInput || !bioIBANInput.value.trim()) {
    alert('❌ No Bio‑IBAN to copy.');
    return;
  }
  navigator.clipboard.writeText(bioIBANInput.value.trim())
    .then(() => alert('✅ Bio‑IBAN copied!'))
    .catch(err => {
      console.error('❌ Copy failed:', err);
      alert('⚠️ Failed to copy!');
    });
}
function exportTransactionTable() {
  const table = document.getElementById('transactionTable');
  if (!table) { alert('No transaction table found.'); return; }
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";
  rows.forEach(r => {
    const cols = r.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(c => {
      let d = c.innerText.replace(/"/g, '""');
      if (d.includes(',')) d = `"${d}"`;
      rowData.push(d);
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
function exportVaultBackup() {
  const backupData = JSON.stringify(vaultData, null, 2);
  const blob = new Blob([backupData], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vault_backup.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/******************************
 * On-Chain Stub
 ******************************/
async function redeemBonusOnChain(tx) {
  console.log("[redeemBonusOnChain] => Attempting redemption for bonusTx:", tx);
  if (!tx || !tx.bonusId) {
    alert("❌ Invalid bonus or missing bonusId. Can't redeem on chain.");
    return;
  }
  if (!vaultData.userWallet || vaultData.userWallet.length < 5) {
    alert("Please set your on-chain wallet address first!");
    return;
  }

  try {
    if (!window.ethereum) {
      alert('No MetaMask or web3 provider found!');
      return;
    }
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const signer = provider.getSigner();
    const userAddr = await signer.getAddress();
    console.log("[redeemBonusOnChain] => userAddr from signer:", userAddr);

    // If you want to ensure userAddr == vaultData.userWallet:
    // if (userAddr.toLowerCase() !== vaultData.userWallet.toLowerCase()) {
    //   alert("Active wallet doesn't match stored userWallet. Proceed anyway...");
    // }

    // Fill in your contract details
    // const contractAddress = "0xYourContractAddress";
    // const contractABI = [ /* your ABI from compilation */ ];
    // const contract = new ethers.Contract(contractAddress, contractABI, signer);

    // example call:
    // let txResp = await contract.validateAndMint(vaultData.userWallet, tx.bonusId);
    // let receipt = await txResp.wait();
    // console.log("Mint receipt:", receipt);
    // alert(`On-chain redemption successful! Bonus #${tx.bonusId} minted.`);

    alert(`(Stub) Redeeming bonus #${tx.bonusId} => wallet ${vaultData.userWallet}. Fill in contract calls!`);
  } catch (err) {
    console.error("[redeemBonusOnChain] => error:", err);
    alert("❌ On-chain redemption failed. Check console.");
  }
}
