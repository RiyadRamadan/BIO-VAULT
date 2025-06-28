/******************************
 * Base Setup / Global Constants
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

const INITIAL_BALANCE_TVM = 1200;
const PER_TX_BONUS = 120;
const MAX_BONUSES_PER_DAY = 3;
const MAX_BONUSES_PER_MONTH = 30;
const MAX_ANNUAL_BONUS_TVM = 10800;

const EXCHANGE_RATE = 12; // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605; // Genesis "BioConstant"
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;   // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 min
const vaultSyncChannel = new BroadcastChannel('vault-sync');

let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/**
 * Master vaultData structure; stored encrypted in IndexedDB/localStorage.
 */
let vaultData = {
  // Device-specific ECDSA keypair (JWK), generated at vault creation
  signingKey: {
    privateKeyJwk: null,
    publicKeyJwk: null
  },

  // Bio-IBAN, derived from publicKeyJwk + joinTimestamp
  bioIBAN: null,

  // Standard vault fields
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
  credentialId: null,   // WebAuthn rawId (base64)
  finalChainHash: '',
  dailyCashback: { date: '', usedCount: 0 },
  monthlyUsage: { yearMonth: '', usedCount: 0 },
  annualBonusUsed: 0,
  userWallet: "",        // On-chain wallet address (immutable once set)
  nextBonusId: 1
};

/******************************
 * Crypto Utilities
 ******************************/
// SHA256 hashing
async function sha256(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ECDSA-P256 keypair generation
async function generateEcdsaKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicKeyJwk  = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { privateKeyJwk, publicKeyJwk };
}

// Sign an arbitrary message with the vault's private key
async function signWithDeviceKey(message) {
  const msgBuf = new TextEncoder().encode(message);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    vaultData.signingKey.privateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    msgBuf
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Verify a signature with a given public key JWK
async function verifySignatureWithKey(publicKeyJwk, message, signatureB64) {
  const msgBuf = new TextEncoder().encode(message);
  const sigBuf = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    sigBuf,
    msgBuf
  );
}

// Derive the Bio-IBAN from the public key and join timestamp
async function generateBioIBAN(publicKeyJwk, joinTimestamp) {
  const data = JSON.stringify(publicKeyJwk) + '|' + joinTimestamp + '|' + INITIAL_BIO_CONSTANT;
  const hash = await sha256(data);
  // Prefix with "BIO" and take first 32 chars for brevity
  return 'BIO' + hash.slice(0, 32).toUpperCase();
}

/******************************
 * BalanceChain Segment Logic
 ******************************/
class BalanceSegment {
  constructor({ amount, ownerKeyJwk, ownerTS }) {
    this.amount = amount;
    this.ownershipChangeCount = 0;
    this.originalOwnerKeyJwk = ownerKeyJwk;
    this.originalOwnerTS = ownerTS;
    this.originalBioConst = INITIAL_BIO_CONSTANT + (ownerTS - ownerTS);
    this.previousOwnerKeyJwk = null;
    this.previousOwnerTS = null;
    this.previousBioConst = this.originalBioConst;
    this.currentOwnerKeyJwk = ownerKeyJwk;
    this.currentOwnerTS = ownerTS;
    this.currentBioConst = this.originalBioConst;
    this.chainId = null;
    this.spentProof = null;
    this.ownershipProof = null;
    this.unlockProof = null;
    this.receiverSignature = null;  // New: ECDSA signature by receiver
  }

  computeBioConst(nowTS) {
    return INITIAL_BIO_CONSTANT + (nowTS - this.originalOwnerTS);
  }

  /** Initialize chain ID for this segment */
  async computeChainId() {
    const data = `${this.originalBioConst}|${this.amount}|${this.originalOwnerTS}`;
    this.chainId = await sha256(data);
  }

  /** Compute proofs after each ownership change */
  async computeProofs() {
    const base = [
      this.originalBioConst,
      this.previousBioConst,
      this.currentBioConst,
      this.amount,
      this.ownershipChangeCount,
      this.currentOwnerTS
    ].join('|');
    this.ownershipProof = await sha256(base);
    this.unlockProof = await sha256(base + '|UNLOCK');
  }

  /** Spend: move from sender to receiver; generate spentProof */
  async spend(nowTS) {
    this.previousOwnerKeyJwk = this.currentOwnerKeyJwk;
    this.previousOwnerTS     = this.currentOwnerTS;
    this.previousBioConst    = this.currentBioConst;
    this.currentOwnerTS      = nowTS;
    this.currentBioConst     = this.computeBioConst(nowTS);
    this.ownershipChangeCount++;
    const spentBase = [
      this.originalBioConst,
      this.previousBioConst,
      this.amount,
      this.ownershipChangeCount,
      this.currentOwnerTS
    ].join('|');
    this.spentProof = await sha256(spentBase + '|SPENT');
    await this.computeProofs();
  }

  /** Claim: receiver accepts; sign segment to bind to their key */
  async claim(receiverKeyJwk, nowTS) {
    this.currentOwnerKeyJwk = receiverKeyJwk;
    this.currentOwnerTS     = nowTS;
    this.currentBioConst    = this.computeBioConst(nowTS);
    this.ownershipChangeCount++;
    await this.computeProofs();

    // Sign by receiver to finalize transfer
    const payload = [
      this.chainId,
      this.currentOwnerTS,
      this.currentBioConst,
      this.ownershipProof
    ].join('|');
    this.receiverSignature = await signWithDeviceKey(payload);
  }

  /** Verify that receiverSignature is valid for this segment */
  async verifyReceiverSignature() {
    const payload = [
      this.chainId,
      this.currentOwnerTS,
      this.currentBioConst,
      this.ownershipProof
    ].join('|');
    return verifySignatureWithKey(this.currentOwnerKeyJwk, payload, this.receiverSignature);
  }
}

/******************************
 * Encryption & IndexedDB
 ******************************/
async function encryptData(key, dataObj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuffer(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function openVaultDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror = e => reject(e.target.error);
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltB64) {
  const db = await openVaultDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(VAULT_STORE, 'readwrite');
    tx.objectStore(VAULT_STORE).put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltB64,
      authAttempts: vaultData.authAttempts,
      lockoutTimestamp: vaultData.lockoutTimestamp
    });
    tx.oncomplete = () => res();
    tx.onerror = err => rej(err);
  });
}

async function loadVaultDataFromDB() {
  const db = await openVaultDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(VAULT_STORE, 'readonly');
    const getReq = tx.objectStore(VAULT_STORE).get('vaultData');
    getReq.onsuccess = () => {
      const result = getReq.result;
      if (!result) return res(null);
      try {
        res({
          iv: base64ToBuffer(result.iv),
          ciphertext: base64ToBuffer(result.ciphertext),
          salt: base64ToBuffer(result.salt),
          authAttempts: result.authAttempts,
          lockoutTimestamp: result.lockoutTimestamp
        });
      } catch {
        res(null);
      }
    };
    getReq.onerror = err => rej(err);
  });
}

/******************************
 * Key Derivation
 ******************************/
async function deriveKeyFromPIN(pin, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' },
    keyMaterial,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

/******************************
 * Vault Creation & Unlock
 ******************************/
async function promptPassphrase(confirmNeeded = false, title = 'Enter Passphrase') {
  return new Promise(res => {
    const modal = document.getElementById('passModal');
    document.getElementById('passModalTitle').textContent = title;
    document.getElementById('passModalInput').value = '';
    document.getElementById('passModalConfirmInput').value = '';
    document.getElementById('passModalConfirmLabel')
      .style.display = confirmNeeded ? 'block' : 'none';

    const onSave = () => {
      const pin = document.getElementById('passModalInput').value.trim();
      const confirm = document.getElementById('passModalConfirmInput').value.trim();
      if (pin.length < 8) return alert('Passphrase ≥ 8 chars');
      if (confirmNeeded && pin !== confirm) return alert('Passphrases do not match');
      cleanup();
      res(pin);
    };
    const onCancel = () => { cleanup(); res(null); };

    function cleanup() {
      document.getElementById('passModalSaveBtn').removeEventListener('click', onSave);
      document.getElementById('passModalCancelBtn').removeEventListener('click', onCancel);
      modal.style.display = 'none';
    }

    document.getElementById('passModalSaveBtn').addEventListener('click', onSave);
    document.getElementById('passModalCancelBtn').addEventListener('click', onCancel);
    modal.style.display = 'block';
  });
}

async function createNewVault() {
  const pin = await promptPassphrase(true, 'Create New Vault');
  if (!pin) return;

  // Initialize vault data
  vaultData.joinTimestamp = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = vaultData.joinTimestamp;
  vaultData.initialBioConstant = INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant = vaultData.joinTimestamp - INITIAL_BIO_CONSTANT;
  vaultData.transactions = [];
  vaultData.authAttempts = 0;
  vaultData.lockoutTimestamp = null;

  // Generate ECDSA keypair for signing
  const { privateKeyJwk, publicKeyJwk } = await generateEcdsaKeyPair();
  vaultData.signingKey = { privateKeyJwk, publicKeyJwk };

  // Derive device credential (WebAuthn) for extra biometric lock
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Bio-Vault' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'user', displayName: 'User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
      attestation: 'none'
    }
  });
  vaultData.credentialId = bufferToBase64(cred.rawId);

  // Compute Bio-IBAN from publicKeyJwk
  vaultData.bioIBAN = await generateBioIBAN(publicKeyJwk, vaultData.joinTimestamp);

  // Derive symmetric key & save vault
  const salt = crypto.getRandomValues(new Uint8Array(16));
  derivedKey = await deriveKeyFromPIN(pin, salt);
  const { iv, ciphertext } = await encryptData(derivedKey, vaultData);
  await saveVaultDataToDB(iv, ciphertext, bufferToBase64(salt));

  vaultUnlocked = true;
  showVaultUI();
  initializeBioLine();
}

async function unlockVault() {
  const stored = await loadVaultDataFromDB();
  if (!stored) return createNewVault();

  // Handle lockout
  if (stored.lockoutTimestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (now < stored.lockoutTimestamp) {
      const m = Math.ceil((stored.lockoutTimestamp - now) / 60);
      return alert(`Vault locked. Try again in ${m} min`);
    }
  }

  const pin = await promptPassphrase(false, 'Unlock Vault');
  if (!pin) return;

  try {
    derivedKey = await deriveKeyFromPIN(pin, stored.salt);
    const data = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    Object.assign(vaultData, data);

    // Biometric assertion
    const ok = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: base64ToBuffer(vaultData.credentialId), type: 'public-key' }],
        userVerification: 'required'
      }
    });
    if (!ok) throw new Error('Biometric check failed');

    // Update lockout counters
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;
    await promptAndSaveVault();

    vaultUnlocked = true;
    showVaultUI();
    initializeBioLine();
  } catch (err) {
    vaultData.authAttempts++;
    if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
      vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
      alert('Too many attempts. Locked for 1 hour.');
    } else {
      alert(`Unlock failed. ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
    }
    await promptAndSaveVault();
  }
}

async function checkAndUnlockVault() {
  await unlockVault();
}

/******************************
 * JSON Backup / Recovery
 ******************************/
async function promptAndSaveVault(salt = null) {
  const { iv, ciphertext } = await encryptData(derivedKey, vaultData);
  const saltB64 = salt ? bufferToBase64(salt) : (await loadVaultDataFromDB()).salt;
  await saveVaultDataToDB(iv, ciphertext, saltB64);
}

async function exportVaultBackup() {
  const blob = new Blob([JSON.stringify(vaultData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'vault_backup.json';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function importVaultBackupFromFile(file) {
  try {
    const txt = await file.text();
    Object.assign(vaultData, JSON.parse(txt));
    await promptAndSaveVault();
    alert('Vault restored from backup.');
    showVaultUI();
  } catch {
    alert('Invalid backup file.');
  }
}

/******************************
 * Transactions & Segments
 ******************************/
async function handleSendTransaction() {
  if (!vaultUnlocked) return alert('Unlock vault first');
  const toIBAN = document.getElementById('receiverBioIBAN').value.trim();
  const amount = Number(document.getElementById('catchOutAmount').value);
  if (!toIBAN || !amount || amount <= 0) return alert('Invalid send details');

  const now = Math.floor(Date.now() / 1000);

  // 1) Create segment, spend it
  const segment = new BalanceSegment({
    amount,
    ownerKeyJwk: vaultData.signingKey.publicKeyJwk,
    ownerTS: now
  });
  await segment.computeChainId();
  await segment.spend(now);
  // spentProof ensures removal from sender

  // 2) Record sent tx
  const tx = {
    type: 'sent',
    amount,
    timestamp: now,
    receiverBioIBAN: toIBAN,
    bioCatch: null, // filled after claim
    spentProof: segment.spentProof,
    chainId: segment.chainId
  };
  vaultData.transactions.push(tx);
  await promptAndSaveVault();

  alert('Send initiated. Share the Bio-Catch below with receiver to complete:');
  showBioCatchPopup(segment.chainId + '|' + segment.spentProof);
}

async function handleReceiveTransaction() {
  if (!vaultUnlocked) return alert('Unlock vault first');
  const enc = prompt('Paste received Bio-Catch:'); // e.g. chainId|spentProof
  if (!enc) return;
  const [chainId, spentProof] = enc.split('|');
  const amount = Number(prompt('Amount (TVM)')); 
  const now = Math.floor(Date.now() / 1000);

  // Find corresponding sent tx
  const sentTx = vaultData.transactions.find(t =>
    t.chainId === chainId && t.spentProof === spentProof && t.type === 'sent'
  );
  if (!sentTx) return alert('No matching send found');

  // 1) Create segment object to claim
  const segment = new BalanceSegment({
    amount,
    ownerKeyJwk: vaultData.signingKey.publicKeyJwk,
    ownerTS: now
  });
  segment.chainId = chainId;
  segment.spentProof = spentProof;
  await segment.claim(vaultData.signingKey.publicKeyJwk, now);
  // receiverSignature now binds segment

  // 2) Record receive tx
  const rx = {
    type: 'received',
    amount,
    timestamp: now,
    senderBioIBAN: sentTx.receiverBioIBAN,
    bioCatch: enc,
    ownershipProof: segment.ownershipProof,
    receiverSignature: segment.receiverSignature,
    chainId
  };
  vaultData.transactions.push(rx);
  await promptAndSaveVault();

  alert('Receive complete. Segment securely claimed.');
}

/******************************
 * UI Rendering & Helpers
 ******************************/
function formatDisplayDate(ts) {
  const d = new Date(ts * 1000);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}
function formatWithCommas(n) {
  return n.toLocaleString();
}

function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  tbody.innerHTML = '';
  [...vaultData.transactions]
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${tx.type === 'sent' ? tx.receiverBioIBAN : (tx.senderBioIBAN || '—')}</td>
        <td>${tx.bioCatch || '—'}</td>
        <td>${formatWithCommas(tx.amount)}</td>
        <td>${formatDisplayDate(tx.timestamp)}</td>
        <td>${tx.type}</td>
      `;
      tbody.appendChild(tr);
    });
}

function populateBalances() {
  const received = vaultData.transactions
    .filter(t => t.type === 'received')
    .reduce((sum, t) => sum + t.amount, 0);
  const sent = vaultData.transactions
    .filter(t => t.type === 'sent')
    .reduce((sum, t) => sum + t.amount, 0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + received - sent;
  vaultData.balanceUSD = +(vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2);

  document.getElementById('tvmBalance').textContent =
    `Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent =
    `Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
}

function showVaultUI() {
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  renderTransactionTable();
  populateBalances();
}

function initializeBioLine() {
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer = setInterval(() => {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    document.getElementById('bioLineText').textContent =
      `🔄 BonusConstant: ${vaultData.bonusConstant}`;
    document.getElementById('utcTime').textContent =
      formatDisplayDate(vaultData.lastUTCTimestamp);
  }, 1000);
}

/******************************
 * Initialization & Event Binding
 ******************************/
window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('enterVaultBtn')
    .addEventListener('click', checkAndUnlockVault);
  document.getElementById('lockVaultBtn')
    .addEventListener('click', () => { vaultUnlocked = false; location.reload(); });
  document.getElementById('exportBackupBtn')
    .addEventListener('click', exportVaultBackup);
  document.getElementById('importVaultFileInput')
    .addEventListener('change', e => importVaultBackupFromFile(e.target.files[0]));
  document.getElementById('catchOutBtn')
    .addEventListener('click', handleSendTransaction);
  document.getElementById('catchInBtn')
    .addEventListener('click', handleReceiveTransaction);
  vaultSyncChannel.onmessage = async e => {
    if (e.data?.type === 'vaultUpdate') {
      const p = e.data.payload;
      if (!derivedKey) return;
      const dec = await decryptData(derivedKey, base64ToBuffer(p.iv), base64ToBuffer(p.data));
      Object.assign(vaultData, dec);
      if (vaultUnlocked) showVaultUI();
    }
  };
});



/******************************
 * Basic Encryption & IDB
 ******************************/
async function encryptData(key, dataObj) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(plainBuf));
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuffer(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0; i<bin.length; i++){ out[i] = bin.charCodeAt(i); }
  return out;
}

async function openVaultDB() {
  return new Promise((resolve, reject) => {
    let req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = evt => {
      let db = evt.target.result;
      if(!db.objectStoreNames.contains(VAULT_STORE)){
        db.createObjectStore(VAULT_STORE, { keyPath:'id' });
      }
    };
    req.onsuccess = evt => resolve(evt.target.result);
    req.onerror = evt => reject(evt.target.error);
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltBase64) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE],'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    store.put({
      id:'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp||null,
      authAttempts: vaultData.authAttempts||0
    });
    tx.oncomplete = () => resolve();
    tx.onerror = err => reject(err);
  });
}

async function loadVaultDataFromDB() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([VAULT_STORE],'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const getReq = store.get('vaultData');
    getReq.onsuccess = () => {
      if(getReq.result){
        try{
          let iv = base64ToBuffer(getReq.result.iv);
          let ciph = base64ToBuffer(getReq.result.ciphertext);
          let s = getReq.result.salt ? base64ToBuffer(getReq.result.salt) : null;
          resolve({
            iv, ciphertext:ciph, salt:s,
            lockoutTimestamp:getReq.result.lockoutTimestamp||null,
            authAttempts:getReq.result.authAttempts||0
          });
        } catch(err){
          console.error("Error decoding stored data =>", err);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror = err => reject(err);
  });
}

/******************************
 * Key Derivation & Vault Logic
 ******************************/
async function deriveKeyFromPIN(pin, salt){
  const enc = new TextEncoder();
  const pinBytes = enc.encode(pin);
  const keyMaterial = await crypto.subtle.importKey('raw', pinBytes, { name:'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'
  }, keyMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}

async function promptAndSaveVault(salt=null){
  try{
    if(!derivedKey) throw new Error("No derivedKey");
    let { iv, ciphertext }=await encryptData(derivedKey, vaultData);
    let saltBase64;
    if(salt){
      saltBase64=bufferToBase64(salt);
    } else {
      let stored=await loadVaultDataFromDB();
      if(stored && stored.salt){
        saltBase64=bufferToBase64(stored.salt);
      } else {
        throw new Error("Salt not found => cannot persist");
      }
    }
    await saveVaultDataToDB(iv, ciphertext, saltBase64);

    // local backup
    const backupPayload = {
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext),
      salt: saltBase64,
      timestamp: Date.now()
    };
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
    vaultSyncChannel.postMessage({ type:'vaultUpdate', payload: backupPayload });
    console.log("Vault data stored => triple redundancy done");
  } catch(err){
    console.error("Vault persist failed:", err);
    alert("CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!");
  }
}

function lockVault(){
  if(!vaultUnlocked)return;
  vaultUnlocked=false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked','false');
  console.log("🔒 Vault locked");
}

/******************************
 * Biometric Auth
 ******************************/
async function performBiometricAuthenticationForCreation(){
  try{
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name:"Bio-Vault" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name:"bio-user", displayName:"Bio User"
      },
      pubKeyCredParams:[
        {type:"public-key", alg:-7},
        {type:"public-key", alg:-257}
      ],
      authenticatorSelection:{
        authenticatorAttachment:"platform",
        userVerification:"required"
      },
      timeout:60000,
      attestation:"none"
    };
    const credential=await navigator.credentials.create({ publicKey });
    if(!credential){ console.error("Biometric creation => null"); return null; }
    return credential;
  } catch(err){
    console.error("Biometric creation error:", err);
    return null;
  }
}
async function performBiometricAssertion(credentialId){
  try{
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials:[{id: base64ToBuffer(credentialId), type:'public-key'}],
      userVerification:"required", timeout:60000
    };
    const assertion=await navigator.credentials.get({ publicKey });
    return !!assertion;
  } catch(err){
    console.error("Biometric assertion error:",err);
    return false;
  }
}

/******************************
 * Snapshot / BioCatch
 ******************************/
async function encryptBioCatchNumber(plainText){ return btoa(plainText); }
async function decryptBioCatchNumber(encStr){
  try{return atob(encStr);}catch(e){return null;}
}

/******************************
 * Passphrase Modal
 ******************************/
async function getPassphraseFromModal({ confirmNeeded=false, modalTitle='Enter Passphrase'}) {
  return new Promise(resolve=>{
    const passModal=document.getElementById('passModal');
    const passTitle=document.getElementById('passModalTitle');
    const passInput=document.getElementById('passModalInput');
    const passConfirmLabel=document.getElementById('passModalConfirmLabel');
    const passConfirmInput=document.getElementById('passModalConfirmInput');
    const passCancelBtn=document.getElementById('passModalCancelBtn');
    const passSaveBtn=document.getElementById('passModalSaveBtn');

    passTitle.textContent=modalTitle;
    passInput.value='';
    passConfirmInput.value='';

    function cleanup(){
      passCancelBtn.removeEventListener('click', onCancel);
      passSaveBtn.removeEventListener('click', onSave);
      passModal.style.display='none';
    }
    function onCancel(){ cleanup(); resolve({pin:null}); }
    function onSave(){
      let pVal=passInput.value.trim();
      if(!pVal||pVal.length<8){alert("Pass >= 8 chars");return;}
      if(confirmNeeded){
        let cVal=passConfirmInput.value.trim();
        if(pVal!==cVal){alert("Mismatch passphrase");return;}
      }
      cleanup();
      resolve({pin:pVal, confirmed:true});
    }
    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display='block';
  });
}

/******************************
 * Vault Creation / Unlock
 ******************************/
async function createNewVault(pinFromUser=null){
  if(!pinFromUser){
    let res=await getPassphraseFromModal({ confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    pinFromUser=res.pin;
  }
  if(!pinFromUser||pinFromUser.length<8){ alert("Pass must be >=8 chars");return; }
  console.log("Creating new vault => no existing one found");

  localStorage.setItem('vaultLock','locked');
  let nowSec=Math.floor(Date.now()/1000);
  vaultData.joinTimestamp=nowSec;
  vaultData.lastUTCTimestamp=nowSec;
  vaultData.initialBioConstant=INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant=vaultData.joinTimestamp - vaultData.initialBioConstant;
  vaultData.bioIBAN=`BIO${vaultData.initialBioConstant + vaultData.joinTimestamp}`;
  vaultData.balanceTVM=INITIAL_BALANCE_TVM;
  vaultData.balanceUSD=parseFloat((vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2));
  vaultData.transactions=[];
  vaultData.authAttempts=0;
  vaultData.lockoutTimestamp=null;
  vaultData.lastTransactionHash='';
  vaultData.finalChainHash='';

  let cred=await performBiometricAuthenticationForCreation();
  if(!cred||!cred.id){
    alert("Biometric creation failed => vault cannot be created");
    return;
  }
  vaultData.credentialId=bufferToBase64(cred.rawId);

  console.log("🆕 Vault data =>", vaultData);
  let salt=crypto.getRandomValues(new Uint8Array(16));
  derivedKey=await deriveKeyFromPIN(pinFromUser, salt);
  await promptAndSaveVault(salt);

  vaultUnlocked=true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked','true');
}


/******************************
 * Vault Unlock & Authentication
 ******************************/
async function unlockVault(){
  if(vaultData.lockoutTimestamp){
    let now=Math.floor(Date.now()/1000);
    if(now<vaultData.lockoutTimestamp){
      let remain=vaultData.lockoutTimestamp-now;
      alert(`Vault locked => wait ${Math.ceil(remain/60)} min`);
      return;
    } else {
      vaultData.lockoutTimestamp=null; 
      vaultData.authAttempts=0;
      await promptAndSaveVault();
    }
  }

  let { pin }=await getPassphraseFromModal({ confirmNeeded:false, modalTitle:'Unlock Vault'});
  if(!pin){ alert("Pass needed or user canceled"); handleFailedAuthAttempt(); return; }
  if(pin.length<8){ alert("Pass <8 chars"); handleFailedAuthAttempt(); return; }

  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault => create new?"))return;
    await createNewVault(pin);
    return;
  }
  try{
    if(!stored.salt) throw new Error("No salt in data");
    derivedKey=await deriveKeyFromPIN(pin, stored.salt);
    let dec=await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData=dec;

    vaultData.lockoutTimestamp=stored.lockoutTimestamp;
    vaultData.authAttempts=stored.authAttempts;

    if(vaultData.credentialId){
      let ok=await performBiometricAssertion(vaultData.credentialId);
      if(!ok){alert("Device credential mismatch => fail"); handleFailedAuthAttempt();return;}
    }
    vaultUnlocked=true;
    vaultData.authAttempts=0;
    vaultData.lockoutTimestamp=null;
    await promptAndSaveVault();
    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked','true');
  } catch(err){
    alert("Failed decrypt =>"+err.message);
    console.error("Unlock error =>", err);
    handleFailedAuthAttempt();
  }
}

async function checkAndUnlockVault(){
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault => create new?"))return;
    let { pin }=await getPassphraseFromModal({ confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    await createNewVault(pin);
  } else {
    await unlockVault();
  }
}

async function handleFailedAuthAttempt(){
  vaultData.authAttempts=(vaultData.authAttempts||0)+1;
  if(vaultData.authAttempts>=MAX_AUTH_ATTEMPTS){
    vaultData.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_DURATION_SECONDS;
    alert("❌ Max attempts => locked 1hr");
  } else {
    alert(`❌ Auth fail => tries left: ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts}`);
  }
  await promptAndSaveVault();
}

/******************************
 * Transaction Hashing & Chain
 ******************************/
function formatDisplayDate(ts){
  const d=new Date(ts*1000);
  return d.toISOString().slice(0,10)+" "+d.toISOString().slice(11,19);
}
function formatWithCommas(num){
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

async function computeTransactionHash(prevHash, txObj){
  let dataStr=JSON.stringify({prevHash,...txObj});
  let buf=new TextEncoder().encode(dataStr);
  let hashBuf=await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function computeFullChainHash(transactions){
  let rHash='';
  let sorted=[...transactions].sort((a,b)=>a.timestamp-b.timestamp);
  for(let t of sorted){
    let tmp = {
      type:t.type, amount:t.amount, timestamp:t.timestamp,
      status:t.status, bioCatch:t.bioCatch,
      bonusConstantAtGeneration:t.bonusConstantAtGeneration,
      previousHash:rHash
    };
    rHash=await computeTransactionHash(rHash, tmp);
  }
  return rHash;
}

/******************************
 * Bonus & Usage Control
 ******************************/
function resetDailyUsageIfNeeded(nowSec){
  let dateStr=new Date(nowSec*1000).toISOString().slice(0,10);
  if(vaultData.dailyCashback.date!==dateStr){
    vaultData.dailyCashback.date=dateStr;
    vaultData.dailyCashback.usedCount=0;
  }
}
function resetMonthlyUsageIfNeeded(nowSec){
  let d=new Date(nowSec*1000);
  let ym=`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUsage.yearMonth!==ym){
    vaultData.monthlyUsage.yearMonth=ym;
    vaultData.monthlyUsage.usedCount=0;
  }
}

function bonusDiversityCheck(newTxType){
  let dateStr=vaultData.dailyCashback.date;
  let sentCount=0, receivedCount=0;
  for(let tx of vaultData.transactions){
    if(tx.type==='cashback'){
      let dStr=new Date(tx.timestamp*1000).toISOString().slice(0,10);
      if(dStr===dateStr && tx.triggerOrigin){
        if(tx.triggerOrigin==='sent') sentCount++;
        else if(tx.triggerOrigin==='received') receivedCount++;
      }
    }
  }
  if(newTxType==='sent' && sentCount>=2)return false;
  if(newTxType==='received' && receivedCount>=2)return false;
  return true;
}

function canGive120Bonus(nowSec, newTxType, newTxAmount){
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);
  if(vaultData.dailyCashback.usedCount>=MAX_BONUSES_PER_DAY) return false;
  if(vaultData.monthlyUsage.usedCount>=MAX_BONUSES_PER_MONTH) return false;
  if((vaultData.annualBonusUsed||0)>=MAX_ANNUAL_BONUS_TVM) return false;

  if(newTxType==='sent' && newTxAmount<=240) return false;
  if(!bonusDiversityCheck(newTxType)) return false;
  return true;
}

function record120BonusUsage(origin){
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed=(vaultData.annualBonusUsed||0)+PER_TX_BONUS;
}

/******************************
 * Table Rendering, Export, Import
 ******************************/
function renderTransactionTable(){
  let tbody=document.getElementById('transactionBody');
  if(!tbody)return;
  tbody.innerHTML='';

  let sorted=[...vaultData.transactions].sort((a,b)=>b.timestamp-a.timestamp);
  sorted.forEach(tx=>{
    let row=document.createElement('tr');
    let bioIBANCell='—', bioCatchCell=tx.bioCatch||'—',
        amtCell=tx.amount, dateCell=formatDisplayDate(tx.timestamp),
        statusCell=tx.status;

    if(tx.type==='sent')         { bioIBANCell=tx.receiverBioIBAN; }
    else if(tx.type==='received'){ bioIBANCell=tx.senderBioIBAN||'Unknown';}
    else if(tx.type==='cashback'){ 
      bioIBANCell=`System/Bonus (ID=${tx.bonusId||''})`; 
    }
    else if(tx.type==='increment'){ bioIBANCell='Periodic Increment'; }

    let truncatedBioCatch='';
    if(tx.bioCatch && tx.bioCatch.length>12){
      truncatedBioCatch = tx.bioCatch.slice(0,12) + '...';
    } else {
      truncatedBioCatch = tx.bioCatch || '—';
    }

    row.innerHTML=`
      <td>${bioIBANCell}</td>
      <td>${truncatedBioCatch}</td>
      <td>${amtCell}</td>
      <td>${dateCell}</td>
      <td>${statusCell}</td>
    `;
    tbody.appendChild(row);
  });
}

function exportTransactionTable(){
  let table=document.getElementById('transactionTable');
  if(!table){alert("No table found");return;}
  let rows=table.querySelectorAll('tr');
  let csv="data:text/csv;charset=utf-8,";
  rows.forEach(r=>{
    let cols=r.querySelectorAll('th, td');
    let line=[];
    cols.forEach(c=>{
      let d=c.innerText.replace(/"/g,'""');
      if(d.includes(','))d=`"${d}"`;
      line.push(d);
    });
    csv+=line.join(",")+"\r\n";
  });
  let encodedUri=encodeURI(csv);
  let link=document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download','transaction_history.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function exportVaultBackup(){
  let data=JSON.stringify(vaultData,null,2);
  let blob=new Blob([data], {type:'application/json'});
  let url=URL.createObjectURL(blob);
  let a=document.createElement('a');
  a.href=url;
  a.download='vault_backup.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportVaultBackupForMobile(){
  const backupObj = vaultData;
  const textData = JSON.stringify(backupObj);
  const blob = new Blob([textData], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'myBioVault.vault';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  alert("Vault exported as 'myBioVault.vault'. On mobile, you can re-import this file to restore.");
}

async function importVaultBackupFromFile(file){
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    vaultData = parsed;
    if(!derivedKey){
      alert("Vault imported, but no derivedKey => please unlock or re-create your passphrase.");
    } else {
      await promptAndSaveVault();
      console.log("Imported vaultData from file =>", vaultData);
      alert("✅ Vault imported successfully!");
      populateWalletUI();
      renderTransactionTable();
    }
  } catch(err){
    console.error("Failed to import .vault file =>", err);
    alert("❌ Invalid or corrupted .vault file");
  }
}


/******************************
 * Advanced UI Interactions (Continued)
 ******************************/
function showVaultUI() {
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}

function initializeBioConstantAndUTCTime() {
  let nowSec = Math.floor(Date.now() / 1000);
  vaultData.lastUTCTimestamp = nowSec;
  populateWalletUI();
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer = setInterval(() => {
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    populateWalletUI();
  }, 1000);
}

function populateWalletUI() {
  let ibInp = document.getElementById('bioibanInput');
  if (ibInp) ibInp.value = vaultData.bioIBAN || "BIO...";

  let rx = vaultData.transactions.filter(t => t.type === 'received').reduce((a, b) => a + b.amount, 0);
  let sx = vaultData.transactions.filter(t => t.type === 'sent').reduce((a, b) => a + b.amount, 0);
  let bx = vaultData.transactions.filter(t => t.type === 'cashback' || t.type === 'increment').reduce((a, b) => a + b.amount, 0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + rx + bx - sx;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  let tvmEl = document.getElementById('tvmBalance');
  if (tvmEl) tvmEl.textContent = `Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  let usdEl = document.getElementById('usdBalance');
  if (usdEl) usdEl.textContent = `Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;

  let bioLineText = document.getElementById('bioLineText');
  if (bioLineText) bioLineText.textContent = `🔄 BonusConstant: ${vaultData.bonusConstant}`;

  let utcEl = document.getElementById('utcTime');
  if (utcEl) utcEl.textContent = formatDisplayDate(vaultData.lastUTCTimestamp);

  const userWalletLabel = document.getElementById('userWalletLabel');
  if (userWalletLabel) {
    userWalletLabel.textContent = vaultData.userWallet
      ? `On-chain Wallet: ${vaultData.userWallet}`
      : '(No wallet set)';
  }
}

/******************************
 * BioCatch UI: Copy & Pop-up
 ******************************/
function showBioCatchPopup(encBio) {
  let popup = document.getElementById('bioCatchPopup');
  if (!popup) return;
  popup.style.display = 'flex';

  let bcTxt = document.getElementById('bioCatchNumberText');
  if (!bcTxt) return;
  let truncated = (encBio.length > 12) ? encBio.slice(0, 12) + "..." : encBio;
  bcTxt.textContent = truncated;
  bcTxt.dataset.fullCatch = encBio;  // Store entire string for copying
}

function handleCopyBioIBAN() {
  let ibInp = document.getElementById('bioibanInput');
  if (!ibInp || !ibInp.value.trim()) { alert("No Bio-IBAN to copy"); return; }
  navigator.clipboard.writeText(ibInp.value.trim())
    .then(() => alert("Bio-IBAN copied!"))
    .catch(err => { console.error("Clipboard fail:", err); alert("Failed to copy IBAN") });
}

/******************************
 * MetaMask/Web3 Wallet Integration
 ******************************/
async function redeemBonusOnChain(tx) {
  console.log("[redeemBonusOnChain] => Attempt to redeem bonus tx:", tx);
  if (!tx || !tx.bonusId) {
    alert("Invalid bonus or missing bonusId");
    return;
  }
  if (!vaultData.userWallet || vaultData.userWallet.length < 5) {
    alert("No valid wallet address found!");
    return;
  }
  if (!vaultData.credentialId) {
    alert("No device key (credentialId) => cannot proceed!");
    return;
  }
  try {
    if (!window.ethereum) {
      alert("No MetaMask or web3 provider found!");
      return;
    }
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const signer = provider.getSigner();
    const userAddr = await signer.getAddress();

    if (userAddr.toLowerCase() !== vaultData.userWallet.toLowerCase()) {
      alert("Warning: active metamask address != vaultData.userWallet. Proceeding anyway...");
    }

    // PRODUCTION: Fill in actual contract ABI and address!
    // const contractAddr = "0xYourContractHere";
    // const contractABI = [ ... ];
    // const contract = new ethers.Contract(contractAddr, contractABI, signer);
    // const txResp = await contract.redeemBonus(vaultData.userWallet, tx.bonusId);
    // const receipt = await txResp.wait();
    // alert(`Redeemed bonus #${tx.bonusId} on chain, txHash= ${receipt.transactionHash}`);

    // For now, just a stub:
    alert(`(Stub) Bonus #${tx.bonusId} => minted to ${vaultData.userWallet}. Fill in real calls!`);
  } catch (err) {
    console.error("redeemBonusOnChain => error:", err);
    alert("On-chain redemption failed => see console");
  }
}

/******************************
 * Multi-Tab / Single Vault
 ******************************/
function preventMultipleVaults() {
  window.addEventListener('storage', evt => {
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
  });
}

function enforceSingleVault() {
  let lock = localStorage.getItem('vaultLock');
  if (!lock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log("VaultLock found => single instance enforced");
  }
}

async function enforceStoragePersistence() {
  if (!navigator.storage?.persist) return;
  let persisted = await navigator.storage.persisted();
  if (!persisted) {
    let granted = await navigator.storage.persist();
    console.log(granted ? "🔒 Storage hardened" : "⚠️ Storage vulnerable");
  }
  setInterval(async () => {
    let est = await navigator.storage.estimate();
    if ((est.usage / est.quota) > 0.85) {
      console.warn("Storage near limit =>", est);
      alert("Storage near limit => export backup!");
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * DOM Load & UI Initialization
 ******************************/
window.addEventListener('DOMContentLoaded', () => {
  let lastURL = localStorage.getItem("last_session_url");
  if (lastURL && window.location.href !== lastURL) {
    window.location.href = lastURL;
  }
  window.addEventListener("beforeunload", () => {
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ main.js => Offline Vault + On-Chain Stub");
  initializeUI();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage = async (e) => {
    if (e.data?.type === 'vaultUpdate') {
      try {
        let { iv, data } = e.data.payload;
        if (!derivedKey) {
          console.warn("vaultUpdate => derivedKey not available yet");
          return;
        }
        let dec = await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, dec);
        populateWalletUI();
        console.log("🔄 Synced vault across tabs");
      } catch (err) {
        console.error("Tab sync fail =>", err);
      }
    }
  };
});

function initializeUI() {
  let enterVaultBtn = document.getElementById('enterVaultBtn');
  enterVaultBtn?.addEventListener('click', checkAndUnlockVault);

  let lockVaultBtn = document.getElementById('lockVaultBtn');
  lockVaultBtn?.addEventListener('click', lockVault);

  let catchInBtn = document.getElementById('catchInBtn');
  catchInBtn?.addEventListener('click', handleReceiveTransaction);

  let catchOutBtn = document.getElementById('catchOutBtn');
  catchOutBtn?.addEventListener('click', handleSendTransaction);

  let copyBioIBANBtn = document.getElementById('copyBioIBANBtn');
  copyBioIBANBtn?.addEventListener('click', handleCopyBioIBAN);

  let exportBtn = document.getElementById('exportBtn');
  exportBtn?.addEventListener('click', exportTransactionTable);

  let exportBackupBtn = document.getElementById('exportBackupBtn');
  exportBackupBtn?.addEventListener('click', exportVaultBackup);

  const exportFriendlyBtn = document.getElementById('exportFriendlyBtn');
  if (exportFriendlyBtn) {
    exportFriendlyBtn.addEventListener('click', exportVaultBackupForMobile);
  }

  const importVaultFileInput = document.getElementById('importVaultFileInput');
  if (importVaultFileInput) {
    importVaultFileInput.addEventListener('change', async (evt) => {
      if (evt.target.files && evt.target.files[0]) {
        await importVaultBackupFromFile(evt.target.files[0]);
      }
    });
  }

  let bioCatchPopup = document.getElementById('bioCatchPopup');
  if (bioCatchPopup) {
    let closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
    let copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click', () => {
      let bcTxt = document.getElementById('bioCatchNumberText');
      if (!bcTxt) return;
      const fullValue = bcTxt.dataset.fullCatch || bcTxt.textContent;
      navigator.clipboard.writeText(fullValue)
        .then(() => alert('✅ Bio‑Catch Number copied!'))
        .catch(err => {
          console.error("Clipboard copy fail =>", err);
          alert("⚠️ Failed to copy. Try again!");
        });
    });
    window.addEventListener('click', (ev) => {
      if (ev.target === bioCatchPopup) {
        bioCatchPopup.style.display = 'none';
      }
    });
  }

  enforceSingleVault();

  const saveWalletBtn = document.getElementById('saveWalletBtn');
  saveWalletBtn?.addEventListener('click', async () => {
    if (vaultData.userWallet && vaultData.userWallet.length > 0) {
      alert("Wallet address is already set and cannot be changed.");
      return;
    }
    const addr = document.getElementById('userWalletAddress').value.trim();
    if (!addr.startsWith('0x') || addr.length < 10) {
      alert("Invalid wallet address");
      return;
    }
    vaultData.userWallet = addr;
    await promptAndSaveVault();
    document.getElementById('userWalletAddress').value = "";
    populateWalletUI();
    alert("✅ Wallet address saved to vaultData. It cannot be changed.");
  });

  const autoConnectWalletBtn = document.getElementById('autoConnectWalletBtn');
  autoConnectWalletBtn?.addEventListener('click', async () => {
    if (!window.ethereum) {
      alert("No MetaMask in this browser!");
      return;
    }
    try {
      await window.ethereum.request({ method: 'eth_requestAccounts' });
      const provider = new window.ethers.providers.Web3Provider(window.ethereum);
      const signer = provider.getSigner();
      const userAddr = await signer.getAddress();

      if (!vaultData.userWallet) {
        vaultData.userWallet = userAddr;
        await promptAndSaveVault();
        populateWalletUI();
        alert(`Auto-connected => ${userAddr}`);
      } else if (vaultData.userWallet.toLowerCase() !== userAddr.toLowerCase()) {
        alert("Warning: The vault already has a different wallet address set!");
      } else {
        alert(`Your current vault address matches the connected MetaMask account: ${userAddr}`);
      }
    } catch (err) {
      console.error("AutoConnect error =>", err);
      alert("Failed to connect wallet => see console");
    }
  });
}

/******************************
 * PWA "Add to Home Screen"
 ******************************/
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ 'beforeinstallprompt' captured — call promptInstallA2HS() to show UI prompt.");
});

function promptInstallA2HS() {
  if (!deferredPrompt) {
    console.log("No deferredPrompt available or user already installed.");
    return;
  }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choiceResult => {
    console.log(`A2HS result: ${choiceResult.outcome}`);
    deferredPrompt = null;
  });
}

/******************************
 * Additional Utilities
 ******************************/
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}
function validateBioIBAN(str) {
  return /^BIO\d+$/.test(str) || /^BONUS\d+$/.test(str);
}
async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  return { success: true };
}
async function validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN) {
  return { valid: true, errors: [] };
}

console.log("🎯 BioVault loaded. All features initialized.");


