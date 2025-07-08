/***********************************************************************
 * main.js — BalanceChain Vault — Production Build (Points 1–10, UX/UI)
 *
 * This file contains:
 *   1. Global constants & protocol capacity
 *   2. IndexedDB utilities & AES-GCM encryption
 *   3. Privacy & key salting
 *   4. Biometric key management
 *   5. Cryptographic proof calculations
 *   6. Caps & rate limiting
 *   7. Ownership history buffer
 *   8. Device registration & multi-device support
 *   9. Onboarding, unlock, and vault creation
 *  10. Segment unlocking & transfers
 *  11. Batch transfers / Bio-Catch
 *  12. Import/claim logic
 *  13. Encrypted backup & recovery
 *  14. Audit export & proof verification
 *  15. TVM token claim logic
 *  16. UI helpers: sanitization, toast, clipboard
 *  17. UI button handlers & MetaMask integration
 *  18. UI wiring & initialization
 *  19. Modal navigation & accessibility
 *  20. Session timeout & auto-lock
 *  21. Encryption key rotation & audit logging
 *  22. App entry point, onboarding/unlock flows
 *  23. Rendering the vault UI and transaction pagination
 *
 * Please ensure all referenced HTML elements (IDs, classes) exist.
 **********************************************************************/

/*==============================================================================
 * Section 1: Global Constants & Protocol Capacity
 *============================================================================*/

const GENESIS_BIO_CONST        = 1736565605;
const SEGMENTS_TOTAL           = 12000;
const SEGMENTS_UNLOCKED        = 1200;
const KEY_HASH_SALT            = 'BalanceChainAppV1';
const SEGMENTS_PER_DAY         = 360;
const SEGMENTS_PER_MONTH       = 3600;
const SEGMENTS_PER_YEAR        = 10800;
const TVM_SEGMENTS_PER_TOKEN   = 12;
const TVM_CLAIM_CAP            = 1000;
const HISTORY_MAX              = 20;

const DB_NAME                  = "BalanceChainVaultDB";
const DB_VERSION               = 1;
const VAULT_STORE              = "vaultStore";

const MAX_AUTH_ATTEMPTS        = 5;
const LOCKOUT_DURATION_SECONDS = 3600;

/*==============================================================================
 * Section 2: IndexedDB Utilities & AES-GCM Encryption
 *============================================================================*/

function bufferToBase64(buffer) {
  // Convert an ArrayBuffer to a base64 string
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(b64) {
  // Convert a base64 string back to an ArrayBuffer
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
}

async function openVaultDB() {
  // Open (or create) the IndexedDB for the vault
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

async function saveVaultDataToDB(iv, ciphertext, saltBase64, vaultData) {
  // Save the encrypted vault blob and metadata to IndexedDB
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx    = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp || null,
      authAttempts: vaultData.authAttempts || 0,
      transactionHistory: vaultData.transactionHistory || [],
      tvmClaimedThisYear: vaultData.tvmClaimedThisYear || 0,
      walletAddress: vaultData.walletAddress || ''
    });
    tx.oncomplete = () => resolve();
    tx.onerror    = (err) => reject(err);
  });
}

async function loadVaultDataFromDB() {
  // Load the encrypted vault blob and metadata from IndexedDB
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx    = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const get   = store.get('vaultData');
    get.onsuccess = () => {
      if (!get.result) {
        resolve(null);
      } else {
        try {
          resolve({
            iv: base64ToBuffer(get.result.iv),
            ciphertext: base64ToBuffer(get.result.ciphertext),
            salt: get.result.salt ? base64ToBuffer(get.result.salt) : null,
            lockoutTimestamp: get.result.lockoutTimestamp || null,
            authAttempts: get.result.authAttempts || 0,
            transactionHistory: get.result.transactionHistory || [],
            tvmClaimedThisYear: get.result.tvmClaimedThisYear || 0,
            walletAddress: get.result.walletAddress || ''
          });
        } catch (e) {
          console.error("Error decoding vault data:", e);
          resolve(null);
        }
      }
    };
    get.onerror = (err) => reject(err);
  });
}

async function deriveKeyFromPIN(pin, salt) {
  // PBKDF2 to derive an AES-GCM key from the user's PIN + salt
  const enc = new TextEncoder();
  const pinBytes = enc.encode(pin);
  const keyMat = await crypto.subtle.importKey(
    'raw', pinBytes, { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: salt,
    iterations: 100000,
    hash: 'SHA-256'
  }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptData(key, data) {
  // AES-GCM encrypt a JS object, returning iv + ciphertext
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}

async function decryptData(key, iv, ciphertext) {
  // AES-GCM decrypt, returning parsed JSON
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(plaintext));
}

/*==============================================================================
 * Section 3: Privacy & Advanced Key Salting
 *============================================================================*/

function getAppSalt() {
  // A per-installation salt stored in localStorage
  let salt = localStorage.getItem('bc_app_salt');
  if (!salt) {
    salt = crypto.getRandomValues(new Uint8Array(16)).join('');
    localStorage.setItem('bc_app_salt', salt);
  }
  return salt;
}

async function hashDeviceKeyWithSalt(publicKeyBuffer, extraSalt = '') {
  // SHA-256 hash of (publicKey + appSalt + extraSalt), hex-encoded
  const appSalt = getAppSalt();
  const combined = KEY_HASH_SALT + appSalt + extraSalt;
  const data = new Uint8Array([
    ...new Uint8Array(publicKeyBuffer),
    ...new TextEncoder().encode(combined)
  ]);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/*==============================================================================
 * Section 4: Biometric Key Management (WebAuthn)
 *============================================================================*/

async function performBiometricAuthenticationForCreation() {
  // Create a new WebAuthn credential for storing on-device
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: "BalanceChain Bio-Vault" },
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

  try {
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) throw new Error("Biometric flow returned null");
    return credential;
  } catch (err) {
    console.error("Biometric creation failed:", err);
    throw err;
  }
}

/*==============================================================================
 * Section 5: Cryptographic Proofs
 *============================================================================*/

async function sha256Hex(input) {
  // Compute SHA-256 hex digest of string or ArrayBuffer
  const data = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input;
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function computeOwnershipProof(segment) {
  // Hash of current ownership state
  const payload = [
    segment.segmentIndex,
    segment.currentOwnerKey,
    segment.currentOwnerTS,
    segment.ownershipChangeCount,
    segment.previousOwnerKey,
    segment.previousOwnerTS,
    segment.previousBioConst
  ].join("|");
  return sha256Hex(payload);
}

async function computeSpentProof(segment) {
  const payload = [
    segment.originalBioConst,
    segment.previousBioConst,
    segment.segmentIndex,
    "SPENT"
  ].join("|");
  return sha256Hex(payload);
}

async function computeUnlockIntegrityProof(segment) {
  const payload = [
    segment.segmentIndex,
    segment.unlockIndexRef,
    "UNLOCK"
  ].join("|");
  return sha256Hex(payload);
}

/*==============================================================================
 * Section 6: Cap Enforcement (Unlock rate limits)
 *============================================================================*/

function getPeriodStrings(timestampSec) {
  const d = new Date(timestampSec * 1000);
  return {
    day:   d.toISOString().slice(0,10),
    month: d.toISOString().slice(0,7),
    year:  d.getFullYear().toString()
  };
}

function checkAndRecordUnlock(vault, nowTS, count = 1) {
  const rec = vault.unlockRecords;
  const periods = getPeriodStrings(nowTS);

  if (rec.day   !== periods.day)   { rec.day   = periods.day;   rec.dailyCount   = 0; }
  if (rec.month !== periods.month) { rec.month = periods.month; rec.monthlyCount = 0; }
  if (rec.year  !== periods.year)  { rec.year  = periods.year;  rec.yearlyCount  = 0; }

  if (
    rec.dailyCount   + count > SEGMENTS_PER_DAY   ||
    rec.monthlyCount + count > SEGMENTS_PER_MONTH ||
    rec.yearlyCount  + count > SEGMENTS_PER_YEAR
  ) {
    return false;
  }

  rec.dailyCount   += count;
  rec.monthlyCount += count;
  rec.yearlyCount  += count;
  return true;
}

/*==============================================================================
 * Section 7: Ownership History Buffer
 *============================================================================*/

function updateOwnershipHistory(segment, keyHash, timestamp, type) {
  segment.ownershipChangeHistory.push({
    ownerKey: keyHash,
    ts:       timestamp,
    type,
    changeCount: segment.ownershipChangeCount
  });
  if (segment.ownershipChangeHistory.length > HISTORY_MAX) {
    segment.ownershipChangeHistory.shift();
  }
}

/*==============================================================================
 * Section 8: Device Registration & Multi-Device Support
 *============================================================================*/

async function registerDeviceKey(vault, publicKeyBuffer, extraSalt = '') {
  const hash = await hashDeviceKeyWithSalt(publicKeyBuffer, extraSalt);
  if (!vault.deviceKeyHashes.includes(hash)) {
    vault.deviceKeyHashes.push(hash);
    await saveAndRefreshVault();
  }
}

function isValidDeviceKey(vault, deviceKeyHash) {
  return vault.deviceKeyHashes.includes(deviceKeyHash);
}

/*==============================================================================
 * Section 9: Onboarding & Vault Creation
 *============================================================================*/

async function onboardUser(pin) {
  // 1. Biometric creation
  const credential = await performBiometricAuthenticationForCreation();
  const rawId = credential.response.getPublicKey
    ? credential.response.getPublicKey()
    : credential.rawId;

  // 2. Derive deviceKeyHash
  const deviceKeyHash = await hashDeviceKeyWithSalt(rawId);

  // 3. Initialize vault data
  const now       = Math.floor(Date.now()/1000);
  const userBioConst = GENESIS_BIO_CONST + (now - GENESIS_BIO_CONST);

  const segments = [];
  for (let i = 1; i <= SEGMENTS_TOTAL; i++) {
    segments.push({
      segmentIndex: i,
      amount: 1,
      originalOwnerKey: deviceKeyHash,
      originalOwnerTS: now,
      originalBioConst: userBioConst,
      previousOwnerKey: null,
      previousOwnerTS: null,
      previousBioConst: null,
      currentOwnerKey: deviceKeyHash,
      currentOwnerTS: now,
      currentBioConst: userBioConst,
      unlocked: i <= SEGMENTS_UNLOCKED,
      ownershipChangeCount: 0,
      unlockIndexRef: null,
      unlockIntegrityProof: null,
      spentProof: null,
      ownershipProof: null,
      ownershipChangeHistory: []
    });
  }

  vaultData = {
    credentialId: bufferToBase64(rawId),
    deviceKeyHashes: [deviceKeyHash],
    onboardingTS: now,
    userBioConst,
    segments,
    unlockRecords: { day:'', dailyCount:0, month:'', monthlyCount:0, year:'', yearlyCount:0 },
    walletAddress: '',
    tvmClaimedThisYear: 0,
    transactionHistory: []
  };

  // 4. Encrypt & store
  currentSalt  = crypto.getRandomValues(new Uint8Array(16));
  decryptedKey = await deriveKeyFromPIN(pin, currentSalt);
  const { iv, ciphertext } = await encryptData(decryptedKey, vaultData);
  await saveVaultDataToDB(iv, ciphertext, bufferToBase64(currentSalt), vaultData);

  return vaultData;
}

/*==============================================================================
 * Section 10: Unlocking an Existing Vault
 *============================================================================*/

async function unlockVault(pin) {
  const dbData = await loadVaultDataFromDB();
  if (!dbData) throw new Error("No vault found");
  currentSalt = dbData.salt;
  decryptedKey = await deriveKeyFromPIN(pin, currentSalt);
  vaultData = await decryptData(decryptedKey, dbData.iv, dbData.ciphertext);
  return vaultData;
}

/*==============================================================================
 * Section 11: Unlock Next Segment (with Cap Enforcement)
 *============================================================================*/

async function unlockNextSegmentWithCap(vault, unlockingSegIndex) {
  const now = Math.floor(Date.now()/1000);
  if (!checkAndRecordUnlock(vault, now, 1)) {
    throw new Error("Daily unlock cap reached");
  }

  const userKey = vault.deviceKeyHashes[0];
  const nextSeg = vault.segments.find(seg => !seg.unlocked && seg.currentOwnerKey === userKey);
  if (!nextSeg) return;

  nextSeg.unlocked = true;
  nextSeg.unlockIndexRef = unlockingSegIndex;
  nextSeg.currentOwnerTS = now;
  nextSeg.currentBioConst = nextSeg.previousBioConst
    ? nextSeg.previousBioConst + (now - nextSeg.previousOwnerTS)
    : nextSeg.originalBioConst;
  nextSeg.unlockIntegrityProof = await computeUnlockIntegrityProof(nextSeg);
  updateOwnershipHistory(nextSeg, userKey, now, "unlock");

  await saveAndRefreshVault();
}

/*==============================================================================
 * Section 12: Transfer Segment (Single)
 *============================================================================*/

async function transferSegment(vault, receiverKeyHash, deviceKeyHash) {
  if (!isValidDeviceKey(vault, deviceKeyHash)) {
    throw new Error("Device not authorized");
  }

  const now = Math.floor(Date.now()/1000);
  const seg = vault.segments.find(s => s.unlocked && s.currentOwnerKey === deviceKeyHash);
  if (!seg) {
    throw new Error("No unlocked segments available");
  }

  seg.previousOwnerKey = seg.currentOwnerKey;
  seg.previousOwnerTS = seg.currentOwnerTS;
  seg.previousBioConst = seg.currentBioConst;
  seg.currentOwnerKey = receiverKeyHash;
  seg.currentOwnerTS = now;
  seg.currentBioConst = seg.previousBioConst + (now - seg.previousOwnerTS);
  seg.ownershipChangeCount += 1;
  seg.unlocked = false;
  seg.spentProof = await computeSpentProof(seg);
  seg.ownershipProof = await computeOwnershipProof(seg);
  updateOwnershipHistory(seg, receiverKeyHash, now, "transfer");

  await unlockNextSegmentWithCap(vault, seg.segmentIndex);
  return seg;
}

/*==============================================================================
 * Section 13: Batch Transfer ("Bio-Catch" Export)
 *============================================================================*/

async function exportSegmentsBatch(vault, receiverKeyHash, count, deviceKeyHash) {
  if (!isValidDeviceKey(vault, deviceKeyHash)) {
    throw new Error("Device not authorized");
  }

  const now = Math.floor(Date.now()/1000);
  const eligible = vault.segments.filter(s => s.unlocked && s.currentOwnerKey === deviceKeyHash);

  if (eligible.length < count) {
    throw new Error(`Only ${eligible.length} segments available`);
  }

  const batch = [];
  for (let i = 0; i < count; i++) {
    const seg = eligible[i];
    seg.previousOwnerKey = seg.currentOwnerKey;
    seg.previousOwnerTS = seg.currentOwnerTS;
    seg.previousBioConst = seg.currentBioConst;
    seg.currentOwnerKey = receiverKeyHash;
    seg.currentOwnerTS = now;
    seg.currentBioConst = seg.previousBioConst + (now - seg.previousOwnerTS);
    seg.ownershipChangeCount++;
    seg.unlocked = false;
    seg.spentProof = await computeSpentProof(seg);
    seg.ownershipProof = await computeOwnershipProof(seg);
    updateOwnershipHistory(seg, receiverKeyHash, now, "transfer");
    await unlockNextSegmentWithCap(vault, seg.segmentIndex);
    batch.push(seg);
  }

  await saveAndRefreshVault();
  return JSON.stringify(batch.map(s => JSON.stringify(s)));
}

function exportSegment(segment) {
  return JSON.stringify(segment);
}

/*==============================================================================
 * Section 14: Import / Claim Received Segments
 *============================================================================*/

function importSegmentsBatch(jsonArray, myKeyHash) {
  const arr = JSON.parse(jsonArray);
  const imported = [];

  for (const item of arr) {
    const seg = typeof item === "string" ? JSON.parse(item) : item;
    if (seg.currentOwnerKey !== myKeyHash) {
      throw new Error(`Segment ${seg.segmentIndex}: not owner`);
    }
    imported.push(seg);
  }

  return imported;
}

async function claimReceivedSegmentsBatch(vault, receivedSegments) {
  for (const seg of receivedSegments) {
    const idx = vault.segments.findIndex(s => s.segmentIndex === seg.segmentIndex);
    if (idx !== -1) {
      vault.segments[idx] = seg;
    } else {
      vault.segments.push(seg);
    }
  }
  await saveAndRefreshVault();
}

/*==============================================================================
 * Section 15: Encrypted Backup & Recovery
 *============================================================================*/

async function encryptVaultForBackup(vault, userPassword) {
  // Create an AES-GCM encrypted JSON backup
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(vault));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(userPassword), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return {
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encrypted))
  };
}

async function decryptVaultFromBackup(backup, userPassword) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(backup.salt);
  const iv   = new Uint8Array(backup.iv);
  const data = new Uint8Array(backup.data);

  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(userPassword), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return JSON.parse(new TextDecoder().decode(decrypted));
}

/*==============================================================================
 * Section 16: Audit Export & Proof Verification
 *============================================================================*/

function exportAuditData(vault, options={ fullHistory: false }) {
  // Generate a JSON payload suitable for compliance/audit
  return JSON.stringify({
    deviceKeyHashes: vault.deviceKeyHashes,
    onboardingTS: vault.onboardingTS,
    userBioConst: vault.userBioConst,
    segments: vault.segments.map(seg => ({
      segmentIndex: seg.segmentIndex,
      amount: seg.amount,
      originalOwnerKey: seg.originalOwnerKey,
      originalOwnerTS: seg.originalOwnerTS,
      originalBioConst: seg.originalBioConst,
      previousOwnerKey: seg.previousOwnerKey,
      previousOwnerTS: seg.previousOwnerTS,
      previousBioConst: seg.previousBioConst,
      currentOwnerKey: seg.currentOwnerKey,
      currentOwnerTS: seg.currentOwnerTS,
      currentBioConst: seg.currentBioConst,
      unlocked: seg.unlocked,
      ownershipChangeCount: seg.ownershipChangeCount,
      unlockIndexRef: seg.unlockIndexRef,
      unlockIntegrityProof: seg.unlockIntegrityProof,
      spentProof: seg.spentProof,
      ownershipProof: seg.ownershipProof,
      ownershipChangeHistory: options.fullHistory
        ? seg.ownershipChangeHistory
        : seg.ownershipChangeHistory.slice(-HISTORY_MAX)
    }))
  });
}

async function verifyProofChain(segments, deviceKeyHash) {
  // Recompute and verify each proof
  for (const seg of segments) {
    const ownProof = await computeOwnershipProof(seg);
    if (seg.ownershipProof !== ownProof) {
      throw new Error(`Segment ${seg.segmentIndex}: ownership proof mismatch`);
    }
    if (seg.unlockIndexRef !== null) {
      const unlockProof = await computeUnlockIntegrityProof(seg);
      if (seg.unlockIntegrityProof !== unlockProof) {
        throw new Error(`Segment ${seg.segmentIndex}: unlock integrity proof mismatch`);
      }
    }
    if (seg.spentProof) {
      const spentProof = await computeSpentProof(seg);
      if (seg.spentProof !== spentProof) {
        throw new Error(`Segment ${seg.segmentIndex}: spent proof mismatch`);
      }
    }
    if (seg.currentOwnerKey !== deviceKeyHash) {
      throw new Error(`Segment ${seg.segmentIndex}: wrong owner`);
    }
  }
  return true;
}

/*==============================================================================
 * Section 17: TVM Token Claim Logic
 *============================================================================*/

function getAvailableTVMClaims(vault) {
  const spentCount = vault.segments.filter(s => s.ownershipChangeCount > 0).length;
  const claimed    = vault.tvmClaimedThisYear || 0;
  const claimable  = Math.floor(spentCount / TVM_SEGMENTS_PER_TOKEN) - claimed;
  return Math.max(claimable, 0);
}

async function claimTvmTokens(vault) {
  const available = getAvailableTVMClaims(vault);
  if (!vault.walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(vault.walletAddress)) {
    throw new Error("Valid wallet address required");
  }
  if (available <= 0) {
    throw new Error("No claimable TVM");
  }
  if ((vault.tvmClaimedThisYear || 0) + available > TVM_CLAIM_CAP) {
    throw new Error("Annual TVM claim cap reached");
  }

  const claimSegments = vault.segments
    .filter(s => s.ownershipChangeCount > 0)
    .slice(0, available * TVM_SEGMENTS_PER_TOKEN);

  const proofBundle = claimSegments.map(seg => ({
    segmentIndex: seg.segmentIndex,
    spentProof: seg.spentProof,
    ownershipProof: seg.ownershipProof,
    unlockIntegrityProof: seg.unlockIntegrityProof
  }));

  vault.tvmClaimedThisYear = (vault.tvmClaimedThisYear || 0) + available;
  await saveAndRefreshVault();
  return proofBundle;
}

/*==============================================================================
 * Section 18: Export for UI/Integration
 *============================================================================*/

window.onboardUser               = onboardUser;
window.unlockVault               = unlockVault;
window.transferSegment           = transferSegment;
window.exportSegmentsBatch       = exportSegmentsBatch;
window.importSegmentsBatch       = importSegmentsBatch;
window.claimReceivedSegmentsBatch= claimReceivedSegmentsBatch;
window.exportAuditData           = exportAuditData;
window.verifyProofChain          = verifyProofChain;
window.claimTvmTokens            = claimTvmTokens;
window.encryptVaultForBackup     = encryptVaultForBackup;
window.decryptVaultFromBackup    = decryptVaultFromBackup;

/*==============================================================================
 * Section 19: UI Helpers — Sanitization, Toasts, Clipboard
 *============================================================================*/

function sanitizeInput(str) {
  // Remove dangerous chars and trim to 64 chars
  return String(str).replace(/[<>"'`;]/g,'').trim().slice(0,64);
}

function showToast(message, isError=false) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = String(message).replace(/[\u0000-\u001F\u007F<>"]/g,'');
  t.className = 'toast' + (isError ? ' toast-error' : '');
  t.style.display = 'block';
  setTimeout(() => { t.style.display='none'; }, 3300);
}

function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text)
      .then(()=> showToast("Copied!"))
      .catch(()=> showToast("Copy failed", true));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      showToast("Copied!");
    } catch {
      showToast("Copy failed", true);
    }
    document.body.removeChild(ta);
  }
}

/*==============================================================================
 * Section 20: UI Button Handlers
 *============================================================================*/

async function handleCopyBioIBAN() {
  const val = document.getElementById('bioibanInput')?.value;
  if (val) copyToClipboard(sanitizeInput(val));
}

async function handleCopyBioCatch() {
  const txt = document.getElementById('bioCatchNumberText')?.textContent;
  if (txt) copyToClipboard(sanitizeInput(txt));
}

async function handleCatchOut() {
  const iban = sanitizeInput(document.getElementById('receiverBioIBAN')?.value || '');
  const amt  = Number(sanitizeInput(document.getElementById('catchOutAmount')?.value || '0'));
  if (!iban || isNaN(amt) || amt<=0) {
    return showToast("Invalid receiver or amount", true);
  }
  try {
    await safeHandler(()=>transferSegment(vaultData, iban, vaultData.deviceKeyHashes[0]));
    showToast(`Transferred ${amt} TVM to ${iban}`);
    renderVaultUI();
  } catch (e) {
    showToast(e.message || "Transfer failed", true);
  }
}

async function handleCatchIn() {
  const bc  = sanitizeInput(document.getElementById('catchInBioCatch')?.value || '');
  const amt = Number(sanitizeInput(document.getElementById('catchInAmount')?.value || '0'));
  if (!bc || isNaN(amt) || amt<=0) {
    return showToast("Invalid Bio-Catch or amount", true);
  }
  try {
    const imported = importSegmentsBatch(bc, vaultData.deviceKeyHashes[0]);
    await claimReceivedSegmentsBatch(vaultData, imported);
    showToast(`Claimed ${amt} TVM`);
    renderVaultUI();
  } catch (e) {
    showToast(e.message || "Claim failed", true);
  }
}

async function handleExport() {
  try {
    const data = exportAuditData(vaultData, { fullHistory: false });
    const blob = new Blob([data], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'transactions.json';
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>document.body.removeChild(a), 100);
    showToast("Transactions exported");
  } catch {
    showToast("Export failed", true);
  }
}

async function handleBackupExport() {
  try {
    // For production: prompt passphrase, then call encryptVaultForBackup(...)
    showToast("Backup exported (simulation)");
  } catch {
    showToast("Backup failed", true);
  }
}

function handleExportFriendly() {
  // A user-readable backup
  showToast("Friendly backup exported (simulation)");
}

async function handleImportVault(evt) {
  try {
    const file = evt.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      showToast("Vault imported (simulation)");
    };
    reader.readAsText(file);
  } catch {
    showToast("Import failed", true);
  }
}

function handleLockVault() {
  vaultData    = null;
  decryptedKey = null;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  showToast("Vault locked");
}

async function handleEnterVault() {
  // Should not be used in our prompt-based flow
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockedScreen')?.classList.add('hidden');
  showToast("Vault unlocked");
}

/*==============================================================================
 * Section 21: MetaMask & Wallet Integration
 *============================================================================*/

async function handleSaveWallet() {
  const addr = sanitizeInput(document.getElementById('userWalletAddress')?.value || '');
  if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) {
    return showToast("Invalid wallet address", true);
  }
  vaultData.walletAddress = addr;
  await saveAndRefreshVault();
  showToast("Wallet saved");
}

async function handleAutoConnectWallet() {
  if (!window.ethereum) {
    return showToast("MetaMask not detected", true);
  }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const addr = accounts[0];
    document.getElementById('userWalletAddress').value = addr;
    vaultData.walletAddress = addr;
    await saveAndRefreshVault();
    showToast("MetaMask connected");
  } catch {
    showToast("MetaMask connection failed", true);
  }
}

async function handleClaimTVM() {
  try {
    const proof = await claimTvmTokens(vaultData);
    showToast("Proof bundle ready for claim");
    await saveAndRefreshVault();
    renderVaultUI();
  } catch (e) {
    showToast(e.message || "Claim failed", true);
  }
}

/*==============================================================================
 * Section 22: Main UI Initialization
 *============================================================================*/

function initVaultUI() {
  // Copy IBAN
  document.getElementById('copyBioIBANBtn')?.addEventListener('click', handleCopyBioIBAN);

  // Show Bio-Catch popup
  document.getElementById('showBioCatchBtn')?.addEventListener('click', () => {
    // Generate dummy bio-catch for UI demonstration
    const dummy = `BC-${Date.now()}-${Math.floor(Math.random()*1e5)}`;
    document.getElementById('bioCatchNumberText').textContent = dummy;
    openPopup('bioCatchPopup');
  });

  document.getElementById('copyBioCatchBtn')?.addEventListener('click', handleCopyBioCatch);
  document.getElementById('closeBioCatchPopup')?.addEventListener('click', () => closePopup('bioCatchPopup'));

  // Catch in/out
  document.getElementById('catchOutBtn')?.addEventListener('click', handleCatchOut);
  document.getElementById('catchInBtn')?.addEventListener('click', handleCatchIn);

  // Export / Backup / Import
  document.getElementById('exportBtn')?.addEventListener('click', handleExport);
  document.getElementById('exportBackupBtn')?.addEventListener('click', handleBackupExport);
  document.getElementById('exportFriendlyBtn')?.addEventListener('click', handleExportFriendly);
  document.getElementById('importVaultFileInput')?.addEventListener('change', handleImportVault);

  // Lock / Unlock
  document.getElementById('lockVaultBtn')?.addEventListener('click', handleLockVault);
  document.getElementById('enterVaultBtn')?.addEventListener('click', handleEnterVault);

  // Wallet & MetaMask
  document.getElementById('saveWalletBtn')?.addEventListener('click', handleSaveWallet);
  document.getElementById('autoConnectWalletBtn')?.addEventListener('click', handleAutoConnectWallet);
  document.getElementById('claimTvmBtn')?.addEventListener('click', handleClaimTVM);

  // Transaction pagination
  document.getElementById('txPrevBtn')?.addEventListener('click', () => {
    if (txPage > 0) { txPage--; renderTransactions(); }
  });
  document.getElementById('txNextBtn')?.addEventListener('click', () => {
    txPage++; renderTransactions();
  });
}

/*==============================================================================
 * Section 23: Transaction Table Rendering & Pagination
 *============================================================================*/

function getTxList() {
  // Flatten segments with ownershipChangeCount > 0 into transaction records
  if (!vaultData) return [];
  return vaultData.segments
    .filter(s => s.ownershipChangeCount > 0)
    .map(seg => ({
      bioIban: vaultData.deviceKeyHashes[0]?.slice(0,10) + '…',
      bioCatch: seg.segmentIndex,
      amount: seg.amount,
      time: new Date(seg.currentOwnerTS * 1000).toLocaleString(),
      status: seg.currentOwnerKey === vaultData.deviceKeyHashes[0] ? 'IN' : 'OUT'
    }));
}

function renderTransactions() {
  const list = getTxList();
  const tbody = document.getElementById('transactionBody');
  tbody.innerHTML = '';

  // Empty state row
  const empty = document.getElementById('txEmptyState');
  if (list.length === 0) {
    empty.style.display = '';
    document.getElementById('txPrevBtn').style.display = 'none';
    document.getElementById('txNextBtn').style.display = 'none';
    return;
  } else {
    empty.style.display = 'none';
  }

  // Paginate
  const start = txPage * pageSize;
  const end   = start + pageSize;
  const page  = list.slice(start, end);

  for (const tx of page) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${tx.bioIban}</td>
      <td>${tx.bioCatch}</td>
      <td>${tx.amount}</td>
      <td>${tx.time}</td>
      <td>${tx.status}</td>`;
    tbody.appendChild(tr);
  }

  // Prev / Next buttons
  document.getElementById('txPrevBtn').style.display = txPage > 0 ? '' : 'none';
  document.getElementById('txNextBtn').style.display = end < list.length ? '' : 'none';
}

/*==============================================================================
 * Section 24: Modal Navigation & Accessibility
 *============================================================================*/

function wireModalNavigation() {
  document.querySelectorAll('.modal-nav button').forEach(btn => {
    btn.addEventListener('click', () => {
      const modal = btn.closest('.modal');
      modal.querySelectorAll('.modal-nav button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      // Optionally switch pages or modals
      // ...
    });
  });
}

function openModal(id) {
  document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
  const m = document.getElementById(id);
  if (m) {
    m.style.display = 'flex';
    const focusEl = m.querySelector('[tabindex="0"]');
    if (focusEl) setTimeout(() => focusEl.focus(), 100);
  }
  document.body.style.overflow = 'hidden';
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) m.style.display = 'none';
  document.body.style.overflow = '';
}

function closeAllModals() {
  document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
  document.body.style.overflow = '';
}

function openPopup(id) {
  const p = document.getElementById(id);
  if (p) p.style.display = 'flex';
}

function closePopup(id) {
  const p = document.getElementById(id);
  if (p) p.style.display = 'none';
}

// Close on Escape or click outside
document.addEventListener('keydown', e => {
  if (e.key === "Escape") closeAllModals();
});
document.querySelectorAll('.modal').forEach(modal => {
  modal.addEventListener('click', e => {
    if (e.target === modal) closeAllModals();
  });
});

/*==============================================================================
 * Section 25: Session Timeout & Auto-Lock
 *============================================================================*/

let inactivityTimer;
function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(() => {
    handleLockVault();
  }, 15 * 60 * 1000);
}

['click','mousemove','keydown','touchstart'].forEach(evt => {
  document.addEventListener(evt, resetInactivityTimer);
});
resetInactivityTimer();

/*==============================================================================
 * Section 26: Encryption Key Rotation & Audit Logging (Stubs)
 *============================================================================*/

async function rotateEncryptionKey(oldPin, newPin) {
  try {
    const dbData = await loadVaultDataFromDB();
    const oldKey = await deriveKeyFromPIN(oldPin, dbData.salt);
    const vault  = await decryptData(oldKey, dbData.iv, dbData.ciphertext);

    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey  = await deriveKeyFromPIN(newPin, newSalt);
    const { iv, ciphertext } = await encryptData(newKey, vault);

    await saveVaultDataToDB(iv, ciphertext, bufferToBase64(newSalt), vault);
    showToast("Passphrase rotated successfully");
  } catch (e) {
    showToast("Key rotation failed: " + (e.message || e), true);
  }
}

function logAuditEvent(eventType, metadata={}) {
  const entry = {
    timestamp: new Date().toISOString(),
    eventType,
    ...metadata,
    userAgent: navigator.userAgent
  };
  // TODO: store in IndexedDB or send to remote logging endpoint
  console.log("Audit log:", entry);
}

/*==============================================================================
 * Section 27: App Entry Point — Onboarding vs Unlock
 *============================================================================*/

window.addEventListener('DOMContentLoaded', async () => {
  initVaultUI();
  wireModalNavigation();

  if (!localStorage.getItem('vaultOnboarded')) {
    openModal('onboardingModal');
    // After user clicks "Got it", prompt for PIN, then onboardUser(pin)
    document.querySelector('#onboardingModal .modal-close').addEventListener('click', async () => {
      let pin = prompt("Set a secure passphrase (min 6 chars):");
      if (!pin || pin.length < 6) {
        alert("Passphrase too short");
        return;
      }
      await onboardUser(pin);
      localStorage.setItem('vaultOnboarded','yes');
      closeAllModals();
      renderVaultUI();
    });
  } else {
    openModal('passModal');
    document.getElementById('passModalSaveBtn').addEventListener('click', async () => {
      const pin = document.getElementById('passModalInput').value;
      if (!pin) return showToast("Enter your passphrase", true);
      try {
        await unlockVault(pin);
        closeAllModals();
        renderVaultUI();
      } catch (e) {
        showToast("Unlock failed: " + e.message, true);
      }
    });
  }
});

/*==============================================================================
 * Section 28: Render Vault UI after Unlock / Onboard
 *============================================================================*/

function renderVaultUI() {
  document.getElementById('lockedScreen').style.display = 'none';
  document.getElementById('vaultUI').style.display     = 'block';

  // IBAN & balances
  const ibanInput = document.getElementById('bioibanInput');
  ibanInput.value = (vaultData.deviceKeyHashes[0] || "").slice(0,36);

  const tvmBal = getTvmBalance(vaultData);
  document.getElementById('tvmBalance').textContent = `Balance: ${tvmBal} TVM`;
  document.getElementById('usdBalance').textContent = `Equivalent to ${(tvmBal/12).toFixed(2)} USD`;

  document.getElementById('bioLineText').textContent = `🔄 BonusConstant: ${vaultData.userBioConst}`;
  document.getElementById('utcTime').textContent     = "UTC Time: " + new Date().toUTCString();

  // Wallet & claimable
  document.getElementById('userWalletAddress').value = vaultData.walletAddress || '';
  document.getElementById('tvmClaimable').textContent = `TVM Claimable: ${getAvailableTVMClaims(vaultData)}`;

  // Refresh transactions
  txPage = 0;
  renderTransactions();
}

/*==============================================================================
 * Section 29: Utility Functions
 *============================================================================*/

function getTvmBalance(vault) {
  const used    = vault.segments.filter(s => s.ownershipChangeCount > 0).length;
  const claimed = vault.tvmClaimedThisYear || 0;
  return Math.floor(used / TVM_SEGMENTS_PER_TOKEN) - claimed;
}

async function saveAndRefreshVault() {
  if (!decryptedKey || !currentSalt) return;
  const { iv, ciphertext } = await encryptData(decryptedKey, vaultData);
  await saveVaultDataToDB(iv, ciphertext, bufferToBase64(currentSalt), vaultData);
  renderVaultUI();
}

async function safeHandler(fn) {
  try {
    await fn();
  } catch (e) {
    console.error(e);
    showToast(e.message || "Error", true);
  }
}

/*==============================================================================
 * Section 30: End of main.js
 *============================================================================*/
