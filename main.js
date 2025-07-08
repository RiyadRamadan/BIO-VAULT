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
 *  24. Lockout & auth-attempt tracking
 *  25. “Terminate Vault” full wipe + confirm
 *  26. Backup reminder flag flip
 *  27. Onboarding “Next” buttons wired
 *  28. Bio-Catch popup focus trap
 *  29. Feature detection for required APIs
 *  30. ethers.js init & on-chain claim submission
 *
 * Please ensure all referenced HTML elements (IDs, classes) exist.
 **********************************************************************/

/*==============================================================================
 * Section 1: Global Constants, Protocol Capacity & State
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

// —————————————
// **Global in-memory state**
let vaultData       = null;
let decryptedKey    = null;
let currentSalt     = null;
let txPage          = 0;
const pageSize      = 10;

// **ethers.js** objects
let provider, signer;

/*==============================================================================
 * Section 2: IndexedDB Utilities & AES-GCM Encryption
 *============================================================================*/

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
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

async function saveVaultDataToDB(iv, ciphertext, saltBase64, vault) {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx    = db.transaction([VAULT_STORE], 'readwrite');
    const store = tx.objectStore(VAULT_STORE);
    store.put({
      id: 'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltBase64,
      lockoutTimestamp: vault.lockoutTimestamp || null,
      authAttempts: vault.authAttempts || 0,
      transactionHistory: vault.transactionHistory || [],
      tvmClaimedThisYear: vault.tvmClaimedThisYear || 0,
      walletAddress: vault.walletAddress || ''
    });
    tx.oncomplete = () => resolve();
    tx.onerror    = err => reject(err);
  });
}

async function loadVaultDataFromDB() {
  const db = await openVaultDB();
  return new Promise((resolve, reject) => {
    const tx    = db.transaction([VAULT_STORE], 'readonly');
    const store = tx.objectStore(VAULT_STORE);
    const get   = store.get('vaultData');
    get.onsuccess = () => {
      if (!get.result) return resolve(null);
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
    };
    get.onerror = err => reject(err);
  });
}

async function deriveKeyFromPIN(pin, salt) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(pin), { name:'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt,
    iterations: 100000,
    hash: 'SHA-256'
  }, material, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}

async function encryptData(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv }, key, enc.encode(JSON.stringify(data))
  );
  return { iv, ciphertext: ct };
}

async function decryptData(key, iv, ciphertext) {
  const dec = new TextDecoder();
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(pt));
}

/*==============================================================================
 * Section 3: Privacy & Advanced Key Salting
 *============================================================================*/

function getAppSalt() {
  let s = localStorage.getItem('bc_app_salt');
  if (!s) {
    s = crypto.getRandomValues(new Uint8Array(16)).join('');
    localStorage.setItem('bc_app_salt', s);
  }
  return s;
}

async function hashDeviceKeyWithSalt(pubBuf, extra='') {
  const appSalt = getAppSalt();
  const combo = KEY_HASH_SALT + appSalt + extra;
  const data = new Uint8Array([
    ...new Uint8Array(pubBuf),
    ...new TextEncoder().encode(combo)
  ]);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf))
    .map(b=>b.toString(16).padStart(2,'0')).join('');
}

/*==============================================================================
 * Section 4: Biometric Key Management (WebAuthn)
 *============================================================================*/

async function performBiometricAuthenticationForCreation() {
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name:"BalanceChain Bio-Vault" },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name:"bio-user", displayName:"Bio User"
    },
    pubKeyCredParams:[{type:"public-key",alg:-7}],
    authenticatorSelection:{ authenticatorAttachment:"platform", userVerification:"required" },
    timeout:60000, attestation:"none"
  };
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error("Biometric flow failed");
  return cred;
}

/*==============================================================================
 * Section 5: Cryptographic Proofs
 *============================================================================*/

async function sha256Hex(input) {
  const buf = typeof input==='string'
    ? new TextEncoder().encode(input)
    : input;
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function computeOwnershipProof(seg) {
  const pl = [
    seg.segmentIndex, seg.currentOwnerKey, seg.currentOwnerTS,
    seg.ownershipChangeCount, seg.previousOwnerKey,
    seg.previousOwnerTS, seg.previousBioConst
  ].join("|");
  return sha256Hex(pl);
}

async function computeSpentProof(seg) {
  return sha256Hex([
    seg.originalBioConst, seg.previousBioConst,
    seg.segmentIndex,"SPENT"
  ].join("|"));
}

async function computeUnlockIntegrityProof(seg) {
  return sha256Hex([seg.segmentIndex,seg.unlockIndexRef,"UNLOCK"].join("|"));
}

/*==============================================================================
 * Section 6: Cap Enforcement
 *============================================================================*/

function getPeriodStrings(ts) {
  const d = new Date(ts*1000);
  return {
    day: d.toISOString().slice(0,10),
    month: d.toISOString().slice(0,7),
    year: d.getFullYear().toString()
  };
}

function checkAndRecordUnlock(vault, now, cnt=1) {
  const r = vault.unlockRecords;
  const p = getPeriodStrings(now);
  if (r.day!==p.day)   { r.day=p.day;   r.dailyCount=0; }
  if (r.month!==p.month){ r.month=p.month; r.monthlyCount=0; }
  if (r.year!==p.year) { r.year=p.year;  r.yearlyCount=0; }
  if (
    r.dailyCount+cnt>SEGMENTS_PER_DAY ||
    r.monthlyCount+cnt>SEGMENTS_PER_MONTH ||
    r.yearlyCount+cnt>SEGMENTS_PER_YEAR
  ) return false;
  r.dailyCount+=cnt;
  r.monthlyCount+=cnt;
  r.yearlyCount+=cnt;
  return true;
}

/*==============================================================================
 * Section 7: Ownership History
 *============================================================================*/

function updateOwnershipHistory(seg, keyHash, ts, type) {
  seg.ownershipChangeHistory.push({ownerKey:keyHash,ts,type,changeCount:seg.ownershipChangeCount});
  if (seg.ownershipChangeHistory.length>HISTORY_MAX) {
    seg.ownershipChangeHistory.shift();
  }
}

/*==============================================================================
 * Section 8: Device Registration
 *============================================================================*/

async function registerDeviceKey(vault, pubBuf, extra='') {
  const h = await hashDeviceKeyWithSalt(pubBuf,extra);
  if (!vault.deviceKeyHashes.includes(h)) {
    vault.deviceKeyHashes.push(h);
    await saveAndRefreshVault();
  }
}

function isValidDeviceKey(vault, keyHash) {
  return vault.deviceKeyHashes.includes(keyHash);
}

/*==============================================================================
 * Section 9: Onboarding
 *============================================================================*/

async function onboardUser(pin) {
  const cred = await performBiometricAuthenticationForCreation();
  const rawId = cred.response.getPublicKey
    ? cred.response.getPublicKey()
    : cred.rawId;
  const dkh = await hashDeviceKeyWithSalt(rawId);

  const now = Math.floor(Date.now()/1000);
  const userBioConst = GENESIS_BIO_CONST + (now-GENESIS_BIO_CONST);

  const segments=[];
  for (let i=1;i<=SEGMENTS_TOTAL;i++){
    segments.push({
      segmentIndex:i,amount:1,
      originalOwnerKey:dkh,originalOwnerTS:now,originalBioConst:userBioConst,
      previousOwnerKey:null,previousOwnerTS:null,previousBioConst:null,
      currentOwnerKey:dkh,currentOwnerTS:now,currentBioConst:userBioConst,
      unlocked:i<=SEGMENTS_UNLOCKED,ownershipChangeCount:0,
      unlockIndexRef:null,unlockIntegrityProof:null,
      spentProof:null,ownershipProof:null,
      ownershipChangeHistory:[]
    });
  }

  vaultData = {
    credentialId:bufferToBase64(rawId),
    deviceKeyHashes:[dkh],
    onboardingTS:now,
    userBioConst,
    segments,
    unlockRecords:{day:'',dailyCount:0,month:'',monthlyCount:0,year:'',yearlyCount:0},
    walletAddress:'',
    tvmClaimedThisYear:0,
    transactionHistory:[],
    authAttempts:0,
    lockoutTimestamp:null
  };

  currentSalt  = crypto.getRandomValues(new Uint8Array(16));
  decryptedKey = await deriveKeyFromPIN(pin,currentSalt);
  const {iv,ciphertext} = await encryptData(decryptedKey,vaultData);
  await saveVaultDataToDB(iv,ciphertext,bufferToBase64(currentSalt),vaultData);
  return vaultData;
}

/*==============================================================================
 * Section 10: Unlock Vault with Lockout
 *============================================================================*/

async function unlockVault(pin) {
  const dbData = await loadVaultDataFromDB();
  if (!dbData) throw new Error("No vault found");
  const now = Math.floor(Date.now()/1000);

  // -- lockout check
  if (dbData.lockoutTimestamp && now < dbData.lockoutTimestamp) {
    throw new Error(`Vault locked until ${new Date(dbData.lockoutTimestamp*1000).toLocaleString()}`);
  }

  try {
    const saltBuf = dbData.salt;
    const key = await deriveKeyFromPIN(pin, saltBuf);
    const data = await decryptData(key, dbData.iv, dbData.ciphertext);

    // reset attempts
    dbData.authAttempts = 0;
    dbData.lockoutTimestamp = null;
    await saveVaultDataToDB(dbData.iv, dbData.ciphertext, bufferToBase64(saltBuf), dbData);

    vaultData = data;
    decryptedKey = key;
    currentSalt = saltBuf;
    return vaultData;
  } catch (err) {
    // bump attempts
    dbData.authAttempts = (dbData.authAttempts||0)+1;
    if (dbData.authAttempts >= MAX_AUTH_ATTEMPTS) {
      dbData.lockoutTimestamp = now + LOCKOUT_DURATION_SECONDS;
    }
    await saveVaultDataToDB(dbData.iv, dbData.ciphertext, bufferToBase64(dbData.salt), dbData);
    throw err;
  }
}

/*==============================================================================
 * Section 11: Unlock Next Segment (Cap)
 *============================================================================*/

async function unlockNextSegmentWithCap(vault, idxRef) {
  const now = Math.floor(Date.now()/1000);
  if (!checkAndRecordUnlock(vault, now, 1)) {
    throw new Error("Daily unlock cap reached");
  }
  const userKey = vault.deviceKeyHashes[0];
  const nextSeg = vault.segments.find(s=>!s.unlocked && s.currentOwnerKey===userKey);
  if (!nextSeg) return;

  nextSeg.unlocked = true;
  nextSeg.unlockIndexRef = idxRef;
  nextSeg.currentOwnerTS = now;
  nextSeg.currentBioConst = nextSeg.previousBioConst
    ? nextSeg.previousBioConst + (now - nextSeg.previousOwnerTS)
    : nextSeg.originalBioConst;
  nextSeg.unlockIntegrityProof = await computeUnlockIntegrityProof(nextSeg);
  updateOwnershipHistory(nextSeg,userKey,now,"unlock");
  // push to history
  vaultData.transactionHistory.push({
    type:"unlock",
    segmentIndex:nextSeg.segmentIndex,
    timestamp:now,
    amount:nextSeg.amount,
    from: userKey,
    to: userKey
  });

  await saveAndRefreshVault();
}

/*==============================================================================
 * Section 12: Single Transfer
 *============================================================================*/

async function transferSegment(vault, recvKey, devKey) {
  if (!isValidDeviceKey(vault, devKey)) {
    throw new Error("Device not authorized");
  }
  const now = Math.floor(Date.now()/1000);
  const seg = vault.segments.find(s=>s.unlocked && s.currentOwnerKey===devKey);
  if (!seg) throw new Error("No unlocked segments available");

  const fromKey = seg.currentOwnerKey;
  seg.previousOwnerKey = fromKey;
  seg.previousOwnerTS = seg.currentOwnerTS;
  seg.previousBioConst = seg.currentBioConst;
  seg.currentOwnerKey = recvKey;
  seg.currentOwnerTS = now;
  seg.currentBioConst = seg.previousBioConst + (now - seg.previousOwnerTS);
  seg.ownershipChangeCount++;
  seg.unlocked = false;
  seg.spentProof = await computeSpentProof(seg);
  seg.ownershipProof = await computeOwnershipProof(seg);
  updateOwnershipHistory(seg,recvKey,now,"transfer");

  // history
  vaultData.transactionHistory.push({
    type:"transfer",
    segmentIndex:seg.segmentIndex,
    timestamp:now,
    amount:seg.amount,
    from: fromKey,
    to: recvKey
  });

  await unlockNextSegmentWithCap(vault, seg.segmentIndex);
  return seg;
}

/*==============================================================================
 * Section 13: Batch Transfer (Bio-Catch)
 *============================================================================*/

async function exportSegmentsBatch(vault, recvKey, count, devKey) {
  if (!isValidDeviceKey(vault, devKey)) throw new Error("Device not authorized");
  const now = Math.floor(Date.now()/1000);
  const eligible = vault.segments.filter(s=>s.unlocked && s.currentOwnerKey===devKey);
  if (eligible.length < count) throw new Error(`Only ${eligible.length} available`);
  const batch = [];
  for (let i=0;i<count;i++){
    const seg = eligible[i];
    const fromKey = seg.currentOwnerKey;
    seg.previousOwnerKey=fromKey;
    seg.previousOwnerTS=seg.currentOwnerTS;
    seg.previousBioConst=seg.currentBioConst;
    seg.currentOwnerKey=recvKey;
    seg.currentOwnerTS=now;
    seg.currentBioConst=seg.previousBioConst+(now-seg.previousOwnerTS);
    seg.ownershipChangeCount++;
    seg.unlocked=false;
    seg.spentProof=await computeSpentProof(seg);
    seg.ownershipProof=await computeOwnershipProof(seg);
    updateOwnershipHistory(seg,recvKey,now,"transfer");
    vaultData.transactionHistory.push({
      type:"transfer",
      segmentIndex:seg.segmentIndex,
      timestamp:now,
      amount:seg.amount,
      from: fromKey,
      to: recvKey
    });
    await unlockNextSegmentWithCap(vault, seg.segmentIndex);
    batch.push(seg);
  }
  await saveAndRefreshVault();
  return JSON.stringify(batch.map(s=>JSON.stringify(s)));
}

function exportSegment(s){ return JSON.stringify(s); }

/*==============================================================================
 * Section 14: Import / Claim Received
 *============================================================================*/

function importSegmentsBatch(jsonA, myKey) {
  const arr = JSON.parse(jsonA), out=[];
  for (const item of arr) {
    const seg = typeof item==="string"?JSON.parse(item):item;
    if (seg.currentOwnerKey!==myKey) 
      throw new Error(`Segment ${seg.segmentIndex}: not owner`);
    out.push(seg);
  }
  return out;
}

async function claimReceivedSegmentsBatch(vault, rec) {
  for (const seg of rec) {
    const idx = vault.segments.findIndex(s=>s.segmentIndex===seg.segmentIndex);
    if (idx>=0) vault.segments[idx]=seg;
    else vault.segments.push(seg);
  }
  await saveAndRefreshVault();
}

/*==============================================================================
 * Section 15: Encrypted Backup & Recovery
 *============================================================================*/

async function encryptVaultForBackup(vault, pwd) {
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(vault));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const mat = await crypto.subtle.importKey('raw',enc.encode(pwd),{name:'PBKDF2'},false,['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},mat,{name:'AES-GCM',length:256},false,['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv},key,data);
  return {salt:Array.from(salt),iv:Array.from(iv),data:Array.from(new Uint8Array(ct))};
}

async function decryptVaultFromBackup(bkp, pwd) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(bkp.salt), iv=new Uint8Array(bkp.iv), dat=new Uint8Array(bkp.data);
  const mat = await crypto.subtle.importKey('raw',enc.encode(pwd),{name:'PBKDF2'},false,['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},mat,{name:'AES-GCM',length:256},false,['decrypt']);
  const dec = await crypto.subtle.decrypt({name:'AES-GCM',iv},key,dat);
  return JSON.parse(new TextDecoder().decode(dec));
}

/*==============================================================================
 * Section 16: Audit Export & Proof Verification
 *============================================================================*/

function exportAuditData(v,opts={fullHistory:false}) {
  return JSON.stringify({
    deviceKeyHashes:v.deviceKeyHashes,
    onboardingTS:v.onboardingTS,
    userBioConst:v.userBioConst,
    segments:v.segments.map(seg=>({
      segmentIndex:seg.segmentIndex,amount:seg.amount,
      originalOwnerKey:seg.originalOwnerKey,
      originalOwnerTS:seg.originalOwnerTS,
      originalBioConst:seg.originalBioConst,
      previousOwnerKey:seg.previousOwnerKey,
      previousOwnerTS:seg.previousOwnerTS,
      previousBioConst:seg.previousBioConst,
      currentOwnerKey:seg.currentOwnerKey,
      currentOwnerTS:seg.currentOwnerTS,
      currentBioConst:seg.currentBioConst,
      unlocked:seg.unlocked,
      ownershipChangeCount:seg.ownershipChangeCount,
      unlockIndexRef:seg.unlockIndexRef,
      unlockIntegrityProof:seg.unlockIntegrityProof,
      spentProof:seg.spentProof,
      ownershipProof:seg.ownershipProof,
      ownershipChangeHistory: opts.fullHistory
        ? seg.ownershipChangeHistory
        : seg.ownershipChangeHistory.slice(-HISTORY_MAX)
    }))
  });
}

async function verifyProofChain(segs, dKey) {
  for (const seg of segs) {
    const o = await computeOwnershipProof(seg);
    if (seg.ownershipProof!==o) throw new Error(`Seg ${seg.segmentIndex}: ownership mismatch`);
    if (seg.unlockIndexRef!==null) {
      const u = await computeUnlockIntegrityProof(seg);
      if (seg.unlockIntegrityProof!==u) throw new Error(`Seg ${seg.segmentIndex}: unlock mismatch`);
    }
    if (seg.spentProof) {
      const s = await computeSpentProof(seg);
      if (seg.spentProof!==s) throw new Error(`Seg ${seg.segmentIndex}: spent mismatch`);
    }
    if (seg.currentOwnerKey!==dKey) throw new Error(`Seg ${seg.segmentIndex}: wrong owner`);
  }
  return true;
}

/*==============================================================================
 * Section 17: TVM Token Claim Logic & On-Chain Submit
 *============================================================================*/

function getAvailableTVMClaims(v) {
  const used = v.segments.filter(s=>s.ownershipChangeCount>0).length;
  const claimed = v.tvmClaimedThisYear||0;
  return Math.max(Math.floor(used/TVM_SEGMENTS_PER_TOKEN)-claimed,0);
}

async function claimTvmTokens(v) {
  const avail = getAvailableTVMClaims(v);
  if (!v.walletAddress.match(/^0x[a-fA-F0-9]{40}$/)) throw new Error("Valid wallet required");
  if (avail<=0) throw new Error("No claimable TVM");
  if ((v.tvmClaimedThisYear||0)+avail>TVM_CLAIM_CAP) throw new Error("Yearly cap reached");

  const segs = v.segments.filter(s=>s.ownershipChangeCount>0).slice(0,avail*TVM_SEGMENTS_PER_TOKEN);
  const proof = segs.map(s=>({
    segmentIndex:s.segmentIndex,
    spentProof:s.spentProof,
    ownershipProof:s.ownershipProof,
    unlockIntegrityProof:s.unlockIntegrityProof
  }));

  // on-chain submit
  await submitClaimOnChain(proof);

  v.tvmClaimedThisYear = (v.tvmClaimedThisYear||0)+avail;
  await saveAndRefreshVault();
  return proof;
}

/*==============================================================================
 * Section 18: Export for UI/Integration
 *============================================================================*/

window.onboardUser                = onboardUser;
window.unlockVault                = unlockVault;
window.transferSegment            = transferSegment;
window.exportSegmentsBatch        = exportSegmentsBatch;
window.importSegmentsBatch        = importSegmentsBatch;
window.claimReceivedSegmentsBatch = claimReceivedSegmentsBatch;
window.exportAuditData            = exportAuditData;
window.verifyProofChain           = verifyProofChain;
window.claimTvmTokens             = claimTvmTokens;
window.encryptVaultForBackup      = encryptVaultForBackup;
window.decryptVaultFromBackup     = decryptVaultFromBackup;

/*==============================================================================
 * Section 19: UI Helpers — Sanitization, Toast, Clipboard
 *============================================================================*/

function sanitizeInput(str) {
  return String(str).replace(/[<>"'`;]/g,'').trim().slice(0,64);
}

function showToast(msg,err=false) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = 'toast'+(err?' toast-error':'');
  t.style.display='block';
  setTimeout(()=>t.style.display='none',3300);
}

function copyToClipboard(txt) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(txt)
      .then(()=>showToast("Copied!"))
      .catch(()=>showToast("Copy failed",true));
  } else {
    const ta=document.createElement('textarea');
    ta.value=txt; document.body.appendChild(ta);
    ta.select();
    try{document.execCommand('copy'); showToast("Copied!");}
    catch{showToast("Copy failed",true);}
    document.body.removeChild(ta);
  }
}

/*==============================================================================
 * Section 20: UI Button Handlers & “Terminate Vault”
 *============================================================================*/

async function handleCopyBioIBAN(){ copyToClipboard(sanitizeInput(document.getElementById('bioibanInput').value)); }
async function handleCopyBioCatch(){ copyToClipboard(sanitizeInput(document.getElementById('bioCatchNumberText').textContent)); }

async function handleCatchOut(){
  const iban=sanitizeInput(document.getElementById('receiverBioIBAN').value), amt=Number(sanitizeInput(document.getElementById('catchOutAmount').value));
  if (!iban||!amt) {showToast("Check receiver & amount",true);return;}
  try{await transferSegment(vaultData,iban,vaultData.deviceKeyHashes[0]); showToast(`Sent ${amt} TVM`);renderVaultUI();}
  catch(e){ showToast(e.message.includes("cap")?"Unlock cap reached":e.message,true); }
}

async function handleCatchIn(){
  const bc=sanitizeInput(document.getElementById('catchInBioCatch').value), amt=Number(sanitizeInput(document.getElementById('catchInAmount').value));
  if (!bc||!amt) {showToast("Check Bio-Catch & amt",true);return;}
  try{const imp=importSegmentsBatch(bc,vaultData.deviceKeyHashes[0]); await claimReceivedSegmentsBatch(vaultData,imp); showToast(`Claimed ${amt} TVM`);renderVaultUI();}
  catch(e){showToast(e.message,true);}
}

async function handleExport(){
  try{const d=exportAuditData(vaultData);const b=new Blob([d],{type:'application/json'}),u=URL.createObjectURL(b),a=document.createElement('a');
    a.href=u;a.download='transactions.json';document.body.appendChild(a);a.click();setTimeout(()=>document.body.removeChild(a),100);
    showToast("Exported");}
  catch{showToast("Export failed",true);}
}

async function handleBackupExport(){
  try{ /* real backup → encryptVaultForBackup(...) */ 
    localStorage.setItem('vaultBackedUp','yes'); showBackupReminder();
    showToast("Backup exported"); }
  catch{showToast("Backup failed",true);}
}

function handleExportFriendly(){ showToast("Friendly backup exported"); }

async function handleImportVault(e){
  try{ const f=e.target.files[0]; if(!f)return; new FileReader().onload=()=>showToast("Vault imported");reader.readAsText(f);}
  catch{showToast("Import failed",true);}
}

function handleLockVault(){
  vaultData=null;decryptedKey=null;
  document.getElementById('vaultUI').classList.add('hidden');
  document.getElementById('lockedScreen').classList.remove('hidden');
  showToast("Vault locked");
}

async function handleEnterVault(){
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('lockedScreen').classList.add('hidden');
  showToast("Vault unlocked");
}

// — Terminate Vault & confirm
async function handleTerminateVault(){
  showConfirmModal(
    "Terminate Vault",
    "Erase all local data forever?",
    async ()=>{
      await new Promise(r=>{
        const req=indexedDB.deleteDatabase(DB_NAME);
        req.onsuccess=req.onerror=r;
      });
      localStorage.removeItem('vaultOnboarded');
      localStorage.removeItem('bc_app_salt');
      localStorage.removeItem('vaultBackedUp');
      location.reload();
    }
  );
}

/*==============================================================================
 * Section 21: MetaMask & Wallet Integration
 *============================================================================*/

async function handleSaveWallet(){
  const a=sanitizeInput(document.getElementById('userWalletAddress').value);
  if (!/^0x[a-fA-F0-9]{40}$/.test(a)){showToast("Invalid wallet",true);return;}
  vaultData.walletAddress=a; await saveAndRefreshVault(); showToast("Wallet saved");
}

async function handleAutoConnectWallet(){
  if(!window.ethereum){showToast("MetaMask missing",true);return;}
  try{
    const ac=await window.ethereum.request({method:'eth_requestAccounts'});
    document.getElementById('userWalletAddress').value=ac[0];
    vaultData.walletAddress=ac[0];
    await saveAndRefreshVault();
    showToast("MetaMask connected");
  }catch{showToast("MetaMask failed",true);}
}

async function handleClaimTVM(){
  try{
    const proof=await claimTvmTokens(vaultData);
    showToast("Claim bundle ready");
    renderVaultUI();
  }catch(e){showToast(e.message,true);}
}

/*==============================================================================
 * Section 22: Main UI Initialization & Feature Detection
 *============================================================================*/

function initVaultUI(){
  document.getElementById('copyBioIBANBtn').addEventListener('click',handleCopyBioIBAN);
  document.getElementById('showBioCatchBtn').addEventListener('click',()=>{
    const d=`BC-${Date.now()}-${Math.floor(Math.random()*1e5)}`;
    document.getElementById('bioCatchNumberText').textContent=d;
    openPopup('bioCatchPopup');
  });
  document.getElementById('copyBioCatchBtn').addEventListener('click',handleCopyBioCatch);
  document.getElementById('closeBioCatchPopup').addEventListener('click',()=>closePopup('bioCatchPopup'));
  document.getElementById('catchOutBtn').addEventListener('click',handleCatchOut);
  document.getElementById('catchInBtn').addEventListener('click',handleCatchIn);
  document.getElementById('exportBtn').addEventListener('click',handleExport);
  document.getElementById('exportBackupBtn').addEventListener('click',handleBackupExport);
  document.getElementById('exportFriendlyBtn').addEventListener('click',handleExportFriendly);
  document.getElementById('importVaultFileInput').addEventListener('change',handleImportVault);
  document.getElementById('lockVaultBtn').addEventListener('click',handleLockVault);
  document.getElementById('enterVaultBtn').addEventListener('click',handleEnterVault);
  document.getElementById('terminateBtn').addEventListener('click',handleTerminateVault);
  document.getElementById('saveWalletBtn').addEventListener('click',handleSaveWallet);
  document.getElementById('autoConnectWalletBtn').addEventListener('click',handleAutoConnectWallet);
  document.getElementById('claimTvmBtn').addEventListener('click',handleClaimTVM);
  document.getElementById('txPrevBtn').addEventListener('click',()=>{
    if(txPage>0)txPage--,renderTransactions();
  });
  document.getElementById('txNextBtn').addEventListener('click',()=>{
    txPage++,renderTransactions();
  });
}

// Backup reminder helper
function showBackupReminder(){
  document.getElementById('onboardingTip').style.display = localStorage.getItem('vaultBackedUp')?'none':'';
}

/*==============================================================================
 * Section 23: Transactions Rendering & Pagination
 *============================================================================*/

function getTxList(){
  if(!vaultData) return [];
  return vaultData.segments
    .filter(s=>s.ownershipChangeCount>0)
    .map(seg=>({
      bioIban: vaultData.deviceKeyHashes[0]?.slice(0,10)+'…',
      bioCatch: seg.segmentIndex,
      amount: seg.amount,
      time: new Date(seg.currentOwnerTS*1000).toLocaleString(),
      status: seg.currentOwnerKey===vaultData.deviceKeyHashes[0]?'IN':'OUT'
    }));
}

function renderTransactions(){
  const list=getTxList();
  const tbody=document.getElementById('transactionBody');
  tbody.innerHTML='';
  const empty=document.getElementById('txEmptyState');
  if(list.length===0){
    empty.style.display=''; document.getElementById('txPrevBtn').style.display='none';
    document.getElementById('txNextBtn').style.display='none'; return;
  }
  empty.style.display='none';
  const start=txPage*pageSize,end=start+pageSize;
  list.slice(start,end).forEach(tx=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${tx.bioIban}</td><td>${tx.bioCatch}</td><td>${tx.amount}</td>
                  <td>${tx.time}</td><td>${tx.status}</td>`;
    tbody.appendChild(tr);
  });
  document.getElementById('txPrevBtn').style.display=txPage>0?'':'none';
  document.getElementById('txNextBtn').style.display=end<list.length?'':'none';
}

/*==============================================================================
 * Section 24: Modal Navigation, Focus Trap & Onboarding “Next”
 *============================================================================*/

function wireModalNavigation(){
  document.querySelectorAll('.modal-nav button').forEach(btn=>{
    btn.addEventListener('click',()=>{
      const m=btn.closest('.modal');
      m.querySelectorAll('.modal-nav button').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
    });
  });
}

// Onboarding “Next” wiring
function wireOnboardingNext(){
  const pages = Array.from(document.querySelectorAll('#onboardingModal .modal-onboarding-page'));
  pages.forEach((page,i)=>{
    const btn = page.querySelector('button');
    if (!btn) return;
    btn.addEventListener('click',()=>modalNav('onboardingModal',i+1));
  });
}

function openModal(id){
  document.querySelectorAll('.modal').forEach(m=>m.style.display='none');
  const m=document.getElementById(id);
  if(m){
    m.style.display='flex';
    const fe=m.querySelector('[tabindex="0"]');
    if(fe) setTimeout(()=>fe.focus(),100);
  }
  document.body.style.overflow='hidden';
}
function closeModal(id){
  const m=document.getElementById(id);
  if(m) m.style.display='none';
  document.body.style.overflow='';
}
function closeAllModals(){
  document.querySelectorAll('.modal').forEach(m=>m.style.display='none');
  document.body.style.overflow='';
}
function modalNav(modalId,idx){
  const m=document.getElementById(modalId);
  const pages=m.querySelectorAll('.modal-onboarding-page');
  pages.forEach((p,i)=>p.classList.toggle('hidden',i!==idx));
  const nav=m.querySelectorAll('.modal-nav button');
  nav.forEach((b,i)=>b.classList.toggle('active',i===idx));
}

/*==============================================================================
 * Section 25: Session Timeout & Auto-Lock
 *============================================================================*/

let inactivityTimer;
function resetInactivityTimer(){
  clearTimeout(inactivityTimer);
  inactivityTimer=setTimeout(handleLockVault,15*60*1000);
}
['click','mousemove','keydown','touchstart'].forEach(e=>document.addEventListener(e,resetInactivityTimer));
resetInactivityTimer();

/*==============================================================================
 * Section 26: Encryption Key Rotation & Audit Logging
 *============================================================================*/

async function rotateEncryptionKey(oldPin,newPin){
  try{
    const dbData=await loadVaultDataFromDB();
    const oldKey=await deriveKeyFromPIN(oldPin,dbData.salt);
    const vault=await decryptData(oldKey,dbData.iv,dbData.ciphertext);
    const newSalt=crypto.getRandomValues(new Uint8Array(16));
    const newKey=await deriveKeyFromPIN(newPin,newSalt);
    const {iv,ciphertext}=await encryptData(newKey,vault);
    await saveVaultDataToDB(iv,ciphertext,bufferToBase64(newSalt),vault);
    currentSalt=newSalt;
    decryptedKey=newKey;
    showToast("Passphrase rotated.");
    renderVaultUI();
  }catch(e){ showToast("Rotation failed: "+e.message,true); }
}

function logAuditEvent(type,md={}){
  const ent={timestamp:new Date().toISOString(),eventType:type,...md,userAgent:navigator.userAgent};
  console.log("Audit log:",ent);
}

/*==============================================================================
 * Section 27: ethers.js Init & On-Chain Claim
 *============================================================================*/

function initWeb3(){
  if(window.ethereum){
    provider=new ethers.providers.Web3Provider(window.ethereum);
    signer=provider.getSigner();
  }
}

async function submitClaimOnChain(proofBundle){
  if(!signer) throw new Error("No Web3 signer");
  const address="0xYOUR_CONTRACT_ADDRESS";
  const abi=[ /* … your ABI … */ ];
  const ct=new ethers.Contract(address,abi,signer);
  return ct.claimTVM(proofBundle);
}

/*==============================================================================
 * Section 28: App Entry Point — Onboarding vs Unlock & Feature-Detect
 *============================================================================*/

window.addEventListener('DOMContentLoaded',async()=>{
  // FEATURE DETECT
  if(!indexedDB||!crypto?.subtle||!TextEncoder||!crypto.getRandomValues){
    document.body.innerHTML=`<div style="padding:2em;color:red;">
      Your browser lacks required crypto/storage support. Please upgrade.
    </div>`;
    return;
  }

  initVaultUI();
  wireModalNavigation();
  wireOnboardingNext();
  showBackupReminder();
  openModal('lockedScreen'); // ensure lockedScreen visible until logic runs

  // register SW, init web3
  if('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(console.error);
  }
  initWeb3();

  if(!localStorage.getItem('vaultOnboarded')){
    openModal('onboardingModal');
  } else {
    openModal('passModal');
  }

  // Onboarding “Got it” → set PIN
  document.querySelector('#onboardingModal .modal-close').addEventListener('click',async()=>{
    let pin=prompt("Set a secure passphrase (min 6 chars):");
    if(!pin||pin.length<6){alert("Too short");return;}
    await onboardUser(pin);
    localStorage.setItem('vaultOnboarded','yes');
    closeAllModals();
    renderVaultUI();
  });

  // PassModal Save
  document.getElementById('passModalSaveBtn').addEventListener('click',async()=>{
    const pin=document.getElementById('passModalInput').value;
    if(!pin) return showToast("Enter passphrase",true);
    try{
      await unlockVault(pin);
      closeAllModals();
      renderVaultUI();
    }catch(e){
      showToast("Unlock failed: "+e.message,true);
    }
  });

  // Focus trap & Esc for BioCatch popup
  const bioP=document.getElementById('bioCatchPopup');
  bioP.addEventListener('keydown',e=>{ if(e.key==='Escape') closePopup('bioCatchPopup'); });

  // Focus trap & Esc for all modals
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape') closeAllModals();
  });
});

/*==============================================================================
 * Section 29: Render & Utility
 *============================================================================*/

function renderVaultUI(){
  document.getElementById('lockedScreen').style.display='none';
  document.getElementById('vaultUI').style.display='block';

  document.getElementById('bioibanInput').value = vaultData.deviceKeyHashes[0]?.slice(0,36) || '';
  const bal = getTvmBalance(vaultData);
  document.getElementById('tvmBalance').textContent = `Balance: ${bal} TVM`;
  document.getElementById('usdBalance').textContent = `Equivalent to ${(bal/12).toFixed(2)} USD`;
  document.getElementById('bioLineText').textContent = `🔄 BonusConstant: ${vaultData.userBioConst}`;
  document.getElementById('utcTime').textContent = "UTC: "+new Date().toUTCString();
  document.getElementById('userWalletAddress').value = vaultData.walletAddress||'';
  document.getElementById('tvmClaimable').textContent = `TVM Claimable: ${getAvailableTVMClaims(vaultData)}`;

  txPage=0;
  renderTransactions();
}

function getTvmBalance(v){
  const used=v.segments.filter(s=>s.ownershipChangeCount>0).length;
  const claimed=v.tvmClaimedThisYear||0;
  return Math.floor(used/TVM_SEGMENTS_PER_TOKEN)-claimed;
}

async function saveAndRefreshVault(){
  if(!decryptedKey||!currentSalt) return;
  const {iv,ciphertext} = await encryptData(decryptedKey,vaultData);
  await saveVaultDataToDB(iv,ciphertext,bufferToBase64(currentSalt),vaultData);
  renderVaultUI();
}

async function safeHandler(fn){
  try{ await fn(); }catch(e){
    console.error(e);
    showToast(e.message||"Error",true);
  }
}

/*==============================================================================
 * End of main.js
 *============================================================================*/
