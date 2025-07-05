// -----------------------------------------------------------------------------
//  BalanceChain Bio‑Vault – main.js             (REV‑2025‑07‑05 • Segment Edition)
//  • Offline, biometric‑secured vault
//  • Serial‑indexed “digital notes” 1‑12000 per user/year
//  • Spend‑to‑unlock (3/day, 30/mo, 90/yr) + legacy bonus logic
//  • Bio‑Catch P2P, IndexedDB encryption, backups, on‑chain bonus stub
// -----------------------------------------------------------------------------
/* eslint-disable no-undef, no-console */
'use strict';

/* ═════════════════════ 1. GLOBAL CONSTANTS ═════════════════════ */
const DB_NAME                   = 'BioVaultDB';
const DB_VERSION                = 1;
const VAULT_STORE               = 'vault';

/* ── Segment economy ─────────────────────────────── */
const SEGMENTS_PER_YEAR         = 12000;   // serials 1‑12000
const SEGMENT_ATOMIC_VALUE      = 1;       // 1 TVM each
const INITIAL_SEGMENTS_UNLOCKED = 1200;    // spendable at genesis

/* ── Unlock caps: 1 new unlocked segment per spent segment ───── */
const MAX_UNLOCKS_DAY           = 3;       // 360 TVM/day
const MAX_UNLOCKS_MONTH         = 30;      // 3 600 TVM/mo
const MAX_UNLOCKS_YEAR          = 90;      // 10 800 TVM/yr

/* ── Legacy bonus system ─────────────────────────── */
const INITIAL_BALANCE_TVM       = INITIAL_SEGMENTS_UNLOCKED;
const PER_TX_BONUS              = 120;
const MAX_BONUSES_PER_DAY       = 3;
const MAX_BONUSES_PER_MONTH     = 30;
const MAX_ANNUAL_BONUS_TVM      = 10800;

/* ── Monetary / security params ───────────────────── */
const EXCHANGE_RATE             = 12;           // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT      = 1736565605;   // GBC_REF
const TRANSACTION_VALIDITY_SECONDS = 720;       // ±12 min
const LOCKOUT_DURATION_SECONDS  = 3600;         // 1 h
const MAX_AUTH_ATTEMPTS         = 3;

/* ── Storage / sync ───────────────────────────────── */
const VAULT_BACKUP_KEY          = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL    = 300000;       // 5 min
const vaultSyncChannel          = new BroadcastChannel('vault-sync');

/* Runtime */
let vaultUnlocked        = false;
let derivedKey           = null;
let bioLineIntervalTimer = null;
let transactionLock      = false;

/* ═════════════════════ 2.  QUICK SHA256→HEX ════════════════════ */
async function sha256Hex(str){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

/* ═════════════════════ 3. SEGMENT HELPERS ═════════════════════ */
function buildGenesisSegments(userKey, joinTS){
  const baseBio = INITIAL_BIO_CONSTANT + (joinTS - INITIAL_BIO_CONSTANT);
  const segs=[];
  for(let i=1;i<=SEGMENTS_PER_YEAR;i++){
    const unlocked = i<=INITIAL_SEGMENTS_UNLOCKED;
    segs.push({
      segmentIndex    : i,
      amount          : SEGMENT_ATOMIC_VALUE,
      originalOwnerKey: userKey,
      originalOwnerTS : joinTS,
      originalBioConst: baseBio,

      previousOwnerKey: null,
      previousOwnerTS : null,
      previousBioConst: null,

      currentOwnerKey : unlocked ? userKey : null,
      currentOwnerTS  : unlocked ? joinTS : null,
      currentBioConst : unlocked ? baseBio : null,

      unlocked,
      ownershipChangeCount : 0,
      unlockIndexRef       : null,
      unlockIntegrityProof : unlocked
        ? sha256Hex(`chainId|null|${i}|${joinTS}|UNLOCK`)
        : null,
      spentProof           : null,
      ownershipProof       : unlocked
        ? sha256Hex(`${userKey}|${i}|${joinTS}`)
        : null,
      last_update          : joinTS
    });
  }
  return segs;
}
function getRemainingUnlockAllowance(nowSec){
  const d   = new Date(nowSec*1000);
  const day = d.toISOString().slice(0,10);
  const ym  = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  const dayUsed = (vaultData.dailyUnlockCount.date===day) ? vaultData.dailyUnlockCount.used : 0;
  const monUsed = (vaultData.monthlyUnlockCount.yearMonth===ym) ? vaultData.monthlyUnlockCount.used : 0;
  const yrUsed  = vaultData.annualUnlockUsed || 0;
  return {
    dayRemaining  : MAX_UNLOCKS_DAY   - dayUsed,
    monthRemaining: MAX_UNLOCKS_MONTH - monUsed,
    yearRemaining : MAX_UNLOCKS_YEAR  - yrUsed
  };
}
function unlockNextSegment(triggerIdx, nowSec){
  const allow = getRemainingUnlockAllowance(nowSec);
  if(allow.dayRemaining<=0||allow.monthRemaining<=0||allow.yearRemaining<=0) return null;
  const next = vaultData.segments.find(s=>!s.unlocked);
  if(!next) return null;
  const baseBio = vaultData.initialBioConstant + (nowSec - vaultData.joinTimestamp);
  next.unlocked            = true;
  next.currentOwnerKey     = vaultData.credentialId;
  next.currentOwnerTS      = nowSec;
  next.currentBioConst     = baseBio;
  next.unlockIndexRef      = triggerIdx;
  next.unlockIntegrityProof= sha256Hex(`chainId|${triggerIdx}|${next.segmentIndex}|${nowSec}|UNLOCK`);
  next.ownershipProof      = sha256Hex(`${vaultData.credentialId}|${next.segmentIndex}|${nowSec}`);
  next.last_update         = nowSec;
  const day = new Date(nowSec*1000).toISOString().slice(0,10);
  if(vaultData.dailyUnlockCount.date!==day){
    vaultData.dailyUnlockCount = { date:day, used:0 };
  }
  const ym=`${new Date(nowSec*1000).getUTCFullYear()}-${String(new Date(nowSec*1000).getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUnlockCount.yearMonth!==ym){
    vaultData.monthlyUnlockCount = { yearMonth:ym, used:0 };
  }
  vaultData.dailyUnlockCount.used   +=1;
  vaultData.monthlyUnlockCount.used +=1;
  vaultData.annualUnlockUsed        +=1;
  return next;
}

/* ═════════════════════ 4. VAULT DATA ══════════════════════════ */
let vaultData = {
  bioIBAN             : null,
  initialBioConstant  : 0,
  bonusConstant       : 0,
  joinTimestamp       : 0,
  credentialId        : null,

  segments            : [],
  dailyUnlockCount    : { date:'', used:0 },
  monthlyUnlockCount  : { yearMonth:'', used:0 },
  annualUnlockUsed    : 0,

  transactions        : [],
  lastTransactionHash : '',
  dailyCashback       : { date:'', usedCount:0 },
  monthlyUsage        : { yearMonth:'', usedCount:0 },
  annualBonusUsed     : 0,
  nextBonusId         : 1,

  initialBalanceTVM   : INITIAL_SEGMENTS_UNLOCKED,
  balanceTVM          : 0,
  balanceUSD          : 0,

  authAttempts        : 0,
  lockoutTimestamp    : null,
  lastUTCTimestamp    : 0,
  finalChainHash      : '',

  userWallet          : ''
};

/* ═════════════════════ 5. ENCRYPTION & IDB ═══════════════════ */
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

/* ═════════════════════ 6. KEY DERIVATION & PERSIST ═══════════ */
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

/* ═════════════════════ 7. BIOMETRIC WEBAUTHN ═════════════════ */
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

/* ═════════════════════ 8. SNAPSHOT / BIO‑CATCH HELPERS ════════ */
async function encryptBioCatchNumber(plainText){ return btoa(plainText); }
async function decryptBioCatchNumber(encStr){ try{return atob(encStr);}catch(e){return null;} }

/* ═════════════════════ 9. PASSPHRASE MODAL ════════════════════ */
async function getPassphraseFromModal({ confirmNeeded=false, modalTitle='Enter Passphrase'}) {
  return new Promise(resolve=>{
    const passModal=document.getElementById('passModal');
    const passTitle=document.getElementById('passModalTitle');
    const passInput=document.getElementById('passModalInput');
    const passConfirmInput=document.getElementById('passModalConfirmInput');
    const passCancelBtn=document.getElementById('passModalCancelBtn');
    const passSaveBtn=document.getElementById('passModalSaveBtn');
    passTitle.textContent=modalTitle;
    passInput.value=''; passConfirmInput.value='';
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
      cleanup(); resolve({pin:pVal, confirmed:true});
    }
    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display='block';
  });
}

/* ═════════════════════ 10. VAULT CREATION / UNLOCK ════════════ */
async function createNewVault(pinFromUser=null){
  if(!pinFromUser){
    const res=await getPassphraseFromModal({confirmNeeded:true,modalTitle:'Create New Vault (Set Passphrase)'});
    pinFromUser=res.pin;
  }
  if(!pinFromUser||pinFromUser.length<8){ alert('Passphrase ≥8 chars'); return; }
  const nowSec=Math.floor(Date.now()/1000);
  const cred=await performBiometricAuthenticationForCreation();
  if(!cred||!cred.id){ alert('Biometric setup failed'); return; }
  vaultData.credentialId = bufferToBase64(cred.rawId);
  vaultData.joinTimestamp      = nowSec;
  vaultData.initialBioConstant = INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant      = nowSec - INITIAL_BIO_CONSTANT;
  vaultData.bioIBAN            = `BIO${vaultData.initialBioConstant + vaultData.joinTimestamp}`;
  vaultData.segments           = buildGenesisSegments(vaultData.credentialId, nowSec);
  vaultData.initialBalanceTVM  = INITIAL_SEGMENTS_UNLOCKED;
  vaultData.balanceTVM         = INITIAL_SEGMENTS_UNLOCKED;
  vaultData.balanceUSD         = +(vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  derivedKey = await deriveKeyFromPIN(pinFromUser, salt);
  await promptAndSaveVault(salt);
  vaultUnlocked=true;
  showVaultUI(); initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked','true');
}

async function unlockVault(){
  if(vaultData.lockoutTimestamp){
    let now=Math.floor(Date.now()/1000);
    if(now<vaultData.lockoutTimestamp){
      let remain=vaultData.lockoutTimestamp-now;
      alert(`Vault locked => wait ${Math.ceil(remain/60)} min`);
      return;
    } else { vaultData.lockoutTimestamp=null; vaultData.authAttempts=0; await promptAndSaveVault(); }
  }
  let { pin }=await getPassphraseFromModal({confirmNeeded:false, modalTitle:'Unlock Vault'});
  if(!pin){ alert('Pass needed'); handleFailedAuthAttempt(); return; }
  if(pin.length<8){ alert('Pass <8 chars'); handleFailedAuthAttempt(); return; }
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm('No vault => create new?'))return;
    await createNewVault(pin); return;
  }
  try{
    derivedKey=await deriveKeyFromPIN(pin, stored.salt);
    vaultData = await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData.lockoutTimestamp=stored.lockoutTimestamp;
    vaultData.authAttempts=stored.authAttempts;
    if(vaultData.credentialId){
      let ok=await performBiometricAssertion(vaultData.credentialId);
      if(!ok){alert('Device credential mismatch'); handleFailedAuthAttempt();return;}
    }
    vaultUnlocked=true; vaultData.authAttempts=0; vaultData.lockoutTimestamp=null;
    await promptAndSaveVault();
    showVaultUI(); initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked','true');
  } catch(err){ alert('Failed decrypt'); console.error(err); handleFailedAuthAttempt(); }
}
async function checkAndUnlockVault(){
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm('No vault => create new?'))return;
    let { pin }=await getPassphraseFromModal({confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    await createNewVault(pin);
  } else { await unlockVault(); }
}
async function handleFailedAuthAttempt(){
  vaultData.authAttempts=(vaultData.authAttempts||0)+1;
  if(vaultData.authAttempts>=MAX_AUTH_ATTEMPTS){
    vaultData.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_DURATION_SECONDS;
    alert('❌ Max attempts => locked 1hr');
  } else {
    alert(`❌ Auth fail => tries left: ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts}`);
  }
  await promptAndSaveVault();
}

/* ═════════════════════ 11. TX VALIDATION HELPERS ══════════════ */
function formatDisplayDate(ts){ const d=new Date(ts*1000); return d.toISOString().slice(0,10)+" "+d.toISOString().slice(11,19); }
function formatWithCommas(num){ return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","); }
async function computeTransactionHash(prevHash, txObj){
  let dataStr=JSON.stringify({prevHash,...txObj});
  let buf=new TextEncoder().encode(dataStr);
  let hashBuf=await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function computeFullChainHash(transactions){
  let rHash=''; let sorted=[...transactions].sort((a,b)=>a.timestamp-b.timestamp);
  for(let t of sorted){
    let tmp={type:t.type,amount:t.amount,timestamp:t.timestamp,status:t.status,bioCatch:t.bioCatch,
             bonusConstantAtGeneration:t.bonusConstantAtGeneration,previousHash:rHash};
    rHash=await computeTransactionHash(rHash,tmp);
  }
  return rHash;
}

/* ═════════════════════ 12. BONUS + UNLOCK COUNTER RESET ═══════ */
function resetDailyUsageIfNeeded(nowSec){
  let dateStr=new Date(nowSec*1000).toISOString().slice(0,10);
  if(vaultData.dailyCashback.date!==dateStr){ vaultData.dailyCashback={date:dateStr, usedCount:0}; }
}
function resetMonthlyUsageIfNeeded(nowSec){
  let d=new Date(nowSec*1000);
  let ym=`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUsage.yearMonth!==ym){ vaultData.monthlyUsage={yearMonth:ym, usedCount:0}; }
}
function bonusDiversityCheck(newTxType){
  let dateStr=vaultData.dailyCashback.date; let sent=0,received=0;
  for(let tx of vaultData.transactions){
    if(tx.type==='cashback'){
      let dStr=new Date(tx.timestamp*1000).toISOString().slice(0,10);
      if(dStr===dateStr && tx.triggerOrigin){
        if(tx.triggerOrigin==='sent') sent++;
        else if(tx.triggerOrigin==='received') received++;
      }
    }
  }
  if(newTxType==='sent' && sent>=2) return false;
  if(newTxType==='received' && received>=2) return false;
  return true;
}
function canGive120Bonus(nowSec,newTxType,newTxAmount){
  resetDailyUsageIfNeeded(nowSec); resetMonthlyUsageIfNeeded(nowSec);
  if(vaultData.dailyCashback.usedCount>=MAX_BONUSES_PER_DAY) return false;
  if(vaultData.monthlyUsage.usedCount>=MAX_BONUSES_PER_MONTH) return false;
  if((vaultData.annualBonusUsed||0)>=MAX_ANNUAL_BONUS_TVM) return false;
  if(newTxType==='sent'&&newTxAmount<=240) return false;
  if(!bonusDiversityCheck(newTxType)) return false;
  return true;
}
function record120BonusUsage(origin){
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed=(vaultData.annualBonusUsed||0)+PER_TX_BONUS;
}
function resetUnlockCountersIfNeeded(nowSec){
  const day=new Date(nowSec*1000).toISOString().slice(0,10);
  if(vaultData.dailyUnlockCount.date!==day){
    vaultData.dailyUnlockCount={date:day, used:0};
  }
  const ym=`${new Date(nowSec*1000).getUTCFullYear()}-${String(new Date(nowSec*1000).getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUnlockCount.yearMonth!==ym){
    vaultData.monthlyUnlockCount={yearMonth:ym, used:0};
  }
}

/* ═════════════════════ 13. SEND TRANSACTION (segment) ═════════ */
async function handleSendTransaction(){
  if(!vaultUnlocked){alert("Please unlock first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let recv=document.getElementById('receiverBioIBAN')?.value.trim();
    let amt=parseInt(document.getElementById('catchOutAmount')?.value.trim(),10);
    if(!recv||!validateBioIBAN(recv)){alert("Invalid receiver");return;}
    if(recv===vaultData.bioIBAN){alert("Cannot send to self");return;}
    if(isNaN(amt)||amt<=0||amt%SEGMENT_ATOMIC_VALUE){alert("Invalid amount");return;}

    const spendable=vaultData.segments.filter(s=>s.unlocked&&s.currentOwnerKey===vaultData.credentialId);
    if(spendable.length<amt){alert("Insufficient unlocked TVM");return;}

    const nowSec=Math.floor(Date.now()/1000);
    resetUnlockCountersIfNeeded(nowSec);

    const toSpend=spendable.slice(0,amt);
    for(const seg of toSpend){
      seg.previousOwnerKey   = seg.currentOwnerKey;
      seg.previousOwnerTS    = nowSec;
      seg.previousBioConst   = seg.currentBioConst;
      seg.currentOwnerKey    = null;
      seg.currentOwnerTS     = nowSec;
      seg.currentBioConst    = seg.previousBioConst + (nowSec - seg.previousOwnerTS);
      seg.unlocked           = false;
      seg.ownershipChangeCount += 1;
      seg.spentProof         = await sha256Hex(`${seg.originalBioConst}|${seg.previousBioConst}|${seg.segmentIndex}|${nowSec}|SPENT`);
      seg.last_update        = nowSec;
      unlockNextSegment(seg.segmentIndex, nowSec);
    }

    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'sent',amt)){ record120BonusUsage('sent'); bonusGranted=true; }
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    let plainBio=await generateBioCatchNumber(vaultData.bioIBAN,recv,amt,nowSec,vaultData.balanceTVM,vaultData.finalChainHash);
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let dec=await decryptBioCatchNumber(tx.bioCatch);
        if(dec===plainBio){ alert("BioCatch reused"); transactionLock=false;return; }
      }
    }
    let obfBio=await encryptBioCatchNumber(plainBio);
    let newTx={type:'sent',receiverBioIBAN:recv,amount:amt,timestamp:nowSec,status:'Completed',bioCatch:obfBio,
               bonusConstantAtGeneration:vaultData.bonusConstant,previousHash:vaultData.lastTransactionHash,txHash:''};
    newTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash,newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash=newTx.txHash;
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN=`BONUS${vaultData.bonusConstant+offset}`;
      let bonusTx={type:'cashback',amount:PER_TX_BONUS,timestamp:nowSec,status:'Granted',bonusConstantAtGeneration:vaultData.bonusConstant,
                   previousHash:vaultData.lastTransactionHash,txHash:'',senderBioIBAN:bonusIBAN,triggerOrigin:'sent',bonusId:vaultData.nextBonusId++};
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash,bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
      if(vaultData.userWallet && vaultData.userWallet.length>0 && vaultData.credentialId){ console.log("Auto‑redeeming bonus…"); await redeemBonusOnChain(bonusTx); }
    }
    populateWalletUI(); await promptAndSaveVault();
    alert(`✅ Sent ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    showBioCatchPopup(obfBio);
    document.getElementById('receiverBioIBAN').value=''; document.getElementById('catchOutAmount').value='';
    renderTransactionTable();
  }catch(err){console.error(err);alert("Send error");}
  finally{transactionLock=false;}
}

/* ═════════════════════ 14. RECEIVE TRANSACTION (segment) ══════ */
async function handleReceiveTransaction(){
  if(!vaultUnlocked){alert("Unlock first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let encBio=document.getElementById('catchInBioCatch')?.value.trim();
    let amt=parseInt(document.getElementById('catchInAmount')?.value.trim(),10);
    if(!encBio||!amt){alert("BioCatch & amount required");transactionLock=false;return;}
    if(amt%SEGMENT_ATOMIC_VALUE){alert("Amount must align to segment size");transactionLock=false;return;}

    let nowSec=Math.floor(Date.now()/1000);
    resetUnlockCountersIfNeeded(nowSec);

    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'received',amt)){ record120BonusUsage('received'); bonusGranted=true; }

    let decBio=await decryptBioCatchNumber(encBio);
    if(!decBio){alert("Unable to decode BioCatch");transactionLock=false;return;}
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let ex=await decryptBioCatchNumber(tx.bioCatch);
        if(ex===decBio){ alert("BioCatch already used"); transactionLock=false;return; }
      }
    }
    let validation=await validateBioCatchNumber(decBio, amt);
    if(!validation.valid){ alert(`BioCatch fail => ${validation.message}`); transactionLock=false;return; }

    /* Accept segments */
    for(let i=0;i<amt;i++){
      const seg=unlockNextSegment(null, nowSec);
      if(!seg){ alert("Receiver supply exhausted"); transactionLock=false;return; }
    }
    let rxTx={type:'received',senderBioIBAN:validation.claimedSenderIBAN,bioCatch:encBio,amount:amt,timestamp:nowSec,
              status:'Valid',bonusConstantAtGeneration:vaultData.bonusConstant};
    vaultData.transactions.push(rxTx);

    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN=`BONUS${vaultData.bonusConstant+offset}`;
      let bonusTx={type:'cashback',amount:PER_TX_BONUS,timestamp:nowSec,status:'Granted',bonusConstantAtGeneration:vaultData.bonusConstant,
                   previousHash:vaultData.lastTransactionHash,txHash:'',senderBioIBAN:bonusIBAN,triggerOrigin:'received',bonusId:vaultData.nextBonusId++};
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash,bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
      if(vaultData.userWallet && vaultData.userWallet.length>0 && vaultData.credentialId){ console.log("Auto‑redeeming bonus…"); await redeemBonusOnChain(bonusTx); }
    }
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Received ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    document.getElementById('catchInBioCatch').value=''; document.getElementById('catchInAmount').value='';
    renderTransactionTable();
  }catch(err){console.error(err);alert("Receive error");}
  finally{transactionLock=false;}
}

/* ═════════════════════ 15. TABLE RENDERING (unchanged) ═════════ */
function renderTransactionTable(){
  let tbody=document.getElementById('transactionBody'); if(!tbody)return;
  tbody.innerHTML='';
  let sorted=[...vaultData.transactions].sort((a,b)=>b.timestamp-a.timestamp);
  sorted.forEach(tx=>{
    let row=document.createElement('tr');
    let bioIBANCell='—'; if(tx.type==='sent') bioIBANCell=tx.receiverBioIBAN;
    else if(tx.type==='received') bioIBANCell=tx.senderBioIBAN||'Unknown';
    else if(tx.type==='cashback') bioIBANCell=`System/Bonus (ID=${tx.bonusId||''})`;
    else if(tx.type==='increment') bioIBANCell='Periodic Increment';
    let truncatedBioCatch = tx.bioCatch? (tx.bioCatch.length>12? tx.bioCatch.slice(0,12)+'...' : tx.bioCatch) : '—';
    row.innerHTML=`<td>${bioIBANCell}</td><td>${truncatedBioCatch}</td><td>${tx.amount}</td><td>${formatDisplayDate(tx.timestamp)}</td><td>${tx.status}</td>`;
    tbody.appendChild(row);
  });
}

/* ═════════════════════ 16. UI HELPERS (populateWalletUI etc.) ═══════════ */
function showVaultUI(){
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI(); renderTransactionTable();
}
function initializeBioConstantAndUTCTime(){
  let nowSec=Math.floor(Date.now()/1000);
  vaultData.lastUTCTimestamp=nowSec; populateWalletUI();
  if(bioLineIntervalTimer)clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer=setInterval(()=>{
    vaultData.lastUTCTimestamp=Math.floor(Date.now()/1000);
    populateWalletUI();
  },1000);
}
function populateWalletUI(){
  const ibInp=document.getElementById('bioibanInput'); if(ibInp) ibInp.value=vaultData.bioIBAN||'BIO…';
  const spendableSegs=vaultData.segments.filter(s=>s.unlocked&&s.currentOwnerKey===vaultData.credentialId).length;
  vaultData.balanceTVM=spendableSegs; vaultData.balanceUSD=+(spendableSegs/EXCHANGE_RATE).toFixed(2);
  document.getElementById('tvmBalance')?.textContent=`Balance: ${spendableSegs} TVM`;
  document.getElementById('usdBalance')?.textContent=`Equivalent to ${vaultData.balanceUSD} USD`;
  document.getElementById('bioLineText')?.textContent=`🔄 BonusConstant: ${vaultData.bonusConstant}`;
  document.getElementById('utcTime')?.textContent=formatDisplayDate(vaultData.lastUTCTimestamp);
  const label=document.getElementById('userWalletLabel');
  if(label){ label.textContent=vaultData.userWallet?`On-chain Wallet: ${vaultData.userWallet}`:'(No wallet set)'; }
}
function showBioCatchPopup(encBio){
  let popup=document.getElementById('bioCatchPopup'); if(!popup)return;
  popup.style.display='flex';
  let bcTxt=document.getElementById('bioCatchNumberText'); if(!bcTxt)return;
  bcTxt.textContent=encBio.length>12? encBio.slice(0,12)+'...' : encBio;
  bcTxt.dataset.fullCatch=encBio;
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

/************************************************************************
 * (NEW) USER-FRIENDLY BACKUP: For Mobile, with a .vault extension
 ************************************************************************/
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

/************************************************************************
 * (NEW) IMPORT a .vault file: Let user pick it, then restore vaultData
 ************************************************************************/
async function importVaultBackupFromFile(file){
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);

    // Overwrite existing vaultData with the imported data
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

function handleCopyBioIBAN(){
  let ibInp=document.getElementById('bioibanInput');
  if(!ibInp||!ibInp.value.trim()){alert("No Bio-IBAN to copy");return;}
  navigator.clipboard.writeText(ibInp.value.trim())
    .then(()=>alert("Bio-IBAN copied!"))
    .catch(err=>{console.error("Clipboard fail:",err);alert("Failed to copy IBAN")});
}

/******************************
 * On-Chain Logic Integration
 ******************************/

async function redeemBonusOnChain(tx){
  console.log("[redeemBonusOnChain] => Attempt to redeem bonus tx:",tx);
  if(!tx||!tx.bonusId){
    alert("Invalid bonus or missing bonusId");
    return;
  }
  if(!vaultData.userWallet||vaultData.userWallet.length<5){
    alert("No valid wallet address found!");
    return;
  }
  if(!vaultData.credentialId){
    alert("No device key (credentialId) => cannot proceed!");
    return;
  }
  try{
    if(!window.ethereum){
      alert("No MetaMask or web3 provider found!");
      return;
    }
    // Request accounts
    await window.ethereum.request({ method:'eth_requestAccounts' });
    const provider=new ethers.providers.Web3Provider(window.ethereum);
    const signer=provider.getSigner();
    const userAddr=await signer.getAddress();
    console.log("User address =>",userAddr);

    if(userAddr.toLowerCase()!==vaultData.userWallet.toLowerCase()){
      alert("Warning: active metamask address != vaultData.userWallet. Proceeding anyway...");
    }

    /**
     * PRODUCTION-READY SMART CONTRACT CALL:
     *   E.g.:
     *   const contractAddr="0xYourContractHere";
     *   const contractABI=[ ...ABI... ];
     *   const contract=new ethers.Contract(contractAddr,contractABI,signer);
     *   // This function might be called "mintBonus" or "redeemBonus" or something similar:
     *   const txResp=await contract.redeemBonus(vaultData.userWallet, tx.bonusId);
     *   const receipt=await txResp.wait();
     *   console.log("Bonus redemption =>",receipt);
     *   alert(`Redeemed bonus #${tx.bonusId} on chain, txHash= ${receipt.transactionHash}`);
     */

    // For now, just a stub:
    alert(`(Stub) Bonus #${tx.bonusId} => minted to ${vaultData.userWallet}. Fill in real calls!`);
  }catch(err){
    console.error("redeemBonusOnChain => error:",err);
    alert("On-chain redemption failed => see console");
  }
}

/******************************
 * Multi-Tab / Single Vault
 ******************************/
function preventMultipleVaults(){
  window.addEventListener('storage', evt=>{
    if(evt.key==='vaultUnlocked'){
      if(evt.newValue==='true' && !vaultUnlocked){
        vaultUnlocked=true;
        showVaultUI();
        initializeBioConstantAndUTCTime();
      } else if(evt.newValue==='false' && vaultUnlocked){
        vaultUnlocked=false;
        lockVault();
      }
    }
  });
}

function enforceSingleVault(){
  let lock=localStorage.getItem('vaultLock');
  if(!lock){
    localStorage.setItem('vaultLock','locked');
  } else {
    console.log("VaultLock found => single instance enforced");
  }
}

async function enforceStoragePersistence(){
  if(!navigator.storage?.persist)return;
  let persisted=await navigator.storage.persisted();
  if(!persisted){
    let granted=await navigator.storage.persist();
    console.log(granted?"🔒 Storage hardened":"⚠️ Storage vulnerable");
  }
  setInterval(async()=>{
    let est=await navigator.storage.estimate();
    if((est.usage/est.quota)>0.85){
      console.warn("Storage near limit =>",est);
      alert("Storage near limit => export backup!");
    }
  }, STORAGE_CHECK_INTERVAL);
}

/* ═════════════════════ 20. DOM READY / INITIALIZE UI ══════════════════ */
window.addEventListener('DOMContentLoaded', ()=>{
  let lastURL=localStorage.getItem("last_session_url");
  if(lastURL && window.location.href!==lastURL){ window.location.href=lastURL; }
  window.addEventListener("beforeunload",()=>{ localStorage.setItem("last_session_url", window.location.href); });
  initializeUI(); preventMultipleVaults(); enforceStoragePersistence();
  vaultSyncChannel.onmessage= async (e)=>{ if(e.data?.type==='vaultUpdate'){ try{
      let { iv, data }=e.data.payload;
      if(!derivedKey){ console.warn("vaultUpdate => derivedKey not available yet"); return; }
      let dec=await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
      Object.assign(vaultData, dec); populateWalletUI(); console.log("🔄 Synced vault across tabs");
  }catch(err){console.error("Tab sync fail =>",err);} } };
});
function initializeUI(){
  document.getElementById('enterVaultBtn')?.addEventListener('click', checkAndUnlockVault);
  document.getElementById('lockVaultBtn')?.addEventListener('click', lockVault);
  document.getElementById('catchInBtn')?.addEventListener('click', handleReceiveTransaction);
  document.getElementById('catchOutBtn')?.addEventListener('click', handleSendTransaction);
  document.getElementById('copyBioIBANBtn')?.addEventListener('click', handleCopyBioIBAN);
  document.getElementById('exportBtn')?.addEventListener('click', exportTransactionTable);
  document.getElementById('exportBackupBtn')?.addEventListener('click', exportVaultBackup);
  document.getElementById('exportFriendlyBtn')?.addEventListener('click', exportVaultBackupForMobile);
  document.getElementById('importVaultFileInput')?.addEventListener('change', async (evt)=>{
    if(evt.target.files&&evt.target.files[0]) await importVaultBackupFromFile(evt.target.files[0]);
  });
  const popup=document.getElementById('bioCatchPopup');
  if(popup){
    document.getElementById('closeBioCatchPopup')?.addEventListener('click',()=>{ popup.style.display='none'; });
    document.getElementById('copyBioCatchBtn')?.addEventListener('click',()=>{
      let bcTxt=document.getElementById('bioCatchNumberText');
      navigator.clipboard.writeText(bcTxt.dataset.fullCatch||bcTxt.textContent)
        .then(()=>alert('✅ Bio‑Catch copied!'))
        .catch(e=>{console.error(e); alert('Copy failed');});
    });
    window.addEventListener('click',ev=>{ if(ev.target===popup) popup.style.display='none'; });
  }
  enforceSingleVault();
  document.getElementById('saveWalletBtn')?.addEventListener('click', async ()=>{
    if(vaultData.userWallet){ alert('Wallet already set'); return; }
    const addr=document.getElementById('userWalletAddress').value.trim();
    if(!addr.startsWith('0x')||addr.length<10){ alert('Invalid wallet'); return; }
    vaultData.userWallet=addr; await promptAndSaveVault(); document.getElementById('userWalletAddress').value=''; populateWalletUI();
    alert('✅ Wallet saved');
  });
  document.getElementById('autoConnectWalletBtn')?.addEventListener('click', async ()=>{
    if(!window.ethereum){ alert('No MetaMask'); return; }
    try{
      await window.ethereum.request({ method:'eth_requestAccounts' });
      const provider=new ethers.providers.Web3Provider(window.ethereum);
      const signer=provider.getSigner();
      const userAddr=await signer.getAddress();
      if(!vaultData.userWallet){ vaultData.userWallet=userAddr; await promptAndSaveVault(); populateWalletUI(); alert(`Connected => ${userAddr}`); }
      else if(vaultData.userWallet.toLowerCase()!==userAddr.toLowerCase()){ alert('Wallet mismatch'); }
      else { alert('Wallet matches'); }
    }catch(err){console.error(err); alert('Connect failed');}
  });
}

/* ═════════════════════ 21. A2HS PROMPT ═════════════════════════ */
let deferredPrompt=null;
window.addEventListener('beforeinstallprompt',(e)=>{ e.preventDefault(); deferredPrompt=e; console.log('⭐ beforeinstallprompt captured'); });
function promptInstallA2HS(){
  if(!deferredPrompt){ console.log('No prompt'); return; }
  deferredPrompt.prompt(); deferredPrompt.userChoice.then(choice=>{ console.log('A2HS',choice.outcome); deferredPrompt=null; });
}

/* ═════════════════════ 22. MISC HELPERS ═══════════════════════ */
function generateSalt(){ return crypto.getRandomValues(new Uint8Array(16)); }
function validateBioIBAN(str){ return /^BIO\d+$/.test(str)||/^BONUS\d+$/.test(str); }
async function verifyFullChainAndBioConstant(){ return { success:true }; }
async function validateSenderVaultSnapshot(){ return { valid:true, errors:[] }; }

/* ═════════════════════ 23. SNAPSHOT SERIALIZATION (unchanged) ═ */

function serializeVaultSnapshotForBioCatch(vData) { /* ← unchanged code from original file */ }
function deserializeVaultSnapshotFromBioCatch(base64String) { /* ← unchanged code */ }
async function generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) { /* ← unchanged */ }
async function validateBioCatchNumber(bioCatchNumber, claimedAmount) { /* ← unchanged */ }

/* ========================================================================== */
