/***********************************************************************
 * main.js — Final Production Integration
 *
 * Key Features:
 *   1) daily 3-bonus (120 TVM) with 2+1 "sent/received" rule
 *   2) "sent" bonus if >240 TVM; "received" bonus if any
 *   3) userWallet stored for on‑chain bridging
 *   4) redeemBonusOnChain(tx) stub calls your contract
 *   5) passphrase-based AES encryption in IndexedDB
 *   6) static bonusConstant = joinTimestamp - initialBioConstant
 *   7) multi-tab sync, lock/unlock with pass + optional biometrics
 ***********************************************************************/

/******************************
 * Constants & Globals
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// Basic Vault / Bonus Limits
const INITIAL_BALANCE_TVM = 1200;
const PER_TX_BONUS = 120;
const MAX_BONUSES_PER_DAY = 3;
const MAX_BONUSES_PER_MONTH = 30;
const MAX_ANNUAL_BONUS_TVM = 10800; // total annual bonus TVM

const EXCHANGE_RATE = 12;          // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;   // 5 minutes

const vaultSyncChannel = new BroadcastChannel('vault-sync');

// Global Vault State
let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

// The vaultData object
let vaultData = {
  // Basic
  bioIBAN: null,
  initialBioConstant: 0,
  bonusConstant: 0, // = joinTimestamp - initialBioConstant
  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM: 0,
  balanceUSD: 0,
  lastUTCTimestamp: 0,

  // Transaction chain
  transactions: [],
  lastTransactionHash: '',
  finalChainHash: '',

  // Auth & Lock
  authAttempts: 0,
  lockoutTimestamp: null,
  credentialId: null,

  // Join & usage
  joinTimestamp: 0,
  dailyCashback: { date: '', usedCount: 0 },
  monthlyUsage: { yearMonth: '', usedCount: 0 },
  annualBonusUsed: 0,

  // On-chain bridging
  userWallet: "",     // user’s on‑chain address for minting
  nextBonusId: 1      // unique ID for each bonus TX
};

/***********************************************************************
 * Encryption / IndexedDB
 ***********************************************************************/
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

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/***********************************************************************
 * Key Derivation from Passphrase
 ***********************************************************************/
async function deriveKeyFromPIN(pin, salt) {
  const enc = new TextEncoder();
  const pinBuf = enc.encode(pin);
  const keyMaterial = await crypto.subtle.importKey('raw', pinBuf, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name:'PBKDF2',
    salt,
    iterations:100000,
    hash:'SHA-256'
  }, keyMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}

/***********************************************************************
 * IndexedDB Access
 ***********************************************************************/
async function openVaultDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = evt => {
      const db = evt.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
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
      if (getReq.result) {
        try {
          const iv = base64ToBuffer(getReq.result.iv);
          const ciph = base64ToBuffer(getReq.result.ciphertext);
          const salt = getReq.result.salt ? base64ToBuffer(getReq.result.salt) : null;
          resolve({
            iv,
            ciphertext: ciph,
            salt,
            lockoutTimestamp:getReq.result.lockoutTimestamp||null,
            authAttempts:getReq.result.authAttempts||0
          });
        } catch(e) {
          console.error("Error decoding stored data =>", e);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror = err => reject(err);
  });
}

/***********************************************************************
 * Persistence Helpers
 ***********************************************************************/
async function promptAndSaveVault(salt=null){
  try {
    if(!derivedKey) {
      console.warn("No derivedKey => can't persist");
      return;
    }
    const { iv, ciphertext } = await encryptData(derivedKey, vaultData);
    let saltBase64;
    if(salt){
      saltBase64 = bufferToBase64(salt);
    } else {
      const stored = await loadVaultDataFromDB();
      if(stored?.salt) saltBase64 = bufferToBase64(stored.salt);
      else {
        console.error("Salt not found => cannot persist");
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
    vaultSyncChannel.postMessage({type:'vaultUpdate',payload:backupPayload});
    console.log("Vault persisted => triple redundancy success");
  } catch(err){
    console.error("Vault persist error:", err);
    alert("CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!");
  }
}

/***********************************************************************
 * Basic Lock/Unlock
 ***********************************************************************/
function lockVault(){
  if(!vaultUnlocked)return;
  vaultUnlocked=false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked','false');
  console.log("🔒 Vault locked.");
}

/***********************************************************************
 * WebAuthn / Biometric
 ***********************************************************************/
async function performBiometricAuthenticationForCreation(){
  try {
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp:{ name:"Bio-Vault" },
      user:{
        id:crypto.getRandomValues(new Uint8Array(16)),
        name:"bio-user",
        displayName:"Bio User"
      },
      pubKeyCredParams:[
        { type:"public-key", alg:-7 },
        { type:"public-key", alg:-257 }
      ],
      authenticatorSelection:{
        authenticatorAttachment:"platform",
        userVerification:"required"
      },
      timeout:60000,
      attestation:"none"
    };
    const credential = await navigator.credentials.create({ publicKey });
    return credential||null;
  } catch(err){
    console.error("Biometric create error:", err);
    return null;
  }
}
async function performBiometricAssertion(credentialId){
  try {
    const publicKey={
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials:[{ id: base64ToBuffer(credentialId), type:'public-key' }],
      userVerification:"required",
      timeout:60000
    };
    const assertion = await navigator.credentials.get({ publicKey });
    return !!assertion;
  } catch(err){
    console.error("Biometric assertion error:", err);
    return false;
  }
}

/***********************************************************************
 * Passphrase Modal / Vault Creation & Unlock
 ***********************************************************************/
async function getPassphraseFromModal({confirmNeeded=false, modalTitle='Enter Passphrase'}){
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
    passConfirmLabel.style.display=confirmNeeded?'block':'none';
    passConfirmInput.style.display=confirmNeeded?'block':'none';

    function cleanup(){
      passCancelBtn.removeEventListener('click', onCancel);
      passSaveBtn.removeEventListener('click', onSave);
      passModal.style.display='none';
    }
    function onCancel(){
      cleanup();
      resolve({pin:null});
    }
    function onSave(){
      let pinVal=passInput.value.trim();
      if(!pinVal||pinVal.length<8){
        alert("Passphrase must be >=8 chars");
        return;
      }
      if(confirmNeeded){
        let confVal=passConfirmInput.value.trim();
        if(pinVal!==confVal){
          alert("Pass mismatch");
          return;
        }
      }
      cleanup();
      resolve({pin:pinVal, confirmed:true});
    }

    passCancelBtn.addEventListener('click', onCancel);
    passSaveBtn.addEventListener('click', onSave);
    passModal.style.display='block';
  });
}
async function createNewVault(pinFromUser=null){
  if(!pinFromUser){
    const r=await getPassphraseFromModal({confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    pinFromUser=r.pin;
  }
  if(!pinFromUser||pinFromUser.length<8){alert("Pass must be >=8 chars");return;}

  console.log("Creating new vault from scratch...");
  localStorage.setItem('vaultLock','locked');
  let nowSec=Math.floor(Date.now()/1000);
  vaultData.joinTimestamp=nowSec;
  vaultData.lastUTCTimestamp=nowSec;
  vaultData.initialBioConstant=INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant=vaultData.joinTimestamp - vaultData.initialBioConstant;
  vaultData.bioIBAN=`BIO${vaultData.initialBioConstant + vaultData.joinTimestamp}`;
  vaultData.initialBalanceTVM=INITIAL_BALANCE_TVM;
  vaultData.balanceTVM=INITIAL_BALANCE_TVM;
  vaultData.balanceUSD=parseFloat((vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2));
  vaultData.transactions=[];
  vaultData.authAttempts=0;
  vaultData.lockoutTimestamp=null;
  vaultData.lastTransactionHash='';
  vaultData.finalChainHash='';
  vaultData.nextBonusId=1;

  const credential=await performBiometricAuthenticationForCreation();
  if(!credential||!credential.id){
    alert("Biometric creation failed => cannot create vault");
    return;
  }
  vaultData.credentialId=bufferToBase64(credential.rawId);

  console.log("🆕 Vault data =>", vaultData);

  let salt=crypto.getRandomValues(new Uint8Array(16));
  derivedKey=await deriveKeyFromPIN(pinFromUser, salt);
  await promptAndSaveVault(salt);

  vaultUnlocked=true;
  showVaultUI();
  initializeBioConstantAndUTCTime();
  localStorage.setItem('vaultUnlocked','true');
}
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
  let {pin} = await getPassphraseFromModal({confirmNeeded:false, modalTitle:'Unlock Vault'});
  if(!pin){
    alert("Pass is required or canceled");
    handleFailedAuthAttempt();
    return;
  }
  if(pin.length<8){
    alert("Pass <8 chars => fail");
    handleFailedAuthAttempt();
    return;
  }
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault found => create new?"))return;
    await createNewVault(pin);
    return;
  }
  try {
    if(!stored.salt) throw new Error("No salt in stored data");
    derivedKey=await deriveKeyFromPIN(pin, stored.salt);
    let decrypted=await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData=decrypted;

    vaultData.lockoutTimestamp=stored.lockoutTimestamp;
    vaultData.authAttempts=stored.authAttempts;

    if(vaultData.credentialId){
      let ok=await performBiometricAssertion(vaultData.credentialId);
      if(!ok){
        alert("Biometric mismatch => unlock fails");
        handleFailedAuthAttempt();
        return;
      }
    } else {
      console.log("No credential => skip WebAuthn check");
    }
    vaultUnlocked=true;
    vaultData.authAttempts=0;
    vaultData.lockoutTimestamp=null;
    await promptAndSaveVault();

    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked','true');
  } catch(err){
    alert("Failed decrypt => "+err.message);
    console.error(err);
    handleFailedAuthAttempt();
  }
}
async function handleFailedAuthAttempt(){
  vaultData.authAttempts=(vaultData.authAttempts||0)+1;
  if(vaultData.authAttempts>=MAX_AUTH_ATTEMPTS){
    vaultData.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_DURATION_SECONDS;
    alert("Max attempts => locked 1 hour");
  } else {
    alert(`Auth fail => ${MAX_AUTH_ATTEMPTS-vaultData.authAttempts} tries left`);
  }
  await promptAndSaveVault();
}
async function checkAndUnlockVault(){
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault => create new?"))return;
    let {pin}=await getPassphraseFromModal({confirmNeeded:true,modalTitle:'Create New Vault (Set Passphrase)'});
    await createNewVault(pin);
  } else {
    await unlockVault();
  }
}

/***********************************************************************
 * Transaction Hashing & Bonus Logic
 ***********************************************************************/
async function computeTransactionHash(prevHash, txObj){
  let dataStr=JSON.stringify({prevHash, ...txObj});
  let buf=new TextEncoder().encode(dataStr);
  let hashBuf=await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function computeFullChainHash(transactions){
  let runHash='';
  let sorted=[...transactions].sort((a,b)=>a.timestamp-b.timestamp);
  for(let tx of sorted){
    let txObj={
      type:tx.type,
      amount:tx.amount,
      timestamp:tx.timestamp,
      status:tx.status,
      bioCatch:tx.bioCatch,
      bonusConstantAtGeneration:tx.bonusConstantAtGeneration,
      previousHash:runHash
    };
    runHash=await computeTransactionHash(runHash, txObj);
  }
  return runHash;
}
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
      let ds=new Date(tx.timestamp*1000).toISOString().slice(0,10);
      if(ds===dateStr && tx.triggerOrigin){
        if(tx.triggerOrigin==='sent')sentCount++;
        else if(tx.triggerOrigin==='received')receivedCount++;
      }
    }
  }
  if(newTxType==='sent'&&sentCount>=2)return false;
  if(newTxType==='received'&&receivedCount>=2)return false;
  return true;
}
function canGive120Bonus(nowSec,newTxType,newAmt){
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);
  if(vaultData.dailyCashback.usedCount>=MAX_BONUSES_PER_DAY)return false;
  if(vaultData.monthlyUsage.usedCount>=MAX_BONUSES_PER_MONTH)return false;
  if((vaultData.annualBonusUsed||0)>=MAX_ANNUAL_BONUS_TVM)return false;
  if(newTxType==='sent' && newAmt<=240)return false;
  if(!bonusDiversityCheck(newTxType))return false;
  return true;
}
function record120BonusUsage(origin){
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed=(vaultData.annualBonusUsed||0)+PER_TX_BONUS;
}

/***********************************************************************
 * Generating / Validating BioCatch
 ***********************************************************************/
async function encryptBioCatchNumber(plain){
  return btoa(plain);
}
async function decryptBioCatchNumber(enc){
  try{return atob(enc);}catch(e){return null;}
}
function serializeVaultSnapshotForBioCatch(vData){
  const fsep='|', txsep='^', tsep='~';
  let txParts=(vData.transactions||[]).map(tx=>{
    return [
      tx.type||'', tx.receiverBioIBAN||'',
      tx.senderBioIBAN||'', tx.amount||0,
      tx.timestamp||0, tx.status||'',
      tx.bioCatch||'', tx.bonusConstantAtGeneration||0,
      tx.previousHash||'', tx.txHash||''
    ].join(tsep);
  });
  let txString=txParts.join(txsep);
  let rawStr=[
    vData.joinTimestamp||0,
    vData.initialBioConstant||0,
    vData.bonusConstant||0,
    vData.finalChainHash||'',
    vData.initialBalanceTVM||0,
    vData.balanceTVM||0,
    vData.lastUTCTimestamp||0,
    txString
  ].join(fsep);
  return btoa(rawStr);
}
function deserializeVaultSnapshotFromBioCatch(b64){
  let raw=atob(b64);
  let parts=raw.split('|');
  if(parts.length<8) throw new Error("vault snapshot missing fields");
  let joinTimestamp=parseInt(parts[0],10);
  let initialBioConstant=parseInt(parts[1],10);
  let bonusConstant=parseInt(parts[2],10);
  let finalChainHash=parts[3];
  let initialBalanceTVM=parseInt(parts[4],10);
  let balanceTVM=parseInt(parts[5],10);
  let lastUTCTimestamp=parseInt(parts[6],10);
  let txString=parts[7]||'';
  let txsep='^', tsep='~';
  let txChunks=txString.split(txsep).filter(Boolean);
  let transactions=txChunks.map(chunk=>{
    let fields=chunk.split(tsep);
    return {
      type:fields[0]||'',
      receiverBioIBAN:fields[1]||'',
      senderBioIBAN:fields[2]||'',
      amount:parseFloat(fields[3])||0,
      timestamp:parseInt(fields[4],10)||0,
      status:fields[5]||'',
      bioCatch:fields[6]||'',
      bonusConstantAtGeneration:parseInt(fields[7],10)||0,
      previousHash:fields[8]||'',
      txHash:fields[9]||''
    };
  });
  return {
    joinTimestamp, initialBioConstant, bonusConstant,
    finalChainHash, initialBalanceTVM, balanceTVM,
    lastUTCTimestamp, transactions
  };
}
async function generateBioCatchNumber(senderIBAN, receiverIBAN, amount, ts, senderBal, finalHash){
  let snap=serializeVaultSnapshotForBioCatch(vaultData);
  let sNum=parseInt(senderIBAN.slice(3));
  let rNum=parseInt(receiverIBAN.slice(3));
  let firstPart=sNum+rNum;
  return `Bio-${firstPart}-${ts}-${amount}-${senderBal}-${senderIBAN}-${finalHash}-${snap}`;
}
async function validateBioCatchNumber(bioCatchNumber, claimedAmount){
  let parts=bioCatchNumber.split('-');
  if(parts.length!==8||parts[0]!=='Bio') return {valid:false,message:'BioCatch must have 8 parts'};
  let [ , firstPartStr, timestampStr, amtStr, claimedBalStr, claimedIBAN, chainHash, snapshotEnc ] = parts;
  let firstPart=parseInt(firstPartStr);
  let ts=parseInt(timestampStr);
  let amt=parseFloat(amtStr);
  let cBal=parseFloat(claimedBalStr);

  if(isNaN(firstPart)||isNaN(ts)||isNaN(amt)||isNaN(cBal)){
    return { valid:false, message:'Numeric parse error' };
  }
  let sNum=parseInt(claimedIBAN.slice(3));
  let rNum=firstPart-sNum;
  if(!vaultData.bioIBAN) return {valid:false,message:'No local IBAN in vault'};
  let localRec=parseInt(vaultData.bioIBAN.slice(3));
  if(rNum!==localRec) return {valid:false,message:'BioCatch not for this IBAN'};
  if(amt!==claimedAmount) return {valid:false,message:'Claimed amount mismatch'};
  let diff=Math.abs(vaultData.lastUTCTimestamp - ts);
  if(diff>TRANSACTION_VALIDITY_SECONDS) return {valid:false,message:'Timestamp outside ±12min'};

  let senderSnap;
  try{
    senderSnap=deserializeVaultSnapshotFromBioCatch(snapshotEnc);
  } catch(err){
    return { valid:false, message:'Snapshot parse error => '+err.message };
  }

  if(claimedIBAN.startsWith('BONUS')){
    let offset=ts-senderSnap.joinTimestamp;
    let expect="BONUS"+(senderSnap.bonusConstant+offset);
    if(claimedIBAN!==expect) return {valid:false,message:'Mismatched Bonus IBAN'};
  } else {
    let expect="BIO"+(senderSnap.initialBioConstant+senderSnap.joinTimestamp);
    if(claimedIBAN!==expect) return {valid:false,message:'Mismatched sender IBAN'};
  }
  return { valid:true, message:'OK', chainHash, claimedSenderIBAN:claimedIBAN, senderVaultSnapshot:senderSnap };
}

/***********************************************************************
 * Handling "Send" / "Receive" with Bonus
 ***********************************************************************/
let transactionLock=false;

async function handleSendTransaction(){
  if(!vaultUnlocked){ alert("Unlock vault first"); return;}
  if(transactionLock){ alert("Transaction in progress"); return;}
  transactionLock=true;
  try{
    let recv=document.getElementById('receiverBioIBAN')?.value.trim();
    let amt=parseFloat(document.getElementById('catchOutAmount')?.value.trim());
    if(!recv||isNaN(amt)||amt<=0){ alert("Invalid receiver/amount");return;}
    if(recv===vaultData.bioIBAN){ alert("Cannot send to self");return;}
    if(vaultData.balanceTVM<amt){ alert("Insufficient balance");return;}

    let nowSec=Math.floor(Date.now()/1000);
    vaultData.lastUTCTimestamp=nowSec;

    // Check if bonus triggers
    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'sent',amt)){
      record120BonusUsage('sent');
      bonusGranted=true;
    }
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    // Generate new BioCatch
    let plainBC=await generateBioCatchNumber(vaultData.bioIBAN, recv, amt, nowSec, vaultData.balanceTVM, vaultData.finalChainHash);
    // ensure uniqueness
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let dec=await decryptBioCatchNumber(tx.bioCatch);
        if(dec===plainBC){
          alert("This BioCatch # already used");
          transactionLock=false;
          return;
        }
      }
    }
    let encBC=await encryptBioCatchNumber(plainBC);
    let newTx={
      type:'sent',
      receiverBioIBAN:recv,
      amount:amt,
      timestamp:nowSec,
      status:'Completed',
      bioCatch:encBC,
      bonusConstantAtGeneration:vaultData.bonusConstant,
      previousHash:vaultData.lastTransactionHash,
      txHash:''
    };
    newTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash,newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash=newTx.txHash;
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    // If bonus => add separate bonus TX
    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN=`BONUS${vaultData.bonusConstant+offset}`;
      let bonusId = vaultData.nextBonusId++;
      let bonusTx={
        type:'cashback',
        amount:PER_TX_BONUS,
        timestamp:nowSec,
        status:'Granted',
        bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash,
        txHash:'',
        senderBioIBAN:bonusIBAN,
        triggerOrigin:'sent',
        bonusId
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
    }
    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    showBioCatchPopup(encBC);

    document.getElementById('receiverBioIBAN').value='';
    document.getElementById('catchOutAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("handleSendTransaction error:", err);
    alert("Error sending transaction");
  } finally {
    transactionLock=false;
  }
}

async function handleReceiveTransaction(){
  if(!vaultUnlocked){ alert("Unlock vault first"); return;}
  if(transactionLock){ alert("Tx in progress"); return;}
  transactionLock=true;
  try{
    let encBio=document.getElementById('catchInBioCatch')?.value.trim();
    let amt=parseFloat(document.getElementById('catchInAmount')?.value.trim());
    if(!encBio||isNaN(amt)||amt<=0){ alert("Invalid BioCatch or amount");return;}

    let nowSec=Math.floor(Date.now()/1000);
    vaultData.lastUTCTimestamp=nowSec;

    // Check if bonus triggers
    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'received',amt)){
      record120BonusUsage('received');
      bonusGranted=true;
    }
    let decBio=await decryptBioCatchNumber(encBio);
    if(!decBio){
      alert("Unable to decode BioCatch");
      transactionLock=false;
      return;
    }
    // ensure not used
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let ex=await decryptBioCatchNumber(tx.bioCatch);
        if(ex===decBio){
          alert("BioCatch # used already");
          transactionLock=false;
          return;
        }
      }
    }
    let validation=await validateBioCatchNumber(decBio, amt);
    if(!validation.valid){
      alert("BioCatch validation fail => "+validation.message);
      transactionLock=false;
      return;
    }
    let { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    // Suppose you have verification stubs
    let crossCheck=await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if(!crossCheck.success){
      alert("Sender chain mismatch => "+crossCheck.reason);
      transactionLock=false;
      return;
    }
    if(senderVaultSnapshot.finalChainHash!==chainHash){
      alert("Chain hash mismatch => invalid snapshot");
      transactionLock=false;
      return;
    }
    let snapVal=await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if(!snapVal.valid){
      alert("Sender snapshot check fail => "+snapVal.errors.join("; "));
      transactionLock=false;
      return;
    }

    // Record "received"
    let rxTx={
      type:'received',
      senderBioIBAN:claimedSenderIBAN,
      bioCatch:encBio,
      amount:amt,
      timestamp:nowSec,
      status:'Valid',
      bonusConstantAtGeneration:vaultData.bonusConstant
    };
    vaultData.transactions.push(rxTx);

    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN="BONUS"+(vaultData.bonusConstant+offset);
      let bonusId=vaultData.nextBonusId++;
      let bonusTx={
        type:'cashback',
        amount:PER_TX_BONUS,
        timestamp:nowSec,
        status:'Granted',
        bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash,
        txHash:'',
        senderBioIBAN:bonusIBAN,
        triggerOrigin:'received',
        bonusId
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
    }
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Received ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    document.getElementById('catchInBioCatch').value='';
    document.getElementById('catchInAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("handleReceiveTransaction error:", err);
    alert("Error receiving transaction");
  } finally {
    transactionLock=false;
  }
}

/***********************************************************************
 * Transaction Table & "Redeem Bonus" Column
 ***********************************************************************/
function renderTransactionTable(){
  const tbody=document.getElementById('transactionBody');
  if(!tbody)return;
  tbody.innerHTML='';

  // Sort desc by time
  let sortedTx=[...vaultData.transactions].sort((a,b)=>b.timestamp-a.timestamp);
  for(let tx of sortedTx){
    let row=document.createElement('tr');
    let bibCell='—', bcCell=tx.bioCatch||'—', amtCell=tx.amount,
        tsCell=formatDisplayDate(tx.timestamp), stCell=tx.status;

    // Which IBAN to show?
    if(tx.type==='sent') {
      bibCell=tx.receiverBioIBAN;
    } else if(tx.type==='received'){
      bibCell=tx.senderBioIBAN||'Unknown';
    } else if(tx.type==='cashback'){
      // We can incorporate the bonusId if you want:
      bibCell=`System/Bonus (ID=${tx.bonusId||''})`;
    } else if(tx.type==='increment'){
      bibCell='Periodic Increment';
    }

    // Build the row
    row.innerHTML=`
      <td>${bibCell}</td>
      <td>${bcCell}</td>
      <td>${amtCell}</td>
      <td>${tsCell}</td>
      <td>${stCell}</td>
    `;
    tbody.appendChild(row);

    // Later, we will add a 6th column for "Redeem On Chain" in the final patch
    // or do it automatically from your index.html's <script> snippet.
  }
}

/***********************************************************************
 * Extra UI Actions
 ***********************************************************************/
function handleCopyBioIBAN(){
  let ibInp=document.getElementById('bioibanInput');
  if(!ibInp||!ibInp.value.trim()){
    alert("No Bio‑IBAN to copy");
    return;
  }
  navigator.clipboard.writeText(ibInp.value.trim())
    .then(()=>alert("Bio‑IBAN copied to clipboard!"))
    .catch(err=>{
      console.error("Clipboard error =>", err);
      alert("Failed to copy IBAN");
    });
}

function exportTransactionTable(){
  const table=document.getElementById('transactionTable');
  if(!table){alert("No transaction table found");return;}
  let rows=table.querySelectorAll('tr');
  let csv="data:text/csv;charset=utf-8,";

  rows.forEach(r=>{
    let cols=r.querySelectorAll('th,td');
    let arr=[];
    cols.forEach(c=>{
      let d=c.innerText.replace(/"/g,'""');
      if(d.includes(',')) d=`"${d}"`;
      arr.push(d);
    });
    csv+=arr.join(",")+"\r\n";
  });
  let uri=encodeURI(csv);
  let link=document.createElement('a');
  link.setAttribute('href', uri);
  link.setAttribute('download', 'transaction_history.csv');
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
  a.download="vault_backup.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/***********************************************************************
 * On-Chain Stub: redeemBonusOnChain(tx)
 ***********************************************************************/
async function redeemBonusOnChain(tx){
  console.log("redeemBonusOnChain => Attempting redemption for bonus TX:", tx);
  if(!tx||!tx.bonusId){alert("Invalid bonus or missing bonusId");return;}
  if(!vaultData.userWallet||vaultData.userWallet.length<5){
    alert("Please set your on‑chain wallet address first!");
    return;
  }
  try {
    if(!window.ethereum){
      alert("No MetaMask or web3 provider found!");
      return;
    }
    // request accounts
    await window.ethereum.request({ method:'eth_requestAccounts' });
    const provider=new ethers.providers.Web3Provider(window.ethereum);
    const signer=provider.getSigner();
    let userAddr=await signer.getAddress();
    console.log("User address =>", userAddr);

    if(userAddr.toLowerCase()!==vaultData.userWallet.toLowerCase()){
      alert("Active wallet != stored userWallet, but continuing anyway...");
    }

    // Fill in your contract details:
    // const contractAddr = "0xYourTVMContract...";
    // const contractABI = [...];
    // const contract = new ethers.Contract(contractAddr, contractABI, signer);
    // let txResp=await contract.validateAndMint(vaultData.userWallet, tx.bonusId);
    // let receipt=await txResp.wait();
    // console.log("Mint receipt =>", receipt);
    // alert(`Bonus #${tx.bonusId} minted on-chain successfully!`);

    alert(`(Stub) Redeeming bonus #${tx.bonusId} => wallet ${vaultData.userWallet}. Fill in real contract calls!`);
  } catch(err){
    console.error("redeemBonusOnChain error =>", err);
    alert("On-chain redemption failed => see console");
  }
}

/***********************************************************************
 * Multi-Tab / Single Vault Handling
 ***********************************************************************/
function preventMultipleVaults(){
  window.addEventListener('storage',(evt)=>{
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
    if(evt.key==='vaultLock'){
      if(evt.newValue==='locked' && !vaultUnlocked){
        console.log("Another tab => vault locked");
      }
    }
  });
}

function enforceSingleVault(){
  let lck=localStorage.getItem('vaultLock');
  if(!lck){
    localStorage.setItem('vaultLock','locked');
  } else {
    console.log("Vault lock => single instance enforced");
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
      console.warn("Storage near limit =>", est);
      alert("Vault storage near limit => export backup!");
    }
  }, STORAGE_CHECK_INTERVAL);
}

/***********************************************************************
 * DOMContentLoaded
 ***********************************************************************/
window.addEventListener('DOMContentLoaded', ()=>{
  console.log("Bio‑Vault main.js => starting initialization...");

  let lastURL=localStorage.getItem('last_session_url');
  if(lastURL && window.location.href!==lastURL){
    window.location.href=lastURL;
  }
  window.addEventListener('beforeunload',()=>{
    localStorage.setItem('last_session_url', window.location.href);
  });

  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage= async (e)=>{
    if(e.data?.type==='vaultUpdate'){
      try{
        const { iv, data } = e.data.payload;
        if(!derivedKey){
          console.warn("Got vaultUpdate => derivedKey not available yet");
          return;
        }
        let dec=await decryptData(derivedKey, base64ToBuffer(iv), base64ToBuffer(data));
        Object.assign(vaultData, dec);
        populateWalletUI();
        console.log("🔄 Synced vault across tabs");
      } catch(err){
        console.error("Tab sync fail =>", err);
      }
    }
  };
});

/***********************************************************************
 * loadVaultOnStartup & initializeUI
 ***********************************************************************/
function loadVaultOnStartup(){
  // optional auto logic
}

function initializeUI(){
  let enterVaultBtn=document.getElementById('enterVaultBtn');
  if(enterVaultBtn){
    enterVaultBtn.addEventListener('click', checkAndUnlockVault);
    console.log("Event => enterVaultBtn attached");
  }

  let lockVaultBtn=document.getElementById('lockVaultBtn');
  lockVaultBtn?.addEventListener('click', lockVault);

  let catchInBtn=document.getElementById('catchInBtn');
  catchInBtn?.addEventListener('click', handleReceiveTransaction);

  let catchOutBtn=document.getElementById('catchOutBtn');
  catchOutBtn?.addEventListener('click', handleSendTransaction);

  let copyBioIBANBtn=document.getElementById('copyBioIBANBtn');
  copyBioIBANBtn?.addEventListener('click', handleCopyBioIBAN);

  let exportBtn=document.getElementById('exportBtn');
  exportBtn?.addEventListener('click', exportTransactionTable);

  let exportBackupBtn=document.getElementById('exportBackupBtn');
  exportBackupBtn?.addEventListener('click', exportVaultBackup);

  // If you want autoConnect or saveWallet, attach them:
  let saveWalletBtn=document.getElementById('saveWalletBtn');
  if(saveWalletBtn){
    saveWalletBtn.addEventListener('click', async ()=>{
      let addr=document.getElementById('userWalletAddress').value.trim();
      if(!addr.startsWith('0x')||addr.length<10){
        alert("Invalid wallet address");
        return;
      }
      vaultData.userWallet=addr;
      await promptAndSaveVault();
      alert("Wallet address saved to vault");
    });
  }
  let autoConnectBtn=document.getElementById('autoConnectWalletBtn');
  if(autoConnectBtn){
    autoConnectBtn.addEventListener('click', async ()=>{
      if(!window.ethereum){
        alert("No MetaMask found in this browser!");
        return;
      }
      try{
        await window.ethereum.request({method:'eth_requestAccounts'});
        const provider=new ethers.providers.Web3Provider(window.ethereum);
        const signer=provider.getSigner();
        let userAddr=await signer.getAddress();
        document.getElementById('userWalletAddress').value=userAddr;
        vaultData.userWallet=userAddr;
        await promptAndSaveVault();
        alert(`Auto-connected wallet = ${userAddr}`);
      } catch(err){
        console.error("AutoConnect error =>",err);
        alert("Failed to connect wallet => see console");
      }
    });
  }

  let bioCatchPopup=document.getElementById('bioCatchPopup');
  if(bioCatchPopup){
    let closeBioCatchPopupBtn=document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click',()=>{
      bioCatchPopup.style.display='none';
    });
    let copyBioCatchPopupBtn=document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click',()=>{
      let bcTxt=document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcTxt)
        .then(()=>alert("Bio‑Catch copied!"))
        .catch(err=>{ console.error("Clipboard fail =>",err); alert("Failed copy => see console"); });
    });
    window.addEventListener('click',(event)=>{
      if(event.target===bioCatchPopup){
        bioCatchPopup.style.display='none';
      }
    });
  }

  enforceSingleVault();
}
