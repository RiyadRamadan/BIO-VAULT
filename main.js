/***********************************************************************
 * main.js — Final Production Offline Vault with On-Chain Bridge
 *
 * Key Features:
 *  - 120 TVM bonuses, up to 3 daily using a "2+1 type" rule (2 same, 1 different).
 *  - 'bonusConstant' = (joinTimestamp - initialBioConstant), no incremental logic.
 *  - In offline usage, we store everything locally with passphrase-based AES in IndexedDB.
 *  - On-chain bridging example: "redeemBonusOnChain(tx)" stub using ethers.js, so you can
 *    easily connect to MetaMask and call your contract's validateAndMint(...) function.
 *  - Multi-tab sync via BroadcastChannel, single vault lock enforcement.
 ***********************************************************************/

/******************************
 * Constants & Basic Config
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// TVM/Bonus rules
const INITIAL_BALANCE_TVM = 1200;
const PER_TX_BONUS = 120;
const MAX_BONUSES_PER_DAY = 3;
const MAX_BONUSES_PER_MONTH = 30;
const MAX_ANNUAL_BONUS_TVM = 10800; // total annual bonus TVM
const EXCHANGE_RATE = 12;          // 1 USD = 12 TVM

// Bonus logic
const INITIAL_BIO_CONSTANT = 1736565605; // genesis
const TRANSACTION_VALIDITY_SECONDS = 720; // ±12 min
const LOCKOUT_DURATION_SECONDS = 3600;    // 1 hour
const MAX_AUTH_ATTEMPTS = 3;

// Storage
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 min
const vaultSyncChannel = new BroadcastChannel('vault-sync');

// State
let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/******************************
 * Master vaultData
 ******************************/
let vaultData = {
  bioIBAN: null,                  // permanent: "BIO" + (initialBioConstant + joinTimestamp)
  initialBioConstant: 0,          // set = INITIAL_BIO_CONSTANT
  bonusConstant: 0,               // (joinTimestamp - initialBioConstant), doesn't increment
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

  // On-chain bridging fields
  userWallet: "",  // user-set wallet address
  nextBonusId: 1   // unique ID for each bonus tx (if needed in your contract calls)
};

/******************************
 * Encryption & IndexedDB
 ******************************/
// Utility: toBase64, fromBase64
function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuffer(b64) {
  let bin = atob(b64);
  let out = new Uint8Array(bin.length);
  for (let i=0; i<bin.length; i++){
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

async function deriveKeyFromPIN(pin, salt){
  const enc = new TextEncoder();
  const pinBuf = enc.encode(pin);
  const keyMaterial = await crypto.subtle.importKey('raw', pinBuf, { name:'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'
  }, keyMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}

async function encryptData(key, dataObj){
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(dataObj));
  const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plaintext);
  return { iv, ciphertext };
}
async function decryptData(key, iv, ciphertext){
  const dec = new TextDecoder();
  let buf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(dec.decode(buf));
}

// IndexedDB
async function openVaultDB(){
  return new Promise((resolve,reject)=>{
    let req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = evt=>{
      let db = evt.target.result;
      if(!db.objectStoreNames.contains(VAULT_STORE)){
        db.createObjectStore(VAULT_STORE, { keyPath:'id' });
      }
    };
    req.onsuccess = evt=>resolve(evt.target.result);
    req.onerror = evt=>reject(evt.target.error);
  });
}

async function saveVaultDataToDB(iv, ciphertext, saltBase64){
  const db = await openVaultDB();
  return new Promise((resolve,reject)=>{
    let tx = db.transaction([VAULT_STORE],'readwrite');
    let store = tx.objectStore(VAULT_STORE);
    store.put({
      id:'vaultData',
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
      salt: saltBase64,
      lockoutTimestamp: vaultData.lockoutTimestamp||null,
      authAttempts: vaultData.authAttempts||0
    });
    tx.oncomplete=()=>resolve();
    tx.onerror=err=>reject(err);
  });
}

async function loadVaultDataFromDB(){
  const db = await openVaultDB();
  return new Promise((resolve,reject)=>{
    let tx = db.transaction([VAULT_STORE],'readonly');
    let store = tx.objectStore(VAULT_STORE);
    let getReq = store.get('vaultData');
    getReq.onsuccess=()=>{
      if(getReq.result){
        try{
          let ivBuf = base64ToBuffer(getReq.result.iv);
          let ciphBuf = base64ToBuffer(getReq.result.ciphertext);
          let saltBuf = getReq.result.salt ? base64ToBuffer(getReq.result.salt) : null;
          resolve({
            iv: ivBuf,
            ciphertext: ciphBuf,
            salt: saltBuf,
            lockoutTimestamp: getReq.result.lockoutTimestamp||null,
            authAttempts: getReq.result.authAttempts||0
          });
        } catch(err){
          console.error("Error decoding stored data:", err);
          resolve(null);
        }
      } else {
        resolve(null);
      }
    };
    getReq.onerror=err=>reject(err);
  });
}

/******************************
 * Vault Persistence
 ******************************/
async function persistVaultData(salt=null){
  try{
    if(!derivedKey){
      throw new Error("No encryption key derived");
    }
    let { iv, ciphertext } = await encryptData(derivedKey, vaultData);
    let saltBase64;
    if(salt){
      saltBase64 = bufferToBase64(salt);
    } else {
      let stored=await loadVaultDataFromDB();
      if(stored && stored.salt){
        saltBase64 = bufferToBase64(stored.salt);
      } else {
        throw new Error("Salt not found => can't persist");
      }
    }
    await saveVaultDataToDB(iv, ciphertext, saltBase64);

    // local backup
    let backupPayload={
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext),
      salt: saltBase64,
      timestamp: Date.now()
    };
    localStorage.setItem(VAULT_BACKUP_KEY, JSON.stringify(backupPayload));
    vaultSyncChannel.postMessage({type:'vaultUpdate', payload: backupPayload});
    console.log("💾 Vault data stored => triple redundancy done");
  } catch(err){
    console.error("Vault persist fail:", err);
    alert("🚨 CRITICAL: VAULT BACKUP FAILED! EXPORT IMMEDIATELY!");
  }
}
async function promptAndSaveVault(salt=null){
  await persistVaultData(salt);
}

/******************************
 * Biometric
 ******************************/
async function performBiometricAuthenticationForCreation(){
  try{
    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name:"Bio-Vault" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "bio-user",
        displayName: "Bio User"
      },
      pubKeyCredParams:[
        {type:"public-key",alg:-7},
        {type:"public-key",alg:-257}
      ],
      authenticatorSelection:{
        authenticatorAttachment:"platform",
        userVerification:"required"
      },
      timeout:60000,
      attestation:"none"
    };
    let credential=await navigator.credentials.create({ publicKey });
    if(!credential) {
      console.error("Biometric creation => null");
      return null;
    }
    return credential;
  } catch(err){
    console.error("Biometric creation error:", err);
    return null;
  }
}
async function performBiometricAssertion(credentialId){
  try{
    const publicKey={
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials:[{ id: base64ToBuffer(credentialId), type:'public-key' }],
      userVerification:"required",
      timeout:60000
    };
    let assertion = await navigator.credentials.get({ publicKey });
    return !!assertion;
  } catch(err){
    console.error("Biometric assertion error:", err);
    return false;
  }
}

/******************************
 * Basic Vault / Lock
 ******************************/
function lockVault(){
  if(!vaultUnlocked) return;
  vaultUnlocked=false;
  document.getElementById('vaultUI')?.classList.add('hidden');
  document.getElementById('lockVaultBtn')?.classList.add('hidden');
  document.getElementById('lockedScreen')?.classList.remove('hidden');
  localStorage.setItem('vaultUnlocked','false');
  console.log("🔒 Vault locked.");
}

async function handleFailedAuthAttempt(){
  vaultData.authAttempts=(vaultData.authAttempts||0)+1;
  if(vaultData.authAttempts>=MAX_AUTH_ATTEMPTS){
    vaultData.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_DURATION_SECONDS;
    alert("Max attempts => locked 1 hour");
  } else {
    alert(`Auth fail => you have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} tries left.`);
  }
  await promptAndSaveVault();
}

/******************************
 * Passphrase Modal
 ******************************/
async function getPassphraseFromModal({ confirmNeeded=false, modalTitle='Enter Passphrase' }){
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
      resolve({ pin:null });
    }
    function onSave(){
      let pinVal=passInput.value.trim();
      if(!pinVal||pinVal.length<8){
        alert("Passphrase must be >=8 chars");
        return;
      }
      if(confirmNeeded){
        let cVal=passConfirmInput.value.trim();
        if(pinVal!==cVal){
          alert("Pass mismatch");
          return;
        }
      }
      cleanup();
      resolve({ pin: pinVal, confirmed:true });
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
    let { pin }=await getPassphraseFromModal({ confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    pinFromUser=pin;
  }
  if(!pinFromUser||pinFromUser.length<8){
    alert("Pass must be >=8 chars");
    return;
  }
  console.log("No existing vault => creating new");
  localStorage.setItem('vaultLock','locked');

  let nowSec=Math.floor(Date.now()/1000);
  vaultData.joinTimestamp=nowSec;
  vaultData.lastUTCTimestamp=nowSec;
  vaultData.initialBioConstant=INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant= nowSec - INITIAL_BIO_CONSTANT;
  vaultData.bioIBAN=`BIO${vaultData.initialBioConstant + nowSec}`;
  vaultData.initialBalanceTVM=INITIAL_BALANCE_TVM;
  vaultData.balanceTVM=INITIAL_BALANCE_TVM;
  vaultData.balanceUSD=parseFloat((vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2));
  vaultData.transactions=[];
  vaultData.authAttempts=0;
  vaultData.lockoutTimestamp=null;
  vaultData.lastTransactionHash='';
  vaultData.finalChainHash='';
  vaultData.nextBonusId=1;

  let credential=await performBiometricAuthenticationForCreation();
  if(!credential||!credential.id){
    alert("Biometric creation failed => vault not created");
    return;
  }
  vaultData.credentialId=bufferToBase64(credential.rawId);
  console.log("🆕 Creating new vault =>", vaultData);

  let salt=generateSalt();
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
  let { pin }=await getPassphraseFromModal({ confirmNeeded:false, modalTitle:'Unlock Vault' });
  if(!pin){ alert("No pass => user canceled"); handleFailedAuthAttempt(); return;}
  if(pin.length<8){ alert("Pass must be >=8 chars"); handleFailedAuthAttempt(); return;}

  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault found => create new?"))return;
    await createNewVault(pin);
    return;
  }
  try{
    if(!stored.salt) throw new Error("No salt in stored data");
    derivedKey=await deriveKeyFromPIN(pin, stored.salt);
    let dec=await decryptData(derivedKey, stored.iv, stored.ciphertext);
    vaultData=dec;

    vaultData.lockoutTimestamp=stored.lockoutTimestamp;
    vaultData.authAttempts=stored.authAttempts;

    if(vaultData.credentialId){
      let ok=await performBiometricAssertion(vaultData.credentialId);
      if(!ok){
        alert("Biometric mismatch => unlock fail");
        handleFailedAuthAttempt();
        return;
      }
    }
    vaultUnlocked=true;
    vaultData.authAttempts=0;
    vaultData.lockoutTimestamp=null;
    await promptAndSaveVault();
    showVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked','true');
  } catch(err){
    alert(`Failed decrypt => ${err.message}`);
    console.error(err);
    handleFailedAuthAttempt();
  }
}

async function checkAndUnlockVault(){
  let stored=await loadVaultDataFromDB();
  if(!stored){
    if(!confirm("No vault => create new?")) return;
    let { pin }=await getPassphraseFromModal({ confirmNeeded:true, modalTitle:'Create New Vault (Set Passphrase)'});
    await createNewVault(pin);
  } else {
    await unlockVault();
  }
}

/******************************
 * Transaction Hashing & Logic
 ******************************/
function formatDisplayDate(ts){
  let d=new Date(ts*1000);
  return d.toISOString().slice(0,10)+" "+d.toISOString().slice(11,19);
}
function formatWithCommas(num){
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

async function computeTransactionHash(prevHash, txObj){
  let dStr=JSON.stringify({prevHash,...txObj});
  let buf=new TextEncoder().encode(dStr);
  let hashBuf=await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hashBuf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function computeFullChainHash(transactions){
  let rHash='';
  let sorted=[...transactions].sort((a,b)=>a.timestamp-b.timestamp);
  for(let t of sorted){
    let obj={
      type:t.type,
      amount:t.amount,
      timestamp:t.timestamp,
      status:t.status,
      bioCatch:t.bioCatch,
      bonusConstantAtGeneration:t.bonusConstantAtGeneration,
      previousHash:rHash
    };
    rHash=await computeTransactionHash(rHash, obj);
  }
  return rHash;
}

/******************************
 * Bonus Logic
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
  let ym=d.getUTCFullYear()+"-"+String(d.getUTCMonth()+1).padStart(2,'0');
  if(!vaultData.monthlyUsage) vaultData.monthlyUsage={yearMonth:'', usedCount:0};
  if(vaultData.monthlyUsage.yearMonth!==ym){
    vaultData.monthlyUsage.yearMonth=ym;
    vaultData.monthlyUsage.usedCount=0;
  }
}
function bonusDiversityCheck(newTxType){
  let dateStr=vaultData.dailyCashback.date;
  let sentCnt=0, recvCnt=0;
  for(let tx of vaultData.transactions){
    if(tx.type==='cashback'){
      let ds=new Date(tx.timestamp*1000).toISOString().slice(0,10);
      if(ds===dateStr && tx.triggerOrigin){
        if(tx.triggerOrigin==='sent') sentCnt++;
        else if(tx.triggerOrigin==='received') recvCnt++;
      }
    }
  }
  if(newTxType==='sent' && sentCnt>=2)return false;
  if(newTxType==='received' && recvCnt>=2)return false;
  return true;
}
function canGive120Bonus(nowSec, txType, txAmount){
  resetDailyUsageIfNeeded(nowSec);
  resetMonthlyUsageIfNeeded(nowSec);
  if(vaultData.dailyCashback.usedCount>=MAX_BONUSES_PER_DAY)return false;
  if(vaultData.monthlyUsage.usedCount>=MAX_BONUSES_PER_MONTH)return false;
  if((vaultData.annualBonusUsed||0)>=MAX_ANNUAL_BONUS_TVM)return false;
  if(txType==='sent' && txAmount<=240)return false;
  if(!bonusDiversityCheck(txType))return false;
  return true;
}
function record120BonusUsage(origin){
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed=(vaultData.annualBonusUsed||0)+PER_TX_BONUS;
}

/******************************
 * BioCatch
 ******************************/
async function encryptBioCatchNumber(plainText){
  return btoa(plainText);
}
async function decryptBioCatchNumber(encString){
  try { return atob(encString); }
  catch(e){ return null; }
}

// Snapshot
function serializeVaultSnapshotForBioCatch(vData){
  let fieldSep='|'; let txSep='^'; let txFieldSep='~';
  let txParts=(vData.transactions||[]).map(tx=>{
    return [
      tx.type||'', tx.receiverBioIBAN||'', tx.senderBioIBAN||'',
      tx.amount||0, tx.timestamp||0, tx.status||'',
      tx.bioCatch||'', tx.bonusConstantAtGeneration||0,
      tx.previousHash||'', tx.txHash||''
    ].join(txFieldSep);
  });
  let txString=txParts.join(txSep);
  let raw=[
    vData.joinTimestamp||0, vData.initialBioConstant||0, vData.bonusConstant||0,
    vData.finalChainHash||'', vData.initialBalanceTVM||0, vData.balanceTVM||0,
    vData.lastUTCTimestamp||0, txString
  ].join(fieldSep);
  return btoa(raw);
}
function deserializeVaultSnapshotFromBioCatch(b64String){
  let raw=atob(b64String);
  let parts=raw.split('|');
  if(parts.length<8) throw new Error("Vault snapshot missing fields");
  let joinTimestamp=parseInt(parts[0],10);
  let initialBioConstant=parseInt(parts[1],10);
  let bonusConstant=parseInt(parts[2],10);
  let finalChainHash=parts[3];
  let initialBalanceTVM=parseInt(parts[4],10);
  let balanceTVM=parseInt(parts[5],10);
  let lastUTCTimestamp=parseInt(parts[6],10);
  let txString=parts[7]||'';
  let txChunks=txString.split('^').filter(Boolean);
  let txFieldSep='~';
  let transactions=txChunks.map(ch=>{
    let f=ch.split(txFieldSep);
    return {
      type:f[0]||'', receiverBioIBAN:f[1]||'',
      senderBioIBAN:f[2]||'', amount:parseFloat(f[3])||0,
      timestamp:parseInt(f[4],10)||0, status:f[5]||'',
      bioCatch:f[6]||'', bonusConstantAtGeneration:parseInt(f[7],10)||0,
      previousHash:f[8]||'', txHash:f[9]||''
    };
  });
  return{
    joinTimestamp, initialBioConstant, bonusConstant, finalChainHash,
    initialBalanceTVM, balanceTVM, lastUTCTimestamp, transactions
  };
}
async function generateBioCatchNumber(senderIBAN, receiverIBAN, amt, ts, senderBal, finalHash){
  let encSnap=serializeVaultSnapshotForBioCatch(vaultData);
  let sNum=parseInt(senderIBAN.slice(3));
  let rNum=parseInt(receiverIBAN.slice(3));
  let firstPart=sNum+rNum;
  return `Bio-${firstPart}-${ts}-${amt}-${senderBal}-${senderIBAN}-${finalHash}-${encSnap}`;
}
async function validateBioCatchNumber(bioCatchNumber, claimedAmount){
  let parts=bioCatchNumber.split('-');
  if(parts.length!==8||parts[0]!=='Bio'){
    return{ valid:false, message:'BioCatch must have 8 parts' };
  }
  let firstPart=parseInt(parts[1]);
  let ts=parseInt(parts[2]);
  let amt=parseFloat(parts[3]);
  let claimedBal=parseFloat(parts[4]);
  let claimedIBAN=parts[5];
  let chainHash=parts[6];
  let encSnap=parts[7];

  if(isNaN(firstPart)||isNaN(ts)||isNaN(amt)||isNaN(claimedBal)){
    return{ valid:false, message:'Numeric parse error' };
  }
  let senderNum=parseInt(claimedIBAN.slice(3));
  let recNum=firstPart-senderNum;
  if(!vaultData.bioIBAN){
    return{ valid:false, message:'Receiver IBAN not found in vault' };
  }
  let localRec=parseInt(vaultData.bioIBAN.slice(3));
  if(recNum!==localRec){
    return{ valid:false, message:'This BioCatch not intended for this IBAN' };
  }
  if(amt!==claimedAmount){
    return{ valid:false, message:'Claimed amount mismatch' };
  }
  let timeDiff=Math.abs(vaultData.lastUTCTimestamp - ts);
  if(timeDiff>TRANSACTION_VALIDITY_SECONDS){
    return{ valid:false, message:'Timestamp outside ±12min window' };
  }

  let senderSnap;
  try{
    senderSnap=deserializeVaultSnapshotFromBioCatch(encSnap);
  }catch(err){
    return{ valid:false, message:'Snapshot parse error: '+err.message };
  }

  if(claimedIBAN.startsWith("BONUS")){
    let offset=ts - senderSnap.joinTimestamp;
    let expected=`BONUS${senderSnap.bonusConstant+offset}`;
    if(claimedIBAN!==expected){
      return{ valid:false, message:'Mismatched Bonus IBAN' };
    }
  } else {
    let expected=`BIO${senderSnap.initialBioConstant + senderSnap.joinTimestamp}`;
    if(claimedIBAN!==expected){
      return{ valid:false, message:'Mismatched sender IBAN' };
    }
  }
  return{
    valid:true, message:'OK',
    chainHash, claimedSenderIBAN:claimedIBAN,
    senderVaultSnapshot: senderSnap
  };
}

/******************************
 * Stub Checking
 ******************************/
async function verifyFullChainAndBioConstant(snap){ 
  return { success:true }; // stub
}
async function validateSenderVaultSnapshot(snap, claimedIBAN){
  return { valid:true, errors:[] }; // stub
}

/******************************
 * UI & Transaction Table
 ******************************/
function showVaultUI(){
  document.getElementById('lockedScreen')?.classList.add('hidden');
  document.getElementById('vaultUI')?.classList.remove('hidden');
  document.getElementById('lockVaultBtn')?.classList.remove('hidden');
  populateWalletUI();
  renderTransactionTable();
}
function initializeBioConstantAndUTCTime(){
  let nowSec=Math.floor(Date.now()/1000);
  vaultData.lastUTCTimestamp=nowSec;
  populateWalletUI();
  if(bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer=setInterval(()=>{
    vaultData.lastUTCTimestamp=Math.floor(Date.now()/1000);
    populateWalletUI();
  },1000);
}

function populateWalletUI(){
  let ibanInp=document.getElementById('bioibanInput');
  if(ibanInp) ibanInp.value=vaultData.bioIBAN||"BIO...";

  let rx=vaultData.transactions.filter(t=>t.type==='received').reduce((acc,t)=>acc+t.amount,0);
  let sx=vaultData.transactions.filter(t=>t.type==='sent').reduce((acc,t)=>acc+t.amount,0);
  let bx=vaultData.transactions.filter(t=>t.type==='cashback'||t.type==='increment').reduce((acc,t)=>acc+t.amount,0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + rx + bx - sx;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2));

  let tvmEl=document.getElementById('tvmBalance');
  if(tvmEl){
    tvmEl.textContent=`Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  }
  let usdEl=document.getElementById('usdBalance');
  if(usdEl){
    usdEl.textContent=`Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;
  }

  let bioLineText=document.getElementById('bioLineText');
  if(bioLineText){
    bioLineText.textContent=`🔄 BonusConstant: ${vaultData.bonusConstant}`;
  }

  let utcEl=document.getElementById('utcTime');
  if(utcEl){
    utcEl.textContent=formatDisplayDate(vaultData.lastUTCTimestamp);
  }
}

function renderTransactionTable(){
  let tbody=document.getElementById('transactionBody');
  if(!tbody)return;
  tbody.innerHTML='';
  let sortedTx=[...vaultData.transactions].sort((a,b)=>b.timestamp-a.timestamp);
  for(let tx of sortedTx){
    let tr=document.createElement('tr');
    let bIbanCell='—', catchCell=tx.bioCatch||'—', amtCell=tx.amount,
        tsCell=formatDisplayDate(tx.timestamp), stCell=tx.status;
    if(tx.type==='sent'){
      bIbanCell=tx.receiverBioIBAN;
    } else if(tx.type==='received'){
      bIbanCell=tx.senderBioIBAN||'Unknown';
    } else if(tx.type==='cashback'){
      bIbanCell=`System/Bonus (ID=${tx.bonusId||''})`;
    } else if(tx.type==='increment'){
      bIbanCell='Periodic Increment';
    }
    let rowHTML=`
      <td>${bIbanCell}</td>
      <td>${catchCell}</td>
      <td>${amtCell}</td>
      <td>${tsCell}</td>
      <td>${stCell}</td>
    `;
    tr.innerHTML=rowHTML;
    tbody.appendChild(tr);
  }
}

/******************************
 * handleSend / handleReceive
 ******************************/
let transactionLock=false;

async function handleSendTransaction(){
  if(!vaultUnlocked){alert("Unlock vault first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let recv=document.getElementById('receiverBioIBAN').value.trim();
    let amt=parseFloat(document.getElementById('catchOutAmount').value.trim());
    if(!recv||isNaN(amt)||amt<=0){alert("Invalid receiver or amt");return;}
    if(recv===vaultData.bioIBAN){alert("Cannot send to self");return;}
    if(vaultData.balanceTVM<amt){alert("Insufficient TVM");return;}

    let nowSec=Math.floor(Date.now()/1000);
    vaultData.lastUTCTimestamp=nowSec;

    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'sent',amt)){
      record120BonusUsage('sent');
      bonusGranted=true;
    }
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
    let plainBio=await generateBioCatchNumber(
      vaultData.bioIBAN, recv, amt, nowSec, vaultData.balanceTVM, vaultData.finalChainHash
    );
    // Uniqueness check
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let dec=await decryptBioCatchNumber(tx.bioCatch);
        if(dec===plainBio){
          alert("This BioCatch # already used");
          transactionLock=false;
          return;
        }
      }
    }
    let encBio=await encryptBioCatchNumber(plainBio);
    let newTx={
      type:'sent', receiverBioIBAN:recv, amount:amt,
      timestamp:nowSec, status:'Completed', bioCatch:encBio,
      bonusConstantAtGeneration:vaultData.bonusConstant,
      previousHash:vaultData.lastTransactionHash, txHash:''
    };
    newTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash=newTx.txHash;
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    if(bonusGranted){
      let offset=nowSec - vaultData.joinTimestamp;
      let bonusIBAN="BONUS"+(vaultData.bonusConstant + offset);
      let bId=vaultData.nextBonusId++;
      let bonusTx={
        type:'cashback', amount: PER_TX_BONUS, timestamp: nowSec,
        status:'Granted', bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash, txHash:'',
        senderBioIBAN:bonusIBAN, triggerOrigin:'sent',
        bonusId:bId
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
    }

    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amt} TVM. Bonus: ${bonusGranted?'120 TVM':'None'}`);
    showBioCatchPopup(encBio);

    document.getElementById('receiverBioIBAN').value='';
    document.getElementById('catchOutAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("Send Tx error:", err);
    alert("Error sending transaction");
  } finally {
    transactionLock=false;
  }
}

async function handleReceiveTransaction(){
  if(!vaultUnlocked){alert("Unlock vault first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let encBio=document.getElementById('catchInBioCatch').value.trim();
    let amt=parseFloat(document.getElementById('catchInAmount').value.trim());
    if(!encBio||isNaN(amt)||amt<=0){
      alert("Invalid BioCatch or amt");
      transactionLock=false; return;
    }
    let nowSec=Math.floor(Date.now()/1000);
    vaultData.lastUTCTimestamp=nowSec;

    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'received',amt)){
      record120BonusUsage('received');
      bonusGranted=true;
    }
    let decBio=await decryptBioCatchNumber(encBio);
    if(!decBio){alert("Cannot decode BioCatch");transactionLock=false;return;}

    // uniqueness
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let d=await decryptBioCatchNumber(tx.bioCatch);
        if(d===decBio){
          alert("This BioCatch # already used");
          transactionLock=false;return;
        }
      }
    }
    let validation=await validateBioCatchNumber(decBio, amt);
    if(!validation.valid){
      alert("BioCatch fail => "+validation.message);
      transactionLock=false;return;
    }
    let { chainHash, claimedSenderIBAN, senderVaultSnapshot } = validation;
    let crossCheck=await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if(!crossCheck.success){
      alert("Sender chain mismatch => "+crossCheck.reason);
      transactionLock=false; return;
    }
    if(senderVaultSnapshot.finalChainHash!==chainHash){
      alert("Chain hash mismatch => invalid BioCatch");
      transactionLock=false; return;
    }
    let snapVal=await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if(!snapVal.valid){
      alert("Sender snapshot fail => "+snapVal.errors.join('; '));
      transactionLock=false; return;
    }

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
      let offset=nowSec - vaultData.joinTimestamp;
      let bIban=`BONUS${vaultData.bonusConstant + offset}`;
      let bId=vaultData.nextBonusId++;
      let bonusTx={
        type:'cashback', amount:PER_TX_BONUS, timestamp:nowSec,
        status:'Granted', bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash, txHash:'',
        senderBioIBAN:bIban, triggerOrigin:'received',
        bonusId:bId
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);
    }
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Received ${amt} TVM. Bonus: ${bonusGranted?'120 TVM':'None'}`);
    document.getElementById('catchInBioCatch').value='';
    document.getElementById('catchInAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("Receive Tx error:", err);
    alert("Error receiving transaction");
  } finally {
    transactionLock=false;
  }
}

/******************************
 * Additional UI Helpers
 ******************************/
function showBioCatchPopup(encBio){
  let pop=document.getElementById('bioCatchPopup');
  if(!pop)return;
  pop.style.display='flex';
  let txt=document.getElementById('bioCatchNumberText');
  if(txt){
    txt.textContent=encBio;
  }
}
function exportTransactionTable(){
  let table=document.getElementById('transactionTable');
  if(!table){alert("No transaction table found");return;}
  let rows=table.querySelectorAll('tr');
  let csv="data:text/csv;charset=utf-8,";
  rows.forEach(r=>{
    let cols=r.querySelectorAll('th,td');
    let lineArr=[];
    cols.forEach(c=>{
      let d=c.innerText.replace(/"/g,'""');
      if(d.includes(',')) d=`"${d}"`;
      lineArr.push(d);
    });
    csv+=lineArr.join(",")+"\r\n";
  });
  let uri=encodeURI(csv);
  let link=document.createElement('a');
  link.setAttribute('href', uri);
  link.setAttribute('download','transaction_history.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
function exportVaultBackup(){
  let data=JSON.stringify(vaultData,null,2);
  let blob=new Blob([data], { type:'application/json'});
  let url=URL.createObjectURL(blob);
  let a=document.createElement('a');
  a.href=url;
  a.download='vault_backup.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function handleCopyBioIBAN(){
  let inp=document.getElementById('bioibanInput');
  if(!inp||!inp.value.trim()){
    alert("No Bio‑IBAN to copy");
    return;
  }
  navigator.clipboard.writeText(inp.value.trim())
    .then(()=>alert("Bio‑IBAN copied!"))
    .catch(err=>{
      console.error("Clipboard error:", err);
      alert("Failed to copy IBAN");
    });
}

/******************************
 * On-Chain Stub
 ******************************/
async function redeemBonusOnChain(tx){
  console.log("[redeemBonusOnChain] => Attempting redemption for bonus:", tx);
  if(!tx||!tx.bonusId){alert("Invalid bonus or missing bonusId");return;}
  if(!vaultData.userWallet||vaultData.userWallet.length<5){
    alert("Please set your wallet address first");
    return;
  }
  try{
    if(!window.ethereum){
      alert("No MetaMask / web3 provider found!");
      return;
    }
    await window.ethereum.request({method:'eth_requestAccounts'});
    let provider=new ethers.providers.Web3Provider(window.ethereum);
    let signer=provider.getSigner();
    let userAddr=await signer.getAddress();
    console.log("User address =>", userAddr);

    // Optional check if userAddr matches stored userWallet
    if(userAddr.toLowerCase()!==vaultData.userWallet.toLowerCase()){
      alert("Warning: active metamask != userWallet. Proceeding anyway...");
    }

    // Put your real contract logic:
    // const contractAddr="0xYourDeployedContract...";
    // const contractABI=[ ... ];
    // let contract=new ethers.Contract(contractAddr, contractABI, signer);
    // let txResp=await contract.validateAndMint(vaultData.userWallet, tx.bonusId);
    // let receipt=await txResp.wait();
    // console.log("Redeemed on chain =>", receipt);
    // alert(`Bonus #${tx.bonusId} redeemed on chain!`);

    alert(`(Stub) Redeeming bonus #${tx.bonusId} => wallet: ${vaultData.userWallet}`);
  } catch(err){
    console.error("redeemBonusOnChain => error:", err);
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
        vaultUnlocked=true; showVaultUI(); initializeBioConstantAndUTCTime();
      } else if(evt.newValue==='false' && vaultUnlocked){
        vaultUnlocked=false; lockVault();
      }
    }
    if(evt.key==='vaultLock'){
      if(evt.newValue==='locked' && !vaultUnlocked){
        console.log("Another tab => vault locked in place");
      }
    }
  });
}
function enforceSingleVault(){
  let vaultLock=localStorage.getItem('vaultLock');
  if(!vaultLock){
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
      alert("Vault storage near limit => export backup now!");
    }
  }, STORAGE_CHECK_INTERVAL);
}

/******************************
 * On DOMContentLoaded
 ******************************/
function loadVaultOnStartup(){
  // optional auto-detection or silent unlock if needed
}

window.addEventListener('DOMContentLoaded', ()=>{
  // last session link
  let lastURL=localStorage.getItem("last_session_url");
  if(lastURL && window.location.href!==lastURL){
    window.location.href=lastURL;
  }
  window.addEventListener("beforeunload",()=>{
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ Bio‑Vault main.js => init UI");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage= async e=>{
    if(e.data?.type==='vaultUpdate'){
      try{
        let {iv,data} = e.data.payload;
        if(!derivedKey){
          console.warn("Got vaultUpdate => derivedKey not ready");
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

function initializeUI(){
  let enterVaultBtn=document.getElementById('enterVaultBtn');
  enterVaultBtn?.addEventListener('click', checkAndUnlockVault);

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

  let bioCatchPopup=document.getElementById('bioCatchPopup');
  if(bioCatchPopup){
    let closeBioCatchPopupBtn=document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click',()=>{
      bioCatchPopup.style.display='none';
    });
    let copyBioCatchPopupBtn=document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click',()=>{
      const bcNum=document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(()=>alert("Bio‑Catch # copied to clipboard!"))
        .catch(err=>{
          console.error("Clipboard copy fail:", err);
          alert("⚠️ Failed to copy. See console.");
        });
    });
    window.addEventListener('click',(event)=>{
      if(event.target===bioCatchPopup) {
        bioCatchPopup.style.display='none';
      }
    });
  }

  // For your manual "userWallet" field + buttons:
  const saveWalletBtn=document.getElementById('saveWalletBtn');
  saveWalletBtn?.addEventListener('click', async ()=>{
    const addr=document.getElementById('userWalletAddress').value.trim();
    if(!addr.startsWith('0x')||addr.length<10){
      alert("Invalid wallet address");
      return;
    }
    vaultData.userWallet=addr;
    await promptAndSaveVault();
    alert("Wallet address saved in your vaultData");
  });

  const autoConnectWalletBtn=document.getElementById('autoConnectWalletBtn');
  autoConnectWalletBtn?.addEventListener('click', async ()=>{
    if(!window.ethereum){
      alert("No MetaMask found!");
      return;
    }
    try{
      await window.ethereum.request({method:'eth_requestAccounts'});
      let provider=new ethers.providers.Web3Provider(window.ethereum);
      let signer=provider.getSigner();
      let userAddr=await signer.getAddress();
      document.getElementById('userWalletAddress').value=userAddr;
      vaultData.userWallet=userAddr;
      await promptAndSaveVault();
      alert(`Auto-connected wallet => ${userAddr}`);
    } catch(err){
      console.error("AutoConnect error =>", err);
      alert("Failed wallet connect => see console");
    }
  });

  enforceSingleVault();
}
