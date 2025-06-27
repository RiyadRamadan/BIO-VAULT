/******************************
 * Base Setup / Global Constants
 ******************************/
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';

// Vault & Bonus Limits
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

// IDB & Storage
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000; // 5 min
const vaultSyncChannel = new BroadcastChannel('vault-sync');

// State
let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;

/**
 * Master vaultData. userWallet => for on-chain bridging.
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
  credentialId: null,   // Tied to biometric
  finalChainHash: '',
  dailyCashback: { date:'', usedCount:0 },
  monthlyUsage: { yearMonth:'', usedCount:0 },
  annualBonusUsed: 0,

  userWallet: "",        // On-chain wallet address (once saved, cannot change)
  nextBonusId: 1
};

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
 * Transaction Validation
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
  let ym=`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUsage.yearMonth!==ym){
    vaultData.monthlyUsage.yearMonth=ym;
    vaultData.monthlyUsage.usedCount=0;
  }
}

/** 
 * "2+1" rule => in 3 daily bonuses, max 2 can share the same origin type 
 * (either 'sent' or 'received').
 */
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
 * Offline Send/Receive
 ******************************/
let transactionLock=false;

async function handleSendTransaction(){
  if(!vaultUnlocked){alert("Please unlock first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let recv=document.getElementById('receiverBioIBAN')?.value.trim();
    let amt=parseFloat(document.getElementById('catchOutAmount')?.value.trim());
    if(!recv||isNaN(amt)||amt<=0){alert("Invalid receiver or amount");return;}
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
    // Ensure uniqueness
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let dec=await decryptBioCatchNumber(tx.bioCatch);
        if(dec===plainBio){
          alert("This BioCatch # was used before");
          transactionLock=false; return;
        }
      }
    }
    let obfBio=await encryptBioCatchNumber(plainBio);
    let newTx={
      type:'sent', receiverBioIBAN:recv, amount:amt,
      timestamp:nowSec, status:'Completed', bioCatch:obfBio,
      bonusConstantAtGeneration:vaultData.bonusConstant,
      previousHash:vaultData.lastTransactionHash, txHash:''
    };
    newTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash,newTx);
    vaultData.transactions.push(newTx);
    vaultData.lastTransactionHash=newTx.txHash;
    vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN=`BONUS${vaultData.bonusConstant+offset}`;
      let bonusTx={
        type:'cashback', amount:PER_TX_BONUS, timestamp:nowSec,
        status:'Granted', bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash, txHash:'',
        senderBioIBAN:bonusIBAN, triggerOrigin:'sent',
        bonusId: vaultData.nextBonusId++
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

      // Auto‑redeem if wallet & credential are present
      if (vaultData.userWallet && vaultData.userWallet.length > 0 && vaultData.credentialId) {
        console.log("Auto‑redeeming bonus on chain...");
        await redeemBonusOnChain(bonusTx);
      }
    }
    populateWalletUI();
    await promptAndSaveVault();
    alert(`✅ Sent ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    showBioCatchPopup(obfBio);

    document.getElementById('receiverBioIBAN').value='';
    document.getElementById('catchOutAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("Send Tx Error=>", err);
    alert("Error in sending transaction");
  } finally{
    transactionLock=false;
  }
}

async function handleReceiveTransaction(){
  if(!vaultUnlocked){alert("Unlock vault first");return;}
  if(transactionLock){alert("Transaction in progress");return;}
  transactionLock=true;
  try{
    let encBio=document.getElementById('catchInBioCatch')?.value.trim();
    let amt=parseFloat(document.getElementById('catchInAmount')?.value.trim());
    if(!encBio||isNaN(amt)||amt<=0){alert("Invalid BioCatch or amount");transactionLock=false;return;}

    let nowSec=Math.floor(Date.now()/1000);
    vaultData.lastUTCTimestamp=nowSec;

    let bonusGranted=false;
    if(canGive120Bonus(nowSec,'received',amt)){
      record120BonusUsage('received');
      bonusGranted=true;
    }
    let decBio=await decryptBioCatchNumber(encBio);
    if(!decBio){alert("Unable to decode BioCatch");transactionLock=false;return;}

    // Ensure not used
    for(let tx of vaultData.transactions){
      if(tx.bioCatch){
        let ex=await decryptBioCatchNumber(tx.bioCatch);
        if(ex===decBio){
          alert("This BioCatch was already used");
          transactionLock=false;return;
        }
      }
    }
    let validation=await validateBioCatchNumber(decBio, amt);
    if(!validation.valid){
      alert(`BioCatch fail => ${validation.message}`);
      transactionLock=false;return;
    }
    let { chainHash, claimedSenderIBAN, senderVaultSnapshot }=validation;
    let crossCheck=await verifyFullChainAndBioConstant(senderVaultSnapshot);
    if(!crossCheck.success){
      alert(`Sender chain mismatch => ${crossCheck.reason}`);
      transactionLock=false;return;
    }
    if(senderVaultSnapshot.finalChainHash!==chainHash){
      alert("Chain hash mismatch => invalid snapshot");
      transactionLock=false;return;
    }
    let snapVal=await validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN);
    if(!snapVal.valid){
      alert("Sender snapshot fail =>"+snapVal.errors.join("; "));
      transactionLock=false;return;
    }

    let rxTx={
      type:'received', senderBioIBAN:claimedSenderIBAN,
      bioCatch:encBio, amount:amt, timestamp:nowSec,
      status:'Valid', bonusConstantAtGeneration:vaultData.bonusConstant
    };
    vaultData.transactions.push(rxTx);

    if(bonusGranted){
      let offset=nowSec-vaultData.joinTimestamp;
      let bonusIBAN=`BONUS${vaultData.bonusConstant+offset}`;
      let bonusTx={
        type:'cashback', amount:PER_TX_BONUS, timestamp:nowSec,
        status:'Granted', bonusConstantAtGeneration:vaultData.bonusConstant,
        previousHash:vaultData.lastTransactionHash, txHash:'',
        senderBioIBAN:bonusIBAN, triggerOrigin:'received',
        bonusId:vaultData.nextBonusId++
      };
      bonusTx.txHash=await computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactions.push(bonusTx);
      vaultData.lastTransactionHash=bonusTx.txHash;
      vaultData.finalChainHash=await computeFullChainHash(vaultData.transactions);

      // Auto‑redeem if wallet & credential are present
      if (vaultData.userWallet && vaultData.userWallet.length > 0 && vaultData.credentialId) {
        console.log("Auto‑redeeming bonus on chain...");
        await redeemBonusOnChain(bonusTx);
      }
    }
    await promptAndSaveVault();
    populateWalletUI();
    alert(`✅ Received ${amt} TVM => Bonus: ${bonusGranted?'120 TVM':'None'}`);
    document.getElementById('catchInBioCatch').value='';
    document.getElementById('catchInAmount').value='';
    renderTransactionTable();
  } catch(err){
    console.error("Receive Tx Error=>", err);
    alert("Error receiving transaction");
  } finally{
    transactionLock=false;
  }
}

/******************************
 * Table Rendering
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

    // (1) Truncate the displayed BioCatch to 12 chars
    // but keep the original in tx.bioCatch for copying or other logic
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

/******************************
 * UI Helpers
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
  if(bioLineIntervalTimer)clearInterval(bioLineIntervalTimer);
  bioLineIntervalTimer=setInterval(()=>{
    vaultData.lastUTCTimestamp=Math.floor(Date.now()/1000);
    populateWalletUI();
  }, 1000);
}

function populateWalletUI(){
  let ibInp=document.getElementById('bioibanInput');
  if(ibInp) ibInp.value=vaultData.bioIBAN||"BIO...";

  let rx=vaultData.transactions.filter(t=>t.type==='received').reduce((a,b)=>a+b.amount,0);
  let sx=vaultData.transactions.filter(t=>t.type==='sent').reduce((a,b)=>a+b.amount,0);
  let bx=vaultData.transactions.filter(t=>t.type==='cashback'||t.type==='increment').reduce((a,b)=>a+b.amount,0);
  vaultData.balanceTVM = vaultData.initialBalanceTVM + rx + bx - sx;
  vaultData.balanceUSD = parseFloat((vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2));

  let tvmEl=document.getElementById('tvmBalance');
  if(tvmEl) tvmEl.textContent=`Balance: ${formatWithCommas(vaultData.balanceTVM)} TVM`;
  let usdEl=document.getElementById('usdBalance');
  if(usdEl) usdEl.textContent=`Equivalent to ${formatWithCommas(vaultData.balanceUSD)} USD`;

  let bioLineText=document.getElementById('bioLineText');
  if(bioLineText) bioLineText.textContent=`🔄 BonusConstant: ${vaultData.bonusConstant}`;

  let utcEl=document.getElementById('utcTime');
  if(utcEl) utcEl.textContent=formatDisplayDate(vaultData.lastUTCTimestamp);

  const userWalletLabel = document.getElementById('userWalletLabel');
  if(userWalletLabel){
    userWalletLabel.textContent = vaultData.userWallet 
      ? `On-chain Wallet: ${vaultData.userWallet}`
      : '(No wallet set)';
  }
}

/**
 * (2) When showing BioCatch in the pop-up, we only display 12 chars,
 * but store the full text in data-fullCatch so the Copy button
 * grabs the entire string.
 */
function showBioCatchPopup(encBio){
  let popup=document.getElementById('bioCatchPopup');
  if(!popup)return;
  popup.style.display='flex';
  
  let bcTxt=document.getElementById('bioCatchNumberText');
  if(!bcTxt) return;

  // Truncated for display
  let truncated = (encBio.length>12) ? encBio.slice(0,12)+"..." : encBio;
  bcTxt.textContent = truncated;
  bcTxt.dataset.fullCatch = encBio;  // Store entire string for copying
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

/******************************
 * DOM Load & UI Initialization
 ******************************/
function loadVaultOnStartup(){
  // Optional: auto-detect or skip
}

window.addEventListener('DOMContentLoaded', ()=>{
  let lastURL=localStorage.getItem("last_session_url");
  if(lastURL && window.location.href!==lastURL){
    window.location.href=lastURL;
  }
  window.addEventListener("beforeunload",()=>{
    localStorage.setItem("last_session_url", window.location.href);
  });

  console.log("✅ main.js => Offline Vault + On-Chain Stub");
  initializeUI();
  loadVaultOnStartup();
  preventMultipleVaults();
  enforceStoragePersistence();

  vaultSyncChannel.onmessage= async (e)=>{
    if(e.data?.type==='vaultUpdate'){
      try{
        let { iv, data }=e.data.payload;
        if(!derivedKey){
          console.warn("vaultUpdate => derivedKey not available yet");
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
  enforceStoragePersistence();
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

  const exportFriendlyBtn = document.getElementById('exportFriendlyBtn');
  if(exportFriendlyBtn){
    exportFriendlyBtn.addEventListener('click', exportVaultBackupForMobile);
  }

  const importVaultFileInput = document.getElementById('importVaultFileInput');
  if(importVaultFileInput){
    importVaultFileInput.addEventListener('change', async (evt)=>{
      if(evt.target.files && evt.target.files[0]){
        await importVaultBackupFromFile(evt.target.files[0]);
      }
    });
  }

  let bioCatchPopup=document.getElementById('bioCatchPopup');
  if(bioCatchPopup){
    let closeBioCatchPopupBtn=document.getElementById('closeBioCatchPopup');
    closeBioCatchPopupBtn?.addEventListener('click', ()=>{
      bioCatchPopup.style.display='none';
    });
    let copyBioCatchPopupBtn=document.getElementById('copyBioCatchBtn');
    copyBioCatchPopupBtn?.addEventListener('click', ()=>{
      let bcTxt=document.getElementById('bioCatchNumberText');
      if(!bcTxt) return;
      // (2) Copy the full string from data attribute
      const fullValue = bcTxt.dataset.fullCatch || bcTxt.textContent;
      navigator.clipboard.writeText(fullValue)
        .then(()=>alert('✅ Bio‑Catch Number copied!'))
        .catch(err => {
          console.error("Clipboard copy fail =>", err);
          alert("⚠️ Failed to copy. Try again!");
        });
    });
    window.addEventListener('click', (ev)=>{
      if(ev.target===bioCatchPopup){
        bioCatchPopup.style.display='none';
      }
    });
  }

  enforceSingleVault();

  const saveWalletBtn=document.getElementById('saveWalletBtn');
  saveWalletBtn?.addEventListener('click', async ()=>{
    if(vaultData.userWallet && vaultData.userWallet.length>0){
      alert("Wallet address is already set and cannot be changed.");
      return;
    }
    const addr=document.getElementById('userWalletAddress').value.trim();
    if(!addr.startsWith('0x')||addr.length<10){
      alert("Invalid wallet address");
      return;
    }
    vaultData.userWallet=addr;
    await promptAndSaveVault();
    document.getElementById('userWalletAddress').value="";
    populateWalletUI();
    alert("✅ Wallet address saved to vaultData. It cannot be changed.");
  });

  const autoConnectWalletBtn=document.getElementById('autoConnectWalletBtn');
  autoConnectWalletBtn?.addEventListener('click', async ()=>{
    if(!window.ethereum){
      alert("No MetaMask in this browser!");
      return;
    }
    try{
      await window.ethereum.request({ method:'eth_requestAccounts' });
      const provider = new window.ethers.providers.Web3Provider(window.ethereum);
      const signer=provider.getSigner();
      const userAddr=await signer.getAddress();

      if(!vaultData.userWallet){
        vaultData.userWallet=userAddr;
        await promptAndSaveVault();
        populateWalletUI();
        alert(`Auto-connected => ${userAddr}`);
      } else if(vaultData.userWallet.toLowerCase()!==userAddr.toLowerCase()){
        alert("Warning: The vault already has a different wallet address set!");
      } else {
        alert(`Your current vault address matches the connected MetaMask account: ${userAddr}`);
      }
    } catch(err){
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
 * Additional Helpers
 ******************************/
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}
function validateBioIBAN(str) {
  return /^BIO\d+$/.test(str) || /^BONUS\d+$/.test(str);
}
async function verifyFullChainAndBioConstant(senderVaultSnapshot) {
  // Stub: always return success
  return { success: true };
}
async function validateSenderVaultSnapshot(senderVaultSnapshot, claimedSenderIBAN) {
  // Stub: always valid
  return { valid: true, errors: [] };
}

/******************************
 * Snapshot Serialization & Validation
 ******************************/
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
  if (parts.length < 8) {
    throw new Error('Vault snapshot missing fields: need >= 8 top-level fields');
  }
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

  // If it's a BONUS IBAN, verify
  if (claimedSenderIBAN.startsWith("BONUS")) {
    const offset = encodedTimestamp - senderVaultSnapshot.joinTimestamp;
    const expected = "BONUS" + (senderVaultSnapshot.bonusConstant + offset);
    if (claimedSenderIBAN !== expected) {
      return { valid: false, message: 'Mismatched Bonus Sender IBAN in BioCatch.' };
    }
  } else {
    // Normal "BIO"
    const expectedSenderIBAN = `BIO${senderVaultSnapshot.initialBioConstant + senderVaultSnapshot.joinTimestamp}`;
    if (claimedSenderIBAN !== expectedSenderIBAN) {
      return { valid: false, message: 'Mismatched Sender IBAN in BioCatch.' };
    }
  }

  return {
    valid: true,
    message: 'OK',
    chainHash,
    claimedSenderIBAN,
    senderVaultSnapshot
  };
}

/******************************
 * JavaScript to manage the display logic
 ******************************/
document.addEventListener("DOMContentLoaded", function() {
  const infoSection = document.getElementById('infoSection');
  const backBtn = document.getElementById('backBtn');
  const enterVaultBtn = document.getElementById('enterVaultBtn');
  const lockedScreen = document.getElementById('lockedScreen');
  const vaultUI = document.getElementById('vaultUI');
  const lockVaultBtn = document.getElementById('lockVaultBtn');

  // Display the info section when the page loads
  infoSection.style.display = 'block';
  backBtn.style.display = 'none';

  // Handle the back button to hide the info section and show the vault UI
  backBtn.addEventListener('click', function() {
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Handle the enter vault button to hide the info section and show vault UI
  enterVaultBtn.addEventListener('click', function() {
    infoSection.style.display = 'none';
    vaultUI.classList.remove('hidden');
    lockVaultBtn.classList.remove('hidden');
  });

  // Lock Vault Button to hide vault UI and show locked screen
  lockVaultBtn.addEventListener('click', function() {
    vaultUI.classList.add('hidden');
    lockVaultBtn.classList.add('hidden');
    lockedScreen.classList.remove('hidden');
    infoSection.style.display = 'none'; // Ensure infoSection is hidden when vault is locked
  });

  // Make sure the info section appears only when not in vault UI
  if (lockedScreen.classList.contains('hidden')) {
    infoSection.style.display = 'block';
    backBtn.style.display = 'inline-block';
  } else {
    infoSection.style.display = 'none';
  }
});
