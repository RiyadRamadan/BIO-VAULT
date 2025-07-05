/*****************************************************************
 *  Bio-Vault – BalanceChain Segment-Based Vault (Regulator Grade)
 *  Production Build 2025-07 | Author: RR.R
 *****************************************************************/

// ─────────── 1. GLOBAL CONSTANTS ───────────
const DB_NAME      = 'BioVaultDB', DB_VERSION = 1, STORE = 'vault';
const INITIAL_BALANCE_TVM   = 1200;
const PER_TX_BONUS          = 120;
const MAX_BONUS_DAY         = 3;
const MAX_BONUS_MONTH       = 30;
const MAX_BONUS_YEAR_TVM    = 10800;
const EXCHANGE_RATE         = 12;           // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT  = 1736565605;   // genesis epoch
const LOCKOUT_SECS          = 3600;
const MAX_AUTH_TRIES        = 3;
const BACKUP_KEY            = 'vaultArmoredBackup';
const STORAGE_CHECK_MS      = 300_000;
const SYNC_CH               = new BroadcastChannel('vault-sync');

// ─────────── 2. RUNTIME STATE ───────────
let derivedKey  = null;
let vaultOpen   = false;
let utcTimerId  = null;

const VD = {
  signingKey : { privateKeyJwk:null, publicKeyJwk:null },
  bioIBAN    : null,
  initialBioConstant:0, bonusConstant:0,
  initialBalanceTVM:INITIAL_BALANCE_TVM,
  balanceTVM:0, balanceUSD:0,
  joinTimestamp:0, lastUTCTimestamp:0,
  transactions:[], lastTransactionHash:'', finalChainHash:'',
  credentialId:null, authAttempts:0, lockoutTimestamp:null,
  dailyCashback:{date:'',usedCount:0},
  monthlyUsage :{yearMonth:'',usedCount:0},
  annualBonusUsed:0,
  userWallet:'', nextBonusId:1,
  segments: [] // full segment ledger
};

// ─────────── 3. HELPERS ───────────
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = { enc:b=>btoa(String.fromCharCode(...new Uint8Array(b))),
              dec:s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)) };
const sha256 = async (...inputs) => {
  const s = inputs.map(x => String(x)).join('|');
  const h=await crypto.subtle.digest('SHA-256',enc.encode(s));
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('');
};
const num = n=>n.toLocaleString();
const fmt = t=>new Date(t*1000).toISOString().replace('T',' ').slice(0,19);

// ─────────── 4. CRYPTO PRIMITIVES ───────────
async function genECDSA(){
  const kp=await crypto.subtle.generateKey(
    {name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  return {
    privateKeyJwk:await crypto.subtle.exportKey('jwk',kp.privateKey),
    publicKeyJwk :await crypto.subtle.exportKey('jwk',kp.publicKey)
  };
}
async function signPriv(msg){
  const key=await crypto.subtle.importKey(
    'jwk',VD.signingKey.privateKeyJwk,
    {name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const sig=await crypto.subtle.sign(
    {name:'ECDSA',hash:'SHA-256'},key,enc.encode(msg));
  return b64.enc(sig);
}
async function verifySig(pub,msg,sig64){
  const key=await crypto.subtle.importKey(
    'jwk',pub,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  return crypto.subtle.verify(
    {name:'ECDSA',hash:'SHA-256'},key,b64.dec(sig64),enc.encode(msg));
}
const makeBioIBAN = async (pub,ts)=>
  'BIO'+(await sha256(JSON.stringify(pub)+'|'+ts+'|'+INITIAL_BIO_CONSTANT)).slice(0,32).toUpperCase();

// ───── 5. AES-GCM + IndexedDB ─────
async function aesEncrypt(key,obj){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(obj)));
  return {iv,ct};
}
const aesDecrypt=(key,iv,ct)=>
  crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct).then(b=>JSON.parse(dec.decode(b)));

function openDB(){
  return new Promise((ok,no)=>{
    const r=indexedDB.open(DB_NAME,DB_VERSION);
    r.onupgradeneeded=e=>{
      const db=e.target.result;
      if(!db.objectStoreNames.contains(STORE))
        db.createObjectStore(STORE,{keyPath:'id'});
    };
    r.onsuccess=e=>ok(e.target.result); r.onerror=e=>no(e.target.error);
  });
}
async function saveVault(iv,ct,salt64){
  const db=await openDB();
  await new Promise(res=>{
    const tx=db.transaction(STORE,'readwrite');
    tx.objectStore(STORE).put({
      id:'vaultData',iv:b64.enc(iv),ct:b64.enc(ct),
      salt:salt64,authAttempts:VD.authAttempts,lockoutTimestamp:VD.lockoutTimestamp
    });
    tx.oncomplete=res;
  });
}
async function loadVault(){
  const db=await openDB();
  return new Promise(res=>{
    const r=db.transaction(STORE,'readonly').objectStore(STORE).get('vaultData');
    r.onsuccess=()=>res(r.result||null); r.onerror=()=>res(null);
  });
}
async function deriveAes(pin,salt){
  const km=await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:100_000,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}

// ───── 6. SEGMENT LEDGER INIT ─────
function initSegments(){
  if (VD.segments && VD.segments.length) return;
  for (let i = 1; i <= 12000; ++i) {
    VD.segments.push({
      segmentIndex: i,
      amount: 1,
      originalOwnerKey: VD.signingKey.publicKeyJwk,
      originalOwnerTS: VD.joinTimestamp,
      originalBioConst: INITIAL_BIO_CONSTANT + (VD.joinTimestamp - INITIAL_BIO_CONSTANT),
      previousOwnerKey: null,
      previousOwnerTS: null,
      previousBioConst: null,
      currentOwnerKey: i <= INITIAL_BALANCE_TVM ? VD.signingKey.publicKeyJwk : null,
      currentOwnerTS: i <= INITIAL_BALANCE_TVM ? VD.joinTimestamp : null,
      currentBioConst: i <= INITIAL_BALANCE_TVM ? (INITIAL_BIO_CONSTANT + (VD.joinTimestamp - INITIAL_BIO_CONSTANT)) : null,
      unlocked: i <= INITIAL_BALANCE_TVM,
      ownershipChangeCount: 0,
      unlockIndexRef: null,
      unlockIntegrityProof: i <= INITIAL_BALANCE_TVM ? "GENESIS" : null,
      spentProof: null,
      ownershipProof: null,
    });
  }
}

// ───── 7. CAP ENFORCEMENT ─────
function getUnlockCaps(now = Math.floor(Date.now()/1000)) {
  const day = 86400, month = 2592000, year = 31536000;
  let unlocks = VD.segments.filter(s =>
    s.unlocked && s.currentOwnerKey === VD.signingKey.publicKeyJwk && s.segmentIndex > INITIAL_BALANCE_TVM);
  let today = unlocks.filter(s => now - s.currentOwnerTS < day).length;
  let thisMonth = unlocks.filter(s => now - s.currentOwnerTS < month).length;
  let thisYear = unlocks.filter(s => now - s.currentOwnerTS < year).length;
  return {
    todayLeft: MAX_BONUS_DAY - today,
    monthLeft: MAX_BONUS_MONTH - thisMonth,
    yearLeft: (MAX_BONUS_YEAR_TVM / PER_TX_BONUS) - thisYear
  };
}

// ───── 8. PASS-PHRASE MODAL ─────
async function askPass(confirm=false,title='Enter Pass'){
  return new Promise(done=>{
    const mdl=document.getElementById('passModal');
    mdl.style.display='block';
    document.getElementById('passModalTitle').textContent=title;
    const p1=document.getElementById('passModalInput');
    const p2=document.getElementById('passModalConfirmInput');
    p1.value=''; p2.value='';
    document.getElementById('passModalConfirmLabel').style.display=confirm?'block':'none';
    const ok=()=>{
      const pin=p1.value.trim();
      if(pin.length<8) return alert('≥ 8 chars');
      if(confirm && pin!==p2.value.trim()) return alert('Mismatch');
      end(); done(pin);
    };
    const cancel=()=>{end(); done(null);}
    function end(){mdl.style.display='none';b1.removeEventListener('click',ok);b2.removeEventListener('click',cancel);}
    const b1=document.getElementById('passModalSaveBtn');
    const b2=document.getElementById('passModalCancelBtn');
    b1.addEventListener('click',ok); b2.addEventListener('click',cancel);
  });
}

// ───── 9. VAULT CREATION ─────
async function createVault(){
  const pin=await askPass(true,'Create Vault'); if(!pin) return;

  VD.joinTimestamp = VD.lastUTCTimestamp = Math.floor(Date.now()/1000);
  VD.initialBioConstant = INITIAL_BIO_CONSTANT;
  VD.bonusConstant = VD.joinTimestamp - INITIAL_BIO_CONSTANT;

  VD.signingKey = await genECDSA();
  VD.bioIBAN    = await makeBioIBAN(VD.signingKey.publicKeyJwk,VD.joinTimestamp);

  try{                                     // WebAuthn (best-effort)
    const cred=await navigator.credentials.create({
      publicKey:{
        challenge:crypto.getRandomValues(new Uint8Array(32)),
        rp:{name:'Bio-Vault'},
        user:{id:crypto.getRandomValues(new Uint8Array(16)),name:'user',displayName:'User'},
        pubKeyCredParams:[{type:'public-key',alg:-7}],
        authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required'},
        attestation:'none'
      }}); VD.credentialId=b64.enc(cred.rawId);
  }catch{ VD.credentialId='SW-'+Date.now(); }

  const salt=crypto.getRandomValues(new Uint8Array(16));
  derivedKey=await deriveAes(pin,salt);
  initSegments();
  const {iv,ct}=await aesEncrypt(derivedKey,VD);
  await saveVault(iv,ct,b64.enc(salt));

  vaultOpen=true; renderUI(); startUtcTicker();
}

// ───── 10. VAULT UNLOCK ─────
async function unlockFlow(){
  const stored=await loadVault();
  if(!stored) return createVault();

  if(stored.lockoutTimestamp && Date.now()/1000 < stored.lockoutTimestamp)
    return alert('Locked – wait a bit');

  const pin=await askPass(false,'Unlock Vault'); if(!pin) return;
  try{
    derivedKey=await deriveAes(pin,b64.dec(stored.salt));
    Object.assign(VD, await aesDecrypt(derivedKey,b64.dec(stored.iv),b64.dec(stored.ct)));
    if (!VD.segments) initSegments();
    try{ await navigator.credentials.get({
          publicKey:{
            challenge:crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials:VD.credentialId.startsWith('SW-')?[]:
              [{id:b64.dec(VD.credentialId),type:'public-key'}],
            userVerification:'required'}});
    }catch{}
    VD.authAttempts=0; VD.lockoutTimestamp=null;
    const {iv,ct}=await aesEncrypt(derivedKey,VD); await saveVault(iv,ct,stored.salt);
    vaultOpen=true; renderUI(); startUtcTicker();
  }catch{
    VD.authAttempts++;
    if(VD.authAttempts>=MAX_AUTH_TRIES)
      VD.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_SECS;
    const {iv,ct}=await aesEncrypt(derivedKey||await deriveAes('x',b64.dec(stored.salt)),VD);
    await saveVault(iv,ct,stored.salt);
    alert('Unlock failed');
  }
}

// ───── 11. PERSIST (helper) ─────
async function persist(){
  const {iv,ct}=await aesEncrypt(derivedKey,VD);
  const salt=(await loadVault()).salt;
  await saveVault(iv,ct,salt);
  SYNC_CH.postMessage({type:'vaultUpdate',payload:{iv:b64.enc(iv),data:b64.enc(ct)}});
}

// ───── 12. SPEND SEGMENT (CATCH OUT) ─────
async function sendTx() {
  if (!vaultOpen) return alert('Unlock first');
  const to = document.getElementById('receiverBioIBAN').value.trim();
  const amt = +document.getElementById('catchOutAmount').value;
  if (!to || amt <= 0) return alert('Invalid send');
  const now = Math.floor(Date.now() / 1000);

  let segIdx = VD.segments.findIndex(s =>
    s.unlocked && s.currentOwnerKey === VD.signingKey.publicKeyJwk && !s.spentProof);
  if (segIdx === -1) return alert('No unlocked segment available (cap reached?)');

  let seg = VD.segments[segIdx];
  seg.previousOwnerKey = seg.currentOwnerKey;
  seg.previousOwnerTS = seg.currentOwnerTS;
  seg.previousBioConst = seg.currentBioConst;
  seg.currentOwnerKey = to;
  seg.currentOwnerTS = now;
  seg.currentBioConst = seg.previousBioConst + 1;
  seg.ownershipChangeCount += 1;
  seg.spentProof = await sha256(
    seg.originalBioConst, seg.previousBioConst, seg.segmentIndex, seg.currentOwnerTS, await signPriv(seg.segmentIndex), "SPENT"
  );
  seg.ownershipProof = await sha256(
    seg.originalOwnerKey, seg.previousOwnerKey, seg.currentOwnerKey, seg.segmentIndex, seg.ownershipChangeCount, "OWNERSHIP"
  );
  seg.unlocked = false;

  // --- UNLOCK NEXT SEGMENT IF CAP ALLOWS
  let caps = getUnlockCaps(now);
  if (caps.todayLeft > 0 && caps.monthLeft > 0 && caps.yearLeft > 0) {
    let nextIdx = VD.segments.findIndex(s => !s.unlocked && !s.currentOwnerKey);
    if (nextIdx !== -1) {
      let nextSeg = VD.segments[nextIdx];
      nextSeg.unlocked = true;
      nextSeg.currentOwnerKey = VD.signingKey.publicKeyJwk;
      nextSeg.currentOwnerTS = now;
      nextSeg.currentBioConst = seg.currentBioConst;
      nextSeg.ownershipChangeCount = 0;
      nextSeg.unlockIndexRef = seg.segmentIndex;
      nextSeg.unlockIntegrityProof = await sha256(
        VD.bioIBAN, seg.segmentIndex, nextSeg.segmentIndex, now, "UNLOCK"
      );
      nextSeg.ownershipProof = await sha256(
        VD.signingKey.publicKeyJwk, null, VD.signingKey.publicKeyJwk, nextSeg.segmentIndex, 0, "OWNERSHIP"
      );
    }
  }

  VD.transactions.push({
    type: 'sent',
    amount: amt,
    timestamp: now,
    receiverBioIBAN: to,
    segmentIndex: seg.segmentIndex,
    spentProof: seg.spentProof,
    unlockCaps: getUnlockCaps(now)
  });
  await persist(); renderTx(); updateBal(); updateCapsStatus();
  alert('Segment sent and audit-proofed.');
}

// ───── 13. RECEIVE SEGMENT (CATCH IN) ─────
async function receiveTx(){
  if(!vaultOpen) return alert('Unlock first');
  const bc=prompt('Paste Bio-Catch (chainId|spentProof)'); if(!bc) return;
  const [id,spent]=bc.split('|'); const amt=+prompt('Amount (TVM)');
  if(!id||!spent||!amt) return alert('Bad data');
  const now=Math.floor(Date.now()/1000);

  let nextIdx = VD.segments.findIndex(s => !s.unlocked && !s.currentOwnerKey);
  if (nextIdx === -1) return alert('No available segment slot (wallet full)');
  let seg = VD.segments[nextIdx];
  seg.unlocked = true;
  seg.previousOwnerKey = 'unknown';
  seg.previousOwnerTS = now;
  seg.previousBioConst = 0;
  seg.currentOwnerKey = VD.signingKey.publicKeyJwk;
  seg.currentOwnerTS = now;
  seg.currentBioConst = 0 + 1;
  seg.ownershipChangeCount = 1;
  seg.spentProof = spent;
  seg.ownershipProof = await sha256(
    seg.originalOwnerKey, 'unknown', VD.signingKey.publicKeyJwk, seg.segmentIndex, seg.ownershipChangeCount, "OWNERSHIP"
  );

  VD.transactions.push({
    type:'received',amount:amt,timestamp:now,senderBioIBAN:'Unknown',
    segmentIndex: seg.segmentIndex,
    spentProof: spent,
    ownershipProof: seg.ownershipProof
  });
  await persist(); renderTx(); updateBal(); updateCapsStatus();
  alert('Received & claimed');
}

// ───── 14. EXPORT / IMPORT / COPY ─────
function exportBackup(){
  const blob=new Blob([JSON.stringify(VD,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download='vault_backup.json';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function exportCSV(){
  const rows=[['Bio-IBAN','ChainId/Bio-Catch','Amount','Timestamp','Type']];
  VD.transactions.forEach(t=>{
    rows.push([
      t.type==='sent'?t.receiverBioIBAN:t.senderBioIBAN||'',
      t.segmentIndex||'',
      t.amount, fmt(t.timestamp), t.type
    ]);
  });
  const csv='data:text/csv;charset=utf-8,'+rows.map(r=>r.join(',')).join('\r\n');
  const a=document.createElement('a'); a.href=encodeURI(csv); a.download='transactions.csv';
  document.body.appendChild(a); a.click(); a.remove();
}
function exportSegmentsLedger() {
  const blob = new Blob([JSON.stringify(VD.segments,null,2)],{type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'segments_audit.json';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function importBackup(file){
  try{
    Object.assign(VD, JSON.parse(await file.text()));
    await persist();
    alert('Backup imported. Unlock with your pass-phrase.');
  }catch{ alert('Bad backup file'); }
}
const copyIBAN=()=>navigator.clipboard.writeText(VD.bioIBAN||'')
  .then(()=>alert('IBAN copied'));

// ───── 15. RENDERING ─────
function renderTx(){
  const tb=document.getElementById('transactionBody'); tb.innerHTML='';
  [...VD.transactions].sort((a,b)=>b.timestamp-a.timestamp)
    .forEach(t=>tb.insertAdjacentHTML('beforeend',`
      <tr><td>${t.type==='sent'?t.receiverBioIBAN:t.senderBioIBAN||'—'}</td>
          <td>${t.segmentIndex||'—'}</td>
          <td>${num(t.amount)}</td>
          <td>${fmt(t.timestamp)}</td>
          <td>${t.type}</td></tr>`));
}
function updateBal(){
  const rx=VD.transactions.filter(x=>x.type==='received').reduce((s,t)=>s+t.amount,0);
  const sx=VD.transactions.filter(x=>x.type==='sent').reduce((s,t)=>s+t.amount,0);
  VD.balanceTVM=VD.initialBalanceTVM+rx-sx;
  VD.balanceUSD=+(VD.balanceTVM/EXCHANGE_RATE).toFixed(2);
  document.getElementById('tvmBalance').textContent=`Balance: ${num(VD.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent=`≈ ${num(VD.balanceUSD)} USD`;
  updateCapsStatus();
}
function updateCapsStatus(){
  let c = getUnlockCaps();
  document.getElementById('capsStatus').innerHTML =
    `Unlocks left: <b>${c.todayLeft} today</b> / <b>${c.monthLeft} this month</b> / <b>${c.yearLeft} this year</b>`;
}
function renderUI(){
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('bioibanInput').value=VD.bioIBAN||'';
  renderTx(); updateBal();
}
function startUtcTicker(){
  if(utcTimerId) clearInterval(utcTimerId);
  utcTimerId=setInterval(()=>{
    VD.lastUTCTimestamp=Math.floor(Date.now()/1000);
    document.getElementById('utcTime').textContent=fmt(VD.lastUTCTimestamp);
    document.getElementById('bioLineText').textContent=`🔄 BonusConstant: ${VD.bonusConstant}`;
  },1000);
}

// ───── 16. DOM READY ─────
window.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('enterVaultBtn') .addEventListener('click',unlockFlow);
  document.getElementById('catchOutBtn')  .addEventListener('click',sendTx);
  document.getElementById('catchInBtn')   .addEventListener('click',receiveTx);
  document.getElementById('copyBioIBANBtn') ?.addEventListener('click',copyIBAN);
  document.getElementById('exportBackupBtn')?.addEventListener('click',exportBackup);
  document.getElementById('exportBtn')      ?.addEventListener('click',exportCSV);
  document.getElementById('exportSegmentsBtn')?.addEventListener('click',exportSegmentsLedger);
  document.getElementById('importVaultFileInput')
    ?.addEventListener('change',e=>e.target.files[0]&&importBackup(e.target.files[0]));
  document.getElementById('saveWalletBtn')?.addEventListener('click',async()=>{
    if(VD.userWallet) return alert('Wallet already set');
    const addr=document.getElementById('userWalletAddress').value.trim();
    if(!addr.startsWith('0x')||addr.length<10) return alert('Bad address');
    VD.userWallet=addr; await persist(); alert('Wallet saved');
  });
  document.getElementById('autoConnectWalletBtn')?.addEventListener('click',async()=>{
    if(!window.ethereum) return alert('No MetaMask');
    await window.ethereum.request({method:'eth_requestAccounts'});
    const addr=(await new ethers.providers.Web3Provider(window.ethereum).getSigner().getAddress());
    if(!VD.userWallet){ VD.userWallet=addr; await persist(); alert('Wallet saved'); }
    else alert('Wallet already set');
  });

  if(navigator.storage?.persist){
    navigator.storage.persisted().then(p=>{ if(!p) navigator.storage.persist(); });
    setInterval(()=>navigator.storage.estimate().then(est=>{
      if(est&&est.quota&&est.usage/est.quota>0.85) alert('Storage nearly full'); }),
      STORAGE_CHECK_MS);
  }

  SYNC_CH.onmessage = async e=>{
    if(e.data?.type!=='vaultUpdate'||!derivedKey) return;
    const {iv,data}=e.data.payload;
    Object.assign(VD,await aesDecrypt(derivedKey,b64.dec(iv),b64.dec(data)));
    if(vaultOpen){renderTx();updateBal();}
  };
});

console.log('🎯 Bio-Vault loaded – regulator/production build');
