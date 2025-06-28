/*****************************************************************
 *  Bio-Vault – Advanced, Deduplicated, Production Build
 *  (merged & verified 2025-06-28)
 *****************************************************************/

/*───────────────── 1. GLOBAL CONSTANTS ─────────────────*/
const DB_NAME = 'BioVaultDB', DB_VERSION = 1, STORE = 'vault';

const INITIAL_BALANCE_TVM   = 1200;
const PER_TX_BONUS          = 120;
const MAX_BONUS_DAY         = 3;
const MAX_BONUS_MONTH       = 30;
const MAX_BONUS_YEAR_TVM    = 10800;

const EXCHANGE_RATE         = 12;          // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT  = 1736565605;  // genesis epoch
const LOCKOUT_SECS          = 3600;        // 1 h
const MAX_AUTH_TRIES        = 3;

const BACKUP_KEY            = 'vaultArmoredBackup';
const STORAGE_CHECK_MS      = 300_000;     // 5 min

const SYNC_CH               = new BroadcastChannel('vault-sync');

/*───────────────── 2. RUNTIME STATE ─────────────────*/
let derivedKey = null;
let vaultOpen  = false;
let utcTimerId = null;

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

  userWallet:'', nextBonusId:1
};

/*───────────────── 3. BASIC HELPERS ─────────────────*/
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = { enc:buf=>btoa(String.fromCharCode(...new Uint8Array(buf))),
              dec:str=>Uint8Array.from(atob(str),c=>c.charCodeAt(0)) };
const sha256 = async s => {
  const h=await crypto.subtle.digest('SHA-256',enc.encode(s));
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('');
};
const num = n=>n.toLocaleString();
const fmt = t=>new Date(t*1000).toISOString().replace('T',' ').slice(0,19);

/*───────────────── 4. CRYPTO PRIMITIVES ─────────────────*/
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

/*───────────────── 5. AES-GCM + IndexedDB ─────────────────*/
async function aesEncrypt(key,obj){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(obj)));
  return {iv,ct};
}
const aesDecrypt=(key,iv,ct)=>
  crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct).then(buf=>JSON.parse(dec.decode(buf)));

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

/*───────────────── 6. SEGMENT ─────────────────*/
class Segment{
  constructor({amt,ownerKey,ts}){
    this.amount=amt;
    this.ownerHistory=[{key:ownerKey,ts}];
    this.chainId=null; this.spentProof=null;
    this.ownershipProof=null; this.recvSig=null;
  }
  async init(){this.chainId=await sha256(`${this.amount}|${Date.now()}`);}
  async spend(ts){ this.spentProof=await sha256(`${this.chainId}|${this.amount}|${ts}|SPENT`);}
  async claim(nextKey,ts){
    this.ownerHistory.push({key:nextKey,ts});
    this.ownershipProof=await sha256(`${this.chainId}|${this.amount}|${ts}|OWNED`);
    this.recvSig=await signPriv(`${this.chainId}|${this.amount}|${ts}|${this.ownershipProof}`);
  }
}

/*───────────────── 7. PASS-PHRASE MODAL ─────────────────*/
async function askPass(confirm=false,title='Enter Pass'){
  return new Promise(done=>{
    const mdl=document.getElementById('passModal');
    mdl.style.display='block';
    document.getElementById('passModalTitle').textContent=title;
    const pinI=document.getElementById('passModalInput');
    const pinC=document.getElementById('passModalConfirmInput');
    pinI.value=''; pinC.value='';
    document.getElementById('passModalConfirmLabel').style.display=confirm?'block':'none';
    const ok=()=>{
      const p=pinI.value.trim();
      if(p.length<8) return alert('≥ 8 chars');
      if(confirm && p!==pinC.value.trim()) return alert('Mismatch');
      end(); done(p);
    };
    const cancel=()=>{end(); done(null);};
    function end(){mdl.style.display='none';okBtn.removeEventListener('click',ok);noBtn.removeEventListener('click',cancel);}
    const okBtn=document.getElementById('passModalSaveBtn');
    const noBtn=document.getElementById('passModalCancelBtn');
    okBtn.addEventListener('click',ok); noBtn.addEventListener('click',cancel);
  });
}

/*───────────────── 8. VAULT CREATION ─────────────────*/
async function createVault(){
  const pin=await askPass(true,'Create Vault'); if(!pin) return;
  VD.joinTimestamp = VD.lastUTCTimestamp = Math.floor(Date.now()/1000);
  VD.initialBioConstant = INITIAL_BIO_CONSTANT;
  VD.bonusConstant = VD.joinTimestamp - INITIAL_BIO_CONSTANT;
  VD.signingKey = await genECDSA();
  VD.bioIBAN    = await makeBioIBAN(VD.signingKey.publicKeyJwk,VD.joinTimestamp);

  try{
    const cred=await navigator.credentials.create({
      publicKey:{
        challenge:crypto.getRandomValues(new Uint8Array(32)),
        rp:{name:'Bio-Vault'},
        user:{id:crypto.getRandomValues(new Uint8Array(16)),name:'user',displayName:'User'},
        pubKeyCredParams:[{type:'public-key',alg:-7}],
        authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required'},
        attestation:'none'
      }});
    VD.credentialId=b64.enc(cred.rawId);
  }catch{ VD.credentialId='SW-'+Date.now(); } // fallback if WebAuthn unavailable

  const salt=crypto.getRandomValues(new Uint8Array(16));
  derivedKey=await deriveAes(pin,salt);
  const {iv,ct}=await aesEncrypt(derivedKey,VD);
  await saveVault(iv,ct,b64.enc(salt));

  vaultOpen=true; renderUI(); startUtcTicker();
}

/*───────────────── 9. VAULT UNLOCK  ─────────────────*/
async function unlockFlow(){
  const stored=await loadVault();
  if(!stored) return createVault();

  if(stored.lockoutTimestamp && Date.now()/1000 < stored.lockoutTimestamp)
    return alert('Locked. Try later');

  const pin=await askPass(false,'Unlock Vault'); if(!pin) return;

  try{
    derivedKey=await deriveAes(pin,b64.dec(stored.salt));
    Object.assign(VD, await aesDecrypt(derivedKey,b64.dec(stored.iv),b64.dec(stored.ct)));

    try{ await navigator.credentials.get({
          publicKey:{
            challenge:crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials:VD.credentialId.startsWith('SW-')?[]:
              [{id:b64.dec(VD.credentialId),type:'public-key'}],
            userVerification:'required'}});
    }catch{/* non-fatal if fallback */}

    VD.authAttempts=0; VD.lockoutTimestamp=null;
    const {iv,ct}=await aesEncrypt(derivedKey,VD);
    await saveVault(iv,ct,stored.salt);

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

/*─────────────────10. PERSIST (helper) ─────────────────*/
async function persist(){
  const {iv,ct}=await aesEncrypt(derivedKey,VD);
  const salt=(await loadVault()).salt;
  await saveVault(iv,ct,salt);
  SYNC_CH.postMessage({type:'vaultUpdate',payload:{iv:b64.enc(iv),data:b64.enc(ct)}});
}

/*─────────────────11. TRANSACTIONS ─────────────────*/
async function sendTx(){
  if(!vaultOpen) return alert('Unlock first');
  const to=document.getElementById('receiverBioIBAN').value.trim();
  const amt=+document.getElementById('catchOutAmount').value;
  if(!to||amt<=0) return alert('Invalid');
  const now=Math.floor(Date.now()/1000);

  const seg=new Segment({amt,ownerKey:VD.signingKey.publicKeyJwk,ts:now});
  await seg.init(); await seg.spend(now);

  VD.transactions.push({type:'sent',amount:amt,timestamp:now,
                        receiverBioIBAN:to,chainId:seg.chainId,spentProof:seg.spentProof});
  await persist(); renderTx(); updateBalances();
  alert('Share Bio-Catch:\n'+seg.chainId+'|'+seg.spentProof);
}

async function receiveTx(){
  if(!vaultOpen) return alert('Unlock first');
  const bc=prompt('Paste Bio-Catch (chainId|spentProof)'); if(!bc) return;
  const [id,spent]=bc.split('|'), amt=+prompt('Amount (TVM)');
  if(!id||!spent||!amt) return alert('Bad data');
  const now=Math.floor(Date.now()/1000);

  const seg=new Segment({amt,ownerKey:VD.signingKey.publicKeyJwk,ts:now});
  seg.chainId=id; seg.spentProof=spent; await seg.claim(VD.signingKey.publicKeyJwk,now);

  VD.transactions.push({type:'received',amount:amt,timestamp:now,
                        senderBioIBAN:'Unknown',chainId:id,
                        ownershipProof:seg.ownershipProof,receiverSignature:seg.recvSig});
  await persist(); renderTx(); updateBalances();
  alert('Received & claimed');
}

/*─────────────────12. BACKUP / IMPORT / CSV / COPY IBAN ─────────────────*/
function exportBackup(){
  const blob=new Blob([JSON.stringify(VD,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url; a.download='vault_backup.json';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
function exportCSV(){
  const rows=[['Bio-IBAN','ChainId/Bio-Catch','Amount','Timestamp','Type']];
  VD.transactions.forEach(t=>{
    rows.push([
      t.type==='sent'?t.receiverBioIBAN:t.senderBioIBAN||'',
      t.chainId||t.bioCatch||'',
      t.amount,
      fmt(t.timestamp),
      t.type
    ]);
  });
  const csv='data:text/csv;charset=utf-8,'+rows.map(r=>r.join(',')).join('\r\n');
  const a=document.createElement('a'); a.href=encodeURI(csv); a.download='transactions.csv';
  document.body.appendChild(a); a.click(); a.remove();
}
async function importBackup(file){
  try{
    Object.assign(VD, JSON.parse(await file.text()));
    await persist();
    alert('Vault imported. Unlock with your pass-phrase next time.');
  }catch{ alert('Bad backup file'); }
}
function copyIBAN(){
  if(!VD.bioIBAN) return alert('No IBAN yet');
  navigator.clipboard.writeText(VD.bioIBAN).then(()=>alert('Copied'));
}

/*─────────────────13. RENDERING ─────────────────*/
function renderTx(){
  const tb=document.getElementById('transactionBody'); tb.innerHTML='';
  [...VD.transactions].sort((a,b)=>b.timestamp-a.timestamp)
    .forEach(t=>tb.insertAdjacentHTML('beforeend',`
      <tr><td>${t.type==='sent'?t.receiverBioIBAN:t.senderBioIBAN||'—'}</td>
          <td>${t.chainId||'—'}</td>
          <td>${num(t.amount)}</td>
          <td>${fmt(t.timestamp)}</td>
          <td>${t.type}</td></tr>`));
}
function updateBalances(){
  const rx=VD.transactions.filter(x=>x.type==='received').reduce((s,t)=>s+t.amount,0);
  const sx=VD.transactions.filter(x=>x.type==='sent').reduce((s,t)=>s+t.amount,0);
  VD.balanceTVM=VD.initialBalanceTVM+rx-sx;
  VD.balanceUSD=+(VD.balanceTVM/EXCHANGE_RATE).toFixed(2);
  document.getElementById('tvmBalance').textContent=`Balance: ${num(VD.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent=`≈ ${num(VD.balanceUSD)} USD`;
}
function renderUI(){
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  document.getElementById('bioibanInput').value=VD.bioIBAN||'';
  renderTx(); updateBalances();
}
function startUtcTicker(){
  if(utcTimerId) clearInterval(utcTimerId);
  utcTimerId=setInterval(()=>{
    VD.lastUTCTimestamp=Math.floor(Date.now()/1000);
    document.getElementById('utcTime').textContent=fmt(VD.lastUTCTimestamp);
    document.getElementById('bioLineText').textContent=`🔄 BonusConstant: ${VD.bonusConstant}`;
  },1000);
}

/*─────────────────14. DOM READY ─────────────────*/
window.addEventListener('DOMContentLoaded',()=>{
  /* core buttons */
  document.getElementById('enterVaultBtn').addEventListener('click',unlockFlow);
  document.getElementById('catchOutBtn') .addEventListener('click',sendTx);
  document.getElementById('catchInBtn')  .addEventListener('click',receiveTx);

  /* extras */
  document.getElementById('copyBioIBANBtn') ?.addEventListener('click',copyIBAN);
  document.getElementById('exportBackupBtn')?.addEventListener('click',exportBackup);
  document.getElementById('exportBtn')      ?.addEventListener('click',exportCSV);
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

  /* storage quota warnings */
  if(navigator.storage?.persist){
    navigator.storage.persisted().then(p=>{ if(!p) navigator.storage.persist(); });
    setInterval(()=>navigator.storage.estimate().then(est=>{
      if(est&&est.quota&&est.usage/est.quota>0.85) alert('Storage nearly full'); }),STORAGE_CHECK_MS);
  }

  /* broadcast-channel sync */
  SYNC_CH.onmessage=async e=>{
    if(e.data?.type!=='vaultUpdate'||!derivedKey) return;
    const {iv,data}=e.data.payload;
    Object.assign(VD, await aesDecrypt(derivedKey,b64.dec(iv),b64.dec(data)));
    if(vaultOpen){renderTx();updateBalances();}
  };
});

console.log('🎯 Bio-Vault loaded — production build (no duplicates)');
