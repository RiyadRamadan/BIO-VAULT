/*****************************************************************
 *  Bio-Vault – SINGLE-SOURCE (no duplicates) – production build
 *****************************************************************/

/*───────────────── 1. GLOBAL CONSTANTS ─────────────────*/
const DB_NAME                  = 'BioVaultDB';
const DB_VERSION               = 1;
const VAULT_STORE              = 'vault';

const INITIAL_BALANCE_TVM      = 1200;
const PER_TX_BONUS             = 120;
const MAX_BONUSES_PER_DAY      = 3;
const MAX_BONUSES_PER_MONTH    = 30;
const MAX_ANNUAL_BONUS_TVM     = 10800;

const EXCHANGE_RATE            = 12;          // 1 USD = 12 TVM
const INITIAL_BIO_CONSTANT     = 1736565605;  // genesis
const LOCKOUT_DURATION_SECONDS = 3600;        // 1 h
const MAX_AUTH_ATTEMPTS        = 3;

const VAULT_BACKUP_KEY         = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL   = 300_000;     // 5 min
const vaultSyncChannel         = new BroadcastChannel('vault-sync');

/*───────────────── 2. RUNTIME STATE ─────────────────*/
let derivedKey        = null;
let vaultUnlocked     = false;
let utcTickerId       = null;

const vaultData = {
  signingKey  : { privateKeyJwk:null, publicKeyJwk:null },
  bioIBAN     : null,

  initialBioConstant : 0,
  bonusConstant      : 0,

  initialBalanceTVM: INITIAL_BALANCE_TVM,
  balanceTVM       : 0,
  balanceUSD       : 0,

  joinTimestamp    : 0,
  lastUTCTimestamp : 0,
  transactions     : [],
  lastTransactionHash:'', finalChainHash:'',

  credentialId     : null,
  authAttempts     : 0,
  lockoutTimestamp : null,

  dailyCashback : { date:'', usedCount:0 },
  monthlyUsage  : { yearMonth:'', usedCount:0 },
  annualBonusUsed: 0,

  userWallet : '',
  nextBonusId: 1
};

/*───────────────── 3. CRYPTO HELPERS ─────────────────*/
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = { to:buf=>btoa(String.fromCharCode(...new Uint8Array(buf))),
              from:str=>Uint8Array.from(atob(str),c=>c.charCodeAt(0)) };

async function sha256(str){
  const h=await crypto.subtle.digest('SHA-256',enc.encode(str));
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function genKeyPair(){
  const kp=await crypto.subtle.generateKey(
    {name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  return {
    privateKeyJwk:await crypto.subtle.exportKey('jwk',kp.privateKey),
    publicKeyJwk :await crypto.subtle.exportKey('jwk',kp.publicKey)
  };
}
async function signWithPriv(msg){
  const key=await crypto.subtle.importKey(
    'jwk',vaultData.signingKey.privateKeyJwk,
    {name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const sig=await crypto.subtle.sign(
    {name:'ECDSA',hash:'SHA-256'},key,enc.encode(msg));
  return b64.to(sig);
}
async function verifySig(pub,msg,sigB64){
  const key=await crypto.subtle.importKey(
    'jwk',pub,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  return crypto.subtle.verify(
    {name:'ECDSA',hash:'SHA-256'},key,b64.from(sigB64),enc.encode(msg));
}
async function deriveBioIBAN(pub,ts){
  const h=await sha256(`${JSON.stringify(pub)}|${ts}|${INITIAL_BIO_CONSTANT}`);
  return 'BIO'+h.slice(0,32).toUpperCase();
}

/*───────────────── 4. AES-GCM + IndexedDB ─────────────────*/
async function aesEncrypt(key,obj){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(obj)));
  return {iv,ct};
}
async function aesDecrypt(key,iv,ct){
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);
  return JSON.parse(dec.decode(pt));
}

function openDB(){
  return new Promise((ok,bad)=>{
    const req=indexedDB.open(DB_NAME,DB_VERSION);
    req.onupgradeneeded=e=>{
      const db=e.target.result;
      if(!db.objectStoreNames.contains(VAULT_STORE))
        db.createObjectStore(VAULT_STORE,{keyPath:'id'});
    };
    req.onsuccess=e=>ok(e.target.result);
    req.onerror=e=>bad(e.target.error);
  });
}
async function saveVault(iv,ct,saltB64){
  const db=await openDB();
  return new Promise(res=>{
    const tx=db.transaction(VAULT_STORE,'readwrite');
    tx.objectStore(VAULT_STORE).put({
      id:'vaultData',
      iv:b64.to(iv),
      ct:b64.to(ct),
      salt:saltB64,
      authAttempts:vaultData.authAttempts,
      lockoutTimestamp:vaultData.lockoutTimestamp
    });
    tx.oncomplete=()=>res();
  });
}
async function loadVault(){
  const db=await openDB();
  return new Promise(res=>{
    const r=db.transaction(VAULT_STORE,'readonly')
              .objectStore(VAULT_STORE).get('vaultData');
    r.onsuccess=()=>res(r.result||null);
    r.onerror  =()=>res(null);
  });
}
async function deriveAesKey(pin,salt){
  const km=await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:100_000,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}

/*───────────────── 5. BALANCE SEGMENT ─────────────────*/
class BalanceSegment{
  constructor({amount,ownerKeyJwk,ownerTS}){
    this.amount=amount;
    this.ownerHistory=[{key:ownerKeyJwk,ts:ownerTS}];
    this.chainId=null;this.spentProof=null;
    this.ownershipProof=null;this.receiverSignature=null;
  }
  async init(){ this.chainId=await sha256(`${this.amount}|${Date.now()}`); }
  async spend(ts){ this.spentProof=await sha256(`${this.chainId}|${this.amount}|${ts}|SPENT`); }
  async claim(newKey,ts){
    this.ownerHistory.push({key:newKey,ts});
    this.ownershipProof=await sha256(`${this.chainId}|${this.amount}|${ts}|OWNED`);
    const payload=`${this.chainId}|${this.amount}|${ts}|${this.ownershipProof}`;
    this.receiverSignature=await signWithPriv(payload);
  }
  async verify(){
    const last=this.ownerHistory.at(-1);
    const payload=`${this.chainId}|${this.amount}|${last.ts}|${this.ownershipProof}`;
    return verifySig(last.key,payload,this.receiverSignature);
  }
}

/*───────────────── 6. PASS-PHRASE PROMPT (single impl.) ─────────────────*/
async function askPass(confirm=false,title='Enter Passphrase'){
  return new Promise(done=>{
    const mdl=document.getElementById('passModal');
    document.getElementById('passModalTitle').textContent=title;
    const i=document.getElementById('passModalInput');
    const c=document.getElementById('passModalConfirmInput');
    i.value='';c.value='';
    document.getElementById('passModalConfirmLabel').style.display=confirm?'block':'none';
    const ok=()=>{const p=i.value.trim();
      if(p.length<8)return alert('≥8 chars');
      if(confirm&&p!==c.value.trim())return alert('Mismatch');
      end();done(p);};
    const no=()=>{end();done(null);};
    function end(){mdl.style.display='none';b1.removeEventListener('click',ok);b2.removeEventListener('click',no);}
    const b1=document.getElementById('passModalSaveBtn');
    const b2=document.getElementById('passModalCancelBtn');
    b1.addEventListener('click',ok);b2.addEventListener('click',no);
    mdl.style.display='block';
  });
}

/*───────────────── 7. VAULT CREATION ─────────────────*/
async function createVault(){
  const pin=await askPass(true,'Create Vault'); if(!pin) return;

  vaultData.joinTimestamp = Math.floor(Date.now()/1000);
  vaultData.lastUTCTimestamp=vaultData.joinTimestamp;
  vaultData.initialBioConstant = INITIAL_BIO_CONSTANT;
  vaultData.bonusConstant      = vaultData.joinTimestamp-INITIAL_BIO_CONSTANT;

  vaultData.signingKey = await genKeyPair();
  vaultData.bioIBAN    = await deriveBioIBAN(vaultData.signingKey.publicKeyJwk,vaultData.joinTimestamp);

  const cred=await navigator.credentials.create({
    publicKey:{
      challenge:crypto.getRandomValues(new Uint8Array(32)),
      rp:{name:'Bio-Vault'},
      user:{id:crypto.getRandomValues(new Uint8Array(16)),name:'user',displayName:'User'},
      pubKeyCredParams:[{type:'public-key',alg:-7}],
      authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required'},
      attestation:'none'}
  });
  vaultData.credentialId=b64.to(cred.rawId);

  const salt=crypto.getRandomValues(new Uint8Array(16));
  derivedKey=await deriveAesKey(pin,salt);
  const {iv,ct}=await aesEncrypt(derivedKey,vaultData);
  await saveVault(iv,ct,b64.to(salt));

  vaultUnlocked=true; renderUI(); startUtcTicker();
}

/*───────────────── 8. VAULT UNLOCK ─────────────────*/
async function unlockFlow(){
  const stored=await loadVault();
  if(!stored) return createVault();

  if(stored.lockoutTimestamp && Date.now()/1000 < stored.lockoutTimestamp)
    return alert('Locked. Come back later.');

  const pin=await askPass(false,'Unlock Vault'); if(!pin) return;

  try{
    derivedKey=await deriveAesKey(pin,b64.from(stored.salt));
    Object.assign(vaultData,
      await aesDecrypt(derivedKey,b64.from(stored.iv),b64.from(stored.ct)));

    await navigator.credentials.get({
      publicKey:{
        challenge:crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials:[{id:b64.from(vaultData.credentialId),type:'public-key'}],
        userVerification:'required'} });

    vaultData.authAttempts=0; vaultData.lockoutTimestamp=null;
    const {iv,ct}=await aesEncrypt(derivedKey,vaultData);
    await saveVault(iv,ct,stored.salt);

    vaultUnlocked=true; renderUI(); startUtcTicker();
  }catch(e){
    vaultData.authAttempts++;
    if(vaultData.authAttempts>=MAX_AUTH_ATTEMPTS)
      vaultData.lockoutTimestamp=Math.floor(Date.now()/1000)+LOCKOUT_DURATION_SECONDS;
    const {iv,ct}=await aesEncrypt(derivedKey||await deriveAesKey('dummy',b64.from(stored.salt)),vaultData);
    await saveVault(iv,ct,stored.salt);
    alert('Unlock failed');
  }
}

/*───────────────── 9. BONUS & CASHBACK (single impl.) ─────────────────*/
function _resetDay(now){const d=new Date(now*1000).toISOString().slice(0,10);
  if(vaultData.dailyCashback.date!==d){vaultData.dailyCashback={date:d,usedCount:0};}}
function _resetMonth(now){const d=new Date(now*1000);
  const ym=`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  if(vaultData.monthlyUsage.yearMonth!==ym){vaultData.monthlyUsage={yearMonth:ym,usedCount:0};}}
function canBonus(now,txType,amt){
  _resetDay(now); _resetMonth(now);
  if(vaultData.dailyCashback.usedCount>=MAX_BONUSES_PER_DAY) return false;
  if(vaultData.monthlyUsage.usedCount>=MAX_BONUSES_PER_MONTH) return false;
  if(vaultData.annualBonusUsed>=MAX_ANNUAL_BONUS_TVM) return false;
  if(txType==='sent' && amt<=240) return false;
  return true;
}
function recordBonus(){
  vaultData.dailyCashback.usedCount++;
  vaultData.monthlyUsage.usedCount++;
  vaultData.annualBonusUsed+=PER_TX_BONUS;
}

/*───────────────── 10. TX FLOW ─────────────────*/
async function sendTx(){
  if(!vaultUnlocked) return alert('Unlock first');
  const to=document.getElementById('receiverBioIBAN').value.trim();
  const amt=+document.getElementById('catchOutAmount').value;
  if(!to||amt<=0) return alert('Invalid');
  const now=Math.floor(Date.now()/1000);

  const seg=new BalanceSegment({amount:amt,ownerKeyJwk:vaultData.signingKey.publicKeyJwk,ownerTS:now});
  await seg.init(); await seg.spend(now);

  vaultData.transactions.push({
    type:'sent',amount:amt,timestamp:now,receiverBioIBAN:to,
    chainId:seg.chainId,spentProof:seg.spentProof
  });
  await persist();

  alert('Share this Bio-Catch:\n'+seg.chainId+'|'+seg.spentProof);
  renderTx(); updateBal();
}
async function receiveTx(){
  if(!vaultUnlocked) return alert('Unlock first');
  const encCatch=prompt('Paste Bio-Catch (chainId|spentProof)');
  if(!encCatch)return;
  const [id,spent]=encCatch.split('|');
  const amt=+prompt('Amount (TVM)');
  const now=Math.floor(Date.now()/1000);

  const seg=new BalanceSegment({amount:amt,ownerKeyJwk:vaultData.signingKey.publicKeyJwk,ownerTS:now});
  seg.chainId=id; seg.spentProof=spent; await seg.claim(vaultData.signingKey.publicKeyJwk,now);

  vaultData.transactions.push({
    type:'received',amount:amt,timestamp:now,senderBioIBAN:'Unknown',
    chainId:id,ownershipProof:seg.ownershipProof,receiverSignature:seg.receiverSignature
  });
  await persist(); alert('Received');
  renderTx(); updateBal();
}
async function persist(){const {iv,ct}=await aesEncrypt(derivedKey,vaultData);
  const salt=(await loadVault()).salt; await saveVault(iv,ct,salt);}

/*───────────────── 11. UI HELPERS ─────────────────*/
const fmt=ts=>new Date(ts*1000).toISOString().replace('T',' ').slice(0,19);
const num=n=>n.toLocaleString();

function renderTx(){
  const body=document.getElementById('transactionBody'); body.innerHTML='';
  [...vaultData.transactions].sort((a,b)=>b.timestamp-a.timestamp)
    .forEach(t=>body.insertAdjacentHTML('beforeend',`
      <tr><td>${t.type==='sent'?t.receiverBioIBAN:t.senderBioIBAN||'—'}</td>
          <td>${t.chainId||'—'}</td>
          <td>${num(t.amount)}</td><td>${fmt(t.timestamp)}</td><td>${t.type}</td></tr>`));
}
function updateBal(){
  const rx=vaultData.transactions.filter(x=>x.type==='received').reduce((s,t)=>s+t.amount,0);
  const sx=vaultData.transactions.filter(x=>x.type==='sent').reduce((s,t)=>s+t.amount,0);
  vaultData.balanceTVM=vaultData.initialBalanceTVM+rx-sx;
  vaultData.balanceUSD=+(vaultData.balanceTVM/EXCHANGE_RATE).toFixed(2);
  document.getElementById('tvmBalance').textContent=`Balance: ${num(vaultData.balanceTVM)} TVM`;
  document.getElementById('usdBalance').textContent =`≈ ${num(vaultData.balanceUSD)} USD`;
}
function renderUI(){
  document.getElementById('lockedScreen').classList.add('hidden');
  document.getElementById('vaultUI').classList.remove('hidden');
  renderTx(); updateBal();
}
function startUtcTicker(){
  if(utcTickerId) clearInterval(utcTickerId);
  utcTickerId=setInterval(()=>{
    vaultData.lastUTCTimestamp=Math.floor(Date.now()/1000);
    document.getElementById('utcTime').textContent=fmt(vaultData.lastUTCTimestamp);
    document.getElementById('bioLineText').textContent=`🔄 BonusConstant: ${vaultData.bonusConstant}`;
  },1000);
}

/*───────────────── 12. DOM READY ─────────────────*/
window.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('enterVaultBtn').addEventListener('click',unlockFlow);
  document.getElementById('catchOutBtn') .addEventListener('click',sendTx);
  document.getElementById('catchInBtn')  .addEventListener('click',receiveTx);

  // (export / import / copy IBAN etc. buttons wired here if needed)

  vaultSyncChannel.onmessage=async e=>{
    if(e.data?.type!=='vaultUpdate'||!derivedKey) return;
    const {iv,data}=e.data.payload;
    Object.assign(vaultData,
      await aesDecrypt(derivedKey,b64.from(iv),b64.from(data)));
    if(vaultUnlocked){renderTx();updateBal();}
  };
});

console.log('🎯 Bio-Vault loaded – single-source build');
