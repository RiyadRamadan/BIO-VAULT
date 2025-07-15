
"use strict";

/*────────────────────────── 1.  GLOBAL CONSTANTS ───────────────────────────*/
const KEY_HASH_SALT = "Balance-Chain-v1";

const PBKDF2_ITERS  = 310_000;          

const Protocol = Object.freeze({
  GENESIS_BIO_CONST: 1736565605,        
  SEGMENTS: Object.freeze({
    TOTAL:          12_000,
    UNLOCKED_INIT:  1_200,
    PER_DAY:              3,
    PER_MONTH:           30,
    PER_YEAR:            90
  }),
  TVM: Object.freeze({
    SEGMENTS_PER_TOKEN: 12,
    CLAIM_CAP:          1_000
  }),
  HISTORY_MAX: 10
});

const Limits = Object.freeze({
  AUTH: Object.freeze({ MAX_ATTEMPTS: 5, LOCKOUT_SECONDS: 3_600 }),
  PAGE: Object.freeze({ DEFAULT_SIZE: 10 })
});

const DB = Object.freeze({
  NAME:    "BalanceChainVaultDB",
  VERSION: 1,
  STORE:   "vaultStore"
});

/*────────────────────────── 2.  LOW-LEVEL HELPERS ──────────────────────────*/
const enc = new TextEncoder();
const dec = new TextDecoder();

function bufferToBase64(buf){
  const u8 = new Uint8Array(buf);
  const CHUNK = 0x8000;
  let bin = "";
  for (let i = 0; i < u8.length; i += CHUNK)
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  return btoa(bin);
}
const base64ToBuffer = b64 =>{
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

const sha256 = async data =>
  bufferToBase64(await crypto.subtle.digest(
    "SHA-256", typeof data === "string" ? enc.encode(data) : data));

const randomBytes = len => crypto.getRandomValues(new Uint8Array(len));

/* simple clipboard util */
function copyToClipboard(text){
  if (navigator.clipboard)
    return navigator.clipboard.writeText(text)
      .then(()=>toast("Copied!"))
      .catch(()=>toast("Copy failed", true));

  /* fallback – execCommand for legacy browsers */
  const ta = Object.assign(document.createElement("textarea"), { value:text });
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand("copy"); toast("Copied!"); }
  catch{ toast("Copy failed", true); }
  ta.remove();
}

/*────────────────────────── 4B.  TIME‑SYNC SERVICE ─────────────────────────*/
class TimeSyncService{
  static _offset = 0;                       // seconds (server − local)
  static async sync(){
    try{
      const r  = await fetch("https://worldtimeapi.org/api/ip");
      const { unixtime } = await r.json();
      TimeSyncService._offset = unixtime - Math.floor(Date.now()/1000);
    }catch{ console.warn("⏰ time‑sync failed – using local clock"); }
  }
  static now(){ return Math.floor(Date.now()/1000) + TimeSyncService._offset; }
}

/*────────────────────────── 3.  INDEXED‑DB LAYER ───────────────────────────*/
class VaultStorage{
  static _open(){
    return new Promise((res,rej)=>{
      const req = indexedDB.open(DB.NAME, DB.VERSION);
      req.onupgradeneeded = e=>{
        const db = e.target.result;
        if (!db.objectStoreNames.contains(DB.STORE))
          db.createObjectStore(DB.STORE, { keyPath:"id" });
      };
      req.onsuccess = ()=>res(req.result);
      req.onerror   = ()=>rej(req.error);
    });
  }
  static async save(iv, ct, saltB64, meta={}){
    const db = await VaultStorage._open();
    await new Promise((res,rej)=>{
      const tx = db.transaction(DB.STORE, "readwrite");
      tx.objectStore(DB.STORE).put({
        id:"vaultData",
        iv:bufferToBase64(iv),
        ciphertext:bufferToBase64(ct),
        salt:saltB64,
        ...meta
      });
      tx.oncomplete = res;
      tx.onerror    = () => rej(tx.error);
    });
  }
  static async load(){
    const db = await VaultStorage._open();
    return new Promise((res,rej)=>{
      const tx  = db.transaction(DB.STORE, "readonly");
      const req = tx.objectStore(DB.STORE).get("vaultData");
      req.onsuccess = ()=>{
        if(!req.result) return res(null);
        const r = req.result;
        res({
          iv:         base64ToBuffer(r.iv),
          ciphertext: base64ToBuffer(r.ciphertext),
          salt:       base64ToBuffer(r.salt),
          ...r
        });
      };
      req.onerror = ()=>rej(req.error);
    });
  }
  static deleteDB(){
    return new Promise((res,rej)=>{
      const req = indexedDB.deleteDatabase(DB.NAME);
      req.onblocked = res; req.onsuccess = res; req.onerror = ()=>rej(req.error);
    });
  }
}

class CryptoService{
  static deriveKeyFromPIN(pin, salt){
    return crypto.subtle.importKey("raw", enc.encode(pin), { name:"PBKDF2" }, false, ["deriveKey"])
      .then(mat=>crypto.subtle.deriveKey(
        { name:"PBKDF2", salt, iterations:PBKDF2_ITERS, hash:"SHA-256" },
        mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]));
  }
  static encrypt(key, obj){
    const iv = randomBytes(12);
    return crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)))
      .then(ciphertext=>({ iv, ciphertext }));
  }
  static decrypt(key, iv, ct){
    return crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct)
      .then(pt=>JSON.parse(dec.decode(pt)));
  }
  
}
/*────────────────────────── 5.  HASH & PROOF HELPERS ───────────────────────*/
const hashDeviceKeyWithSalt = async (buf, extra="") =>
  sha256(new Uint8Array([
    ...enc.encode(KEY_HASH_SALT),
    ...new Uint8Array(buf),
    ...enc.encode(extra)
  ]));
/*──────── constant‑time string compare ────────*/
const ctEqual = (a = "", b = "") => {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
};


import canonicalize from "canonicalize";
const _canon = o => canonicalize(o);
const computeUnlockIntegrityProof = seg=>sha256(`unlock:${_canon(seg)}`);
const computeSpentProof            = seg=>sha256(`spent:${_canon(seg)}`);
const computeOwnershipProof        = seg=>sha256(`own:${_canon(seg)}`);

/*────────────────────────── 6.  CAP & HISTORY ─────────────────────────────*/
const getPeriodStrings = ts=>{
  const d = new Date(ts*1000);
  return {
    day  : d.toISOString().slice(0,10),
    month: d.toISOString().slice(0,7),
    year : String(d.getUTCFullYear())
  };
};
class CapEnforcer{
  static checkAndRecordUnlock(vault, now, cnt=1){
    const rec = vault.unlockRecords;
    const p = getPeriodStrings(now);
    if(rec.day  !== p.day ){ rec.day  = p.day;  rec.dailyCount   = 0; }
    if(rec.month!== p.month){ rec.month= p.month;rec.monthlyCount = 0; }
    if(rec.year !== p.year){ rec.year = p.year; rec.yearlyCount  = 0; }

    if(rec.dailyCount+cnt   > Protocol.SEGMENTS.PER_DAY ||
       rec.monthlyCount+cnt > Protocol.SEGMENTS.PER_MONTH ||
       rec.yearlyCount+cnt  > Protocol.SEGMENTS.PER_YEAR)
      throw new Error("Daily / monthly / yearly unlock cap reached");

    rec.dailyCount   += cnt;
    rec.monthlyCount += cnt;
    rec.yearlyCount  += cnt;
  }
}
class HistoryManager{
  static record(seg, newKey, ts, type){
    seg.ownershipChangeHistory.push({ ownerKey:newKey, ts, type,
      changeCount:seg.ownershipChangeCount });
    if(seg.ownershipChangeHistory.length>Protocol.HISTORY_MAX)
      seg.ownershipChangeHistory.shift();
  }
}

/*────────────────────────── 7.  DEVICE & SEGMENTS ─────────────────────────*/
class DeviceRegistry{
  static async register(vault, pubKeyBuf, extra=""){
    const h = await hashDeviceKeyWithSalt(pubKeyBuf, extra);
    if(!vault.deviceKeyHashes.includes(h)) vault.deviceKeyHashes.push(h);
  }
  static isRegistered(vault, hash){ return vault.deviceKeyHashes.includes(hash); }
}

class SegmentFactory{
  static createAll(ownerKey, bioConst, ts){
    return Array.from({ length:Protocol.SEGMENTS.TOTAL }, (_,i)=>({
      segmentIndex:i+1, amount:1,
      originalOwnerKey:ownerKey, originalOwnerTS:ts, originalBioConst:bioConst,
      previousOwnerKey:null, previousOwnerTS:null, previousBioConst:null,
      currentOwnerKey:ownerKey, currentOwnerTS:ts, currentBioConst:bioConst,
      unlocked:i+1<=Protocol.SEGMENTS.UNLOCKED_INIT,
      ownershipChangeCount:0,
      unlockIndexRef:null, unlockIntegrityProof:null,
      spentProof:null, ownershipProof:null,
      exported:false,                        
      ownershipChangeHistory:[]
    }));
  }
}

/*────────────────────────── 8.  VAULT SERVICE ─────────────────────────────*/
class VaultService{
  /*_session: { vaultData, key, salt }  — null when locked */
  static _session = null;

  /*--------------------------- 8.1 ENROLMENT (mandatory biometrics) -------*/
  static async _bioEnroll(){
    if(!window.PublicKeyCredential || !navigator.credentials?.create)
      throw new Error("This device doesn’t support WebAuthn / biometrics");

    const rp   = { name:"Balance‑Chain", id:location.hostname };
    const user = { id:randomBytes(16), name:"anonymous", displayName:"Bio‑Vault user" };
    const pubKeyCredParams = [
      { type:"public-key", alg:-7   },     /* ES256 */
      { type:"public-key", alg:-257 }      /* RS256 */
    ];
    const opts = {
      publicKey:{
        rp, user, challenge:randomBytes(32),
        pubKeyCredParams,
        authenticatorSelection:{ userVerification:"preferred" },
        timeout:60000
      }
    };
    const cred = await navigator.credentials.create(opts);
    if(!cred) throw new Error("Biometric enrolment was cancelled");
    return cred;
  }

  static async onboard(pin){
    const cred = await VaultService._bioEnroll();       
    const rawId = new Uint8Array(cred.rawId);
    const devHash = await hashDeviceKeyWithSalt(rawId);

    const now = Math.floor(Date.now()/1e3);
    const bioConst = Protocol.GENESIS_BIO_CONST + (now - Protocol.GENESIS_BIO_CONST);
    const segments = SegmentFactory.createAll(devHash, bioConst, now);

    const vault = {
      credentialId: bufferToBase64(rawId),
      deviceKeyHashes:[devHash],
      onboardingTS:now, userBioConst:bioConst,
      segments,
      unlockRecords:{ day:"",dailyCount:0,month:"",monthlyCount:0,year:"",yearlyCount:0 },
      walletAddress:"", tvmClaimedThisYear:0, transactionHistory:[],
      authAttempts:0, lockoutTimestamp:null
    };

    const salt=randomBytes(16);
    const key = await CryptoService.deriveKeyFromPIN(pin, salt);
    const { iv,ciphertext } = await CryptoService.encrypt(key, vault);
    await VaultStorage.save(iv, ciphertext, bufferToBase64(salt), vault);

    VaultService._session = { vaultData:vault, key, salt };
    return vault;
  }

  /*--------------------------- 8.2 AUTH / UNLOCK --------------------------*/
  static async unlock(pin){
    const rec = await VaultStorage.load();
    if(!rec) throw new Error("No vault found");

    const now = Math.floor(Date.now()/1e3);
    if(rec.lockoutTimestamp && now < rec.lockoutTimestamp)
      throw new Error(`Locked until ${new Date(rec.lockoutTimestamp*1000).toLocaleString()}`);

    const key = await CryptoService.deriveKeyFromPIN(pin, rec.salt);

    let data;
    try {
    data = await CryptoService.decrypt(key, rec.iv, rec.ciphertext);
    } catch {
    rec.authAttempts = (rec.authAttempts || 0) + 1;
    if (rec.authAttempts >= Limits.AUTH.MAX_ATTEMPTS) {
        rec.lockoutTimestamp = now + Limits.AUTH.LOCKOUT_SECONDS;
    }
    await VaultStorage.save(rec.iv, rec.ciphertext, bufferToBase64(rec.salt), rec);
    throw new Error("Bad passphrase");
    }

    /* ── one‑time migration if vault was created with the old genesis constant ── */
    if (data.userBioConst && data.onboardingTS) {
    const expected = Protocol.GENESIS_BIO_CONST + (data.onboardingTS - Protocol.GENESIS_BIO_CONST);
    if (data.userBioConst !== expected) {
        data.userBioConst = expected;
        console.info("✅ migrated bio‑constant to new genesis anchor");
    }
}


    /* strong biometric verification */
    const rawIdBuf = await VaultService._currentDeviceRawId(data.credentialId);
    if(!rawIdBuf.byteLength) throw new Error("Biometric verification cancelled");
    const currentDeviceHash = await hashDeviceKeyWithSalt(rawIdBuf);
    if(!DeviceRegistry.isRegistered(data, currentDeviceHash))
      throw new Error("This device is not registered for the vault");

    rec.authAttempts = 0; rec.lockoutTimestamp = null;
    await VaultStorage.save(rec.iv, rec.ciphertext, bufferToBase64(rec.salt), rec);

    VaultService._session = { vaultData:data, key, salt:rec.salt };
    data.segments.forEach(seg=>{
        const base   = seg.previousBioConst ?? seg.originalBioConst;
        const tsBase = seg.previousOwnerTS   ?? seg.originalOwnerTS;
        seg.currentBioConst = base + (now - tsBase);
    });
    await VaultService.persist();        // save refreshed values
   
    return data;
  }

  /* helper − reads rawId for stored credential; empty buffer on cancel */
  static async _currentDeviceRawId(credentialIdB64){
    if(!window.PublicKeyCredential || !navigator.credentials?.get) return new ArrayBuffer(0);
    const allow = [{ id:base64ToBuffer(credentialIdB64), type:"public-key" }];
    try{
      const cred = await navigator.credentials.get({
        publicKey:{
          allowCredentials:allow,
          challenge:randomBytes(16),
          userVerification:"preferred"
        },
        mediation:"optional"
      });
      return cred?.rawId || new ArrayBuffer(0);
    }catch{ return new ArrayBuffer(0); }
  }

  /*--------------------------- 8.3 session helpers ------------------------*/
  static lock(){ VaultService._session = null; }
  static get current(){ return VaultService._session?.vaultData || null; }

  static async persist(){
    const s = VaultService._session;
    if(!s) throw new Error("Vault locked");
    const { iv, ciphertext } = await CryptoService.encrypt(s.key, s.vaultData);
    await VaultStorage.save(iv, ciphertext, bufferToBase64(s.salt), s.vaultData);
  }
  static deleteDatabase(){ return VaultStorage.deleteDB().then(()=>VaultService.lock()); }
}

/*────────────────────────── 9.  SEGMENT SERVICE ───────────────────────────*/
class SegmentService{
  static _now(){ return TimeSyncService.now(); }
  static _sess(){
    if(!VaultService._session) throw new Error("Vault locked");
    return VaultService._session;
  }
  static async _assertBiometric(credentialIdB64, expectedHash){
  const assertion = await navigator.credentials.get({
    publicKey:{ allowCredentials:[{ id:base64ToBuffer(credentialIdB64), type:"public-key"}],
                challenge:randomBytes(16), userVerification:"preferred" },
    mediation:"optional"
  });
  if(!assertion) throw new Error("Biometric cancelled");
  const sigHash = await sha256(assertion.response.signature); 
  const clientData = JSON.parse(dec.decode(assertion.response.clientDataJSON));
    if (clientData.type !== "webauthn.get")
    throw new Error("Bad WebAuthn clientData");

    const ad = new DataView(assertion.response.authenticatorData);
    const flags = ad.getUint8(32);               // bit‑field
    const USER_PRESENT = 0x01, USER_VERIFIED = 0x04;
    if (!(flags & USER_PRESENT) || !(flags & USER_VERIFIED))
    throw new Error("Biometric verification failed (UV/UP flags)");
    
  const h = await hashDeviceKeyWithSalt(assertion.rawId);
  if(h!==expectedHash) throw new Error("Biometric mismatch");
  return sigHash;     
  }
  

  static async unlockNextSegment(idxRef=null){
    const now = this._now();
    const { vaultData } = this._sess();
    const devHash = vaultData.deviceKeyHashes[0];
    await this._assertBiometric(vaultData.credentialId, devHash);
    if(!DeviceRegistry.isRegistered(vaultData, devHash))
      throw new Error("Current device not authorised");

    CapEnforcer.checkAndRecordUnlock(vaultData, now);

    const seg = vaultData.segments.find(
    s => !s.unlocked && !s.exported && s.currentOwnerKey === devHash
    );


    if (!seg) throw new Error("No unlocked segment or already exported");

    seg.unlocked = true;
    seg.unlockIndexRef = idxRef;
    seg.currentOwnerTS = now;
    seg.currentBioConst = seg.previousBioConst
      ? seg.previousBioConst + (now - seg.previousOwnerTS)
      : seg.originalBioConst;
   
    const sigHash = await this._assertBiometric(vaultData.credentialId, devHash);
    seg.lastAuthSig = sigHash;          
    seg.unlockIntegrityProof = await computeUnlockIntegrityProof(seg);
    
    HistoryManager.record(seg, devHash, now, "unlock");
    vaultData.transactionHistory.push({
      type:"unlock", segmentIndex:seg.segmentIndex, timestamp:now,
      amount:seg.amount, from:devHash, to:devHash
    });
    await VaultService.persist();
    return seg;
  }

  static async transferSegment(recvKey, devHash){
    const now = this._now();
    const { vaultData } = this._sess();
    
    if(!DeviceRegistry.isRegistered(vaultData, devHash))
      throw new Error("Device not authorised");
    await this._assertBiometric(vaultData.credentialId, devHash);
    const seg = vaultData.segments.find(s=>s.unlocked && s.currentOwnerKey===devHash);
    if(!seg) throw new Error("No unlocked segment");
    if (seg.exported) throw new Error("Segment already exported");


    seg.previousOwnerKey = seg.currentOwnerKey;
    seg.previousOwnerTS  = seg.currentOwnerTS;
    seg.previousBioConst = seg.currentBioConst;

    seg.currentOwnerKey = recvKey;
    seg.currentOwnerTS  = now;
    seg.currentBioConst = seg.previousBioConst + (now - seg.previousOwnerTS);
    seg.ownershipChangeCount += 1;
    seg.unlocked = false;
    seg.exported = true;                    

    seg.spentProof     = await computeSpentProof(seg);
    seg.ownershipProof = await computeOwnershipProof(seg);
    HistoryManager.record(seg, recvKey, now, "transfer");

    vaultData.transactionHistory.push({
      type:"transfer", segmentIndex:seg.segmentIndex, timestamp:now,
      amount:seg.amount, from:devHash, to:recvKey
    });

    
    try{
      await this.unlockNextSegment(seg.segmentIndex);
    }catch(e){
      console.warn(e.message);
    }
    await VaultService.persist();
    return seg;
  }

  static async exportSegmentsBatch(recvKey, count, devHash){
    const { vaultData } = this._sess();
    const unlocked = vaultData.segments.filter(
      s=>s.unlocked && !s.exported && s.currentOwnerKey===devHash);
    if(unlocked.length < count)
      throw new Error(`Only ${unlocked.length} segment(s) unlocked`);

    const batch=[];
    for(let i=0;i<count;i++) batch.push(await this.transferSegment(recvKey,devHash));
 
    return JSON.stringify(batch);
  }

  static async importSegmentsBatch(raw, recvKey){
  let list;
  try{ list = JSON.parse(raw); }catch{ throw new Error("Corrupt payload"); }
  if(!Array.isArray(list) || list.length === 0) throw new Error("Empty payload");

 for (const seg of list) {
    if(!seg.exported) throw new Error("Payload already claimed");
    if(seg.currentOwnerKey !== recvKey) throw new Error("Segment not addressed to this vault");
    if(!ctEqual(seg.ownershipProof, await computeOwnershipProof(seg)))
      throw new Error("Bad ownership proof");
   if(seg.unlockIndexRef!==null &&
      !ctEqual(seg.unlockIntegrityProof, await computeUnlockIntegrityProof(seg)))
     throw new Error("Bad unlock proof");

 }
  return list;
}

  static async claimReceivedSegmentsBatch(list){
    const { vaultData } = this._sess();
    list.forEach(seg=>{
      const existing = vaultData.segments
        .find(s=>s.segmentIndex===seg.segmentIndex);
      if(existing){
        if(!ctEqual(existing.ownershipProof, seg.ownershipProof))
          throw new Error(`Replay / fork detected for segment #${seg.segmentIndex}`);
        /* identical → already imported, silently skip */
        return;
      }
      seg.exported = false;               // mark as resident
      vaultData.segments.push(seg);
     });
    await VaultService.persist();
  }
}
/*────────────────────────── 10. BACKUP / RESTORE ───────────────────────────*/
class BackupService{
  static async exportEncryptedBackup(vault, pwd){
    if(!pwd || pwd.length<8) throw new Error("Password ≥8 chars");
    const salt = randomBytes(16);
    const key  = await CryptoService.deriveKeyFromPIN(pwd, salt);
    const { iv, ciphertext } = await CryptoService.encrypt(key, vault);
    return {
      salt:bufferToBase64(salt),
      iv:  bufferToBase64(iv),
      ciphertext:bufferToBase64(ciphertext)
    };
  }
  static async importEncryptedBackup(payload, pwd){
    const salt = base64ToBuffer(payload.salt);
    const iv   = base64ToBuffer(payload.iv);
    const ct   = base64ToBuffer(payload.ciphertext);
    const key  = await CryptoService.deriveKeyFromPIN(pwd, salt);
    return CryptoService.decrypt(key, iv, ct);
  }
  static exportFriendly(vault){
    const blob = new Blob([JSON.stringify(vault)], { type:"application/octet-stream" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href:url, download:"myBioVault.vault" });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }
}

/*────────────────────────── 11. AUDIT SERVICE ─────────────────────────────*/
class AuditService{
  static generateAuditReport(vault,{ fullHistory=false }={}){
    const lim = Protocol.HISTORY_MAX;
    return {
      deviceKeyHashes:vault.deviceKeyHashes.map(h => h.slice(0,8)+"…"),
      onboardingTS:vault.onboardingTS,
      userBioConst:vault.userBioConst,
      segments:vault.segments.map(s=>({
        ...s,
        ownershipChangeHistory:fullHistory
          ? s.ownershipChangeHistory
          : s.ownershipChangeHistory.slice(-lim)
      }))
    };
  }
  static async verifyProofChain(segments, expectedKey){
    for(const seg of segments){
      if(!ctEqual(seg.currentOwnerKey, expectedKey))
        throw new Error(`Seg#${seg.segmentIndex}: owner mismatch`);
      if(!ctEqual(seg.ownershipProof, await computeOwnershipProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: ownership proof bad`);
      if(seg.unlockIndexRef!==null &&
         !ctEqual(seg.unlockIntegrityProof, await computeUnlockIntegrityProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: unlock proof bad`);
      if(seg.spentProof && !ctEqual(seg.spentProof, await computeSpentProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: spent proof bad`);
    }
    return true;
  }
}
/*────────────────────────── 12. CHAIN SERVICE (stub) ───────────────────────*/
/* ── injected at build time in production ── */
const CONTRACT = "0xYourDeployedAddressHere";
import claimAbi from "./claimAbi.json" assert { type: "json" };

const ChainService = (()=>{
  let provider=null, signer=null;
  return{
    initWeb3(){
      if(window.ethereum && !provider){
        provider = new ethers.providers.Web3Provider(window.ethereum,"any");
        signer   = provider.getSigner();
      }
    },


    async submitClaimOnChain(bundle){
    if(!signer) throw new Error("Connect wallet first");

    const domain = { name:"TVMClaim", version:"1", chainId: (await signer.getChainId()), verifyingContract:CONTRACT };
    const types = {
    SegmentProof: [
        { name:"segmentIndex", type:"uint32" },
        { name:"spentProof",   type:"bytes32" },
        { name:"ownershipProof", type:"bytes32" },
        { name:"unlockIntegrityProof", type:"bytes32" }
    ]
    };
    const value = { segmentProofs: bundle };  

    const sig = await signer._signTypedData(domain, types, value);
    const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
    const tx = await contract.claimTVM(bundle, sig);
    return tx.wait();
    },

    getSigner(){ return signer; }
  };
})();

/*────────────────────────── 13. TOKEN (TVM) SERVICE ───────────────────────*/
class TokenService{
  static _vault(){
    const v = VaultService.current;
    if(!v) throw new Error("Vault locked");
    return v;
  }
  static getAvailableTVMClaims(){
    const v = this._vault();
    const devHash = v.deviceKeyHashes[0];
      // PATCH‑B: count every segment currently owned (unlocked _or_ already spent)
    const used = v.segments.filter(
    s => s.currentOwnerKey === devHash &&
         (s.unlocked || s.ownershipChangeCount > 0)
  ).length;

    const claimed = v.tvmClaimedThisYear || 0;
    return Math.max(Math.floor(used/Protocol.TVM.SEGMENTS_PER_TOKEN)-claimed,0);
  }
  static async claimTvmTokens(){
    const v = this._vault();
    const avail = this.getAvailableTVMClaims();
    if(!/^0x[a-fA-F0-9]{40}$/.test(v.walletAddress))
      throw new Error("Wallet address required");
    if(avail<=0) throw new Error("Nothing to claim");
    if((v.tvmClaimedThisYear||0)+avail > Protocol.TVM.CLAIM_CAP)
      throw new Error("Yearly TVM cap reached");

    const needed = avail * Protocol.TVM.SEGMENTS_PER_TOKEN;
    const segs   = v.segments.filter(s=>s.ownershipChangeCount>0).slice(0,needed);

    const proofBundle = segs.map(s=>({
      segmentIndex:s.segmentIndex,
      spentProof:s.spentProof,
      ownershipProof:s.ownershipProof,
      unlockIntegrityProof:s.unlockIntegrityProof
    }));

    await ChainService.submitClaimOnChain(proofBundle);

    v.tvmClaimedThisYear += avail;
    await VaultService.persist();
    return proofBundle;
  }
}
/*────────────────────────── 14. UI HELPERS / TOAST ─────────────────────────*/
const toast = (msg,isErr=false)=>{
  const el = document.getElementById("toast");
  if(!el) return;
  el.textContent = msg;
  el.className   = isErr ? "toast toast-error" : "toast";
  el.style.display="block";
  setTimeout(()=>{ el.style.display="none"; },3200);
};

/*────────────────────────── 15. POPUP / MODAL HELPERS ──────────────────────*/
const openModal  = id=>document.getElementById(id)?.classList.add("show");
const closeModal = id=>document.getElementById(id)?.classList.remove("show");
window.openPopup  = openModal;
window.closePopup = closeModal;

/*────────────────────────── 16. BACKUP REMINDER BANNER ─────────────────────*/
const showBackupReminder = ()=>{
  const tip=document.getElementById("onboardingTip");
  if(tip) tip.style.display = localStorage.getItem("vaultBackedUp") ? "none" : "";
};
window.showBackupReminder = showBackupReminder;

/*────────────────────────── 17. TRANSACTION TABLE RENDER ───────────────────*/
(()=>{
  const pageSize = Limits.PAGE.DEFAULT_SIZE;
  let txPage=0;

  const txList = ()=>{
    const v = VaultService.current;
    if(!v) return [];
    const myShort = v.deviceKeyHashes[0]?.slice(0,10)+"…";
    return v.segments.filter(s=>s.ownershipChangeCount>0).map(s=>({
      bioIban:myShort,
      bioCatch:s.segmentIndex,
      amount:s.amount,
      time:new Date(s.currentOwnerTS*1000).toLocaleString(),
      status:s.currentOwnerKey===v.deviceKeyHashes[0]?"IN":"OUT"
    }));
  };

  window.renderTransactions = function(){
    const list = txList();
    const tbody=document.getElementById("transactionBody");
    const empty=document.getElementById("txEmptyState");
    const prev=document.getElementById("txPrevBtn");
    const next=document.getElementById("txNextBtn");
    if(!tbody) return;

    tbody.innerHTML="";
    if(list.length===0){
      empty.style.display="";
      prev.style.display="none"; next.style.display="none";
      return;
    }

    empty.style.display="none";
    const start=txPage*pageSize, end=start+pageSize;
    list.slice(start,end).forEach(tx=>{
      const tr=document.createElement("tr");
      tr.innerHTML=`<td>${tx.bioIban}</td><td>${tx.bioCatch}</td>
        <td>${tx.amount}</td><td>${tx.time}</td><td>${tx.status}</td>`;
      tbody.appendChild(tr);
    });

    prev.style.display = txPage>0      ? "" : "none";
    next.style.display = end<list.length? "" : "none";
  };

  document.getElementById("txPrevBtn")?.addEventListener("click",()=>{
    if(txPage>0){ txPage--; window.renderTransactions(); }
  });
  document.getElementById("txNextBtn")?.addEventListener("click",()=>{
    txPage++; window.renderTransactions();
  });
})();

/*────────────────────────── 18. DASHBOARD RENDER ───────────────────────────*/
const renderVaultUI = ()=>{
  const v = VaultService.current;
  if(!v) return;

  document.getElementById("lockedScreen").style.display="none";
  document.getElementById("vaultUI").style.display="block";

  document.getElementById("bioibanInput").value = v.deviceKeyHashes[0]?.slice(0,8)+"…";
  document.getElementById("bioibanInput").readOnly = true;

  document.getElementById("bioibanShort").textContent = (v.deviceKeyHashes[0]||"").slice(0,8)+"…";

  const segUsed = v.segments.filter(s=>s.ownershipChangeCount>0 || s.unlocked).length;
  const balance = Math.floor(segUsed/Protocol.TVM.SEGMENTS_PER_TOKEN) -
                  (v.tvmClaimedThisYear||0);
  document.getElementById("tvmBalance").textContent = `Balance: ${balance} TVM`;
  document.getElementById("usdBalance").textContent =
    `Equivalent ${balance.toFixed(2)} USD`;
  document.getElementById("bioLineText").textContent =
    `🔄 BonusConstant: ${v.userBioConst}`;
  document.getElementById("utcTime").textContent = "UTC: "+new Date().toUTCString();
  document.getElementById("userWalletAddress").value = v.walletAddress || "";
  document.getElementById("tvmClaimable").textContent =
    `TVM Claimable: ${TokenService.getAvailableTVMClaims()}`;

  window.renderTransactions();
};
window.renderVaultUI = renderVaultUI;

/*────────────────────────── 19. SHARED SAFE‑HANDLER ───────────────────────*/
window.safeHandler = fn=>
  Promise.resolve().then(fn).catch(e=>{
    console.error(e);
    toast(e.message||"Error", true);
  });

/*────────────────────────── 20. BUTTON WIRING (PROD) ───────────────────────*/
(()=>{
  const devHash= ()=>VaultService.current.deviceKeyHashes[0];

  /* copy IBAN */
  document.getElementById("copyBioIBANBtn")
    ?.addEventListener("click",()=>copyToClipboard(
      document.getElementById("bioibanInput").value));

  /* Catch‑Out (export) */
  document.getElementById("catchOutBtn")
    ?.addEventListener("click",()=>safeHandler(async()=>{
      const recv=document.getElementById("receiverBioIBAN").value.trim();
      const amt = Number(document.getElementById("catchOutAmount").value);
      if(!recv || !Number.isInteger(amt) || amt<=0)
        throw new Error("Receiver and integer amount required");

      const payload = await SegmentService.exportSegmentsBatch(recv, amt, devHash());
      copyToClipboard(payload);
      toast(`Exported ${amt} segment${amt>1?"s":""}. Payload copied.`);
      renderVaultUI();
    }));

  /* Catch‑In (import) */
  document.getElementById("catchInBtn")
    ?.addEventListener("click",()=>safeHandler(async()=>{
      const raw=document.getElementById("catchInBioCatch").value.trim();
      if(!raw) throw new Error("Paste the received payload");
      
      const segs = await SegmentService.importSegmentsBatch(raw, devHash());
      await SegmentService.claimReceivedSegmentsBatch(segs);
      toast(`Successfully claimed ${segs.length} segment${segs.length>1?"s":""}`);
      renderVaultUI();
    }));

  /* Bio‑Catch “business card” */
  document.getElementById("showBioCatchBtn")
    ?.addEventListener("click",()=>safeHandler(async()=>{
      const v=VaultService.current;
      const seg=v.segments.find(s=>s.unlocked && s.currentOwnerKey===devHash());
      if(!seg) throw new Error("Unlock a segment first");
      const token = `${devHash().slice(0,10)}‑${seg.segmentIndex}`;
      document.getElementById("bioCatchNumberText").textContent = token;
      openModal("bioCatchPopup");
    }));
  document.getElementById("copyBioCatchBtn")
    ?.addEventListener("click",()=>copyToClipboard(
      document.getElementById("bioCatchNumberText").textContent));
  document.getElementById("closeBioCatchPopup")
    ?.addEventListener("click",()=>closeModal("bioCatchPopup"));

  /* CSV export */
  document.getElementById("exportBtn")
    ?.addEventListener("click",()=>{
      const rows=[["Bio‑IBAN","Bio‑Catch","Amount","Date","Status"],
        ...document.querySelectorAll("#transactionBody tr")
          .entries()].map(([,tr])=>[...tr.children].map(td=>td.textContent.trim()));
      const csv="data:text/csv;charset=utf-8,"+rows.map(r=>r.join(",")).join("\n");
      const a=Object.assign(document.createElement("a"),{
        href:encodeURI(csv), download:"transactions.csv"});
      document.body.appendChild(a); a.click(); a.remove();
    });

  /* encrypted backup */
  document.getElementById("exportBackupBtn")
    ?.addEventListener("click",()=>safeHandler(async()=>{
      const pwd=prompt("Backup password (≥8 chars):");
      if(!pwd) return;
      const data=await BackupService.exportEncryptedBackup(VaultService.current,pwd);
      const blob=new Blob([JSON.stringify(data)],{type:"application/json"});
      const url=URL.createObjectURL(blob);
      const a=Object.assign(document.createElement("a"),{
        href:url, download:"vault_backup.enc.json"});
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      localStorage.setItem("vaultBackedUp","yes"); showBackupReminder();
    }));

  /* friendly .vault export */
  document.getElementById("exportFriendlyBtn")
    ?.addEventListener("click",()=>{ BackupService.exportFriendly(VaultService.current);
       localStorage.setItem("vaultBackedUp","yes"); showBackupReminder();
       toast("Friendly backup exported"); });

  /* .vault import */
  document.getElementById("importVaultFileInput")
    ?.addEventListener("change",e=>safeHandler(async()=>{
      const f=e.target.files[0]; if(!f) return;
      const txt=await f.text();
      const vault=JSON.parse(txt);
      VaultService._session={ vaultData:vault, key:null, salt:null }; // read‑only
      toast("Vault imported (read‑only). Unlock with passphrase to use.");
      renderVaultUI();
    }));
})();

/*────────────────────────── 21. SESSION AUTO‑LOCK ─────────────────────────*/
(()=>{
  const MAX_IDLE = 15*60*1000;
  let timer;
  const reset=()=>{
    clearTimeout(timer);
    timer=setTimeout(()=>{ VaultService.lock(); location.reload(); },MAX_IDLE);
  };
  ["click","mousemove","keydown","touchstart"].forEach(ev=>
    document.addEventListener(ev,reset,{ passive:true }));
  reset();
})();

/*────────────────────────── 22. PIN ROTATION ──────────────────────────────*/
document.getElementById("rotatePinBtn")?.addEventListener("click",()=>safeHandler(async()=>{
  const oldPin=prompt("Current passphrase:");
  const newPin=prompt("New passphrase (≥8 chars):");
  if(!oldPin||!newPin||newPin.length<8) throw new Error("Invalid input");

  const rec=await VaultStorage.load();
  const oldKey=await CryptoService.deriveKeyFromPIN(oldPin,rec.salt);
  const vault=await CryptoService.decrypt(oldKey,rec.iv,rec.ciphertext);

  const newSalt=randomBytes(16);
  const newKey =await CryptoService.deriveKeyFromPIN(newPin,newSalt);
  const { iv,ciphertext } = await CryptoService.encrypt(newKey,vault);
  await VaultStorage.save(iv,ciphertext,bufferToBase64(newSalt),vault);

  VaultService._session={ vaultData:vault, key:newKey, salt:newSalt };
  toast("Passphrase rotated");
}));

/*────────────────────────── 23. INITIAL BOOTSTRAP ─────────────────────────*/
window.addEventListener("DOMContentLoaded",()=>safeHandler(async()=>{
  if(!indexedDB||!crypto?.subtle||!TextEncoder){
    document.body.innerHTML="<h2>Your browser lacks required APIs.</h2>";
    return;
  }
  await TimeSyncService.sync();
  ChainService.initWeb3();
  showBackupReminder();

  if(!localStorage.getItem("vaultOnboarded")){
    openModal("onboardingModal");
    document.querySelector("#onboardingModal .modal-close")
      ?.addEventListener("click",()=>safeHandler(async()=>{
        const pin=prompt("Choose a passphrase (≥8 chars):");
        if(!pin||pin.length<8) throw new Error("Too short");
        await VaultService.onboard(pin);
        localStorage.setItem("vaultOnboarded","yes");
        closeModal("onboardingModal"); renderVaultUI();
      }));
  }else{
    openModal("passModal");
    document.getElementById("passModalSaveBtn")
      ?.addEventListener("click",()=>safeHandler(async()=>{
        const pin=document.getElementById("passModalInput").value;
        if(!pin) throw new Error("Enter passphrase");
        await VaultService.unlock(pin);
        closeModal("passModal"); renderVaultUI();
      }));
  }
}));

document.getElementById("saveWalletBtn")
  ?.addEventListener("click", () => safeHandler(async () => {
    const addr = document.getElementById("userWalletAddress").value.trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Error("Bad address");
    const v = VaultService.current; v.walletAddress = addr;
    await VaultService.persist();
    toast("Wallet address saved");
}));

document.getElementById("autoConnectWalletBtn")
  ?.addEventListener("click", () => safeHandler(async () => {
    ChainService.initWeb3();
    await window.ethereum?.request({ method: "eth_requestAccounts" });
    const signer = ChainService.getSigner();
    const addr   = signer ? await signer.getAddress() : "";
    if (addr) {
      document.getElementById("userWalletAddress").value = addr;
      document.getElementById("saveWalletBtn").click();          // auto‑save
    } else {
      toast("Wallet connect failed", true);
    }
}));
/* focus‑return helper – add once in main.js */
function trapFocus(modal){
  const focusable = modal.querySelectorAll("a,button,input,textarea,[tabindex]:not([tabindex='-1'])");
  const first = focusable[0], last = focusable[focusable.length-1];
  modal.addEventListener("keydown", e=>{
    if(e.key!=="Tab") return;
    if(e.shiftKey && document.activeElement===first){ e.preventDefault(); last.focus(); }
    if(!e.shiftKey && document.activeElement===last){ e.preventDefault(); first.focus(); }
  });
}
document.querySelectorAll(".modal").forEach(m=>{
  m.addEventListener("show",()=>{ m.focus(); trapFocus(m); });
  m.addEventListener("hide",()=>{ lastInvoker?.focus(); });
});

fetch(`i18n/${navigator.language.split("-")[0]||"en"}.json`)
  .then(r=>r.json())
  .then(dict=>{
    document.querySelectorAll("[data-i18n]").forEach(el=>{
      el.textContent = dict[el.dataset.i18n] || el.textContent;
    });
  });


/*────────────────────────── 24. EXPORT GLOBAL API ─────────────────────────*/
window.BalanceChain = Object.freeze({
  Protocol, Limits,
  bufferToBase64, base64ToBuffer, sha256,
  computeUnlockIntegrityProof, computeSpentProof, computeOwnershipProof, hashDeviceKeyWithSalt,
  VaultService, SegmentService, BackupService,
  AuditService, TokenService, ChainService
});
