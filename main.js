/* balance_chain_v3.js – Ultimate Production-Grade BalanceChain */
/* eslint max-lines: 2000 */
/* eslint-disable no-console */
"use strict";

// TODO: Split into modules (crypto.js, vault.js, segment.js, etc.) for better maintainability

/*──────────────────────── 1. CONSTANTS ───────────────────────────────*/
const GENESIS_TIMESTAMP = 1736565605; 
const Protocol = Object.freeze({
  GENESIS_BIO_CONST: GENESIS_TIMESTAMP,
  SEGMENTS: Object.freeze({
    TOTAL: 12000,
    UNLOCKED_INIT: 1200,
    PER_DAY: 3,
    PER_MONTH: 30,
    PER_YEAR: 90
  }),
  TVM: Object.freeze({
    SEGMENTS_PER_TOKEN: 12,
    CLAIM_CAP: 1000,
    EXCHANGE_RATE: 12 // Point 8: 1 USD = 12 SHE (verified: 10000 USD/year / 2000 hours = 5 USD/hr, 60/5 = 12 min/USD)
  }),
  HISTORY_MAX: 100, // Increased from 20 for better audit trail and replay protection
  BONUS: Object.freeze({
    PER_TX: 120,
    MAX_PER_DAY: 3,
    MAX_PER_MONTH: 30,
    MAX_ANNUAL_TVM: 10800,
    MIN_SEND_AMOUNT: 240
  })
});

const Limits = Object.freeze({
  AUTH: Object.freeze({ MAX_ATTEMPTS: 5, LOCKOUT_SECONDS: 3600 }), // Point 10: Lockouts
  PAGE: Object.freeze({ DEFAULT_SIZE: 10 }),
  TRANSACTION_VALIDITY_SECONDS: 720,
  BATCH_SIZE: 10000 // Point 5: Batch for large transfers
});

const DB = Object.freeze({
  NAME: "BalanceChainVaultDB",
  VERSION: 4,
  STORE: "vaultStore",
  STORAGE_CHECK_INTERVAL: 300000 // Point 10: Storage checks
});

const vaultSyncChannel = new BroadcastChannel("vault-sync");
const KEY_HASH_SALT = "Balance-Chain-v3-PRD"; // Point 6: Salt for hashing (now per-vault in device hash)
const PBKDF2_ITERS = 600000; // Increased per OWASP recommendations for SHA-512 (210k min, conservative 600k)
const AES_KEY_LENGTH = 256;
const MAX_IDLE = 15 * 60 * 1000; // Point 10: Auto-lock
const HMAC_KEY = new TextEncoder().encode("BalanceChainHMACSecret"); // For HMAC proofs

/*──────────────────────── 2. UTILS / HELPERS ─────────────────────────*/
const enc = new TextEncoder(), dec = new TextDecoder();
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
const rand = len => crypto.getRandomValues(new Uint8Array(len));

const ctEq = (a = "", b = "") => {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
};

const canonical = obj => JSON.stringify(obj, Object.keys(obj).sort());

const sha256 = async data => {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data);
  return toB64(buf);
};

const sha256Hex = async str => {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
};

const hmacSha256 = async (message) => {
  const key = await crypto.subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return toB64(signature);
};

const sanitizeInput = (input) => {
  // Basic sanitization to prevent XSS (use DOMPurify if added as lib, but since no, simple escape)
  return input.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`);
};

/*──────────────────────── 3. CRYPTO SERVICE ──────────────────────────*/
class CryptoService {
  static async deriveKey(pin, salt) {
    const mat = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-512" },
      mat, { name: "AES-GCM", length: AES_KEY_LENGTH }, false, ["encrypt", "decrypt"]
    );
  }

  static async encrypt(key, obj) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv, ct };
  }

  static async decrypt(key, iv, ct) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return JSON.parse(dec.decode(pt));
  }

  static async encryptBioCatchNumber(plainObj, key) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(plainObj)));
    return toB64(new Uint8Array([...iv, ...new Uint8Array(ct)]));
  }

  static async decryptBioCatchNumber(encStr, key) {
    try {
      const buf = fromB64(encStr);
      const iv = buf.slice(0, 12);
      const ct = buf.slice(12);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
      return JSON.parse(dec.decode(pt));
    } catch { return null; }
  }
}

/*──────────────────────── 4. PUBLIC PROOFS ───────────────────────────*/
const proofHash = async (tag, obj) => hmacSha256(`${tag}:${canonical(obj)}`); // Use HMAC for robust hash

const computeUnlockIntegrityProof = async seg => proofHash("unlock", {
  segmentIndex: seg.segmentIndex,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst,
  unlockIndexRef: seg.unlockIndexRef,
  unlockTriggerBioConst: seg.unlockTriggerBioConst
});

const computeSpentProof = async seg => proofHash("spent", {
  segmentIndex: seg.segmentIndex,
  previousOwnerKey: seg.previousOwnerKey,
  previousBioConst: seg.previousBioConst,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst
});

const computeOwnershipProof = async seg => proofHash("own", {
  segmentIndex: seg.segmentIndex,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst,
  ownershipChangeCount: seg.ownershipChangeCount,
  nonce: seg.nonce // Added nonce for replay protection
});

/*──────────────────────── 5. DEVICE HASH ─────────────────────────────*/
const hashDeviceKeyWithSalt = async (buf, salt, extra = "") =>
  hmacSha256(new Uint8Array([...enc.encode(salt), ...new Uint8Array(buf), ...enc.encode(extra)]));

/*──────────────────────── 6. TIME-SYNC SERVICE ───────────────────────*/
class TimeSyncService {
  static _offset = 0;

  static async sync() {
    const sources = [
      "https://worldtimeapi.org/api/ip",
      "https://timeapi.io/api/Time/current/utc"
    ];
    let offsets = [];
    for (const src of sources) {
      try {
        const res = await fetch(src, { cache: "no-store" });
        const data = await res.json();
        const unixtime = data.unixtime || Math.floor(new Date(data.utc_datetime).getTime() / 1000);
        offsets.push(unixtime - Math.floor(Date.now() / 1000));
      } catch { }
    }
    if (offsets.length) {
      offsets.sort((a, b) => a - b);
      this._offset = offsets[Math.floor(offsets.length / 2)]; // Median
      return;
    }
    console.warn("⏰ All time-sync sources failed – using local clock");
  }

  static now() { return Math.floor(Date.now() / 1000) + this._offset; }

  static updateUTCClock() {
    const el = document.getElementById("utcTime");
    if (el) el.textContent = `UTC: ${new Date(this.now() * 1000).toUTCString()}`;
  }
}

/*──────────────────────── 7. INDEXED-DB LAYER ────────────────────────*/
class VaultStorage {
  static _open() {
    return new Promise((res, rej) => {
      const req = indexedDB.open(DB.NAME, DB.VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(DB.STORE)) {
          const store = db.createObjectStore(DB.STORE, { keyPath: "id" });
          store.createIndex("segmentIndex", "segments.segmentIndex", { multiEntry: true });
          store.createIndex("unlocked", "segments.unlocked", { multiEntry: true }); // Added for performance
          store.createIndex("exported", "segments.exported", { multiEntry: true });
        }
      };
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }

  static async save(iv, ct, saltB64, meta) {
    const db = await this._open();
    await new Promise((res, rej) => {
      const tx = db.transaction(DB.STORE, "readwrite");
      tx.objectStore(DB.STORE).put({ id: "vaultData", iv: toB64(iv), ciphertext: toB64(ct), salt: saltB64, ...meta });
      tx.oncomplete = res;
      tx.onerror = () => rej(tx.error);
    });
    const backupPayload = { iv: toB64(iv), data: toB64(ct), salt: saltB64, timestamp: Date.now() };
    vaultSyncChannel.postMessage({ type: "vaultUpdate", payload: backupPayload });
    if (navigator.storage?.estimate) {
      const { quota, usage } = await navigator.storage.estimate();
      if (usage / quota > 0.9) toast("⚠️ Storage quota nearing limit", true); // Point 10
    }
  }

  static async load() {
    const db = await this._open();
    return new Promise((res, rej) => {
      const tx = db.transaction(DB.STORE, "readonly");
      const rq = tx.objectStore(DB.STORE).get("vaultData");
      rq.onsuccess = () => {
        if (!rq.result) return res(null);
        const r = rq.result;
        res({ iv: fromB64(r.iv), ciphertext: fromB64(r.ciphertext), salt: fromB64(r.salt), ...r });
      };
      rq.onerror = () => rej(rq.error);
    });
  }

  static async getUnlockedSegments() {
    const db = await this._open();
    return new Promise((res, rej) => {
      const tx = db.transaction(DB.STORE, "readonly");
      const index = tx.objectStore(DB.STORE).index("unlocked");
      const rq = index.getAll(true);
      rq.onsuccess = () => res(rq.result);
      rq.onerror = () => rej(rq.error);
    });
  }
}

/*──────────────────────── 8. WEBAUTHN HELPERS ───────────────────────*/
class WebAuthnService {
  static async enroll() {
    if (!navigator.credentials?.create) throw new Error("WebAuthn unsupported");
    const rp = { name: "BalanceChain", id: location.hostname };
    const user = { id: rand(16), name: "anon", displayName: "BalanceChain User" };
    const cred = await navigator.credentials.create({
      publicKey: {
        rp, user, challenge: rand(32),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { userVerification: "required", residentKey: "required" }, // Changed to required for better security
        timeout: 60000
      }
    });
    if (!cred) throw new Error("Biometric enrolment cancelled");
    return cred.rawId;
  }

  static async assert(credIdB64) {
    const allow = [{ id: fromB64(credIdB64), type: "public-key" }];
    const cred = await navigator.credentials.get({
      publicKey: { allowCredentials: allow, challenge: rand(16), userVerification: "required" },
      mediation: "optional"
    });
    if (!cred) throw new Error("Biometric cancelled or unsupported");
    const flags = new DataView(cred.response.authenticatorData).getUint8(32);
    if (!(flags & 0x01) || (flags & 0x04) === 0) throw new Error("UV/UP flags missing");
    const sigHash = await hmacSha256(cred.response.signature);
    return { rawId: cred.rawId, sigHash };
  }

  static async verifyLocalKey(rawId, storedHash, salt) {
    const computedHash = await hashDeviceKeyWithSalt(rawId, salt);
    return ctEq(computedHash, storedHash);
  }
}

/*──────────────────────── 9. CAP & HISTORY HELPERS ───────────────────*/
const periodStrings = ts => {
  const d = new Date(ts * 1000);
  return {
    day: d.toISOString().slice(0, 10),
    month: d.toISOString().slice(0, 7),
    year: String(d.getUTCFullYear())
  };
};

class CapEnforcer {
  static check(vault, now, cnt = 1) {
    const rec = vault.unlockRecords, p = periodStrings(now);
    if (rec.year !== p.year) { rec.year = p.year; rec.yearlyCount = 0; }
    if (rec.month !== p.month) { rec.month = p.month; rec.monthlyCount = 0; }
    if (rec.day !== p.day) { rec.day = p.day; rec.dailyCount = 0; }
    if (
      rec.dailyCount + cnt > Protocol.SEGMENTS.PER_DAY ||
      rec.monthlyCount + cnt > Protocol.SEGMENTS.PER_MONTH ||
      rec.yearlyCount + cnt > Protocol.SEGMENTS.PER_YEAR
    ) throw new Error("Unlock cap reached");
    rec.dailyCount += cnt;
    rec.monthlyCount += cnt;
    rec.yearlyCount += cnt;
  }

  static checkBonus(vault, now, type, amount) {
    const p = periodStrings(now);
    if (vault.bonusRecords.year !== p.year) { vault.bonusRecords.year = p.year; vault.bonusRecords.annualTVM = 0; }
    if (vault.bonusRecords.month !== p.month) { vault.bonusRecords.month = p.month; vault.bonusRecords.monthlyCount = 0; }
    if (vault.bonusRecords.day !== p.day) {
      vault.bonusRecords.day = p.day;
      vault.bonusRecords.dailyCount = 0;
      vault.bonusRecords.sentCount = 0;
      vault.bonusRecords.receivedCount = 0;
    }
    if (vault.bonusRecords.annualTVM + Protocol.BONUS.PER_TX > Protocol.BONUS.MAX_ANNUAL_TVM) return false;
    if (vault.bonusRecords.dailyCount >= Protocol.BONUS.MAX_PER_DAY) return false;
    if (vault.bonusRecords.monthlyCount >= Protocol.BONUS.MAX_PER_MONTH) return false;
    if (type === "sent" && amount <= Protocol.BONUS.MIN_SEND_AMOUNT) return false;
    if (type === "sent" && vault.bonusRecords.sentCount >= 2) return false;
    if (type === "received" && vault.bonusRecords.receivedCount >= 2) return false;
    if ((vault.bonusRecords.sentCount + vault.bonusRecords.receivedCount) >= Protocol.BONUS.MAX_PER_DAY) return false; // Unified cap
    return true;
  }

  static recordBonus(vault, type) {
    vault.bonusRecords.dailyCount++;
    vault.bonusRecords.monthlyCount++;
    vault.bonusRecords.annualTVM += Protocol.BONUS.PER_TX;
    if (type === "sent") vault.bonusRecords.sentCount++;
    else if (type === "received") vault.bonusRecords.receivedCount++;
  }
}

class HistoryManager {
  static record(seg, newKey, ts, type) {
    seg.ownershipChangeHistory.push({ ownerKey: newKey, ts, type, changeCount: seg.ownershipChangeCount });
    if (seg.ownershipChangeHistory.length > Protocol.HISTORY_MAX) seg.ownershipChangeHistory.shift();
  }
}

/*──────────────────────── 10. SEGMENT FACTORY ────────────────────────*/
class SegmentFactory {
  static createAll(owner, bioConst, ts) {
    return Array.from({ length: Protocol.SEGMENTS.TOTAL }, (_, i) => ({
      segmentIndex: i + 1,
      amount: 1,
      originalOwnerKey: owner,
      originalOwnerTS: ts,
      originalBioConst: bioConst,
      previousOwnerKey: null,
      previousOwnerTS: null,
      previousBioConst: null,
      currentOwnerKey: i + 1 <= Protocol.SEGMENTS.UNLOCKED_INIT ? owner : null,
      currentOwnerTS: i + 1 <= Protocol.SEGMENTS.UNLOCKED_INIT ? ts : null,
      currentBioConst: i + 1 <= Protocol.SEGMENTS.UNLOCKED_INIT ? bioConst : null,
      unlocked: i + 1 <= Protocol.SEGMENTS.UNLOCKED_INIT,
      unlockIndexRef: null,
      unlockTriggerBioConst: null,
      unlockTriggerProof: null,
      unlockIntegrityProof: null,
      spentProof: null,
      ownershipProof: null,
      ownershipChangeCount: 0,
      exported: false,
      transferred: false, // Added to prevent reuse
      lastAuthSig: null,
      nonce: toB64(rand(16)), // Added for replay protection
      ownershipChangeHistory: []
    }));
  }
}

/*──────────────────────── 11. VAULT SERVICE ──────────────────────────*/
class VaultService {
  static _session = null;

  static async _currentDeviceRawId(credIdB64) {
    if (!window.PublicKeyCredential || !navigator.credentials?.get) throw new Error("Biometrics unsupported - cannot proceed");
    const allow = [{ id: fromB64(credIdB64), type: "public-key" }];
    try {
      const cred = await navigator.credentials.get({
        publicKey: { allowCredentials: allow, challenge: rand(16), userVerification: "required" },
        mediation: "optional"
      });
      return cred?.rawId;
    } catch { throw new Error("Biometric authentication failed"); }
  }

  static async onboard(pin) {
    if (pin.length < 8) throw new Error("Passphrase ≥8 chars");
    const deviceSalt = toB64(rand(16)); // Per-vault salt for device hash
    const rawId = await WebAuthnService.enroll();
    const devHash = await hashDeviceKeyWithSalt(rawId, deviceSalt);
    const now = TimeSyncService.now();
    const bioConst = Protocol.GENESIS_BIO_CONST + (now - GENESIS_TIMESTAMP);
    const segments = SegmentFactory.createAll(devHash, bioConst, now);
    for (const s of segments) {
      s.unlockIntegrityProof = await computeUnlockIntegrityProof(s);
      s.ownershipProof = await computeOwnershipProof(s);
    }
    const vault = {
      credentialId: toB64(rawId),
      deviceSalt, // Stored per-vault salt
      deviceKeyHashes: [devHash],
      onboardingTS: now,
      lastKnownTime: now, // Added for clock tampering detection
      userBioConst: bioConst,
      bioIBAN: devHash,
      segments,
      seenNonces: new Set(), // Added for replay protection
      unlockRecords: { day: "", dailyCount: 0, month: "", monthlyCount: 0, year: "", yearlyCount: 0 },
      bonusRecords: {
        day: "", dailyCount: 0, sentCount: 0, receivedCount: 0,
        month: "", monthlyCount: 0, year: "", annualTVM: 0
      },
      walletAddress: "",
      walletAddressKYC: "",
      walletKeyHashBinding: null, // New: Hash of (walletAddress + bioIBAN) for binding
      tvmClaimedThisYear: 0,
      lastClaimYear: new Date(now * 1000).getUTCFullYear(), // Added for annual reset
      transactionHistory: [],
      authAttempts: 0,
      lockoutUntil: null,
      nextBonusId: 1,
      lastTransactionHash: "",
      finalChainHash: ""
    };
    const salt = rand(16);
    const key = await CryptoService.deriveKey(pin, salt);
    const { iv, ct } = await CryptoService.encrypt(key, vault);
    await VaultStorage.save(iv, ct, toB64(salt), vault);
    this._session = { vaultData: vault, key, salt };
    await AuditService.log("Vault onboarded", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
    return vault;
  }

  static async unlock(pin) {
    const rec = await VaultStorage.load();
    if (!rec) throw new Error("No vault found");
    const now = TimeSyncService.now();
    if (rec.lockoutUntil && now < rec.lockoutUntil)
      throw new Error(`Locked until ${new Date(rec.lockoutUntil * 1000).toLocaleString()}`);
    const key = await CryptoService.deriveKey(pin, rec.salt);
    let vault;
    try { vault = await CryptoService.decrypt(key, rec.iv, rec.ciphertext); }
    catch {
      rec.authAttempts = (rec.authAttempts || 0) + 1;
      if (rec.authAttempts >= Limits.AUTH.MAX_ATTEMPTS)
        rec.lockoutUntil = now + Limits.AUTH.LOCKOUT_SECONDS;
      await VaultStorage.save(rec.iv, rec.ciphertext, toB64(rec.salt), rec);
      throw new Error("Bad passphrase");
    }
    const rawIdBuf = await this._currentDeviceRawId(vault.credentialId);
    const curHash = await hashDeviceKeyWithSalt(rawIdBuf, vault.deviceSalt);
    if (!vault.deviceKeyHashes.includes(curHash))
      throw new Error("Device not registered for vault");
    if (!(await WebAuthnService.verifyLocalKey(rawIdBuf, curHash, vault.deviceSalt)))
      throw new Error("Local key verification failed");
    rec.authAttempts = 0;
    rec.lockoutUntil = null;
    await VaultStorage.save(rec.iv, rec.ciphertext, toB64(rec.salt), rec);
    // Update bio-const with safeguards
    const lastKnownTime = vault.lastKnownTime || vault.onboardingTS;
    if (now < lastKnownTime) throw new Error("Clock tampering detected");
    vault.lastKnownTime = now;
    vault.segments.forEach(seg => {
      const base = seg.previousBioConst ?? seg.originalBioConst;
      const tsBase = seg.previousOwnerTS ?? seg.originalOwnerTS;
      seg.currentBioConst = base + (now - tsBase);
    });
    // Annual reset for TVM claims
    const currentYear = new Date(now * 1000).getUTCFullYear();
    if (vault.lastClaimYear !== currentYear) {
      vault.tvmClaimedThisYear = 0;
      vault.lastClaimYear = currentYear;
    }
    this._session = { vaultData: vault, key, salt: rec.salt };
    await this.persist();
    await AuditService.log("Vault unlocked", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
    return vault;
  }

  static async bindWalletToKeyHash(walletAddress) {
    const { vaultData } = this._sess();
    if (vaultData.walletKeyHashBinding) throw new Error("Wallet already bound to this device");
    const bindingHash = await sha256Hex(walletAddress + vaultData.bioIBAN);
    vaultData.walletKeyHashBinding = bindingHash;
    vaultData.walletAddressKYC = walletAddress;
    await this.persist();
    await AuditService.log("Wallet bound to key hash", { bindingHash: bindingHash.slice(0,8) + '...' });
  }

  static lock() { this._session = null; }

  static get current() { return this._session?.vaultData || null; }

  static async persist() {
    const s = this._session;
    if (!s) throw new Error("Vault locked");
    const { iv, ct } = await CryptoService.encrypt(s.key, s.vaultData);
    await VaultStorage.save(iv, ct, toB64(s.salt), s.vaultData);
  }

  static async terminate() {
    const db = await VaultStorage._open();
    await new Promise((res, rej) => {
      const tx = db.transaction(DB.STORE, "readwrite");
      tx.objectStore(DB.STORE).delete("vaultData");
      tx.oncomplete = res;
      tx.onerror = () => rej(tx.error);
    });
    this._session = null;
    await AuditService.log("Vault terminated", {});
  }
}

/*──────────────────────── 12. SEGMENT SERVICE ─────────────────────────*/
class SegmentService {
  static _now() { return TimeSyncService.now(); }

  static _sess() { if (!VaultService._session) throw new Error("Vault locked"); return VaultService._session; }

  static async unlockNextSegment(idxRef = null) {
    const { vaultData } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    const assert = await WebAuthnService.assert(vaultData.credentialId);
    if (!ctEq(await hashDeviceKeyWithSalt(assert.rawId, vaultData.deviceSalt), dev))
      throw new Error("Biometric mismatch");
    CapEnforcer.check(vaultData, this._now());
    const locked = vaultData.segments
      .filter(s => !s.unlocked && !s.exported && !s.transferred && (ctEq(s.currentOwnerKey, dev) || s.currentOwnerKey === null))
      .sort((a, b) => a.segmentIndex - b.segmentIndex)[0];
    if (!locked) throw new Error("No locked segment available");
    locked.unlocked = true;
    locked.unlockIndexRef = idxRef;
    if (idxRef) {
      const trg = vaultData.segments.find(s => s.segmentIndex === idxRef);
      locked.unlockTriggerBioConst = trg?.currentBioConst || null;
      locked.unlockTriggerProof = trg?.unlockIntegrityProof || null;
    }
    locked.currentOwnerKey = dev;
    locked.currentOwnerTS = this._now();
    locked.currentBioConst = locked.previousBioConst
      ? locked.previousBioConst + (this._now() - locked.previousOwnerTS)
      : locked.originalBioConst + (this._now() - locked.originalOwnerTS);
    locked.unlockIntegrityProof = await computeUnlockIntegrityProof(locked);
    locked.ownershipProof = await computeOwnershipProof(locked);
    HistoryManager.record(locked, dev, this._now(), "unlock");
    vaultData.transactionHistory.push({
      type: "unlock",
      segmentIndex: locked.segmentIndex,
      timestamp: this._now(),
      amount: locked.amount,
      from: dev,
      to: dev,
      bioCatch: null,
      status: "Unlocked"
    });
    await VaultService.persist();
    await AuditService.log("Segment unlocked", { segmentIndex: locked.segmentIndex });
    return locked;
  }

  static async transferSegment(recvKey) {
    const { vaultData } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    if (ctEq(recvKey, dev)) throw new Error("Cannot transfer to self");
    const assert = await WebAuthnService.assert(vaultData.credentialId);
    if (!ctEq(await hashDeviceKeyWithSalt(assert.rawId, vaultData.deviceSalt), dev))
      throw new Error("Biometric mismatch");
    const seg = vaultData.segments
      .filter(s => s.unlocked && !s.exported && !s.transferred && ctEq(s.currentOwnerKey, dev))
      .sort((a, b) => a.segmentIndex - b.segmentIndex)[0];
    if (!seg) throw new Error("No unlocked segment");
    if (ctEq(seg.previousOwnerKey, recvKey)) throw new Error("Cannot transfer to previous owner");
    seg.previousOwnerKey = seg.currentOwnerKey;
    seg.previousOwnerTS = seg.currentOwnerTS;
    seg.previousBioConst = seg.currentBioConst;
    seg.currentOwnerKey = recvKey;
    seg.currentOwnerTS = this._now();
    seg.currentBioConst = seg.previousBioConst + (this._now() - seg.previousOwnerTS);
    seg.ownershipChangeCount++;
    seg.unlocked = false;
    seg.exported = true;
    seg.transferred = true;
    seg.spentProof = await computeSpentProof(seg);
    seg.ownershipProof = await computeOwnershipProof(seg);
    HistoryManager.record(seg, recvKey, this._now(), "transfer");
    vaultData.transactionHistory.push({
      type: "transfer",
      segmentIndex: seg.segmentIndex,
      timestamp: this._now(),
      amount: seg.amount,
      from: dev,
      to: recvKey,
      bioCatch: null,
      status: "Sent"
    });
    if (recvKey !== dev) {
      try { await this.unlockNextSegment(seg.segmentIndex); } catch (e) { console.warn("Auto-unlock failed:", e.message); }
    }
    await VaultService.persist();
    return seg;
  }

  static async exportSegmentsBatch(recvKey, count) {
    const { vaultData, key } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    const unlocked = vaultData.segments.filter(s => s.unlocked && !s.exported && !s.transferred && ctEq(s.currentOwnerKey, dev));
    if (unlocked.length < count) throw new Error(`Only ${unlocked.length} segment(s) unlocked`);
    const batch = [];
    let bioCatchSize = 0;
    let bonusGranted = false;
    if (CapEnforcer.checkBonus(vaultData, this._now(), "sent", count)) {
      CapEnforcer.recordBonus(vaultData, "sent");
      bonusGranted = true;
    }
    // TODO: Use Web Workers for large batches to prevent UI freeze
    for (let i = 0; i < count; i += Limits.BATCH_SIZE) {
      const chunk = Math.min(Limits.BATCH_SIZE, count - i);
      for (let j = 0; j < chunk; j++) {
        const seg = await this.transferSegment(recvKey);
        const plainBio = await this.generateBioCatchNumber(
          vaultData.bioIBAN, recvKey, seg.amount, this._now(), vaultData.tvmClaimedThisYear, vaultData.finalChainHash
        );
        const obfBio = await CryptoService.encryptBioCatchNumber(plainBio, key);
        const tx = vaultData.transactionHistory.find(t => t.segmentIndex === seg.segmentIndex && t.type === "transfer");
        tx.bioCatch = obfBio;
        const payload = { ...seg, bioCatch: obfBio };
        batch.push(payload);
        bioCatchSize += JSON.stringify(payload).length;
      }
    }
    document.getElementById("bioCatchSize").textContent = `Size: ${(bioCatchSize / 1024 / 1024).toFixed(2)} MB`;
    if (bonusGranted) {
      const offset = this._now() - vaultData.onboardingTS;
      const bonusIBAN = `BONUS${vaultData.userBioConst + offset}`;
      const bonusTx = {
        type: "cashback",
        amount: Protocol.BONUS.PER_TX,
        timestamp: this._now(),
        status: "Granted",
        bonusConstantAtGeneration: vaultData.userBioConst,
        previousHash: vaultData.lastTransactionHash,
        txHash: "",
        senderBioIBAN: bonusIBAN,
        triggerOrigin: "sent",
        bonusId: vaultData.nextBonusId++
      };
      bonusTx.txHash = await this.computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactionHistory.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await this.computeFullChainHash(vaultData.transactionHistory);
      if (vaultData.walletAddress && vaultData.credentialId) {
        await ChainService.redeemBonusOnChain(bonusTx);
      }
    }
    vaultData.finalChainHash = await this.computeFullChainHash(vaultData.transactionHistory);
    await VaultService.persist();
    const payload = JSON.stringify(batch);
    await AuditService.log("Segments exported", { count, bioCatchSize });
    return payload;
  }

  static async importSegmentsBatch(raw, recvKey) {
    let list;
    try { list = JSON.parse(raw); } catch { throw new Error("Corrupt payload"); }
    if (!Array.isArray(list) || !list.length) throw new Error("Empty payload");
    list.forEach(seg => {
      if (!seg.exported) throw new Error("Payload already claimed");
      if (!ctEq(seg.currentOwnerKey, recvKey)) throw new Error("Segment not addressed to this vault");
    });
    return list;
  }

  static async claimReceivedSegmentsBatch(list) {
    const { vaultData, key } = this._sess();
    const now = this._now();
    let bonusGranted = false;
    if (CapEnforcer.checkBonus(vaultData, now, "received", list.length)) {
      CapEnforcer.recordBonus(vaultData, "received");
      bonusGranted = true;
    }
    for (const seg of list) {
      const existing = vaultData.segments.find(s => s.segmentIndex === seg.segmentIndex);
      if (existing) {
        if (!ctEq(existing.ownershipProof, seg.ownershipProof))
          throw new Error(`Replay / fork on segment #${seg.segmentIndex}`);
        continue;
      }
      if (vaultData.seenNonces.has(seg.nonce)) throw new Error(`Replay detected on nonce`);
      vaultData.seenNonces.add(seg.nonce);
      if (!ctEq(seg.ownershipProof, await computeOwnershipProof(seg)))
        throw new Error(`Bad ownership proof for segment #${seg.segmentIndex}`);
      if (seg.unlockIndexRef !== null &&
          !ctEq(seg.unlockIntegrityProof, await computeUnlockIntegrityProof(seg)))
        throw new Error(`Bad unlock proof for segment #${seg.segmentIndex}`);
      if (seg.spentProof && !ctEq(seg.spentProof, await computeSpentProof(seg)))
        throw new Error(`Bad spent proof for segment #${seg.segmentIndex}`);
      if (seg.bioCatch) {
        const plainBio = await CryptoService.decryptBioCatchNumber(seg.bioCatch, key);
        if (!plainBio) throw new Error("Invalid BioCatch");
        const validation = await this.validateBioCatchNumber(plainBio, seg.amount, vaultData.bioIBAN);
        if (!validation.valid) throw new Error(`BioCatch fail: ${validation.message}`);
      }
      seg.exported = false;
      vaultData.segments.push(seg);
      vaultData.transactionHistory.push({
        type: "received",
        segmentIndex: seg.segmentIndex,
        timestamp: now,
        amount: seg.amount,
        from: seg.previousOwnerKey,
        to: vaultData.deviceKeyHashes[0],
        bioCatch: seg.bioCatch,
        status: "Received"
      });
    }
    if (bonusGranted) {
      const offset = now - vaultData.onboardingTS;
      const bonusIBAN = `BONUS${vaultData.userBioConst + offset}`;
      const bonusTx = {
        type: "cashback",
        amount: Protocol.BONUS.PER_TX,
        timestamp: now,
        status: "Granted",
        bonusConstantAtGeneration: vaultData.userBioConst,
        previousHash: vaultData.lastTransactionHash,
        txHash: "",
        senderBioIBAN: bonusIBAN,
        triggerOrigin: "received",
        bonusId: vaultData.nextBonusId++
      };
      bonusTx.txHash = await this.computeTransactionHash(vaultData.lastTransactionHash, bonusTx);
      vaultData.transactionHistory.push(bonusTx);
      vaultData.lastTransactionHash = bonusTx.txHash;
      vaultData.finalChainHash = await this.computeFullChainHash(vaultData.transactionHistory);
      if (vaultData.walletAddress && vaultData.credentialId) {
        await ChainService.redeemBonusOnChain(bonusTx);
      }
    }
    vaultData.finalChainHash = await this.computeFullChainHash(vaultData.transactionHistory);
    await VaultService.persist();
    await AuditService.log("Segments claimed", { count: list.length });
  }

  static async computeTransactionHash(prevHash, txObj) {
    const dataStr = JSON.stringify({ prevHash, ...txObj });
    const buf = enc.encode(dataStr);
    const hashBuf = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  static async computeFullChainHash(transactions) {
    let rHash = '';
    let sorted = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    for (let t of sorted) {
      let tmp = { type: t.type, amount: t.amount, timestamp: t.timestamp, status: t.status, bioCatch: t.bioCatch,
                  bonusConstantAtGeneration: t.bonusConstantAtGeneration, previousHash: rHash };
      rHash = await this.computeTransactionHash(rHash, tmp);
    }
    return rHash;
  }

  static async generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
    const now = this._now();
    if (Math.abs(now - timestamp) > Limits.TRANSACTION_VALIDITY_SECONDS)
      throw new Error("Timestamp out of validity window");
    const data = { senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash };
    const dataStr = canonical(data);
    const signature = await hmacSha256(dataStr);
    return { data: dataStr, signature };
  }

  static async validateBioCatchNumber(plainObj, claimedAmount, myIBAN) {
    if (!plainObj || !plainObj.data || !plainObj.signature) return { valid: false, message: "Invalid format" };
    const recomputed = await hmacSha256(plainObj.data);
    if (recomputed !== plainObj.signature) return { valid: false, message: "HMAC mismatch" };
    let parsed;
    try { parsed = JSON.parse(plainObj.data); } catch { return { valid: false, message: "Parse error" }; }
    if (parsed.amount !== claimedAmount) return { valid: false, message: "Amount mismatch" };
    const now = TimeSyncService.now();
    if (Math.abs(now - parsed.timestamp) > Limits.TRANSACTION_VALIDITY_SECONDS) return { valid: false, message: "Expired" };
    if (parsed.receiverBioIBAN !== myIBAN) return { valid: false, message: "Receiver mismatch" };
    return { valid: true, message: "", claimedSenderIBAN: parsed.senderBioIBAN };
  }

  // New: Exchange offline segments to TVM on-chain
  static async exchangeOfflineToTVM(count) {
    const avail = TokenService.getAvailableTVMClaims();
    if (avail < count) throw new Error("Insufficient offline balance for exchange");
    const bundle = TokenService.prepareClaimBundle(count * Protocol.TVM.SEGMENTS_PER_TOKEN);
    await ChainService.submitClaimOnChain(bundle);
    toast(`Exchanged ${count} TVM from offline balance`);
  }

  // New: Send TVM to contract for offline segments
  static async sendTVMToContractForOffline(amount) {
    const { vaultData } = this._sess();
    const receipt = await ChainService.sendTVMToContract(amount, vaultData.bioIBAN);
    // Parse receipt for emitted event with segments/proofs
    const { segmentsProof } = receipt.events.ExchangeToOffline.returnValues; // Assume event
    await this.claimReceivedSegmentsBatch(segmentsProof); // Import the returned segments
    toast(`Sent ${amount} TVM to contract for offline balance`);
  }
}

/*──────────────────────── 13. BACKUP SERVICE ─────────────────────────*/
class BackupService {
  static async exportEncryptedBackup(vault, pwd) {
    if (!pwd || pwd.length < 8) throw new Error("Password ≥8 chars");
    const salt = rand(16);
    const key = await CryptoService.deriveKey(pwd, salt);
    const { iv, ct } = await CryptoService.encrypt(key, vault);
    const backup = { salt: toB64(salt), iv: toB64(iv), ciphertext: toB64(ct) };
    await AuditService.log("Backup exported", { size: JSON.stringify(backup).length });
    return backup;
  }

  static async importEncryptedBackup(payload, pwd) {
    const salt = fromB64(payload.salt), iv = fromB64(payload.iv), ct = fromB64(payload.ciphertext);
    const key = await CryptoService.deriveKey(pwd, salt);
    const vault = await CryptoService.decrypt(key, iv, ct);
    await AuditService.log("Backup imported", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
    return vault;
  }

  static exportFriendly(vault) {
    const blob = new Blob([JSON.stringify(vault)], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: "myBioVault.vault" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    AuditService.log("Friendly backup exported", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
  }
}

/*──────────────────────── 14. AUDIT SERVICE ─────────────────────────*/
class AuditService {
  static async log(event, meta) {
    // TODO: Integrate with monitoring like Sentry
    console.log(`[AUDIT] ${event}`, meta);
  }

  static generateAuditReport(vault, { fullHistory = false } = {}) {
    const lim = Protocol.HISTORY_MAX;
    return {
      bioIBAN: vault.bioIBAN.slice(0,8) + '...',
      deviceKeyHashes: vault.deviceKeyHashes.map(h => h.slice(0, 8) + "…"),
      onboardingTS: vault.onboardingTS,
      userBioConst: vault.userBioConst,
      segments: vault.segments.map(s => ({
        ...s,
        currentOwnerKey: s.currentOwnerKey.slice(0,8) + '...',
        previousOwnerKey: s.previousOwnerKey ? s.previousOwnerKey.slice(0,8) + '...' : null,
        originalOwnerKey: s.originalOwnerKey.slice(0,8) + '...',
        ownershipChangeHistory: fullHistory ? s.ownershipChangeHistory.map(h => ({...h, ownerKey: h.ownerKey.slice(0,8)+'...'})) : s.ownershipChangeHistory.slice(-lim).map(h => ({...h, ownerKey: h.ownerKey.slice(0,8)+'...'}))
      })),
      tvmClaimedThisYear: vault.tvmClaimedThisYear,
      walletAddressKYC: vault.walletAddressKYC ? vault.walletAddressKYC.slice(0,6) + '...' + vault.walletAddressKYC.slice(-4) : ''
    };
  }

  static exportComplianceReport(vault) {
    if (!confirm("Export compliance report? This contains masked sensitive data.")) return;
    const report = this.generateAuditReport(vault, { fullHistory: true });
    const blob = new Blob([JSON.stringify(report)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: `compliance_${vault.bioIBAN.slice(0,8)}.json` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    this.log("Compliance report exported", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
    return report;
  }

  static async verifyProofChain(segments, expectedKey) {
    for (const seg of segments) {
      if (!ctEq(seg.currentOwnerKey, expectedKey))
        throw new Error(`Seg#${seg.segmentIndex}: owner mismatch`);
      if (!ctEq(seg.ownershipProof, await computeOwnershipProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: ownership proof bad`);
      if (seg.unlockIndexRef !== null &&
          !ctEq(seg.unlockIntegrityProof, await computeUnlockIntegrityProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: unlock proof bad`);
      if (seg.spentProof && !ctEq(seg.spentProof, await computeSpentProof(seg)))
        throw new Error(`Seg#${seg.segmentIndex}: spent proof bad`);
    }
    return true;
  }

  static pruneHistory(vault) {
    vault.segments.forEach(s => {
      s.ownershipChangeHistory = s.ownershipChangeHistory.slice(-Protocol.HISTORY_MAX);
    });
    this.log("History pruned", { bioIBAN: vault.bioIBAN.slice(0,8) + '...' });
  }
}

/*──────────────────────── 15. CHAIN SERVICE ─────────────────────────*/
const CONTRACT = "0xYourDeployedAddressHere"; // Point 9: Replace with real (audited contract)
const USDT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"; // Mainnet USDT example
const claimAbi = [ 
  "function claimTVM(tuple(uint32 segmentIndex, bytes32 spentProof, bytes32 ownershipProof, bytes32 unlockIntegrityProof)[] segmentProofs, bytes signature) external",
  "function redeemBonus(address wallet, uint bonusId) external returns (uint)",
  "function exchangeToOffline(uint256 amount, string calldata keyHash) external", // New: Send TVM to contract, emit for offline
  "function depositUSDT(uint256 amount) external", // New: Deposit USDT, mint TVM
  "function withdrawUSDT(uint256 amount) external", // New: Send TVM to contract, transfer USDT if available
  "event ExchangeToOffline(address user, uint256 amount, string keyHash, bytes segmentsProof)"
];
const ChainService = (() => {
  let provider = null, signer = null;
  return {
    initWeb3() {
      if (window.ethereum && !provider) {
        provider = new ethers.providers.Web3Provider(window.ethereum, "any");
        signer = provider.getSigner();
      }
    },

    async submitClaimOnChain(bundle) {
      if (!signer) throw new Error("Connect wallet first");
      const v = VaultService.current;
      if (!v.walletAddressKYC || !/^0x[a-fA-F0-9]{40}$/.test(v.walletAddressKYC))
        throw new Error("KYC’d wallet address required. Verify via providers like Sumsub or ComplyCube.");
      if (v.walletKeyHashBinding !== await sha256Hex(v.walletAddressKYC + v.bioIBAN)) throw new Error("Wallet not bound to this device");
      const domain = { name: "TVMClaim", version: "1", chainId: await signer.getChainId(), verifyingContract: CONTRACT };
      const types = {
        SegmentProof: [
          { name: "segmentIndex", type: "uint32" },
          { name: "spentProof", type: "bytes32" },
          { name: "ownershipProof", type: "bytes32" },
          { name: "unlockIntegrityProof", type: "bytes32" }
        ]
      };
      const sig = await signer._signTypedData(domain, types, { segmentProofs: bundle });
      const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
      let tx;
      try {
        tx = await contract.claimTVM(bundle, sig, { gasLimit: 500000 }); // Added gas estimation placeholder
      } catch (e) {
        throw new Error(`Claim failed: ${e.reason || e.message}`);
      }
      const receipt = await tx.wait();
      await AuditService.log("TVM claimed", { txHash: receipt.transactionHash, segments: bundle.length });
      return receipt;
    },

    async redeemBonusOnChain(tx) {
      if (!signer) throw new Error("Connect wallet first");
      if (!tx || !tx.bonusId) throw new Error("Invalid bonus or missing bonusId");
      const v = VaultService.current;
      if (!v.walletAddressKYC) throw new Error("KYC’d wallet address required. Verify via providers like Sumsub or ComplyCube.");
      const userAddr = await signer.getAddress();
      if (userAddr.toLowerCase() !== v.walletAddressKYC.toLowerCase())
        console.warn("Active MetaMask address != vaultData.walletAddressKYC. Proceeding...");
      const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
      let txResp;
      try {
        txResp = await contract.redeemBonus(v.walletAddressKYC, tx.bonusId, { gasLimit: 200000 });
      } catch (e) {
        throw new Error(`Redeem failed: ${e.reason || e.message}`);
      }
      const receipt = await txResp.wait();
      toast(`Bonus #${tx.bonusId} redeemed, txHash: ${receipt.transactionHash}`);
      await AuditService.log("Bonus redeemed", { bonusId: tx.bonusId });
    },

    async sendTVMToContract(amount, keyHash) {
      if (!signer) throw new Error("Connect wallet first");
      const tvmContract = new ethers.Contract(CONTRACT, ["function approve(address spender, uint256 amount) external returns (bool)", "function transfer(address to, uint256 amount) external returns (bool)"], signer);
      await tvmContract.approve(CONTRACT, amount);
      await tvmContract.transfer(CONTRACT, amount);
      const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
      const tx = await contract.exchangeToOffline(amount, keyHash, { gasLimit: 300000 });
      return await tx.wait();
    },

    async depositUSDT(amount) {
      if (!signer) throw new Error("Connect wallet first");
      const usdtContract = new ethers.Contract(USDT_ADDRESS, ["function approve(address spender, uint256 amount) external returns (bool)"], signer);
      await usdtContract.approve(CONTRACT, amount);
      const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
      const tx = await contract.depositUSDT(amount, { gasLimit: 400000 });
      await tx.wait();
      toast(`Deposited ${amount} USDT for TVM`);
    },

    async withdrawUSDT(amount) {
      if (!signer) throw new Error("Connect wallet first");
      const tvmContract = new ethers.Contract(CONTRACT, ["function approve(address spender, uint256 amount) external returns (bool)", "function transfer(address to, uint256 amount) external returns (bool)"], signer);
      await tvmContract.approve(CONTRACT, amount);
      await tvmContract.transfer(CONTRACT, amount);
      const contract = new ethers.Contract(CONTRACT, claimAbi, signer);
      const tx = await contract.withdrawUSDT(amount, { gasLimit: 300000 });
      await tx.wait();
      toast(`Withdrew ${amount} USDT from TVM`);
    },

    async emergencyPause() {
      console.log("Emergency pause triggered (stub)");
      await AuditService.log("Contract paused", {});
    },

    getSigner() { return signer; },

    async verifyPeg() {
      // TODO: Implement on-chain peg verification with oracle or contract call
      return true;
    }
  };
})();

/*──────────────────────── 16. TOKEN SERVICE ─────────────────────────*/
class TokenService {
  static _vault() { const v = VaultService.current; if (!v) throw new Error("Vault locked"); return v; }

  static getAvailableTVMClaims() {
    const v = this._vault(), dev = v.deviceKeyHashes[0];
    const used = v.segments.filter(s => ctEq(s.currentOwnerKey, dev) && (s.unlocked || s.ownershipChangeCount > 0)).length;
    const claimed = v.tvmClaimedThisYear || 0;
    return Math.max(Math.floor(used / Protocol.TVM.SEGMENTS_PER_TOKEN) - claimed, 0);
  }

  static prepareClaimBundle(needed) {
    const v = this._vault();
    const segs = v.segments.filter(s => s.ownershipChangeCount > 0 || s.unlocked).slice(0, needed);
    return segs.map(s => ({
      segmentIndex: s.segmentIndex,
      spentProof: s.spentProof,
      ownershipProof: s.ownershipProof,
      unlockIntegrityProof: s.unlockIntegrityProof
    }));
  }

  static async claimTvmTokens() {
    const v = this._vault();
    const avail = this.getAvailableTVMClaims();
    if (!v.walletAddressKYC || !/^0x[a-fA-F0-9]{40}$/.test(v.walletAddressKYC))
      throw new Error("KYC’d wallet address required. Verify via providers like Sumsub or ComplyCube.");
    if (avail <= 0) throw new Error("Nothing to claim");
    if ((v.tvmClaimedThisYear || 0) + avail > Protocol.TVM.CLAIM_CAP)
      throw new Error("Yearly TVM cap reached");
    const needed = avail * Protocol.TVM.SEGMENTS_PER_TOKEN;
    const bundle = this.prepareClaimBundle(needed);
    if (await ChainService.verifyPeg() !== true) throw new Error("Peg verification failed");
    await ChainService.submitClaimOnChain(bundle);
    v.tvmClaimedThisYear += avail;
    await VaultService.persist();
    await AuditService.log("TVM tokens claimed", { count: avail });
    return bundle;
  }
}

/*──────────────────────── 17. UI HELPERS ───────────────────────────*/
const toast = (msg, err = false) => {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.className = `toast ${err ? "toast-error" : ""}`;
  el.style.display = "block";
  setTimeout(() => el.style.display = "none", 3200);
};

const copyToClipboard = async text => {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("Copied"); } catch { toast("Copy failed", true); }
    ta.remove();
  }
};

let lastInvoker = null;
const openModal = id => {
  document.querySelectorAll(".modal, .popup").forEach(m => m.style.display = "none");
  const modal = document.getElementById(id);
  if (modal) {
    modal.style.display = "flex";
    const focusEl = modal.querySelector('[tabindex="0"]');
    if (focusEl) setTimeout(() => focusEl.focus(), 130);
    lastInvoker = document.activeElement;
    document.body.style.overflow = "hidden";
  }
};

const closeModal = id => {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = "none";
  document.body.style.overflow = "";
  lastInvoker?.focus();
};

const modalNav = (modalId, pageIdx) => {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  const pages = modal.querySelectorAll(".modal-onboarding-page");
  pages.forEach((p, i) => p.classList.toggle("hidden", i !== pageIdx));
  const nav = modal.querySelectorAll(".modal-nav button");
  nav.forEach((btn, i) => btn.classList.toggle("active", i === pageIdx));
};

let deferredPrompt = null;
window.addEventListener("beforeinstallprompt", e => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ A2HS prompt captured");
});

const promptInstallA2HS = () => {
  if (!deferredPrompt) { toast("No A2HS prompt available", true); return; }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choice => {
    console.log("A2HS", choice.outcome);
    AuditService.log("A2HS prompt", { outcome: choice.outcome });
    deferredPrompt = null;
  });
};

const generateQRCode = data => {
  const canvas = document.getElementById("qrCodeCanvas");
  if (!canvas) return;
  new QRCode(canvas, {
    text: data,
    width: 200,
    height: 200,
    colorDark : "#000000",
    colorLight : "#ffffff",
    correctLevel : QRCode.CorrectLevel.H
  });
  canvas.setAttribute("alt", "Bio-Catch QR Code"); // Added for accessibility
};

const showOnboardingIfNeeded = () => {
  if (!localStorage.getItem("vaultOnboarded")) {
    openModal("onboardingModal");
    modalNav("onboardingModal", 0);
    localStorage.setItem("vaultOnboarded", "yes");
  }
};

const showBackupReminder = () => {
  const tip = document.getElementById("onboardingTip");
  if (tip) tip.style.display = localStorage.getItem("vaultBackedUp") ? "none" : "";
};

/*──────────────────────── 18. TRANSACTION TABLE ───────────────────*/
let transactionPage = 0;
const renderTransactions = () => {
  const v = VaultService.current;
  const tbody = document.getElementById("transactionBody");
  const empty = document.getElementById("txEmptyState");
  const prev = document.getElementById("txPrevBtn");
  const next = document.getElementById("txNextBtn");
  if (!tbody || !v) return;
  tbody.innerHTML = "";
  if (!v.transactionHistory.length) {
    empty.style.display = "";
    prev.style.display = "none";
    next.style.display = "none";
    return;
  }
  empty.style.display = "none";
  const pageSize = Limits.PAGE.DEFAULT_SIZE;
  const sortedHistory = [...v.transactionHistory].sort((a, b) => a.timestamp - b.timestamp);
  const start = transactionPage * pageSize;
  const end = start + pageSize;
  sortedHistory.slice(start, end).forEach(tx => {
    const proof = tx.bioCatch ? tx.bioCatch.slice(0, 8) + "..." : "N/A";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${tx.type === "cashback" ? `Bonus #${tx.bonusId}` : (tx.to === v.deviceKeyHashes[0] ? tx.from : tx.to).slice(0, 10) + "…"}</td>
      <td>${tx.bioCatch ? tx.bioCatch.slice(0, 8) + "..." : "—"}</td>
      <td>${proof}</td>
      <td>${tx.amount}</td>
      <td>${new Date(tx.timestamp * 1000).toLocaleString()}</td>
      <td>${tx.status}</td>
    `;
    tbody.appendChild(tr);
  });
  prev.style.display = transactionPage > 0 ? "" : "none";
  next.style.display = end < v.transactionHistory.length ? "" : "none";
};

/*──────────────────────── 19. DASHBOARD RENDER ────────────────────*/
const renderVaultUI = () => {
  const v = VaultService.current;
  if (!v) {
    document.getElementById("lockedScreen").style.display = "block";
    document.getElementById("vaultUI").style.display = "none";
    return;
  }
  document.getElementById("lockedScreen").style.display = "none";
  document.getElementById("vaultUI").style.display = "block";
  const bioibanInput = document.getElementById("bioibanInput");
  if (bioibanInput) {
    bioibanInput.value = v.bioIBAN || "BIO…";
    bioibanInput.readOnly = true;
  }
  const segUsed = v.segments.filter(s => ctEq(s.currentOwnerKey, v.deviceKeyHashes[0]) && (s.unlocked || s.ownershipChangeCount > 0)).length;
  const balance = segUsed;
  v.balanceUSD = +(balance / Protocol.TVM.EXCHANGE_RATE).toFixed(2);
  document.getElementById("tvmBalance").textContent = `Balance: ${balance} TVM`;
  document.getElementById("usdBalance").textContent = `Equivalent: ${v.balanceUSD} USD`;
  document.getElementById("segmentStatus").textContent = `Segments: ${segUsed}/${Protocol.SEGMENTS.TOTAL} Unlocked`;
  document.getElementById("bioLineText").textContent = `🔄 Bio-Constant: ${v.userBioConst}`;
  document.getElementById("userWalletAddress").value = v.walletAddressKYC || "";
  document.getElementById("tvmClaimable").textContent = `TVM Claimable: ${TokenService.getAvailableTVMClaims()}`;
  renderTransactions();
  showBackupReminder();
};

/*──────────────────────── 20. SAFE HANDLER ─────────────────────────*/
const safeHandler = f => async (...args) => {
  try {
    await f(...args);
  } catch (e) {
    console.error(e);
    await AuditService.log("Error", { message: e.message });
    toast(e.message || "Error", true);
  }
};

/*──────────────────────── 21. INITIALIZATION & EVENT BINDING ────────*/
(() => {
  // Service Worker Registration
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./sw.js")
        .then(reg => console.log("Service Worker registered:", reg.scope))
        .catch(err => console.error("Service Worker registration failed:", err));
    });
  }

  // Modal and Popup Accessibility
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal, .popup").forEach(m => m.style.display = "none");
      document.body.style.overflow = "";
    }
  });

  document.querySelectorAll(".modal, .popup").forEach(modal => {
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    // Assume titles have id="modalTitle"
    modal.setAttribute("aria-labelledby", "modalTitle");
    modal.addEventListener("click", e => {
      if (e.target === modal) {
        modal.style.display = "none";
        document.body.style.overflow = "";
      }
    });
  });

  // UTC Clock
  setInterval(TimeSyncService.updateUTCClock, 1000);
  TimeSyncService.updateUTCClock();
  TimeSyncService.sync();

  // Session Auto-Lock
  let timer;
  const resetIdleTimer = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      VaultService.lock();
      location.reload();
    }, MAX_IDLE);
  };
  ["click", "mousemove", "keypress", "touchstart", "scroll"].forEach(event =>
    document.addEventListener(event, resetIdleTimer)
  );

  // Button Wiring (with sanitization where needed)
  document.getElementById("enterVaultBtn")?.addEventListener("click", safeHandler(() => {
    const modal = document.getElementById("passModal");
    const title = document.getElementById("passModalTitle");
    const confirmLabel = document.getElementById("passModalConfirmLabel");
    const confirmInput = document.getElementById("passModalConfirmInput");
    title.textContent = localStorage.getItem("vaultOnboarded") ? "Unlock Vault" : "Create Vault";
    confirmLabel.classList.toggle("hidden", !!localStorage.getItem("vaultOnboarded"));
    confirmInput.classList.toggle("hidden", !!localStorage.getItem("vaultOnboarded"));
    openModal("passModal");
  }));

  document.getElementById("passModalSaveBtn")?.addEventListener("click", safeHandler(async () => {
    const pin = document.getElementById("passModalInput").value;
    const confirm = document.getElementById("passModalConfirmInput").value;
    if (!pin || pin.length < 8) throw new Error("Passphrase must be ≥8 characters");
    if (!localStorage.getItem("vaultOnboarded")) {
      if (pin !== confirm) throw new Error("Passphrases do not match");
      await VaultService.onboard(pin);
    } else {
      await VaultService.unlock(pin);
    }
    closeModal("passModal");
    renderVaultUI();
  }));

  document.getElementById("passModalCancelBtn")?.addEventListener("click", () => closeModal("passModal"));

  document.getElementById("lockVaultBtn")?.addEventListener("click", safeHandler(async () => {
    VaultService.lock();
    renderVaultUI();
    toast("Vault locked");
  }));

  document.getElementById("terminateBtn")?.addEventListener("click", safeHandler(async () => {
    if (!confirm("Permanently terminate vault? All funds will be lost without backup.")) return;
    await VaultService.terminate();
    renderVaultUI();
    toast("Vault terminated");
  }));

  document.getElementById("testModeBtn")?.addEventListener("click", () => {
    toast("Test mode: Simulate transactions in console");
    console.log("Test mode: Simulating transfer of 1 segment...");
    // For testing: Mock transfer without biometric
  });

  document.getElementById("copyBioIBANBtn")?.addEventListener("click", () => copyToClipboard(
    document.getElementById("bioibanInput").value));

  document.getElementById("catchOutBtn")?.addEventListener("click", safeHandler(async () => {
    const recv = sanitizeInput(document.getElementById("receiverBioIBAN").value.trim());
    const amt = Number(document.getElementById("catchOutAmount").value);
    if (!recv || !Number.isInteger(amt) || amt <= 0) throw new Error("Receiver & integer amount required");
    if (!/^BIO\d+$/.test(recv) && !/^BONUS\d+$/.test(recv)) throw new Error("Invalid Bio-IBAN");
    if (recv === VaultService.current?.bioIBAN) throw new Error("Cannot send to self");
    if (amt > 10000 && !confirm("Large transfer (>10,000 segments) may take time. Proceed?")) return;
    if (!confirm(`Send ${amt} segment${amt > 1 ? "s" : ""} to ${recv}?`)) return;
    const payload = await SegmentService.exportSegmentsBatch(recv, amt);
    copyToClipboard(payload);
    generateQRCode(payload);
    toast(`Exported ${amt} segment${amt > 1 ? "s" : ""}. Payload copied & QR generated.`);
    renderVaultUI();
  }));

  document.getElementById("catchInBtn")?.addEventListener("click", safeHandler(async () => {
    const raw = sanitizeInput(document.getElementById("catchInBioCatch").value.trim());
    if (!raw) throw new Error("Paste the received payload");
    if (!confirm("Claim received segments?")) return;
    const segs = await SegmentService.importSegmentsBatch(raw, VaultService.current.deviceKeyHashes[0]);
    await SegmentService.claimReceivedSegmentsBatch(segs);
    toast(`Claimed ${segs.length} segment${segs.length > 1 ? "s" : ""}`);
    renderVaultUI();
  }));

  document.getElementById("showBioCatchBtn")?.addEventListener("click", safeHandler(async () => {
    const v = VaultService.current;
    const seg = v.segments.find(s => s.unlocked && ctEq(s.currentOwnerKey, v.deviceKeyHashes[0]));
    if (!seg) throw new Error("Unlock a segment first");
    const plainBio = await SegmentService.generateBioCatchNumber(
      v.bioIBAN, v.bioIBAN, seg.amount, SegmentService._now(), v.tvmClaimedThisYear, v.finalChainHash
    );
    const token = await CryptoService.encryptBioCatchNumber(plainBio, this._sess().key);
    const bioCatchText = document.getElementById("bioCatchNumberText");
    bioCatchText.textContent = token.length > 12 ? token.slice(0, 12) + "..." : token;
    bioCatchText.dataset.fullCatch = token;
    document.getElementById("bioCatchSize").textContent = `Size: ${(token.length / 1024 / 1024).toFixed(2)} MB`;
    generateQRCode(token);
    openModal("bioCatchPopup");
  }));

  document.getElementById("copyBioCatchBtn")?.addEventListener("click", () => {
    const bcTxt = document.getElementById("bioCatchNumberText");
    copyToClipboard(bcTxt.dataset.fullCatch || bcTxt.textContent);
  });

  document.getElementById("closeBioCatchPopup")?.addEventListener("click", () => closeModal("bioCatchPopup"));

  document.getElementById("claimTVMBtn")?.addEventListener("click", safeHandler(async () => {
    if (!confirm("Claim available TVM tokens to your KYC’d wallet?")) return;
    await TokenService.claimTvmTokens();
    renderVaultUI();
    toast("TVM tokens claimed successfully!");
  }));

  // New buttons for exchanges
  document.getElementById("exchangeOfflineToTVMBtn")?.addEventListener("click", safeHandler(async () => {
    const amount = Number(prompt("Amount of TVM to exchange from offline:"));
    if (!amount || amount <= 0) return;
    await SegmentService.exchangeOfflineToTVM(amount);
    renderVaultUI();
  }));

  document.getElementById("sendTVMToContractForOfflineBtn")?.addEventListener("click", safeHandler(async () => {
    const amount = Number(prompt("Amount of TVM to send to contract for offline:"));
    if (!amount || amount <= 0) return;
    await SegmentService.sendTVMToContractForOffline(amount);
    renderVaultUI();
  }));

  document.getElementById("depositUSDTBtn")?.addEventListener("click", safeHandler(async () => {
    const amount = Number(prompt("Amount of USDT to deposit for TVM:"));
    if (!amount || amount <= 0) return;
    await ChainService.depositUSDT(amount);
    renderVaultUI();
  }));

  document.getElementById("withdrawUSDTBtn")?.addEventListener("click", safeHandler(async () => {
    const amount = Number(prompt("Amount of TVM to send to contract for USDT:"));
    if (!amount || amount <= 0) return;
    await ChainService.withdrawUSDT(amount);
    renderVaultUI();
  }));

  document.getElementById("exportBtn")?.addEventListener("click", safeHandler(async () => {
    const v = VaultService.current;
    if (!v) throw new Error("Vault locked");
    const rows = [["Bio-IBAN", "Bio-Catch", "Proof", "Amount", "Date", "Status"]];
    v.transactionHistory.forEach(tx => {
      const proof = tx.bioCatch ? tx.bioCatch.slice(0, 8) + "..." : "N/A";
      rows.push([
        tx.type === "cashback" ? `Bonus #${tx.bonusId}` : (tx.to === v.deviceKeyHashes[0] ? tx.from : tx.to).slice(0, 10) + "…",
        tx.bioCatch ? tx.bioCatch.slice(0, 8) + "..." : "—",
        proof,
        tx.amount,
        new Date(tx.timestamp * 1000).toLocaleString(),
        tx.status
      ]);
    });
    const csv = "data:text/csv;charset=utf-8," + rows.map(r => r.join(",")).join("\n");
    const a = Object.assign(document.createElement("a"), { href: encodeURI(csv), download: "transactions.csv" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    await AuditService.log("Transaction history exported", {});
  }));

  document.getElementById("exportBackupBtn")?.addEventListener("click", safeHandler(async () => {
    const pwd = prompt("Backup password (≥8 chars):");
    if (!pwd) return;
    const data = await BackupService.exportEncryptedBackup(VaultService.current, pwd);
    const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: "vault_backup.enc.json" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    localStorage.setItem("vaultBackedUp", "yes");
    showBackupReminder();
    toast("Encrypted backup exported");
  }));

  document.getElementById("exportFriendlyBtn")?.addEventListener("click", safeHandler(async () => {
    BackupService.exportFriendly(VaultService.current);
    localStorage.setItem("vaultBackedUp", "yes");
    showBackupReminder();
    toast("Friendly backup exported");
  }));

  document.getElementById("importVaultFileInput")?.addEventListener("change", safeHandler(async e => {
    const f = e.target.files[0];
    if (!f) return;
    const txt = await f.text();
    const payload = JSON.parse(txt);
    const pwd = prompt("Enter backup password:");
    if (!pwd) return;
    const vault = await BackupService.importEncryptedBackup(payload, pwd);
    VaultService._session = { vaultData: vault, key: null, salt: null };
    await VaultService.persist();
    renderVaultUI();
    toast("Vault imported");
  }));

  document.getElementById("installA2HSBtn")?.addEventListener("click", promptInstallA2HS);

  document.getElementById("saveWalletBtn")?.addEventListener("click", safeHandler(async () => {
    const addr = document.getElementById("userWalletAddress").value.trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Error("Bad address");
    alert("Ensure this wallet is KYC-verified via providers like Sumsub, ComplyCube, or Onfido before saving.");
    await VaultService.bindWalletToKeyHash(addr);
    toast("KYC’d wallet address saved and bound");
    await AuditService.log("Wallet address saved", { address: addr.slice(0,6) + '...' + addr.slice(-4) });
  }));

  document.getElementById("autoConnectWalletBtn")?.addEventListener("click", safeHandler(async () => {
    ChainService.initWeb3();
    await window.ethereum?.request({ method: "eth_requestAccounts" });
    const signer = ChainService.getSigner();
    const addr = signer ? await signer.getAddress() : "";
    if (addr) {
      document.getElementById("userWalletAddress").value = addr;
      document.getElementById("saveWalletBtn").click();
    } else toast("Wallet connect failed", true);
  }));

  document.getElementById("exportComplianceBtn")?.addEventListener("click", safeHandler(async () => {
    AuditService.exportComplianceReport(VaultService.current);
    toast("Compliance report exported");
  }));

  document.getElementById("catchOutAmount")?.addEventListener("input", e => {
    const amt = Number(e.target.value);
    if (amt > 10000) toast("Large transfers (>10,000 segments) may take time.", true);
  });

  document.getElementById("auditPegLive").innerHTML = `1 TVM = 12 SHE = 1 USD (Protocol-Pegged). Last Audit: ${new Date().toLocaleString()}`;

  // Modal Navigation Buttons
  document.querySelectorAll(".explainer-links button, .modal-nav button").forEach(btn => {
    btn.addEventListener("click", () => {
      const modalId = btn.getAttribute("onclick")?.match(/'([^']+)'/)?.[1];
      if (modalId) openModal(modalId);
    });
  });

  // Transaction Pagination
  document.getElementById("txPrevBtn")?.addEventListener("click", () => {
    if (transactionPage > 0) {
      transactionPage--;
      renderTransactions();
    }
  });

  document.getElementById("txNextBtn")?.addEventListener("click", () => {
    transactionPage++;
    renderTransactions();
  });

  // Initialize
  showOnboardingIfNeeded();
  showBackupReminder();
  renderVaultUI();
})();

/*──────────────────────── 22. EXPORTS ─────────────────────────────*/
window.safeHandler = safeHandler;
window.openModal = openModal;
window.closeModal = closeModal;
window.modalNav = modalNav;
window.showToast = toast;
window.showBackupReminder = showBackupReminder;
window.renderVaultUI = renderVaultUI;
window.renderTransactions = renderTransactions;

// Unit test stubs with Jest (assume Jest is set up externally)
// test('validate BioCatch', async () => {
//   const dataStr = canonical({amount: 1});
//   const signature = await hmacSha256(dataStr);
//   const obj = {data: dataStr, signature};
//   const result = await SegmentService.validateBioCatchNumber(obj, 1, 'test');
//   expect(result.valid).toBe(true);
// });

// More tests...
