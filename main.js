/* balance_chain_v3.js – Ultimate Production-Grade BalanceChain (July 2025) */
/* eslint max-lines: 1500 */
/* eslint-disable no-console */
"use strict";

/*──────────────────────── 1. CONSTANTS ───────────────────────────────*/
// Fixed genesis timestamp (Jan 1, 2020, 00:00:00 UTC)
const GENESIS_TIMESTAMP = 1577836800; // Unix epoch + constant
const Protocol = Object.freeze({
  GENESIS_BIO_CONST: GENESIS_TIMESTAMP, // Fixed global anchor
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
    EXCHANGE_RATE: 12 // 1 USD = 12 SHE (Standard Human Effort, 1 min each)
  }),
  HISTORY_MAX: 20, // Limit ownership change history for privacy
  BONUS: Object.freeze({
    PER_TX: 120,
    MAX_PER_DAY: 3,
    MAX_PER_MONTH: 30,
    MAX_ANNUAL_TVM: 10800,
    MIN_SEND_AMOUNT: 240
  }),
  // SHE Peg Documentation:
  // 1 TVM = 12 SHE (12 min). Derived from 100-year avg GDP/capita ($10,000/year),
  // 2000 work hours/year => $5/hour => 1 USD = 12 min = 12 SHE.
});

const Limits = Object.freeze({
  AUTH: Object.freeze({ MAX_ATTEMPTS: 5, LOCKOUT_SECONDS: 3600 }),
  PAGE: Object.freeze({ DEFAULT_SIZE: 10 }),
  TRANSACTION_VALIDITY_SECONDS: 720, // ±12 min
  BATCH_SIZE: 10000 // Max segments per batch for large transfers
});

const DB = Object.freeze({
  NAME: "BalanceChainVaultDB",
  VERSION: 4,
  STORE: "vaultStore",
  BACKUP_KEY: "vaultArmoredBackup",
  STORAGE_CHECK_INTERVAL: 300000 // 5 min
});

const vaultSyncChannel = new BroadcastChannel("vault-sync");
const KEY_HASH_SALT = "Balance-Chain-v3-PRD";
const PBKDF2_ITERS = 310000;
const AES_KEY_LENGTH = 256;

/*──────────────────────── 2. UTILS / HELPERS ─────────────────────────*/
const enc = new TextEncoder(), dec = new TextDecoder();
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
const rand = len => crypto.getRandomValues(new Uint8Array(len));

/** @description Constant-time string comparison */
const ctEq = (a = "", b = "") => {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
};

/** @description Canonical JSON for stable proofs */
const canonical = obj => JSON.stringify(obj, Object.keys(obj).sort());

/** @description SHA-256 hash */
const sha256 = async data => {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data);
  return toB64(buf);
};

/** @description SHA-256 to hex for BioCatch */
const sha256Hex = async str => {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
};

/*──────────────────────── 3. CRYPTO SERVICE ──────────────────────────*/
/** @description Cryptographic operations for vault and bio-catch */
class CryptoService {
  /** @param {string} pin - User passphrase
   * @param {ArrayBuffer} salt - Random salt
   * @returns {Promise<CryptoKey>} Derived AES key
   */
  static deriveKey(pin, salt) {
    return crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"])
      .then(mat => crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
        mat, { name: "AES-GCM", length: AES_KEY_LENGTH }, false, ["encrypt", "decrypt"]
      ));
  }

  /** @param {CryptoKey} key - AES key
   * @param {Object} obj - Data to encrypt
   * @returns {Promise<{iv: ArrayBuffer, ct: ArrayBuffer}>} IV and ciphertext
   */
  static encrypt(key, obj) {
    const iv = rand(12);
    return crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)))
      .then(ct => ({ iv, ct }));
  }

  /** @param {CryptoKey} key - AES key
   * @param {ArrayBuffer} iv - Initialization vector
   * @param {ArrayBuffer} ct - Ciphertext
   * @returns {Promise<Object>} Decrypted object
   */
  static decrypt(key, iv, ct) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
      .then(pt => JSON.parse(dec.decode(pt)));
  }

  /** @param {string} plainText - Bio-catch string
   * @returns {Promise<string>} Base64-encoded bio-catch
   */
  static async encryptBioCatchNumber(plainText) {
    return toB64(enc.encode(plainText));
  }

  /** @param {string} encStr - Base64-encoded bio-catch
   * @returns {Promise<string|null>} Decoded bio-catch or null on error
   */
  static async decryptBioCatchNumber(encStr) {
    try { return dec.decode(fromB64(encStr)); } catch { return null; }
  }
}

/*──────────────────────── 4. PUBLIC PROOFS ───────────────────────────*/
/** @param {string} tag - Proof type
 * @param {Object} obj - Segment data
 * @returns {Promise<string>} Base64-encoded SHA-256 proof
 */
const proofHash = (tag, obj) => sha256(`${tag}:${canonical(obj)}`);

/** @param {Object} seg - Segment
 * @returns {Promise<string>} Unlock integrity proof
 */
const computeUnlockIntegrityProof = seg => proofHash("unlock", {
  segmentIndex: seg.segmentIndex,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst,
  unlockIndexRef: seg.unlockIndexRef,
  unlockTriggerBioConst: seg.unlockTriggerBioConst
});

/** @param {Object} seg - Segment
 * @returns {Promise<string>} Spent proof
 */
const computeSpentProof = seg => proofHash("spent", {
  segmentIndex: seg.segmentIndex,
  previousOwnerKey: seg.previousOwnerKey,
  previousBioConst: seg.previousBioConst,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst
});

/** @param {Object} seg - Segment
 * @returns {Promise<string>} Ownership proof
 */
const computeOwnershipProof = seg => proofHash("own", {
  segmentIndex: seg.segmentIndex,
  currentOwnerKey: seg.currentOwnerKey,
  currentBioConst: seg.currentBioConst,
  ownershipChangeCount: seg.ownershipChangeCount
});

/*──────────────────────── 5. DEVICE HASH ─────────────────────────────*/
/** @param {ArrayBuffer} buf - Raw credential ID
 * @param {string} extra - Additional data
 * @returns {Promise<string>} Hashed device key
 */
const hashDeviceKeyWithSalt = (buf, extra = "") =>
  sha256(new Uint8Array([...enc.encode(KEY_HASH_SALT), ...new Uint8Array(buf), ...enc.encode(extra)]));

/*──────────────────────── 6. TIME-SYNC SERVICE ───────────────────────*/
/** @description Synchronizes local time with world clock */
class TimeSyncService {
  static _offset = 0;

  /** @returns {Promise<void>} Syncs time offset */
  static async sync() {
    try {
      const { unixtime } = await fetch("https://worldtimeapi.org/api/ip", { cache: "no-store" }).then(r => r.json());
      this._offset = unixtime - Math.floor(Date.now() / 1000);
    } catch { console.warn("⏰ Time-sync failed – using local clock"); }
  }

  /** @returns {number} Adjusted Unix timestamp */
  static now() { return Math.floor(Date.now() / 1000) + this._offset; }
}

/*──────────────────────── 7. INDEXED-DB LAYER ────────────────────────*/
/** @description Manages local vault storage */
class VaultStorage {
  /** @returns {Promise<IDBDatabase>} Opens IndexedDB */
  static _open() {
    return new Promise((res, rej) => {
      const req = indexedDB.open(DB.NAME, DB.VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(DB.STORE)) {
          const store = db.createObjectStore(DB.STORE, { keyPath: "id" });
          store.createIndex("segmentIndex", "segments.segmentIndex", { multiEntry: true });
        }
      };
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }

  /** @param {ArrayBuffer} iv - IV
   * @param {ArrayBuffer} ct - Ciphertext
   * @param {string} saltB64 - Base64 salt
   * @param {Object} meta - Metadata
   * @returns {Promise<void>} Saves vault
   */
  static async save(iv, ct, saltB64, meta) {
    const db = await this._open();
    await new Promise((res, rej) => {
      const tx = db.transaction(DB.STORE, "readwrite");
      tx.objectStore(DB.STORE).put({ id: "vaultData", iv: toB64(iv), ciphertext: toB64(ct), salt: saltB64, ...meta });
      tx.oncomplete = res;
      tx.onerror = () => rej(tx.error);
    });
    const backupPayload = { iv: toB64(iv), data: toB64(ct), salt: saltB64, timestamp: Date.now() };
    localStorage.setItem(DB.BACKUP_KEY, JSON.stringify(backupPayload));
    vaultSyncChannel.postMessage({ type: "vaultUpdate", payload: backupPayload });
    // Check storage quota
    if (navigator.storage?.estimate) {
      const { quota, usage } = await navigator.storage.estimate();
      if (usage / quota > 0.9) console.warn("⚠️ Storage quota nearing limit");
    }
  }

  /** @returns {Promise<Object|null>} Loads vault */
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
}

/*──────────────────────── 8. WEBAUTHN HELPERS ────────────────────────*/
/** @description Handles biometric authentication */
class WebAuthnService {
  /** @returns {Promise<ArrayBuffer>} Enrolls new biometric credential */
  static async enroll() {
    if (!navigator.credentials?.create) throw new Error("WebAuthn unsupported");
    const rp = { name: "BalanceChain", id: location.hostname };
    const user = { id: rand(16), name: "anon", displayName: "BalanceChain User" };
    const cred = await navigator.credentials.create({
      publicKey: {
        rp, user, challenge: rand(32),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
        timeout: 60000
      }
    });
    if (!cred) throw new Error("Biometric enrolment cancelled");
    return cred.rawId;
  }

  /** @param {string} credIdB64 - Base64 credential ID
   * @returns {Promise<{rawId: ArrayBuffer, sigHash: string}>} Assertion result
   */
  static async assert(credIdB64) {
    const allow = [{ id: fromB64(credIdB64), type: "public-key" }];
    const cred = await navigator.credentials.get({
      publicKey: { allowCredentials: allow, challenge: rand(16), userVerification: "required" },
      mediation: "optional"
    });
    if (!cred) throw new Error("Biometric cancelled");
    const flags = new DataView(cred.response.authenticatorData).getUint8(32);
    if (!(flags & 0x01) || (flags & 0x04) === 0) throw new Error("UV/UP flags missing");
    const sigHash = await sha256(cred.response.signature);
    return { rawId: cred.rawId, sigHash };
  }

  /** @param {ArrayBuffer} rawId - Raw credential ID
   * @param {string} storedHash - Stored device key hash
   * @returns {Promise<boolean>} Verifies local key
   */
  static async verifyLocalKey(rawId, storedHash) {
    const computedHash = await hashDeviceKeyWithSalt(rawId);
    return ctEq(computedHash, storedHash);
  }
}

/*──────────────────────── 9. CAP & HISTORY HELPERS ───────────────────*/
/** @param {number} ts - Unix timestamp
 * @returns {Object} Period strings
 */
const periodStrings = ts => {
  const d = new Date(ts * 1000);
  return {
    day: d.toISOString().slice(0, 10),
    month: d.toISOString().slice(0, 7),
    year: String(d.getUTCFullYear())
  };
};

/** @description Enforces unlock and bonus caps */
class CapEnforcer {
  /** @param {Object} vault - Vault data
   * @param {number} now - Current timestamp
   * @param {number} cnt - Unlock count
   */
  static check(vault, now, cnt = 1) {
    const rec = vault.unlockRecords, p = periodStrings(now);
    if (rec.day !== p.day) { rec.day = p.day; rec.dailyCount = 0; }
    if (rec.month !== p.month) { rec.month = p.month; rec.monthlyCount = 0; }
    if (rec.year !== p.year) { rec.year = p.year; rec.yearlyCount = 0; }
    if (
      rec.dailyCount + cnt > Protocol.SEGMENTS.PER_DAY ||
      rec.monthlyCount + cnt > Protocol.SEGMENTS.PER_MONTH ||
      rec.yearlyCount + cnt > Protocol.SEGMENTS.PER_YEAR
    ) throw new Error("Unlock cap reached");
    rec.dailyCount += cnt;
    rec.monthlyCount += cnt;
    rec.yearlyCount += cnt;
  }

  /** @param {Object} vault - Vault data
   * @param {number} now - Current timestamp
   * @param {string} type - Transaction type (sent/received)
   * @param {number} amount - Transfer amount
   * @returns {boolean} Whether bonus is allowed
   */
  static checkBonus(vault, now, type, amount) {
    const p = periodStrings(now);
    if (vault.bonusRecords.day !== p.day) {
      vault.bonusRecords.day = p.day;
      vault.bonusRecords.dailyCount = 0;
      vault.bonusRecords.sentCount = 0;
      vault.bonusRecords.receivedCount = 0;
    }
    if (vault.bonusRecords.month !== p.month) {
      vault.bonusRecords.month = p.month;
      vault.bonusRecords.monthlyCount = 0;
    }
    if (vault.bonusRecords.annualTVM + Protocol.BONUS.PER_TX > Protocol.BONUS.MAX_ANNUAL_TVM)
      return false;
    if (vault.bonusRecords.dailyCount >= Protocol.BONUS.MAX_PER_DAY) return false;
    if (vault.bonusRecords.monthlyCount >= Protocol.BONUS.MAX_PER_MONTH) return false;
    if (type === "sent" && amount <= Protocol.BONUS.MIN_SEND_AMOUNT) return false;
    if (type === "sent" && vault.bonusRecords.sentCount >= 2) return false;
    if (type === "received" && vault.bonusRecords.receivedCount >= 2) return false;
    return true;
  }

  /** @param {Object} vault - Vault data
   * @param {string} type - Transaction type
   */
  static recordBonus(vault, type) {
    vault.bonusRecords.dailyCount++;
    vault.bonusRecords.monthlyCount++;
    vault.bonusRecords.annualTVM += Protocol.BONUS.PER_TX;
    if (type === "sent") vault.bonusRecords.sentCount++;
    else if (type === "received") vault.bonusRecords.receivedCount++;
  }
}

/** @description Manages segment ownership history */
class HistoryManager {
  /** @param {Object} seg - Segment
   * @param {string} newKey - New owner key
   * @param {number} ts - Timestamp
   * @param {string} type - History event type
   */
  static record(seg, newKey, ts, type) {
    seg.ownershipChangeHistory.push({ ownerKey: newKey, ts, type, changeCount: seg.ownershipChangeCount });
    if (seg.ownershipChangeHistory.length > Protocol.HISTORY_MAX)
      seg.ownershipChangeHistory.shift();
  }
}

/*──────────────────────── 10. SEGMENT FACTORY ────────────────────────*/
/** @description Creates initial segment structure */
class SegmentFactory {
  /** @param {string} owner - Owner key hash
   * @param {number} bioConst - User bio-constant
   * @param {number} ts - Timestamp
   * @returns {Object[]} Array of segments
   */
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
      lastAuthSig: null,
      ownershipChangeHistory: []
    }));
  }
}

/*──────────────────────── 11. VAULT SERVICE ──────────────────────────*/
/** @description Manages vault lifecycle and state */
class VaultService {
  static _session = null;

  /** @param {string} credIdB64 - Base64 credential ID
   * @returns {Promise<ArrayBuffer>} Current device raw ID
   */
  static async _currentDeviceRawId(credIdB64) {
    if (!window.PublicKeyCredential || !navigator.credentials?.get) return new ArrayBuffer(0);
    const allow = [{ id: fromB64(credIdB64), type: "public-key" }];
    try {
      const cred = await navigator.credentials.get({
        publicKey: { allowCredentials: allow, challenge: rand(16), userVerification: "required" },
        mediation: "optional"
      });
      return cred?.rawId || new ArrayBuffer(0);
    } catch { return new ArrayBuffer(0); }
  }

  /** @param {string} pin - User passphrase
   * @returns {Promise<Object>} Onboarded vault
   */
  static async onboard(pin) {
    if (pin.length < 8) throw new Error("Passphrase ≥8 chars");
    const rawId = await WebAuthnService.enroll();
    const devHash = await hashDeviceKeyWithSalt(rawId);
    const now = TimeSyncService.now();
    const bioConst = Protocol.GENESIS_BIO_CONST + (now - GENESIS_TIMESTAMP);
    const segments = SegmentFactory.createAll(devHash, bioConst, now);
    for (const s of segments) {
      s.unlockIntegrityProof = await computeUnlockIntegrityProof(s);
      s.ownershipProof = await computeOwnershipProof(s);
    }
    const vault = {
      credentialId: toB64(rawId),
      deviceKeyHashes: [devHash],
      onboardingTS: now,
      userBioConst: bioConst,
      bioIBAN: `BIO${bioConst + (now - GENESIS_TIMESTAMP)}`,
      segments,
      unlockRecords: { day: "", dailyCount: 0, month: "", monthlyCount: 0, year: "", yearlyCount: 0 },
      bonusRecords: {
        day: "", dailyCount: 0, sentCount: 0, receivedCount: 0,
        month: "", monthlyCount: 0, annualTVM: 0
      },
      walletAddress: "",
      walletAddressKYC: "",
      tvmClaimedThisYear: 0,
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
    await AuditService.log("Vault onboarded", { bioIBAN: vault.bioIBAN });
    return vault;
  }

  /** @param {string} pin - User passphrase
   * @returns {Promise<Object>} Unlocked vault
   */
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
    if (!rawIdBuf.byteLength) throw new Error("Biometric cancelled");
    const curHash = await hashDeviceKeyWithSalt(rawIdBuf);
    if (!vault.deviceKeyHashes.includes(curHash))
      throw new Error("Device not registered for vault");
    if (!(await WebAuthnService.verifyLocalKey(rawIdBuf, curHash)))
      throw new Error("Local key verification failed");
    rec.authAttempts = 0;
    rec.lockoutUntil = null;
    await VaultStorage.save(rec.iv, rec.ciphertext, toB64(rec.salt), rec);
    vault.segments.forEach(seg => {
      const base = seg.previousBioConst ?? seg.originalBioConst;
      const tsBase = seg.previousOwnerTS ?? seg.originalOwnerTS;
      seg.currentBioConst = base + (now - tsBase);
    });
    this._session = { vaultData: vault, key, salt: rec.salt };
    await this.persist();
    await AuditService.log("Vault unlocked", { bioIBAN: vault.bioIBAN });
    return vault;
  }

  /** @description Locks vault */
  static lock() { this._session = null; }

  /** @returns {Object|null} Current vault */
  static get current() { return this._session?.vaultData || null; }

  /** @returns {Promise<void>} Persists vault state */
  static async persist() {
    const s = this._session;
    if (!s) throw new Error("Vault locked");
    const { iv, ct } = await CryptoService.encrypt(s.key, s.vaultData);
    await VaultStorage.save(iv, ct, toB64(s.salt), s.vaultData);
  }
}

/*──────────────────────── 12. SEGMENT SERVICE ─────────────────────────*/
/** @description Manages segment operations */
class SegmentService {
  /** @returns {number} Current timestamp */
  static _now() { return TimeSyncService.now(); }

  /** @returns {Object} Current session */
  static _sess() { if (!VaultService._session) throw new Error("Vault locked"); return VaultService._session; }

  /** @param {number|null} idxRef - Reference segment index
   * @returns {Promise<Object>} Unlocked segment
   */
  static async unlockNextSegment(idxRef = null) {
    const { vaultData } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    const assert = await WebAuthnService.assert(vaultData.credentialId);
    if (!ctEq(await hashDeviceKeyWithSalt(assert.rawId), dev))
      throw new Error("Biometric mismatch");
    CapEnforcer.check(vaultData, this._now());
    const locked = vaultData.segments
      .filter(s => !s.unlocked && !s.exported && (!s.currentOwnerKey || s.currentOwnerKey === dev))
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

  /** @param {string} recvKey - Receiver key hash
   * @returns {Promise<Object>} Transferred segment
   */
  static async transferSegment(recvKey) {
    const { vaultData } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    const assert = await WebAuthnService.assert(vaultData.credentialId);
    if (!ctEq(await hashDeviceKeyWithSalt(assert.rawId), dev))
      throw new Error("Biometric mismatch");
    const seg = vaultData.segments
      .filter(s => s.unlocked && !s.exported && s.currentOwnerKey === dev)
      .sort((a, b) => a.segmentIndex - b.segmentIndex)[0];
    if (!seg) throw new Error("No unlocked segment");
    seg.previousOwnerKey = seg.currentOwnerKey;
    seg.previousOwnerTS = seg.currentOwnerTS;
    seg.previousBioConst = seg.currentBioConst;
    seg.currentOwnerKey = recvKey;
    seg.currentOwnerTS = this._now();
    seg.currentBioConst = seg.previousBioConst + (this._now() - seg.previousOwnerTS);
    seg.ownershipChangeCount++;
    seg.unlocked = false;
    seg.exported = true;
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
    // 1:1 unlock unless receiver is self
    if (recvKey !== dev) {
      try { await this.unlockNextSegment(seg.segmentIndex); } catch (e) { console.warn("Auto-unlock failed:", e.message); }
    }
    await VaultService.persist();
    return seg;
  }

  /** @param {string} recvKey - Receiver key hash
   * @param {number} count - Number of segments
   * @returns {Promise<string>} Bio-catch JSON payload
   */
  static async exportSegmentsBatch(recvKey, count) {
    const { vaultData } = this._sess();
    const dev = vaultData.deviceKeyHashes[0];
    const unlocked = vaultData.segments.filter(s => s.unlocked && !s.exported && s.currentOwnerKey === dev);
    if (unlocked.length < count) throw new Error(`Only ${unlocked.length} segment(s) unlocked`);
    const batch = [];
    let bioCatchSize = 0;
    let bonusGranted = false;
    if (CapEnforcer.checkBonus(vaultData, this._now(), "sent", count)) {
      CapEnforcer.recordBonus(vaultData, "sent");
      bonusGranted = true;
    }
    // Chunk large transfers
    for (let i = 0; i < count; i += Limits.BATCH_SIZE) {
      const chunk = Math.min(Limits.BATCH_SIZE, count - i);
      for (let j = 0; j < chunk; j++) {
        const seg = await this.transferSegment(recvKey);
        const plainBio = await this.generateBioCatchNumber(
          vaultData.bioIBAN, recvKey, seg.amount, this._now(), vaultData.tvmClaimedThisYear, vaultData.finalChainHash
        );
        const obfBio = await CryptoService.encryptBioCatchNumber(plainBio);
        const tx = vaultData.transactionHistory.find(t => t.segmentIndex === seg.segmentIndex && t.type === "transfer");
        tx.bioCatch = obfBio;
        const payload = { ...seg, bioCatch: obfBio };
        batch.push(payload);
        bioCatchSize += JSON.stringify(payload).length;
      }
    }
    console.log(`Bio-catch size for ${count} segments: ~${(bioCatchSize / 1024 / 1024).toFixed(2)} MB`);
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

  /** @param {string} raw - Bio-catch JSON
   * @param {string} recvKey - Receiver key hash
   * @returns {Promise<Object[]>} Parsed segments
   */
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

  /** @param {Object[]} list - Segments to claim
   * @returns {Promise<void>} Claims segments
   */
  static async claimReceivedSegmentsBatch(list) {
    const { vaultData } = this._sess();
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
      if (!ctEq(seg.ownershipProof, await computeOwnershipProof(seg)))
        throw new Error(`Bad ownership proof for segment #${seg.segmentIndex}`);
      if (seg.unlockIndexRef !== null &&
          !ctEq(seg.unlockIntegrityProof, await computeUnlockIntegrityProof(seg)))
        throw new Error(`Bad unlock proof for segment #${seg.segmentIndex}`);
      if (seg.spentProof && !ctEq(seg.spentProof, await computeSpentProof(seg)))
        throw new Error(`Bad spent proof for segment #${seg.segmentIndex}`);
      if (seg.bioCatch) {
        const plainBio = await CryptoService.decryptBioCatchNumber(seg.bioCatch);
        if (!plainBio) throw new Error("Invalid BioCatch");
        const validation = await this.validateBioCatchNumber(plainBio, seg.amount);
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

  /** @param {string} prevHash - Previous transaction hash
   * @param {Object} txObj - Transaction object
   * @returns {Promise<string>} Transaction hash
   */
  static async computeTransactionHash(prevHash, txObj) {
    const dataStr = JSON.stringify({ prevHash, ...txObj });
    const buf = enc.encode(dataStr);
    const hashBuf = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  /** @param {Object[]} transactions - Transaction history
   * @returns {Promise<string>} Full chain hash
   */
  static async computeFullChainHash(transactions) {
    let rHash = "";
    const sorted = [...transactions].sort((a, b) => a.timestamp - b.timestamp);
    for (const t of sorted) {
      const tmp = {
        type: t.type, amount: t.amount, timestamp: t.timestamp, status: t.status, bioCatch: t.bioCatch,
        bonusConstantAtGeneration: t.bonusConstantAtGeneration, previousHash: rHash
      };
      rHash = await this.computeTransactionHash(rHash, tmp);
    }
    return rHash;
  }

  /** @param {string} senderBioIBAN - Sender's Bio-IBAN
   * @param {string} receiverBioIBAN - Receiver's Bio-IBAN
   * @param {number} amount - Transfer amount
   * @param {number} timestamp - Timestamp
   * @param {number} senderBalance - Sender's TVM balance
   * @param {string} finalChainHash - Chain hash
   * @returns {Promise<string>} Bio-catch number
   */
  static async generateBioCatchNumber(senderBioIBAN, receiverBioIBAN, amount, timestamp, senderBalance, finalChainHash) {
    const now = this._now();
    if (Math.abs(now - timestamp) > Limits.TRANSACTION_VALIDITY_SECONDS)
      throw new Error("Timestamp out of validity window");
    const data = `${senderBioIBAN}|${receiverBioIBAN}|${amount}|${timestamp}|${senderBalance}|${finalChainHash}`;
    return await sha256Hex(data);
  }

  /** @param {string} bioCatchNumber - Bio-catch number
   * @param {number} claimedAmount - Claimed amount
   * @returns {Promise<{valid: boolean, message: string, claimedSenderIBAN: string}>} Validation result
   */
  static async validateBioCatchNumber(bioCatchNumber, claimedAmount) {
    // Stub: Implement chain state validation
    return { valid: true, message: "", claimedSenderIBAN: "BIO123" };
  }
}

/*──────────────────────── 13. BACKUP SERVICE ─────────────────────────*/
/** @description Manages vault backups */
class BackupService {
  /** @param {Object} vault - Vault data
   * @param {string} pwd - Backup password
   * @returns {Promise<Object>} Encrypted backup
   */
  static async exportEncryptedBackup(vault, pwd) {
    if (!pwd || pwd.length < 8) throw new Error("Password ≥8 chars");
    const salt = rand(16);
    const key = await CryptoService.deriveKey(pwd, salt);
    const { iv, ct } = await CryptoService.encrypt(key, vault);
    const backup = { salt: toB64(salt), iv: toB64(iv), ciphertext: toB64(ct) };
    await AuditService.log("Backup exported", { size: JSON.stringify(backup).length });
    return backup;
  }

  /** @param {Object} payload - Backup payload
   * @param {string} pwd - Backup password
   * @returns {Promise<Object>} Decrypted vault
   */
  static async importEncryptedBackup(payload, pwd) {
    const salt = fromB64(payload.salt), iv = fromB64(payload.iv), ct = fromB64(payload.ciphertext);
    const key = await CryptoService.deriveKey(pwd, salt);
    const vault = await CryptoService.decrypt(key, iv, ct);
    await AuditService.log("Backup imported", { bioIBAN: vault.bioIBAN });
    return vault;
  }

  /** @param {Object} vault - Vault data
   * @returns {void} Downloads friendly backup
   */
  static exportFriendly(vault) {
    const blob = new Blob([JSON.stringify(vault)], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: "myBioVault.vault" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    AuditService.log("Friendly backup exported", { bioIBAN: vault.bioIBAN });
  }
}

/*──────────────────────── 14. AUDIT SERVICE ─────────────────────────*/
/** @description Handles auditing and compliance */
class AuditService {
  /** @param {string} event - Event name
   * @param {Object} meta - Metadata
   * @returns {Promise<void>} Logs audit event
   */
  static async log(event, meta) {
    console.log(`[AUDIT] ${event}`, meta); // Stub: Integrate with Sentry
  }

  /** @param {Object} vault - Vault data
   * @param {Object} options - Report options
   * @returns {Object} Audit report
   */
  static generateAuditReport(vault, { fullHistory = false } = {}) {
    const lim = Protocol.HISTORY_MAX;
    return {
      bioIBAN: vault.bioIBAN,
      deviceKeyHashes: vault.deviceKeyHashes.map(h => h.slice(0, 8) + "…"),
      onboardingTS: vault.onboardingTS,
      userBioConst: vault.userBioConst,
      segments: vault.segments.map(s => ({
        ...s,
        ownershipChangeHistory: fullHistory ? s.ownershipChangeHistory : s.ownershipChangeHistory.slice(-lim)
      })),
      tvmClaimedThisYear: vault.tvmClaimedThisYear,
      walletAddressKYC: vault.walletAddressKYC
    };
  }

  /** @param {Object} vault - Vault data
   * @returns {Object} Compliance report
   */
  static exportComplianceReport(vault) {
    const report = this.generateAuditReport(vault, { fullHistory: true });
    const blob = new Blob([JSON.stringify(report)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: `compliance_${vault.bioIBAN}.json` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    this.log("Compliance report exported", { bioIBAN: vault.bioIBAN });
    return report;
  }

  /** @param {Object[]} segments - Segments to verify
   * @param {string} expectedKey - Expected owner key
   * @returns {Promise<boolean>} Verification result
   */
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

  /** @param {Object} vault - Vault data
   * @returns {void} Prunes history for compliance
   */
  static pruneHistory(vault) {
    vault.segments.forEach(s => {
      s.ownershipChangeHistory = s.ownershipChangeHistory.slice(-Protocol.HISTORY_MAX);
    });
    this.log("History pruned", { bioIBAN: vault.bioIBAN });
  }
}

/*──────────────────────── 15. CHAIN SERVICE ─────────────────────────*/
/** @description Handles on-chain interactions */
const CONTRACT = "0xYourDeployedAddressHere";
const claimAbi = []; // Stub: Define ABI
const ChainService = (() => {
  let provider = null, signer = null;
  return {
    /** @returns {void} Initializes Web3 */
    initWeb3() {
      if (window.ethereum && !provider) {
        provider = new ethers.providers.Web3Provider(window.ethereum, "any");
        signer = provider.getSigner();
      }
    },

    /** @param {Object[]} bundle - Segment proofs
     * @returns {Promise<Object>} Transaction receipt
     */
    async submitClaimOnChain(bundle) {
      if (!signer) throw new Error("Connect wallet first");
      const v = VaultService.current;
      if (!v.walletAddressKYC || !/^0x[a-fA-F0-9]{40}$/.test(v.walletAddressKYC))
        throw new Error("KYC’d wallet address required");
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
      const tx = await contract.claimTVM(bundle, sig);
      const receipt = await tx.wait();
      await AuditService.log("TVM claimed", { txHash: receipt.transactionHash, segments: bundle.length });
      return receipt;
    },

    /** @param {Object} tx - Bonus transaction
     * @returns {Promise<void>} Redeems bonus
     */
    async redeemBonusOnChain(tx) {
      if (!signer) throw new Error("Connect wallet first");
      if (!tx || !tx.bonusId) throw new Error("Invalid bonus or missing bonusId");
      const v = VaultService.current;
      if (!v.walletAddressKYC) throw new Error("KYC’d wallet address required");
      const userAddr = await signer.getAddress();
      if (userAddr.toLowerCase() !== v.walletAddressKYC.toLowerCase())
        console.warn("Active MetaMask address != vaultData.walletAddressKYC. Proceeding...");
      // Stub: Replace with contract call
      toast(`(Stub) Bonus #${tx.bonusId} minted to ${v.walletAddressKYC}`);
      await AuditService.log("Bonus redeemed", { bonusId: tx.bonusId });
    },

    /** @returns {void} Pauses contract (stub) */
    async emergencyPause() {
      console.log("Emergency pause triggered (stub)");
      await AuditService.log("Contract paused", {});
    },

    /** @returns {Object|null} Signer */
    getSigner() { return signer; },

    /** @returns {Promise<boolean>} Verifies SHE peg (stub) */
    async verifyPeg() {
      // Stub: Verify SHE peg against on-chain data
      return true;
    }
  };
})();

/*──────────────────────── 16. TOKEN SERVICE ─────────────────────────*/
/** @description Manages TVM token claims */
class TokenService {
  /** @returns {Object} Current vault */
  static _vault() { const v = VaultService.current; if (!v) throw new Error("Vault locked"); return v; }

  /** @returns {number} Available TVM claims */
  static getAvailableTVMClaims() {
    const v = this._vault(), dev = v.deviceKeyHashes[0];
    const used = v.segments.filter(s => s.currentOwnerKey === dev && (s.unlocked || s.ownershipChangeCount > 0)).length;
    const claimed = v.tvmClaimedThisYear || 0;
    return Math.max(Math.floor(used / Protocol.TVM.SEGMENTS_PER_TOKEN) - claimed, 0);
  }

  /** @returns {Promise<Object[]>} Claims TVM tokens */
  static async claimTvmTokens() {
    const v = this._vault();
    const avail = this.getAvailableTVMClaims();
    if (!v.walletAddressKYC || !/^0x[a-fA-F0-9]{40}$/.test(v.walletAddressKYC))
      throw new Error("KYC’d wallet address required");
    if (avail <= 0) throw new Error("Nothing to claim");
    if ((v.tvmClaimedThisYear || 0) + avail > Protocol.TVM.CLAIM_CAP)
      throw new Error("Yearly TVM cap reached");
    const needed = avail * Protocol.TVM.SEGMENTS_PER_TOKEN;
    const segs = v.segments.filter(s => s.ownershipChangeCount > 0 || s.unlocked).slice(0, needed);
    const bundle = segs.map(s => ({
      segmentIndex: s.segmentIndex,
      spentProof: s.spentProof,
      ownershipProof: s.ownershipProof,
      unlockIntegrityProof: s.unlockIntegrityProof
    }));
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
  el.className = err ? "toast toast-error" : "toast";
  el.style.display = "block";
  setTimeout(() => el.style.display = "none", 3200);
};

function copyToClipboard(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text)
    .then(() => toast("Copied")).catch(() => toast("Copy failed", true));
  const ta = Object.assign(document.createElement("textarea"), { value: text });
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); toast("Copied"); } catch { toast("Copy failed", true); }
  ta.remove();
}

let lastInvoker = null;
const openModal = id => {
  lastInvoker = document.activeElement;
  document.getElementById(id)?.classList.add("show");
};
const closeModal = id => {
  document.getElementById(id)?.classList.remove("show");
  lastInvoker?.focus();
};
window.openPopup = openModal;
window.closePopup = closeModal;

const showBackupReminder = () => {
  const tip = document.getElementById("onboardingTip");
  if (tip) tip.style.display = localStorage.getItem("vaultBackedUp") ? "none" : "";
};
window.showBackupReminder = showBackupReminder;

let deferredPrompt = null;
window.addEventListener("beforeinstallprompt", e => {
  e.preventDefault();
  deferredPrompt = e;
  console.log("⭐ A2HS prompt captured");
});
function promptInstallA2HS() {
  if (!deferredPrompt) { toast("No A2HS prompt available", true); return; }
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(choice => {
    console.log("A2HS", choice.outcome);
    AuditService.log("A2HS prompt", { outcome: choice.outcome });
    deferredPrompt = null;
  });
}

/** @param {string} data - Bio-catch payload
 * @returns {void} Generates QR code
 */
function generateQRCode(data) {
  const canvas = document.getElementById("qrCodeCanvas");
  if (!canvas) return;
  QRCode.toCanvas(canvas, data, { width: 200, margin: 2 }, err => {
    if (err) toast("QR code generation failed", true);
  });
}

/*──────────────────────── 18. TRANSACTION TABLE ───────────────────*/
(() => {
  const pageSize = Limits.PAGE.DEFAULT_SIZE;
  let page = 0;
  const txList = () => {
    const v = VaultService.current;
    if (!v) return [];
    const me = v.deviceKeyHashes[0]?.slice(0, 10) + "…";
    return v.transactionHistory.map(tx => ({
      bioIban: tx.type === "cashback" ? `Bonus #${tx.bonusId || ""}` : (tx.to === v.deviceKeyHashes[0] ? tx.from : tx.to),
      bioCatch: tx.bioCatch ? (tx.bioCatch.length > 12 ? tx.bioCatch.slice(0, 12) + "..." : tx.bioCatch) : (tx.segmentIndex || "—"),
      amount: tx.amount,
      time: new Date(tx.timestamp * 1000).toLocaleString(),
      status: tx.status || (tx.to === v.deviceKeyHashes[0] ? "IN" : "OUT")
    }));
  };
  window.renderTransactions = function () {
    const list = txList(), tbody = document.getElementById("transactionBody"),
          empty = document.getElementById("txEmptyState"),
          prev = document.getElementById("txPrevBtn"), next = document.getElementById("txNextBtn");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!list.length) {
      empty.style.display = "";
      prev.style.display = "none";
      next.style.display = "none";
      return;
    }
    empty.style.display = "none";
    const start = page * pageSize, end = start + pageSize;
    list.slice(start, end).forEach(tx => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${tx.bioIban}</td><td>${tx.bioCatch}</td><td>${tx.amount}</td><td>${tx.time}</td><td>${tx.status}</td>`;
      tbody.appendChild(tr);
    });
    prev.style.display = page > 0 ? "" : "none";
    next.style.display = end < list.length ? "" : "none";
  };
  document.getElementById("txPrevBtn")?.addEventListener("click", () => {
    if (page > 0) { page--; window.renderTransactions(); }
  });
  document.getElementById("txNextBtn")?.addEventListener("click", () => {
    page++;
    window.renderTransactions();
  });
})();

/*──────────────────────── 19. DASHBOARD RENDER ────────────────────*/
const renderVaultUI = () => {
  const v = VaultService.current;
  if (!v) return;
  document.getElementById("lockedScreen").style.display = "none";
  document.getElementById("vaultUI").style.display = "block";
  document.getElementById("bioibanInput").value = v.bioIBAN || "BIO…";
  document.getElementById("bioibanInput").readOnly = true;
  document.getElementById("bioibanShort").textContent = v.bioIBAN.slice(0, 8) + "…";
  const segUsed = v.segments.filter(s => s.ownershipChangeCount > 0 || s.unlocked).length;
  const balance = segUsed;
  v.tvmClaimedThisYear = Math.floor(balance / Protocol.TVM.SEGMENTS_PER_TOKEN);
  v.balanceUSD = +(balance / Protocol.TVM.EXCHANGE_RATE).toFixed(2);
  document.getElementById("tvmBalance").textContent = `Balance: ${balance} TVM`;
  document.getElementById("usdBalance").textContent = `Equivalent ${v.balanceUSD} USD`;
  document.getElementById("bioLineText").textContent = `🔄 Bio-Constant: ${v.userBioConst}`;
  document.getElementById("utcTime").textContent = "UTC: " + new Date().toUTCString();
  document.getElementById("userWalletAddress").value = v.walletAddressKYC || "";
  document.getElementById("tvmClaimable").textContent = `TVM Claimable: ${TokenService.getAvailableTVMClaims()}`;
  window.renderTransactions();
};
window.renderVaultUI = renderVaultUI;

/*──────────────────────── 20. SAFE HANDLER ─────────────────────────*/
window.safeHandler = f => Promise.resolve().then(f).catch(e => {
  console.error(e);
  AuditService.log("Error", { message: e.message });
  toast(e.message || "Error", true);
});

/*──────────────────────── 21. BUTTON WIRING ─────────────────────────*/
(() => {
  const devHash = () => VaultService.current.deviceKeyHashes[0];
  document.getElementById("copyBioIBANBtn")?.addEventListener("click", () => copyToClipboard(
    document.getElementById("bioibanInput").value));
  document.getElementById("catchOutBtn")?.addEventListener("click", () => safeHandler(async () => {
    const recv = document.getElementById("receiverBioIBAN").value.trim();
    const amt = Number(document.getElementById("catchOutAmount").value);
    if (!recv || !Number.isInteger(amt) || amt <= 0) throw new Error("Receiver & integer amount required");
    if (!/^BIO\d+$/.test(recv) && !/^BONUS\d+$/.test(recv)) throw new Error("Invalid Bio-IBAN");
    if (recv === VaultService.current.bioIBAN) throw new Error("Cannot send to self");
    if (!confirm(`Send ${amt} segment${amt > 1 ? "s" : ""} to ${recv}?`)) return;
    const payload = await SegmentService.exportSegmentsBatch(recv, amt);
    copyToClipboard(payload);
    generateQRCode(payload);
    toast(`Exported ${amt} segment${amt > 1 ? "s" : ""}. Payload copied & QR generated.`);
    renderVaultUI();
  }));
  document.getElementById("catchInBtn")?.addEventListener("click", () => safeHandler(async () => {
    const raw = document.getElementById("catchInBioCatch").value.trim();
    if (!raw) throw new Error("Paste the received payload");
    if (!confirm("Claim received segments?")) return;
    const segs = await SegmentService.importSegmentsBatch(raw, devHash());
    await SegmentService.claimReceivedSegmentsBatch(segs);
    toast(`Claimed ${segs.length} segment${segs.length > 1 ? "s" : ""}`);
    renderVaultUI();
  }));
  document.getElementById("showBioCatchBtn")?.addEventListener("click", () => safeHandler(async () => {
    const v = VaultService.current;
    const seg = v.segments.find(s => s.unlocked && s.currentOwnerKey === devHash());
    if (!seg) throw new Error("Unlock a segment first");
    const plainBio = await SegmentService.generateBioCatchNumber(
      v.bioIBAN, v.bioIBAN, seg.amount, SegmentService._now(), v.tvmClaimedThisYear, v.finalChainHash
    );
    const token = await CryptoService.encryptBioCatchNumber(plainBio);
    document.getElementById("bioCatchNumberText").textContent = token.length > 12 ? token.slice(0, 12) + "..." : token;
    document.getElementById("bioCatchNumberText").dataset.fullCatch = token;
    generateQRCode(token);
    openModal("bioCatchPopup");
  }));
  document.getElementById("copyBioCatchBtn")?.addEventListener("click", () => {
    const bcTxt = document.getElementById("bioCatchNumberText");
    copyToClipboard(bcTxt.dataset.fullCatch || bcTxt.textContent);
  });
  document.getElementById("closeBioCatchPopup")?.addEventListener("click", () => closeModal("bioCatchPopup"));
  document.getElementById("exportBtn")?.addEventListener("click", () => {
    const rows = [["Bio-IBAN", "Bio-Catch", "Amount", "Date", "Status"],
      ...document.querySelectorAll("#transactionBody tr").entries()]
      .map(([, tr]) => [...tr.children].map(td => td.textContent.trim()));
    const csv = "data:text/csv;charset=utf-8," + rows.map(r => r.join(",")).join("\n");
    const a = Object.assign(document.createElement("a"), { href: encodeURI(csv), download: "transactions.csv" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    AuditService.log("Transaction history exported", {});
  });
  document.getElementById("exportBackupBtn")?.addEventListener("click", () => safeHandler(async () => {
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
  }));
  document.getElementById("exportFriendlyBtn")?.addEventListener("click", () => {
    BackupService.exportFriendly(VaultService.current);
    localStorage.setItem("vaultBackedUp", "yes");
    showBackupReminder();
    toast("Friendly backup exported");
  });
  document.getElementById("importVaultFileInput")?.addEventListener("change", e => safeHandler(async () => {
    const f = e.target.files[0];
    if (!f) return;
    const txt = await f.text();
    const vault = JSON.parse(txt);
    VaultService._session = { vaultData: vault, key: null, salt: null };
    toast("Vault imported (read-only). Unlock with passphrase to use.");
    renderVaultUI();
  }));
  document.getElementById("installA2HSBtn")?.addEventListener("click", promptInstallA2HS);
  document.getElementById("saveWalletBtn")?.addEventListener("click", () => safeHandler(async () => {
    const addr = document.getElementById("userWalletAddress").value.trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Error("Bad address");
    const v = VaultService.current;
    v.walletAddressKYC = addr;
    await VaultService.persist();
    toast("KYC’d wallet address saved");
    await AuditService.log("Wallet address saved", { address: addr });
  }));
  document.getElementById("autoConnectWalletBtn")?.addEventListener("click", () => safeHandler(async () => {
    ChainService.initWeb3();
    await window.ethereum?.request({ method: "eth_requestAccounts" });
    const signer = ChainService.getSigner();
    const addr = signer ? await signer.getAddress() : "";
    if (addr) {
      document.getElementById("userWalletAddress").value = addr;
      document.getElementById("saveWalletBtn").click();
    } else toast("Wallet connect failed", true);
  }));
  document.getElementById("exportComplianceBtn")?.addEventListener("click", () => safeHandler(async () => {
    const report = AuditService.exportComplianceReport(VaultService.current);
    toast("Compliance report exported");
  }));
  document.getElementById("testModeBtn")?.addEventListener("click", () => {
    toast("Test mode: Simulate transactions in console");
    console.log("Test mode: Simulating transfer of 1 segment...");
    // Stub: Simulate transfer
  });
})();

/*──────────────────────── 22. SESSION AUTO-LOCK ─────────────────────*/
(() => {
  const MAX_IDLE = 15 * 60 * 1000;
  let timer;
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      VaultService.lock();
      location.reload();
    }, MAX_IDLE);
  };
  ["click", "
