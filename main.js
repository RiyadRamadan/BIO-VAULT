/* main.js — Balance-Chain Vault SDK (ES2017+)                */
/* eslint-disable max-classes-per-file, no-console            */
"use strict";

/* ───────────────────────── CONFIG  ───────────────────────── */
const Protocol = Object.freeze({
  GENESIS_BIO_CONST: 1736565605,
  SEGMENTS: Object.freeze({
    TOTAL:          12_000,
    UNLOCKED_INIT:  1_200,
    PER_DAY:          360,
    PER_MONTH:      3_600,
    PER_YEAR:      10_800,
  }),
  TVM: Object.freeze({
    SEGMENTS_PER_TOKEN: 12,
    CLAIM_CAP:          1_000,
  }),
  HISTORY_MAX: 20,
});

const Limits = Object.freeze({
  AUTH: Object.freeze({ MAX_ATTEMPTS: 5, LOCKOUT_SECONDS: 3_600 }),
  PAGE: Object.freeze({ DEFAULT_SIZE: 10 }),
});

const DB = Object.freeze({
  NAME:    "BalanceChainVaultDB",
  VERSION: 1,
  STORE:   "vaultStore",
});

/* ────────────────────── SMALL HELPERS ────────────────────── */
const enc = new TextEncoder();
const dec = new TextDecoder();

/* chunk‑safe */
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const CHUNK = 0x8000;
  let bin = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

function base64ToBuffer(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}


const sha256 = async data =>
  bufferToBase64(
    await crypto.subtle.digest(
      "SHA-256",
      typeof data === "string" ? enc.encode(data) : data
    )
  );

const randomBytes = len => crypto.getRandomValues(new Uint8Array(len));

/* simple clipboard */
function copyToClipboard(text) {
  if (navigator.clipboard) {
    return navigator.clipboard.writeText(text)
      .then(() => toast("Copied!"))
      .catch(() => toast("Copy failed", true));
  }
  /* fallback */
  const ta = Object.assign(document.createElement("textarea"), { value: text });
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); toast("Copied!"); }
  catch { toast("Copy failed", true); }
  ta.remove();
}


/* ──────────────── INDEXED-DB PERSISTENCE ─────────────────── */
class VaultStorage {
  static _open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB.NAME, DB.VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(DB.STORE))
          db.createObjectStore(DB.STORE, { keyPath: "id" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror   = () => reject(req.error);
    });
  }

  static async save(iv, ciphertext, saltB64, meta = {}) {
    const db = await VaultStorage._open();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(DB.STORE, "readwrite");
      tx.objectStore(DB.STORE).put({
        id: "vaultData",
        iv: bufferToBase64(iv),
        ciphertext: bufferToBase64(ciphertext),
        salt: saltB64,
        ...meta,
      });
      tx.oncomplete = resolve;
      tx.onerror    = () => reject(tx.error);
    });
  }

  static async load() {
    const db = await VaultStorage._open();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(DB.STORE, "readonly");
      const req = tx.objectStore(DB.STORE).get("vaultData");
      req.onsuccess = () => {
        if (!req.result) return resolve(null);
        const r = req.result;
        resolve({
          iv:  base64ToBuffer(r.iv),
          ciphertext: base64ToBuffer(r.ciphertext),
          salt: base64ToBuffer(r.salt),
          ...r,
        });
      };
      req.onerror = () => reject(req.error);
    });
  }

  static deleteDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB.NAME);
      req.onsuccess = resolve;
      req.onerror   = () => reject(req.error);
      req.onblocked = resolve;
    });
  }
}

/* ──────────────────── CRYPTO  PRIMITIVES ─────────────────── */
class CryptoService {
  static deriveKeyFromPIN(pin, salt) {
    return crypto.subtle.importKey(
      "raw", enc.encode(pin), { name:"PBKDF2" }, false, ["deriveKey"]
    ).then(keyMat =>
      crypto.subtle.deriveKey(
        { name:"PBKDF2", salt, iterations:100_000, hash:"SHA-256" },
        keyMat,
        { name:"AES-GCM", length:256 },
        false,
        ["encrypt","decrypt"]
      )
    );
  }

  static encrypt(key, obj) {
    const iv = randomBytes(12);
    return crypto.subtle.encrypt(
      { name:"AES-GCM", iv },
      key,
      enc.encode(JSON.stringify(obj))
    ).then(ciphertext => ({ iv, ciphertext }));
  }

  static decrypt(key, iv, ciphertext) {
    return crypto.subtle.decrypt(
      { name:"AES-GCM", iv },
      key,
      ciphertext
    ).then(pt => JSON.parse(dec.decode(pt)));
  }
}

/* ────────── CONST  HASHES & SIMPLE PROOFS ───────── */
const hashDeviceKeyWithSalt = async (buf, extra = "") =>
  sha256(new Uint8Array([...new Uint8Array(buf), ...enc.encode(extra)]));

const _canon = o => JSON.stringify(o, Object.keys(o).sort());
const computeUnlockIntegrityProof = seg => sha256(`unlock:${_canon(seg)}`);
const computeSpentProof            = seg => sha256(`spent:${_canon(seg)}`);
const computeOwnershipProof        = seg => sha256(`own:${_canon(seg)}`);

/* ───────────────── CAP ENFORCER / HISTORY ───────── */
const getPeriodStrings = ts => {
  const d = new Date(ts * 1000);
  return {
    day:   d.toISOString().slice(0, 10),
    month: d.toISOString().slice(0, 7),
    year:  String(d.getUTCFullYear()),
  };
};

class CapEnforcer {
  static checkAndRecordUnlock(vault, now, cnt = 1) {
    const rec = vault.unlockRecords;
    const p   = getPeriodStrings(now);
    if (rec.day   !== p.day)   { rec.day   = p.day;   rec.dailyCount   = 0; }
    if (rec.month !== p.month) { rec.month = p.month; rec.monthlyCount = 0; }
    if (rec.year  !== p.year)  { rec.year  = p.year;  rec.yearlyCount  = 0; }

    if (rec.dailyCount   + cnt > Protocol.SEGMENTS.PER_DAY   ||
        rec.monthlyCount + cnt > Protocol.SEGMENTS.PER_MONTH ||
        rec.yearlyCount  + cnt > Protocol.SEGMENTS.PER_YEAR) return false;

    rec.dailyCount   += cnt;
    rec.monthlyCount += cnt;
    rec.yearlyCount  += cnt;
    return true;
  }
}

class HistoryManager {
  static record(seg, newKey, ts, type) {
    seg.ownershipChangeHistory.push({
      ownerKey: newKey, ts, type, changeCount: seg.ownershipChangeCount,
    });
    if (seg.ownershipChangeHistory.length > Protocol.HISTORY_MAX)
      seg.ownershipChangeHistory.shift();
  }
}

/* ─────────────── DEVICE REG  & SEGMENTS ─────────── */
class DeviceRegistry {
  static async register(vault, pubKeyBuf, extra = "") {
    const hash = await hashDeviceKeyWithSalt(pubKeyBuf, extra);
    if (!vault.deviceKeyHashes.includes(hash)) vault.deviceKeyHashes.push(hash);
  }
  static isRegistered(vault, keyHash) {
    return vault.deviceKeyHashes.includes(keyHash);
  }
}

class SegmentFactory {
  static createAll(ownerKey, bioConst, ts) {
    return Array.from({ length: Protocol.SEGMENTS.TOTAL }, (_, i) => {
      const idx = i + 1;
      return {
        segmentIndex: idx,
        amount: 1,
        originalOwnerKey: ownerKey,
        originalOwnerTS:  ts,
        originalBioConst: bioConst,
        previousOwnerKey: null,
        previousOwnerTS:  null,
        previousBioConst:null,
        currentOwnerKey: ownerKey,
        currentOwnerTS:  ts,
        currentBioConst: bioConst,
        unlocked: idx <= Protocol.SEGMENTS.UNLOCKED_INIT,
        ownershipChangeCount: 0,
        unlockIndexRef: null,
        unlockIntegrityProof: null,
        spentProof: null,
        ownershipProof: null,
        ownershipChangeHistory: [],
      };
    });
  }
}

/* ────────────────────── CORE SERVICES ───────────────────── */
class VaultService {
  static _session = null; // { vaultData, key, salt }

  /* Stubbed biometric enrolment */
  static async _bioEnroll() { return { rawId: randomBytes(32) }; }

  static async onboard(pin) {
    const cred    = await VaultService._bioEnroll();
    const rawId   = cred.rawId;
    const devHash = await hashDeviceKeyWithSalt(rawId);

    const now     = Math.floor(Date.now() / 1000);
    const bioConst= Protocol.GENESIS_BIO_CONST + (now - Protocol.GENESIS_BIO_CONST);
    const segments= SegmentFactory.createAll(devHash, bioConst, now);

    const vault = {
      credentialId: bufferToBase64(rawId),
      deviceKeyHashes: [devHash],
      onboardingTS: now,
      userBioConst: bioConst,
      segments,
      unlockRecords: { day:"",dailyCount:0,month:"",monthlyCount:0,year:"",yearlyCount:0 },
      walletAddress: "",
      tvmClaimedThisYear: 0,
      transactionHistory: [],
      authAttempts: 0,
      lockoutTimestamp: null,
    };

    const salt = randomBytes(16);
    const key  = await CryptoService.deriveKeyFromPIN(pin, salt);
    const { iv, ciphertext } = await CryptoService.encrypt(key, vault);
    await VaultStorage.save(iv, ciphertext, bufferToBase64(salt), vault);

    VaultService._session = { vaultData: vault, key, salt };
    return vault;
  }

  static async unlock(pin) {
    const rec = await VaultStorage.load();
    if (!rec) throw new Error("No vault found");

    const now = Math.floor(Date.now() / 1000);
    if (rec.lockoutTimestamp && now < rec.lockoutTimestamp)
      throw new Error(`Locked until ${new Date(rec.lockoutTimestamp*1000).toLocaleString()}`);

    try {
      const key = await CryptoService.deriveKeyFromPIN(pin, rec.salt);
      const data = await CryptoService.decrypt(key, rec.iv, rec.ciphertext);
      rec.authAttempts = 0;
      rec.lockoutTimestamp = null;
      await VaultStorage.save(rec.iv, rec.ciphertext, bufferToBase64(rec.salt), rec);
      VaultService._session = { vaultData: data, key, salt: rec.salt };
      return data;
    } catch {
      rec.authAttempts = (rec.authAttempts || 0) + 1;
      if (rec.authAttempts >= Limits.AUTH.MAX_ATTEMPTS)
        rec.lockoutTimestamp = now + Limits.AUTH.LOCKOUT_SECONDS;
      await VaultStorage.save(rec.iv, rec.ciphertext, bufferToBase64(rec.salt), rec);
      throw new Error("Invalid passphrase");
    }
  }

  static lock() { VaultService._session = null; }

  static get current() { return VaultService._session?.vaultData || null; }

  static async persist() {
    const s = VaultService._session;
    if (!s) throw new Error("Vault locked");
    const { iv, ciphertext } = await CryptoService.encrypt(s.key, s.vaultData);
    await VaultStorage.save(iv, ciphertext, bufferToBase64(s.salt), s.vaultData);
  }

  static deleteDatabase() { return VaultStorage.deleteDB().then(() => VaultService.lock()); }
}

/* ──────────────── SEGMENT  OPERATIONS ───────────── */
class SegmentService {
  static _now() { return Math.floor(Date.now() / 1000); }
  static _sess() {
    if (!VaultService._session) throw new Error("Vault locked");
    return VaultService._session;
  }

  static async unlockNextSegment(idxRef = null) {
    const now = SegmentService._now();
    const { vaultData } = SegmentService._sess();

    if (!CapEnforcer.checkAndRecordUnlock(vaultData, now))
      throw new Error("Unlock cap reached");

    const myKey = vaultData.deviceKeyHashes[0];
    const seg = vaultData.segments.find(s => !s.unlocked && s.currentOwnerKey === myKey);
    if (!seg) throw new Error("No segment to unlock");

    seg.unlocked = true;
    seg.unlockIndexRef   = idxRef;
    seg.currentOwnerTS   = now;
    seg.currentBioConst  = seg.previousBioConst
      ? seg.previousBioConst + (now - seg.previousOwnerTS)
      : seg.originalBioConst;
    seg.unlockIntegrityProof = await computeUnlockIntegrityProof(seg);

    HistoryManager.record(seg, myKey, now, "unlock");
    vaultData.transactionHistory.push({
      type:"unlock", segmentIndex:seg.segmentIndex, timestamp:now, amount:seg.amount, from:myKey,to:myKey
    });

    await VaultService.persist();
    return seg;
  }

  static async transferSegment(recvKey, myKey) {
    const now = SegmentService._now();
    const { vaultData } = SegmentService._sess();

    if (!DeviceRegistry.isRegistered(vaultData, myKey))
      throw new Error("Device not authorised");

    const seg = vaultData.segments.find(s => s.unlocked && s.currentOwnerKey === myKey);
    if (!seg) throw new Error("No unlocked segment");

    seg.previousOwnerKey = seg.currentOwnerKey;
    seg.previousOwnerTS  = seg.currentOwnerTS;
    seg.previousBioConst = seg.currentBioConst;

    seg.currentOwnerKey = recvKey;
    seg.currentOwnerTS  = now;
    seg.currentBioConst = seg.previousBioConst + (now - seg.previousOwnerTS);
    seg.ownershipChangeCount += 1;
    seg.unlocked = false;

    seg.spentProof      = await computeSpentProof(seg);
    seg.ownershipProof  = await computeOwnershipProof(seg);
    HistoryManager.record(seg, recvKey, now, "transfer");

    vaultData.transactionHistory.push({
      type:"transfer", segmentIndex:seg.segmentIndex, timestamp:now,
      amount:seg.amount, from:myKey, to:recvKey,
    });

    await SegmentService.unlockNextSegment(seg.segmentIndex);
    await VaultService.persist();
    return seg;
  }

  static async exportSegmentsBatch(recvKey, count, myKey) {
    const { vaultData } = SegmentService._sess();
    const unlocked = vaultData.segments.filter(s => s.unlocked && s.currentOwnerKey === myKey);
    if (unlocked.length < count) throw new Error(`Only ${unlocked.length} available`);
    const batch = [];
    for (let i = 0; i < count; i++)
      batch.push(await SegmentService.transferSegment(recvKey, myKey));
    return JSON.stringify(batch);
  }

  static importSegmentsBatch(json, myKey) {
    return JSON.parse(json).map(item => {
      const seg = typeof item === "string" ? JSON.parse(item) : item;
      if (seg.currentOwnerKey !== myKey)
        throw new Error(`Owner mismatch for seg#${seg.segmentIndex}`);
      return seg;
    });
  }

  static async claimReceivedSegmentsBatch(list) {
    const { vaultData } = SegmentService._sess();
    list.forEach(seg => {
      const idx = vaultData.segments.findIndex(s => s.segmentIndex === seg.segmentIndex);
      idx >= 0 ? vaultData.segments.splice(idx,1,seg) : vaultData.segments.push(seg);
    });
    await VaultService.persist();
  }
}

/* ─────────────── BACKUP / RESTORE SERVICE ─────────── */
class BackupService {
  static async exportEncryptedBackup(vault, pwd) {
    if (!pwd || pwd.length < 8) throw new Error("Password ≥8 chars");
    const salt = randomBytes(16);
    const key  = await CryptoService.deriveKeyFromPIN(pwd, salt);
    const { iv, ciphertext } = await CryptoService.encrypt(key, vault);
    return {
      salt: bufferToBase64(salt),
      iv:   bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext),
    };
  }

  static async importEncryptedBackup(payload, pwd) {
    const salt = base64ToBuffer(payload.salt);
    const iv   = base64ToBuffer(payload.iv);
    const ct   = base64ToBuffer(payload.ciphertext);
    const key  = await CryptoService.deriveKeyFromPIN(pwd, salt);
    return CryptoService.decrypt(key, iv, ct);
  }

  static exportFriendly(vault) {
    const blob = new Blob([JSON.stringify(vault)], { type:"application/octet-stream" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), {
      href:url, download:"myBioVault.vault",
    });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }
}

/* ─────────────── AUDIT  &  PROOF CHECKS ───────────── */
class AuditService {
  static generateAuditReport(vault, { fullHistory = false } = {}) {
    const lim = Protocol.HISTORY_MAX;
    return {
      deviceKeyHashes: vault.deviceKeyHashes,
      onboardingTS:    vault.onboardingTS,
      userBioConst:    vault.userBioConst,
      segments: vault.segments.map(s => ({
        ...s,
        ownershipChangeHistory: fullHistory
          ? s.ownershipChangeHistory
          : s.ownershipChangeHistory.slice(-lim),
      })),
    };
  }

  static async verifyProofChain(segments, expectedKey) {
    for (const seg of segments) {
      if (seg.currentOwnerKey !== expectedKey)
        throw new Error(`Seg#${seg.segmentIndex}: owner mismatch`);
      if (seg.ownershipProof !== await computeOwnershipProof(seg))
        throw new Error(`Seg#${seg.segmentIndex}: ownership proof bad`);
      if (seg.unlockIndexRef !== null &&
          seg.unlockIntegrityProof !== await computeUnlockIntegrityProof(seg))
        throw new Error(`Seg#${seg.segmentIndex}: unlock proof bad`);
      if (seg.spentProof &&
          seg.spentProof !== await computeSpentProof(seg))
        throw new Error(`Seg#${seg.segmentIndex}: spent proof bad`);
    }
    return true;
  }
}

/* ───────────── CHAIN SERVICE (web3 stub) ──────────── */
const ChainService = (() => {
  let provider = null, signer = null;

  return {
    initWeb3() {
      if (window.ethereum && !provider) {
        provider = new ethers.providers.Web3Provider(window.ethereum, "any");
        signer   = provider.getSigner();
      }
    },

    /** Stub – replace with real contract call */
    async submitClaimOnChain(bundle) {
      console.log("[Chain] TVM claim bundle", bundle);
      // return contract interaction promise here in production
      return Promise.resolve();
    },

    getSigner() { return signer; },
  };
})();

/* ───────────── TVM TOKEN CLAIMS (uses chain)───────── */
class TokenService {
  static _vault() {
    const v = VaultService.current;
    if (!v) throw new Error("Vault locked");
    return v;
  }

  static getAvailableTVMClaims() {
    const v = TokenService._vault();
    const usedSegs = v.segments.filter(s => s.ownershipChangeCount > 0).length;
    const claimed  = v.tvmClaimedThisYear || 0;
    return Math.max(
      Math.floor(usedSegs / Protocol.TVM.SEGMENTS_PER_TOKEN) - claimed,
      0
    );
  }

  static async claimTvmTokens() {
    const v = TokenService._vault();
    const avail = TokenService.getAvailableTVMClaims();
    if (!/^0x[a-fA-F0-9]{40}$/.test(v.walletAddress))
      throw new Error("Wallet address required");
    if (avail <= 0) throw new Error("Nothing to claim");
    if ((v.tvmClaimedThisYear || 0) + avail > Protocol.TVM.CLAIM_CAP)
      throw new Error("Yearly TVM cap reached");

    const needed = avail * Protocol.TVM.SEGMENTS_PER_TOKEN;
    const segs   = v.segments
      .filter(s => s.ownershipChangeCount > 0)
      .slice(0, needed);

    const proofBundle = segs.map(s => ({
      segmentIndex: s.segmentIndex,
      spentProof:   s.spentProof,
      ownershipProof:s.ownershipProof,
      unlockIntegrityProof:s.unlockIntegrityProof,
    }));

    await ChainService.submitClaimOnChain(proofBundle);

    v.tvmClaimedThisYear += avail;
    await VaultService.persist();
    return proofBundle;
  }
}

/* ──────────────── SIMPLE TOAST / UTILS ───────────── */
const toast = (msg, isErr=false) => {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent   = msg;
  el.className     = isErr ? "toast toast-error" : "toast";
  el.style.display = "block";
  setTimeout(() => (el.style.display = "none"), 3200);
};

/* ───────────────────── POPUP / MODALS ─────────────── */
const openModal  = id => document.getElementById(id)?.classList.add("show");
const closeModal = id => document.getElementById(id)?.classList.remove("show");
window.openPopup  = openModal;   // legacy alias
window.closePopup = closeModal;

window.showConfirmModal = async (title, msg, onAccept) => {
  if (window.confirm(`${title}\n\n${msg}`) && typeof onAccept === "function")
    await onAccept();
};

/* ───────────── BACKUP REMINDER BANNER ─────────────── */
const showBackupReminder = () => {
  const tip = document.getElementById("onboardingTip");
  if (tip) tip.style.display = localStorage.getItem("vaultBackedUp") ? "none" : "";
};
window.showBackupReminder = showBackupReminder;

/* ───────────── TRANSACTION TABLE UI ──────────────── */
(() => {
  const pageSize = Limits.PAGE.DEFAULT_SIZE;
  let txPage = 0;

  const txList = () => {
    const v = VaultService.current;
    if (!v) return [];
    const myShort = v.deviceKeyHashes[0]?.slice(0, 10) + "…";
    return v.segments
      .filter(s => s.ownershipChangeCount > 0)
      .map(s => ({
        bioIban:  myShort,
        bioCatch: s.segmentIndex,
        amount:   s.amount,
        time:     new Date(s.currentOwnerTS * 1000).toLocaleString(),
        status:   s.currentOwnerKey === v.deviceKeyHashes[0] ? "IN" : "OUT",
      }));
  };

  window.renderTransactions = function () {
    const list = txList();
    const tbody = document.getElementById("transactionBody");
    const empty = document.getElementById("txEmptyState");
    const prev  = document.getElementById("txPrevBtn");
    const next  = document.getElementById("txNextBtn");
    if (!tbody) return;

    tbody.innerHTML = "";
    if (list.length === 0) {
      empty.style.display = "";
      prev.style.display  = "none";
      next.style.display  = "none";
      return;
    }

    empty.style.display = "none";
    const start = txPage * pageSize;
    const end   = start + pageSize;

    list.slice(start, end).forEach(tx => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${tx.bioIban}</td><td>${tx.bioCatch}</td>
        <td>${tx.amount}</td><td>${tx.time}</td><td>${tx.status}</td>`;
      tbody.appendChild(tr);
    });

    prev.style.display = txPage > 0              ? "" : "none";
    next.style.display = end   < list.length     ? "" : "none";
  };

  document.getElementById("txPrevBtn")?.addEventListener("click", () => {
    if (txPage > 0) { txPage--; window.renderTransactions(); }
  });

  document.getElementById("txNextBtn")?.addEventListener("click", () => {
    txPage++; window.renderTransactions();
  });
})();

/* ───────────── DASHBOARD RENDER UTILS ────────────── */
const renderVaultUI = () => {
  const v = VaultService.current;
  if (!v) return;
  document.getElementById("lockedScreen").style.display = "none";
  document.getElementById("vaultUI").style.display      = "block";

  document.getElementById("bioibanInput").value =
    v.deviceKeyHashes[0]?.slice(0, 36) || "";

  /* include initial unlocked segments for first‑time balance display */
  const segUsed = v.segments.filter(
    s => s.ownershipChangeCount > 0 || s.unlocked
  ).length;
  const balance = Math.floor(segUsed / Protocol.TVM.SEGMENTS_PER_TOKEN) -
                  (v.tvmClaimedThisYear || 0);
  document.getElementById("tvmBalance").textContent = `Balance: ${balance} TVM`;
  document.getElementById("usdBalance").textContent = `Equivalent to ${(balance/12).toFixed(2)} USD`;
  document.getElementById("bioLineText").textContent = `🔄 BonusConstant: ${v.userBioConst}`;
  document.getElementById("utcTime").textContent = "UTC: " + new Date().toUTCString();
  document.getElementById("userWalletAddress").value = v.walletAddress || "";
  document.getElementById("tvmClaimable").textContent =
    `TVM Claimable: ${TokenService.getAvailableTVMClaims()}`;

  window.renderTransactions();
};
window.renderVaultUI = renderVaultUI;   // expose for handlers

/* ───────────── SHARED ERROR-HANDLER ───────────── */
window.safeHandler = fn =>
  Promise.resolve()
    .then(fn)
    .catch(e => { console.error(e); toast(e.message || "Error", true); });

/* ───────────── BACKUP BUTTON WIRING ───────────── */
(() => {
  const exportEncrypted = async () => {
    const pwd = prompt("Backup password (≥8 chars):");
    const data = await BackupService.exportEncryptedBackup(VaultService.current, pwd);
    const blob = new Blob([JSON.stringify(data)], { type:"application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), {
      href:url, download:"vault_backup.enc.json",
    });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    localStorage.setItem("vaultBackedUp","yes"); showBackupReminder();
  };

  document.getElementById("exportBackupBtn")   ?.addEventListener("click",
    () => safeHandler(exportEncrypted));

  document.getElementById("exportFriendlyBtn") ?.addEventListener("click",
    () => { BackupService.exportFriendly(VaultService.current);
            localStorage.setItem("vaultBackedUp","yes"); showBackupReminder();
            toast("Friendly backup exported"); });
})();
/* ───────────── PRIMARY BUTTON WIRING ───────────── */
(() => {
  /* Copy Bio‑IBAN */
  document.getElementById("copyBioIBANBtn")
    ?.addEventListener("click", () => {
      const v = document.getElementById("bioibanInput").value.trim();
      if (v) copyToClipboard(v);
    });

  /* Generate & show new Bio‑Catch */
  document.getElementById("showBioCatchBtn")
    ?.addEventListener("click", () => {
      const code = `BC-${Date.now()}-${Math.floor(Math.random() * 1e5)}`;
      document.getElementById("bioCatchNumberText").textContent = code;
      openModal("bioCatchPopup");
    });

  /* Copy Bio‑Catch from popup */
  document.getElementById("copyBioCatchBtn")
    ?.addEventListener("click", () => {
      const txt = document.getElementById("bioCatchNumberText").textContent;
      copyToClipboard(txt);
    });

  /* Close popup */
  document.getElementById("closeBioCatchPopup")
    ?.addEventListener("click", () => closeModal("bioCatchPopup"));

  /* Catch‑Out */
  document.getElementById("catchOutBtn")
    ?.addEventListener("click", () => safeHandler(async () => {
      const recv = document.getElementById("receiverBioIBAN").value.trim();
      const amt  = Number(document.getElementById("catchOutAmount").value);
      if (!recv || !amt) throw new Error("Receiver & amount required");
      await SegmentService.transferSegment(recv, VaultService.current.deviceKeyHashes[0]);
      toast(`Sent ${amt} TVM`);
      renderVaultUI();
    }));

  /* Catch‑In */
  document.getElementById("catchInBtn")
    ?.addEventListener("click", () => safeHandler(async () => {
      const bc  = document.getElementById("catchInBioCatch").value.trim();
      const amt = Number(document.getElementById("catchInAmount").value);
      if (!bc || !amt) throw new Error("Bio‑Catch & amount required");

      const myKey = VaultService.current.deviceKeyHashes[0];
      const segs  = SegmentService.importSegmentsBatch(bc, myKey);
      await SegmentService.claimReceivedSegmentsBatch(segs);
      toast(`Received ${amt} TVM`);
      renderVaultUI();
    }));

  /* Export CSV */
  document.getElementById("exportBtn")
    ?.addEventListener("click", () => {
      const rows = [["Bio‑IBAN","Bio‑Catch","Amount","Date","Status"],
        ...document.querySelectorAll("#transactionBody tr")
          .entries()].map(([,tr]) =>
        [...tr.children].map(td => td.textContent.trim()));
      const csv = "data:text/csv;charset=utf-8," +
        rows.map(r => r.join(",")).join("\n");
      const a = Object.assign(document.createElement("a"), {
        href: encodeURI(csv),
        download: "transactions.csv"
      });
      document.body.appendChild(a); a.click(); a.remove();
    });

  /* Import .vault */
  document.getElementById("importVaultFileInput")
    ?.addEventListener("change", e => safeHandler(async () => {
      const f = e.target.files[0]; if (!f) return;
      const txt = await f.text();
      const vault = JSON.parse(txt);
      VaultService._session = {
        vaultData: vault,
        key: null,
        salt: null
      };
      toast("Vault imported (read‑only, please unlock with passphrase)");
      renderVaultUI();
    }));
})();


/* ───────────── SESSION  AUTO-LOCK ─────────────── */
(() => {
  const MAX_IDLE = 15 * 60 * 1000;  // 15 min
  let timer;
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(() => { VaultService.lock(); location.reload(); }, MAX_IDLE);
  };
  ["click","mousemove","keydown","touchstart"].forEach(ev =>
    document.addEventListener(ev, reset, { passive:true })
  );
  reset();
})();

/* ───────────── PIN  ROTATION UI ─────────────── */
document.getElementById("rotatePinBtn")?.addEventListener("click", () =>
  safeHandler(async () => {
    const oldPin = prompt("Current passphrase:");
    const newPin = prompt("New passphrase (≥8 chars):");
    if (!oldPin || !newPin || newPin.length < 8) throw new Error("Invalid input");

    const rec = await VaultStorage.load();
    const oldKey = await CryptoService.deriveKeyFromPIN(oldPin, rec.salt);
    const vault  = await CryptoService.decrypt(oldKey, rec.iv, rec.ciphertext);

    const newSalt = randomBytes(16);
    const newKey  = await CryptoService.deriveKeyFromPIN(newPin, newSalt);
    const { iv, ciphertext } = await CryptoService.encrypt(newKey, vault);
    await VaultStorage.save(iv, ciphertext, bufferToBase64(newSalt), vault);

    VaultService._session = { vaultData:vault, key:newKey, salt:newSalt };
    toast("Passphrase rotated");
  })
);

/* ───────────── INITIAL  APP  BOOTSTRAP ───────── */
window.addEventListener("DOMContentLoaded", () => safeHandler(async () => {
  // Basic feature detect
  if (!indexedDB || !crypto?.subtle || !TextEncoder) {
    document.body.innerHTML = "<h2>Your browser lacks required APIs.</h2>";
    return;
  }

  ChainService.initWeb3();
  showBackupReminder();

  // Onboard or unlock
  if (!localStorage.getItem("vaultOnboarded")) {
    openModal("onboardingModal");
    document.querySelector("#onboardingModal .modal-close")
      ?.addEventListener("click", () => safeHandler(async () => {
        const pin = prompt("Choose a passphrase (≥8 chars):");
        if (!pin || pin.length < 8) throw new Error("Too short");
        await VaultService.onboard(pin);
        localStorage.setItem("vaultOnboarded", "yes");
        closeModal("onboardingModal");
        renderVaultUI();
      }));
  } else {
    openModal("passModal");
    document.getElementById("passModalSaveBtn")
      ?.addEventListener("click", () => safeHandler(async () => {
        const pin = document.getElementById("passModalInput").value;
        if (!pin) throw new Error("Enter passphrase");
        await VaultService.unlock(pin);
        closeModal("passModal");
        renderVaultUI();
      }));
  }
}));

/* ───────────── PUBLIC  GLOBAL  API  ───────────── */
window.BalanceChain = Object.freeze({
  /* config / const */
  Protocol, Limits,
  /* helpers */
  bufferToBase64, base64ToBuffer, sha256,
  /* primitives */
  computeUnlockIntegrityProof, computeSpentProof, computeOwnershipProof, hashDeviceKeyWithSalt,
  /* services */
  VaultService, SegmentService, BackupService,
  AuditService, TokenService, ChainService,
});
