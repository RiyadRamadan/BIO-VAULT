/*──────────────────────────────────────────────────────────────────────────────
 * main.js – Bio‑Vault (Refactored v2025.07) – Modular, ES6+, Best Practices
 *─────────────────────────────────────────────────────────────────────────────*/

'use strict';

//──────────────────────── CONFIGURATION ────────────────────────
const Config = {
  DB: { name: 'BioVaultDB', version: 1, store: 'vault' },
  INITIAL: { balanceTvm: 1200, bioConstant: 1736565605 },
  CAPS: { perTxBonus: 120, maxDailyUnlock: 3, maxMonthlyUnlock: 30, maxYearlyUnlock: 10800 },
  EXCHANGE_RATE: 12, // 1 USD = 12 TVM
  LOCKOUT: { durationSec: 3600, maxAttempts: 3 },
  STORAGE_CHECK_INTERVAL: 300_000,
};

//──────────────────────── UTILITIES ───────────────────────────
const Utils = {
  encoder: new TextEncoder(),
  decoder: new TextDecoder(),

  /**
   * SHA-256 hash of input string, returns hex.
   */
  async sha256(text) {
    const data = this.encoder.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Format UNIX timestamp (seconds) to YYYY-MM-DD HH:mm:ss.
   */
  formatTimestamp(ts) {
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
  },

  /**
   * Format number with locale separators.
   */
  formatNumber(n) {
    return n.toLocaleString();
  }
};

//──────────────────────── CRYPTO SERVICE ──────────────────────
class CryptoService {
  /** Generate ECDSA P-256 key pair. */
  static async generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    return { privateKeyJwk, publicKeyJwk };
  }

  /** Sign message with private JWK, returns Base64. */
  static async sign(privateJwk, message) {
    const key = await crypto.subtle.importKey(
      'jwk', privateJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      Utils.encoder.encode(message)
    );
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
  }

  /** Verify signature. */
  static async verify(publicJwk, message, sigBase64) {
    const key = await crypto.subtle.importKey(
      'jwk', publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const sig = Uint8Array.from(atob(sigBase64), c => c.charCodeAt(0));
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      Utils.encoder.encode(message)
    );
  }

  /** Derive AES-GCM key from passphrase and salt. */
  static async deriveAesKey(passphrase, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', Utils.encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /** AES-GCM encrypt object to { iv, ciphertext }. */
  static async encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = Utils.encoder.encode(JSON.stringify(data));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );
    return { iv, ciphertext: new Uint8Array(ciphertext) };
  }

  /** AES-GCM decrypt. */
  static async decrypt(key, iv, ciphertext) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return JSON.parse(Utils.decoder.decode(plain));
  }

  /** Generate unique BioIBAN. */
  static async makeBioIban(pubJwk, timestamp) {
    const seed = JSON.stringify(pubJwk) + '|' + timestamp + '|' + Config.INITIAL.bioConstant;
    const hash = await Utils.sha256(seed);
    return 'BIO' + hash.slice(0, 32).toUpperCase();
  }
}

//──────────────────────── STORAGE SERVICE ─────────────────────
class StorageService {
  static openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(Config.DB.name, Config.DB.version);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(Config.DB.store)) {
          db.createObjectStore(Config.DB.store, { keyPath: 'id' });
        }
      };
      req.onsuccess = e => resolve(e.target.result);
      req.onerror = e => reject(e.target.error);
    });
  }

  static async saveVault(salt, encrypted) {
    const db = await this.openDB();
    return new Promise(resolve => {
      const tx = db.transaction(Config.DB.store, 'readwrite');
      tx.objectStore(Config.DB.store).put({
        id: 'vault', salt: Array.from(salt), iv: Array.from(encrypted.iv), ct: Array.from(encrypted.ciphertext)
      });
      tx.oncomplete = () => resolve();
    });
  }

  static async loadVault() {
    const db = await this.openDB();
    return new Promise(resolve => {
      const req = db.transaction(Config.DB.store, 'readonly')
        .objectStore(Config.DB.store).get('vault');
      req.onsuccess = () => resolve(req.result || null);
    });
  }
}

//──────────────────────── SEGMENT MODEL ───────────────────────
class Segment {
  constructor(amount, ownerKey, timestamp) {
    this.amount = amount;
    this.ownerHistory = [{ key: ownerKey, timestamp }];
  }

  async init() {
    const seed = `${this.amount}|${Date.now()}`;
    this.chainId = await Utils.sha256(seed);
  }

  async spend(timestamp) {
    this.spentProof = await Utils.sha256(`${this.chainId}|${this.amount}|${timestamp}|SPENT`);
  }

  async claim(nextKey, timestamp, signKey) {
    this.ownerHistory.push({ key: nextKey, timestamp });
    this.ownershipProof = await Utils.sha256(
      `${this.chainId}|${this.amount}|${timestamp}|OWNED`
    );
    this.recvSig = await CryptoService.sign(signKey, `${this.chainId}|${this.amount}|${timestamp}|${this.ownershipProof}`);
  }
}

//──────────────────────── VAULT STATE ────────────────────────
class Vault {
  constructor() {
    this.data = this._resetData();
    this.derivedKey = null;
    this.channel = new BroadcastChannel('vault-sync');
    this.utcTimer = null;
  }

  _resetData() {
    return {
      signingKey: {},
      bioIban: '',
      timestamps: { join: 0, lastUtc: 0 },
      constants: { initialBio: Config.INITIAL.bioConstant, bonus: 0 },
      balances: { initial: Config.INITIAL.balanceTvm, tvm: 0, usd: 0 },
      transactions: [],
      auth: { attempts: 0, lockoutUntil: null, credentialId: null },
      usage: { daily: { date: '', count: 0 }, monthly: { ym: '', count: 0 }, yearly: 0 }
    };
  }

  async initVault(passphrase) {
    const now = Math.floor(Date.now() / 1000);
    this.data.timestamps.join = now;
    this.data.timestamps.lastUtc = now;
    this.data.constants.bonus = now - this.data.constants.initialBio;

    this.data.signingKey = await CryptoService.generateKeyPair();
    this.data.bioIban = await CryptoService.makeBioIban(
      this.data.signingKey.publicKeyJwk, now
    );

    // WebAuthn fallback
    try {
      const cred = await navigator.credentials.create({
        publicKey: { /* ... omitted for brevity ...*/ }
      });
      this.data.auth.credentialId = btoa(String.fromCharCode(...new Uint8Array(cred.rawId)));
    } catch {
      this.data.auth.credentialId = `SW-${now}`;
    }

    await this._persist(passphrase);
  }

  async unlockVault(passphrase) {
    const stored = await StorageService.loadVault();
    if (!stored) return this.initVault(passphrase);

    // Enforce lockout
    if (stored.lockoutUntil && Date.now() / 1000 < stored.lockoutUntil) {
      throw new Error('Vault is locked. Please wait.');
    }

    // Derive key and decrypt
    const salt = new Uint8Array(stored.salt);
    this.derivedKey = await CryptoService.deriveAesKey(passphrase, salt);
    const decrypted = await CryptoService.decrypt(
      this.derivedKey,
      new Uint8Array(stored.iv),
      new Uint8Array(stored.ct)
    );
    Object.assign(this.data, decrypted);

    // Reset auth state
    this.data.auth.attempts = 0;
    this.data.auth.lockoutUntil = null;

    // Persist updated auth state
    await this._persist(passphrase);
  }

  async _persist(passphrase) {
    // derive key if not present
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.derivedKey = await CryptoService.deriveAesKey(passphrase, salt);
    const encrypted = await CryptoService.encrypt(this.derivedKey, this.data);
    await StorageService.saveVault(salt, encrypted);
    this.channel.postMessage({ type: 'update', payload: encrypted });
  }

  async sendSegment(toBioIban, amount) {
    const now = Math.floor(Date.now() / 1000);
    const segment = new Segment(amount, this.data.signingKey.publicKeyJwk, now);
    await segment.init();
    await segment.spend(now);

    this.data.transactions.push({
      type: 'sent', chainId: segment.chainId,
      spentProof: segment.spentProof, amount, to: toBioIban, timestamp: now
    });
    return segment;
  }

  async receiveSegment(chainId, spentProof, amount) {
    const now = Math.floor(Date.now() / 1000);
    const segment = new Segment(amount, this.data.signingKey.publicKeyJwk, now);
    segment.chainId = chainId;
    segment.spentProof = spentProof;
    await segment.claim(
      this.data.signingKey.publicKeyJwk,
      now,
      this.data.signingKey.privateKeyJwk
    );

    this.data.transactions.push({
      type: 'received', chainId, ownershipProof: segment.ownershipProof,
      recvSig: segment.recvSig, amount, timestamp: now
    });
    return segment;
  }

  calculateBalance() {
    const received = this.data.transactions
      .filter(t => t.type === 'received')
      .reduce((sum, t) => sum + t.amount, 0);
    const sent = this.data.transactions
      .filter(t => t.type === 'sent')
      .reduce((sum, t) => sum + t.amount, 0);

    this.data.balances.tvm = this.data.balances.initial + received - sent;
    this.data.balances.usd = (this.data.balances.tvm / Config.EXCHANGE_RATE).toFixed(2);
    return this.data.balances;
  }
}

//──────────────────────── UI CONTROLLER ──────────────────────
class UIController {
  constructor(vault) {
    this.vault = vault;
    this.elements = {};
  }

  cacheElements() {
    const ids = [
      'enterVaultBtn','catchInBtn','catchOutBtn','copyBioIbanBtn',
      'exportBackupBtn','exportBtn','importVaultFileInput',
      'receiverBioIban','catchOutAmount','transactionBody',
      'tvmBalance','usdBalance','bioIbanInput','utcTime','bioLineText'
    ];
    ids.forEach(id => this.elements[id] = document.getElementById(id));
  }

  bindEvents() {
    const e = this.elements;
    e.enterVaultBtn.addEventListener('click', () => this.handleUnlock());
    e.catchOutBtn.addEventListener('click', () => this.handleSend());
    e.catchInBtn.addEventListener('click', () => this.handleReceive());
    e.copyBioIbanBtn.addEventListener('click', () => this.copyToClipboard(this.vault.data.bioIban));
    e.exportBackupBtn.addEventListener('click', () => this.handleExport());
    e.importVaultFileInput.addEventListener('change', e => this.handleImport(e.target.files[0]));

    // sync updates
    this.vault.channel.onmessage = ({ data }) => this.handleSync(data);
  }

  async handleUnlock() {
    try {
      const pass = await UIController.promptPass('Enter Passphrase');
      await this.vault.unlockVault(pass);
      this.render();
      this.startTicker();
    } catch (err) {
      UIController.alert(err.message);
    }
  }

  async handleSend() {
    try {
      const to = this.elements.receiverBioIban.value.trim();
      const amt = Number(this.elements.catchOutAmount.value);
      if (!to || amt <= 0) throw new Error('Invalid recipient or amount');

      const segment = await this.vault.sendSegment(to, amt);
      UIController.alert(`Share Bio-Catch: ${segment.chainId}|${segment.spentProof}`);
      await this.vault._persist(await UIController.promptPass());
      this.renderTransactions();
      this.updateBalanceDisplay();
    } catch (err) {
      UIController.alert(err.message);
    }
  }

  async handleReceive() {
    try {
      const input = prompt('Paste Bio-Catch (chainId|spentProof)');
      const [chainId, spentProof] = input.split('|');
      const amt = Number(prompt('Amount (TVM)'));
      if (!chainId || !spentProof || amt <= 0) throw new Error('Invalid Bio-Catch data');

      const segment = await this.vault.receiveSegment(chainId, spentProof, amt);
      UIController.alert('Received & claimed');
      await this.vault._persist(await UIController.promptPass());
      this.renderTransactions();
      this.updateBalanceDisplay();
    } catch (err) {
      UIController.alert(err.message);
    }
  }

  renderTransactions() {
    const rows = this.vault.data.transactions
      .sort((a, b) => b.timestamp - a.timestamp)
      .map(t => `
        <tr>
          <td>${t.type === 'sent' ? t.to : '—'}</td>
          <td>${t.chainId}</td>
          <td>${Utils.formatNumber(t.amount)}</td>
          <td>${Utils.formatTimestamp(t.timestamp)}</td>
          <td>${t.type}</td>
        </tr>
      `).join('');
    this.elements.transactionBody.innerHTML = rows;
  }

  updateBalanceDisplay() {
    const bal = this.vault.calculateBalance();
    this.elements.tvmBalance.textContent = `Balance: ${Utils.formatNumber(bal.tvm)} TVM`;
    this.elements.usdBalance.textContent = `≈ ${Utils.formatNumber(bal.usd)} USD`;
  }

  render() {
    document.getElementById('lockedScreen').classList.add('hidden');
    document.getElementById('vaultUI').classList.remove('hidden');
    this.elements.bioIbanInput.value = this.vault.data.bioIban;
    this.renderTransactions();
    this.updateBalanceDisplay();
  }

  startTicker() {
    if (this.utcInterval) clearInterval(this.utcInterval);
    this.utcInterval = setInterval(() => {
      const now = Math.floor(Date.now() / 1000);
      this.vault.data.timestamps.lastUtc = now;
      this.elements.utcTime.textContent = Utils.formatTimestamp(now);
      this.elements.bioLineText.textContent = `🔄 BonusConstant: ${this.vault.data.constants.bonus}`;
    }, 1000);
  }

  handleSync({ iv, ciphertext }) {
    // decrypt and update UI if open
    // omitted for brevity
  }

  async handleExport() {
    const blob = new Blob([JSON.stringify(this.vault.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'vault_backup.json';
    a.click(); URL.revokeObjectURL(url);
  }

  async handleImport(file) {
    try {
      const text = await file.text();
      this.vault.data = JSON.parse(text);
      UIController.alert('Backup imported. Unlock to apply.');
    } catch {
      UIController.alert('Invalid backup file');
    }
  }

  static alert(msg) { window.alert(msg); }
  static promptPass(title) { return Promise.resolve(prompt(title)); }
  copyToClipboard(text) { navigator.clipboard.writeText(text); UIController.alert('Copied to clipboard'); }
}

//──────────────────────── BOOTSTRAP ───────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const vault = new Vault();
  const ui = new UIController(vault);
  ui.cacheElements();
  ui.bindEvents();
  console.log('🎯 Bio-Vault initialized – refactored module');
});
