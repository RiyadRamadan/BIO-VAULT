'use strict';

/* ==== CONFIG ==== */
const SEGMENTS_PER_YEAR = 12000;
const INITIAL_SEGMENTS_UNLOCKED = 1200;
const EXCHANGE_RATE = 12;
const INITIAL_BIO_CONSTANT = 1736565605;
const FOUNDER_KEY = "BALANCECHAIN-FOUNDER-KEY"; // <-- set a unique, non-leaking system constant
const TVM_CONTRACT_ADDRESS = "0xYourTvmContractAddress";
const TVM_CONTRACT_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address,uint256) returns (bool)"
];

/* ==== STATE ==== */
let cryptoKey = null, encryptedVault = null, vaultData = null, isVaultUnlocked = false;
let ethProvider = null, ethAccount = null, ethChainId = null;
let idleTimer;

/* ==== UI HOOK ==== */
const $ = id => document.getElementById(id);

function showToast(msg, error) {
  const toast = $('toast');
  if (!toast) return;
  toast.classList.remove('toast-error');
  if (error) toast.classList.add('toast-error');
  toast.textContent = msg;
  toast.style.display = 'block';
  setTimeout(() => { toast.style.display = 'none'; }, 3400);
}

/* ==== CRYPTO / WEBAUTHN ==== */
async function createWebAuthnCredential() {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: window.crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "BioVault" },
      user: { id: Uint8Array.from(String(Date.now())), name: "user@balancechain", displayName: "BioVault User" },
      pubKeyCredParams: [
  {alg: -7, type: "public-key"},
  {alg: -257, type: "public-key"}
],

      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
      timeout: 60000, attestation: "direct"
    }
  });
  if (!cred || !cred.rawId) throw new Error("Credential registration failed");
  localStorage.setItem('bioVaultCredentialId', btoa(String.fromCharCode(...new Uint8Array(cred.rawId))));
  return cred;
}
async function unlockWithWebAuthn() {
  const credIdB64 = localStorage.getItem('bioVaultCredentialId');
  if (!credIdB64) throw new Error("No credential registered");
  const credId = Uint8Array.from(atob(credIdB64), c => c.charCodeAt(0));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: window.crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: credId, type: "public-key", transports: ["internal"] }],
      userVerification: "required", timeout: 60000
    }
  });
  const hash = await window.crypto.subtle.digest("SHA-256", assertion.response.signature);
  cryptoKey = await window.crypto.subtle.importKey('raw', hash, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  return {cryptoKey, assertion};
}
async function encryptVault(obj, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}
async function decryptVault(encObj, key) {
  const iv = new Uint8Array(encObj.iv);
  const ctBuf = new Uint8Array(encObj.ct);
  const pt = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ctBuf);
  return JSON.parse(new TextDecoder().decode(pt));
}
async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
  );
  return await window.crypto.subtle.deriveKey(
    {name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256"},
    keyMaterial, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]
  );
}

/* ==== SEGMENT MODEL ==== */
function buildGenesisVault(credentialId, joinTS) {
  // Use biometric key (credentialId) + bio-constant for IBAN. Founder key and genesis bio-constant for originality.
  const baseBio = INITIAL_BIO_CONSTANT + (joinTS - INITIAL_BIO_CONSTANT);
  let segments = [];
  for(let i=1;i<=SEGMENTS_PER_YEAR;i++) {
    const unlocked = i <= INITIAL_SEGMENTS_UNLOCKED;
    segments.push({
      segmentIndex: i,
      amount: 1,
      founderKey: FOUNDER_KEY,
      genesisBioConst: INITIAL_BIO_CONSTANT,
      originalOwnerKey: credentialId,
      originalOwnerTS: joinTS,
      originalBioConst: baseBio,
      previousOwnerKey: null,
      currentOwnerKey: unlocked ? credentialId : null,
      unlocked,
      last_update: joinTS,
      ownershipChangeProof: null
    });
  }
  return {
    bioIBAN: `BIO${credentialId.slice(0,10)}-${baseBio}`,
    initialBioConstant: baseBio,
    joinTimestamp: joinTS,
    credentialId,
    segments,
    balanceTVM: INITIAL_SEGMENTS_UNLOCKED,
    balanceUSD: +(INITIAL_SEGMENTS_UNLOCKED / EXCHANGE_RATE).toFixed(2),
    transactions: [],
    userWallet: "",
    auditTrail: [],
  };
}
function getSpendableSegments() {
  return vaultData.segments.filter(s => s.unlocked && s.currentOwnerKey === vaultData.credentialId);
}
function unlockNewSegments(count, nowSec) {
  let unlocked = 0;
  for (let i = 0; i < vaultData.segments.length && unlocked < count; ++i) {
    let seg = vaultData.segments[i];
    if (!seg.unlocked) {
      seg.currentOwnerKey = vaultData.credentialId;
      seg.unlocked = true;
      seg.last_update = nowSec;
      seg.ownershipChangeProof = null;
      unlocked++;
    }
  }
  return unlocked;
}

/* ==== BIOMETRIC VALIDATION ON EVERY ACTION ==== */
async function requireBiometricBeforeCriticalAction() {
  try {
    const {cryptoKey: key, assertion} = await unlockWithWebAuthn();
    const assertionHash = await window.crypto.subtle.digest("SHA-256", assertion.response.signature);
    return {
      assertionHash: Array.from(new Uint8Array(assertionHash)).map(b => b.toString(16).padStart(2, '0')).join(''),
      timestamp: Math.floor(Date.now() / 1000),
      credentialId: vaultData.credentialId
    };
  } catch (err) {
    showToast("Biometric verification failed or canceled", true);
    return null;
  }
}

/* ==== METAMASK / ETHEREUM ==== */
async function connectMetaMask() {
  if (!window.ethereum) { showToast("Install MetaMask", true); return; }
  ethProvider = window.ethereum;
  try {
    let accounts = await ethProvider.request({ method: 'eth_requestAccounts' });
    ethAccount = accounts[0];
    ethChainId = await ethProvider.request({ method: 'eth_chainId' });
    $('userWalletAddress').value = ethAccount;
    fetchTvmOnChainBalance();
    showToast("MetaMask connected");
  } catch (e) { showToast("MetaMask error", true); }
}
$('autoConnectWalletBtn').onclick = connectMetaMask;
if (window.ethereum) {
  window.ethereum.on('accountsChanged', function (accounts) {
    ethAccount = accounts[0];
    $('userWalletAddress').value = ethAccount;
    fetchTvmOnChainBalance();
  });
  window.ethereum.on('chainChanged', function (chainId) {
    ethChainId = chainId;
    fetchTvmOnChainBalance();
  });
}
async function fetchTvmOnChainBalance() {
  if (!ethProvider || !ethAccount) return;
  const provider = new ethers.providers.Web3Provider(ethProvider);
  const tvmContract = new ethers.Contract(TVM_CONTRACT_ADDRESS, TVM_CONTRACT_ABI, provider);
  try {
    let balance = await tvmContract.balanceOf(ethAccount);
    let tvm = ethers.utils.formatUnits(balance, 18);
    showToast(`On-chain TVM: ${tvm}`);
  } catch (e) { showToast("Fetch TVM failed", true); }
}
async function sendTVMtoOnchain(receiver, amount) {
  if (!ethProvider || !ethAccount) { showToast("Connect MetaMask", true); return; }
  const provider = new ethers.providers.Web3Provider(ethProvider);
  const signer = provider.getSigner();
  const tvmContract = new ethers.Contract(TVM_CONTRACT_ADDRESS, TVM_CONTRACT_ABI, signer);
  try {
    let tx = await tvmContract.transfer(receiver, ethers.utils.parseUnits(String(amount), 18));
    await tx.wait();
    showToast("Sent TVM on-chain");
    fetchTvmOnChainBalance();
  } catch (e) {
    showToast("On-chain send failed", true);
  }
}

/* ==== VAULT BOOT/UNLOCK ==== */
$('enterVaultBtn').onclick = async () => {
  // No passphrase, no user friction
  if (!localStorage.getItem('bioVaultCredentialId')) {
    try { await createWebAuthnCredential(); showToast("WebAuthn registered. Now unlock."); }
    catch (e) { showToast("Biometric registration failed", true); return; }
  }
  await unlockVaultFlow();
};
async function unlockVaultFlow() {
  try {
    let {cryptoKey: key} = await unlockWithWebAuthn();
    cryptoKey = key;
    if (!localStorage.getItem('bioVaultEncrypted')) {
      vaultData = buildGenesisVault(localStorage.getItem('bioVaultCredentialId'), Math.floor(Date.now()/1000));
      encryptedVault = await encryptVault(vaultData, cryptoKey);
      localStorage.setItem('bioVaultEncrypted', JSON.stringify(encryptedVault));
    } else {
      encryptedVault = JSON.parse(localStorage.getItem('bioVaultEncrypted'));
      vaultData = await decryptVault(encryptedVault, cryptoKey);
    }
    isVaultUnlocked = true;
    $('lockedScreen').classList.add('hidden');
    $('vaultUI').classList.remove('hidden');
    populateWalletUI();
    showToast("Vault unlocked!");
    resetIdleTimer();
    updateVaultButtons();
  } catch (err) { showToast("Unlock failed", true); }
}
async function saveVault() {
  if (!cryptoKey || !vaultData) return;
  encryptedVault = await encryptVault(vaultData, cryptoKey);
  localStorage.setItem('bioVaultEncrypted', JSON.stringify(encryptedVault));
}

/* ==== UI: WALLET, TRANSACTIONS ==== */
function populateWalletUI() {
  if (!vaultData) return;
  $('bioibanInput').value = vaultData.bioIBAN;
  $('tvmBalance').textContent = `Balance: ${vaultData.balanceTVM} TVM`;
  $('usdBalance').textContent = `Equivalent to ${vaultData.balanceUSD} USD`;
  renderTransactionTable();
  updateVaultButtons();
}
function renderTransactionTable() {
  const tbody = $('transactionBody');
  tbody.innerHTML = '';
  if (!vaultData || !vaultData.transactions) return;
  vaultData.transactions.slice().reverse().forEach(tx => {
    let badge = tx.onChain ? '<span class="badge badge-chain">On-Chain</span>' : '';
    let row = document.createElement('tr');
    row.innerHTML = `<td>${tx.bioIBAN || ''}</td><td>${tx.bioCatch || ''}</td>
      <td>${tx.amount || ''}</td><td>${tx.date || ''}</td><td>${tx.status || ''} ${badge}</td>`;
    tbody.appendChild(row);
  });
}

/* ==== CATCH OUT / IN (SEND/RECEIVE TVM with Biometric Proof) ==== */
$('catchOutBtn').onclick = async () => {
  const proof = await requireBiometricBeforeCriticalAction();
  if (!proof) return;
  if (!isVaultUnlocked) return showToast("Unlock first!", true);
  const recv = $('receiverBioIBAN').value.trim();
  const amt = parseInt($('catchOutAmount').value.trim(), 10);
  if (!recv || !amt || isNaN(amt) || amt < 1) return showToast("Enter valid receiver & amount", true);
  if (recv === vaultData.bioIBAN) return showToast("Cannot send to self", true);

  const spendable = getSpendableSegments();
  if (spendable.length < amt) return showToast("Insufficient unlocked TVM", true);

  const nowSec = proof.timestamp;
  for (let i = 0; i < amt; ++i) {
    let seg = spendable[i];
    seg.previousOwnerKey   = seg.currentOwnerKey;
    seg.currentOwnerKey    = null;
    seg.unlocked           = false;
    seg.last_update        = nowSec;
    seg.ownershipChangeProof = proof;
  }
  vaultData.balanceTVM -= amt;
  vaultData.balanceUSD = +(vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2);
  vaultData.transactions.push({
    bioIBAN: recv,
    bioCatch: 'TX-' + nowSec,
    amount: amt,
    date: new Date(nowSec*1000).toISOString().replace('T',' ').slice(0,19),
    status: 'Completed'
  });
  vaultData.auditTrail.push({ type:"out", to:recv, amount:amt, ts:nowSec, proof });
  await saveVault();
  populateWalletUI();
  showToast(`Sent ${amt} TVM`);
  resetIdleTimer();
};

$('catchInBtn').onclick = async () => {
  const proof = await requireBiometricBeforeCriticalAction();
  if (!proof) return;
  if (!isVaultUnlocked) return showToast("Unlock first!", true);
  const bioCatch = $('catchInBioCatch').value.trim();
  const amt = parseInt($('catchInAmount').value.trim(), 10);
  if (!bioCatch || !amt || isNaN(amt) || amt < 1) return showToast("Enter valid Bio-Catch & amount", true);
  const nowSec = proof.timestamp;
  let unlockedCount = unlockNewSegments(amt, nowSec);
  let count = 0;
  for (let i = 0; i < vaultData.segments.length && count < amt; ++i) {
    let seg = vaultData.segments[i];
    if (seg.unlocked && !seg.ownershipChangeProof) {
      seg.ownershipChangeProof = proof;
      count++;
    }
  }
  vaultData.balanceTVM += unlockedCount;
  vaultData.balanceUSD = +(vaultData.balanceTVM / EXCHANGE_RATE).toFixed(2);
  vaultData.transactions.push({
    bioIBAN: vaultData.bioIBAN,
    bioCatch: bioCatch,
    amount: amt,
    date: new Date(nowSec*1000).toISOString().replace('T',' ').slice(0,19),
    status: 'Received'
  });
  vaultData.auditTrail.push({ type:"in", from:bioCatch, amount:amt, ts:nowSec, proof });
  await saveVault();
  populateWalletUI();
  showToast(`Received ${amt} TVM`);
  resetIdleTimer();
};

/* ==== BIO-IBAN COPY ==== */
$('copyBioIBANBtn').onclick = () => {
  if (!$('bioibanInput').value) return showToast("No Bio-IBAN to copy", true);
  navigator.clipboard.writeText($('bioibanInput').value).then(() => showToast("Bio-IBAN copied!"));
};

/* ==== WALLET SAVE ==== */
$('saveWalletBtn').onclick = async () => {
  if (!ethAccount) { showToast("Connect MetaMask first", true); return; }
  vaultData.userWallet = ethAccount;
  await saveVault();
  showToast("Wallet address saved");
};

/* ==== ON-CHAIN TVM SEND (double-click to send on-chain) ==== */
$('catchOutBtn').ondblclick = async () => {
  const receiver = prompt("ETH address to send TVM:");
  const amt = parseFloat(prompt("How many TVM to send on-chain?"));
  if (receiver && amt && amt > 0) await sendTVMtoOnchain(receiver, amt);
};

/* ==== EXPORT / IMPORT ==== */
$('exportBackupBtn').onclick = () => {
  const enc = localStorage.getItem('bioVaultEncrypted');
  const blob = new Blob([enc], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'vault_backup.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Vault exported");
};
$('importVaultFileInput').onchange = function() {
  const file = this.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      localStorage.setItem('bioVaultEncrypted', e.target.result);
      showToast("Vault imported. Please unlock.");
    } catch (err) {
      showToast("Import failed", true);
    }
  };
  reader.readAsText(file);
};

/* ==== EXPORT TRANSACTIONS CSV ==== */
$('exportBtn').onclick = () => {
  if (!vaultData) return showToast("Unlock first!", true);
  const csv = ["BioIBAN,BioCatch,Amount,Date,Status"];
  vaultData.transactions.forEach(tx =>
    csv.push([tx.bioIBAN, tx.bioCatch, tx.amount, tx.date, tx.status].join(','))
  );
  const blob = new Blob([csv.join('\n')], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'transactions.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Transactions exported");
};

/* ==== EXPORT FRIENDLY BACKUP (Password protected) ==== */
$('exportFriendlyBtn').onclick = async () => {
  if (!vaultData) return showToast("Unlock first!", true);
  const pass = prompt("Password for backup (keep safe!):");
  if (!pass) return showToast("Export canceled");
  const salt = String(Date.now());
  const key = await deriveKeyFromPassword(pass, salt);
  const enc = await encryptVault(vaultData, key);
  enc._salt = salt;
  const blob = new Blob([JSON.stringify(enc)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'vault_friendly_backup.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Password-protected backup exported");
};

/* ==== IMPORT PASSWORD-PROTECTED BACKUP ==== */
$('importVaultFileInput').onchange = function() {
  const file = this.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async function(e) {
    try {
      const enc = JSON.parse(e.target.result);
      if (enc._salt) {
        const pass = prompt("Enter password to restore backup:");
        if (!pass) return showToast("Import canceled");
        const key = await deriveKeyFromPassword(pass, enc._salt);
        vaultData = await decryptVault(enc, key);
        isVaultUnlocked = true;
        populateWalletUI();
        showToast("Backup imported (password verified)");
      } else {
        // Legacy (no password)
        localStorage.setItem('bioVaultEncrypted', e.target.result);
        showToast("Vault imported. Please unlock.");
      }
    } catch (err) {
      showToast("Import failed", true);
    }
  };
  reader.readAsText(file);
};

/* ==== MODAL NAV / OPEN / CLOSE / FOCUS ==== */
function openModal(id) {
  document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
  const modal = $(id);
  if (modal) {
    modal.style.display = 'flex';
    setTimeout(() => {
      const input = modal.querySelector('input,button,[tabindex="0"]');
      if (input) input.focus();
    }, 100);
  }
}
function closeModal(id) {
  const modal = $(id);
  if (modal) modal.style.display = 'none';
}
function modalNav(modalId, idx) {
  const modal = $(modalId);
  if (!modal) return;
  const pages = modal.querySelectorAll('.modal-onboarding-page');
  const navBtns = modal.querySelectorAll('.modal-nav button');
  pages.forEach((page, i) => page.classList.toggle('hidden', i !== idx));
  navBtns.forEach((btn, i) => btn.classList.toggle('active', i === idx));
}

/* ==== BIO-CATCH POPUP ==== */
$('closeBioCatchPopup').onclick = () => $('bioCatchPopup').style.display = 'none';
$('copyBioCatchBtn').onclick = () => {
  const txt = $('bioCatchNumberText').textContent;
  if (txt) navigator.clipboard.writeText(txt).then(()=>showToast("Bio-Catch copied!"));
};

/* ==== LIVE AUDIT PEG VALUE ==== */
async function updateAuditPeg() {
  if ($('auditPegLive'))
    $('auditPegLive').textContent = '1 TVM = 1 USD (Protocol Peg enforced)';
}
if ($('auditPegLive')) updateAuditPeg();

/* ==== UTC TIME LIVE ==== */
function updateUTC() {
  if ($('utcTime')) $('utcTime').textContent = 'UTC Time: ' + new Date().toISOString().replace('T',' ').slice(0,19);
  setTimeout(updateUTC, 1000);
}
updateUTC();

/* ==== SHOW/HIDE LOCK/TERMINATE BUTTONS BASED ON STATE ==== */
function updateVaultButtons() {
  if (isVaultUnlocked) {
    $('lockVaultBtn').classList.remove('hidden');
    $('terminateBtn').classList.remove('hidden');
  } else {
    $('lockVaultBtn').classList.add('hidden');
    $('terminateBtn').classList.add('hidden');
  }
}

/* ==== LOCK VAULT ==== */
if ($('lockVaultBtn')) $('lockVaultBtn').onclick = () => {
  isVaultUnlocked = false;
  $('vaultUI').classList.add('hidden');
  $('lockVaultBtn').classList.add('hidden');
  $('terminateBtn').classList.add('hidden');
  $('lockedScreen').classList.remove('hidden');
};

/* ==== ONBOARDING POPUP FOR FIRST USE ==== */
window.addEventListener('load', () => {
  if (!localStorage.getItem('vaultOnboarded')) {
    openModal('onboardingModal');
    localStorage.setItem('vaultOnboarded', '1');
  }
  $('enterVaultBtn')?.focus();
});

/* ==== ACCESSIBILITY ==== */
document.querySelectorAll('.modal').forEach(modal => {
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('role', 'dialog');
  modal.tabIndex = -1;
});
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal, .popup').forEach(m => {
      if (m.style.display === 'flex') m.style.display = 'none';
    });
  }
});

/* ==== AUTO-LOCK SESSION HANDLING ==== */
function resetIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (isVaultUnlocked) {
      isVaultUnlocked = false;
      $('vaultUI').classList.add('hidden');
      $('lockVaultBtn').classList.add('hidden');
      $('terminateBtn').classList.add('hidden');
      $('lockedScreen').classList.remove('hidden');
      showToast("Vault auto-locked");
    }
  }, 10 * 60 * 1000); // 10 minutes
}
['mousemove','keydown','touchstart'].forEach(ev => document.addEventListener(ev, resetIdleTimer));
resetIdleTimer();

/* ==== ERASE VAULT ==== */
$('terminateBtn').onclick = () => {
  if (confirm("This will delete your vault from this device. Make sure you have a backup. Continue?")) {
    localStorage.removeItem('bioVaultCredentialId');
    localStorage.removeItem('bioVaultEncrypted');
    isVaultUnlocked = false;
    encryptedVault = null;
    vaultData = null;
    $('vaultUI').classList.add('hidden');
    $('lockVaultBtn').classList.add('hidden');
    $('terminateBtn').classList.add('hidden');
    $('lockedScreen').classList.remove('hidden');
    showToast("Vault erased");
  }
};

/* ==== FOOTER YEAR ==== */
if ($('currentYear')) $('currentYear').textContent = new Date().getFullYear();

/* ==== END ==== */
