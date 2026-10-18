// Coffre-fort — logique du coffre, indépendante de l'interface (testable sous Node).
import * as C from './crypto.js';

const now = () => Date.now();
const uid = () => C.b64(C.randomBytes(16)).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
const toBox = (r) => ({ iv: r.iv, ct: r.ct });

export class VaultError extends Error {
  constructor(code, info = {}) { super(code); this.code = code; Object.assign(this, info); }
}

export function lockDelayMs(failed) {
  if (failed < 3) return 0;
  return Math.min(30000 * 2 ** (failed - 3), 3600000); // 30 s, 1 min, 2 min… plafonné à 1 h
}

export class Vault {
  constructor(store, { iterations = C.PBKDF2_ITERATIONS } = {}) {
    this.store = store; this.iterations = iterations; this.key = null; this.cfg = null;
  }
  get unlocked() { return !!this.key; }

  async load() { this.cfg = await this.store.getMeta('config'); return this.cfg; }
  async exists() { return !!(await this.load()); }
  async save() { await this.store.setMeta('config', this.cfg); }

  async create(pin) {
    if (!/^\d{6,12}$/.test(pin)) throw new VaultError('PIN_FORMAT');
    const key = await C.generateDataKey();
    const salt = C.randomBytes(16);
    const kek = await C.deriveKeyFromPin(pin, salt, this.iterations);
    this.cfg = {
      v: C.FORMAT_VERSION, created: now(),
      kdf: { alg: 'PBKDF2-SHA256', salt, iterations: this.iterations },
      pinWrap: await C.wrapDataKey(key, kek, C.AAD_PIN),
      prf: null,
      settings: { autoLockMin: 2, wipeAfter: 0, clipboardSec: 30 },
      attempts: { failed: 0, lockUntil: 0 }
    };
    await this.save();
    this.key = key;
  }

  lockStatus() {
    const a = this.cfg?.attempts || { failed: 0, lockUntil: 0 };
    return { failed: a.failed, lockUntil: a.lockUntil, waitMs: Math.max(0, a.lockUntil - now()) };
  }

  // Vérifie le code (déverrouillage ou ré-authentification). Compte les échecs, temporise, efface si configuré.
  async checkPin(pin) {
    await this.load();
    if (!this.cfg) throw new VaultError('NO_VAULT');
    const st = this.lockStatus();
    if (st.waitMs > 0) throw new VaultError('RATE_LIMIT', { waitMs: st.waitMs });
    // L'échec est comptabilisé AVANT la dérivation : couper l'app pendant le calcul ne réinitialise rien.
    const a = this.cfg.attempts;
    a.failed += 1; a.lockUntil = now() + lockDelayMs(a.failed); await this.save();
    let key;
    try {
      const kek = await C.deriveKeyFromPin(pin, this.cfg.kdf.salt, this.cfg.kdf.iterations);
      key = await C.unwrapDataKey(this.cfg.pinWrap, kek, C.AAD_PIN);
    } catch (e) {
      const wipeAfter = this.cfg.settings.wipeAfter;
      if (wipeAfter && a.failed >= wipeAfter) { await this.wipe(); throw new VaultError('WIPED'); }
      throw new VaultError('BAD_PIN', {
        failed: a.failed, waitMs: Math.max(0, a.lockUntil - now()),
        remaining: wipeAfter ? wipeAfter - a.failed : null
      });
    }
    a.failed = 0; a.lockUntil = 0; await this.save();
    return key;
  }
  async unlockWithPin(pin) { this.key = await this.checkPin(pin); }

  // Biométrie : la sortie PRF (32 octets) du passkey dérive une KEK via HKDF.
  async enablePrf({ credentialId, prfSalt, prfOutput }) {
    this.requireUnlocked();
    const hkdfSalt = C.randomBytes(16);
    const kek = await C.deriveKeyFromPrf(prfOutput, hkdfSalt);
    this.cfg.prf = { credentialId, prfSalt, hkdfSalt, wrap: await C.wrapDataKey(this.key, kek, C.AAD_PRF) };
    await this.save();
  }
  // Échecs Face ID : comptés dans le MÊME compteur d'échecs consécutifs que les codes erronés,
  // dès que l'effacement après N échecs est activé. WebAuthn ne distingue pas « visage non reconnu »
  // et « annulé » (NotAllowedError) : toute tentative biométrique non aboutie compte.
  // L'essai est compté AVANT d'ouvrir l'invite (tuer l'app pendant l'invite ne l'annule pas) ;
  // un déverrouillage réussi (code ou Face ID) remet le compteur à zéro.
  biometricCounts() { return !!this.cfg?.settings.wipeAfter; }
  async beginBiometricAttempt() {
    await this.load();
    if (!this.cfg?.prf) throw new VaultError('NO_PRF');
    if (!this.biometricCounts()) return;
    const st = this.lockStatus();
    if (st.waitMs > 0) throw new VaultError('RATE_LIMIT', { waitMs: st.waitMs });
    const a = this.cfg.attempts;
    a.failed += 1; a.lockUntil = now() + lockDelayMs(a.failed); await this.save();
  }
  async biometricFailed() {
    if (!this.biometricCounts()) return { counted: false };
    const a = this.cfg.attempts, wipeAfter = this.cfg.settings.wipeAfter;
    if (a.failed >= wipeAfter) { await this.wipe(); throw new VaultError('WIPED'); }
    return { counted: true, failed: a.failed, remaining: wipeAfter - a.failed, waitMs: Math.max(0, a.lockUntil - now()) };
  }
  async disablePrf() { this.cfg.prf = null; await this.save(); }
  async unlockWithPrf(prfOutput) {
    await this.load();
    if (!this.cfg?.prf) throw new VaultError('NO_PRF');
    const kek = await C.deriveKeyFromPrf(prfOutput, this.cfg.prf.hkdfSalt);
    try { this.key = await C.unwrapDataKey(this.cfg.prf.wrap, kek, C.AAD_PRF); }
    catch { throw new VaultError('BAD_PRF'); }
    this.cfg.attempts = { failed: 0, lockUntil: 0 }; await this.save();
  }

  async changePin(newPin) {
    this.requireUnlocked();
    if (!/^\d{6,12}$/.test(newPin)) throw new VaultError('PIN_FORMAT');
    const salt = C.randomBytes(16);
    const kek = await C.deriveKeyFromPin(newPin, salt, this.iterations);
    this.cfg.kdf = { alg: 'PBKDF2-SHA256', salt, iterations: this.iterations };
    this.cfg.pinWrap = await C.wrapDataKey(this.key, kek, C.AAD_PIN);
    await this.save();
  }
  async setSettings(patch) { Object.assign(this.cfg.settings, patch); await this.save(); }

  lock() { this.key = null; }
  requireUnlocked() { if (!this.key) throw new VaultError('LOCKED'); }

  // ---- Éléments ----
  async listItems() {
    this.requireUnlocked();
    const recs = await this.store.getAll('items');
    const out = [];
    for (const r of recs) out.push({ id: r.id, ts: r.ts, ...(await C.decryptJSON(this.key, toBox(r), 'item:' + r.id)) });
    return out.sort((a, b) => b.ts - a.ts);
  }
  async addItem(meta, bytes = null) {
    this.requireUnlocked();
    const id = uid(), ts = now();
    if (bytes) {
      const b = await C.encryptBytes(this.key, bytes, 'blob:' + id);
      await this.store.put('blobs', { id, iv: b.iv, ct: b.ct });
      meta = { ...meta, hasBlob: true, size: bytes.byteLength };
    }
    const box = await C.encryptJSON(this.key, meta, 'item:' + id);
    await this.store.put('items', { id, ts, iv: box.iv, ct: box.ct });
    return { id, ts, ...meta };
  }
  async updateItem(id, meta) {
    this.requireUnlocked();
    const old = await this.store.get('items', id);
    if (!old) throw new VaultError('NOT_FOUND');
    const box = await C.encryptJSON(this.key, meta, 'item:' + id);
    await this.store.put('items', { id, ts: old.ts, iv: box.iv, ct: box.ct });
  }
  async getBlob(id) {
    this.requireUnlocked();
    const r = await this.store.get('blobs', id);
    if (!r) throw new VaultError('NOT_FOUND');
    return C.decryptBytes(this.key, toBox(r), 'blob:' + id);
  }
  async deleteItem(id) {
    await this.store.del('items', id); await this.store.del('blobs', id);
  }
  async wipe() { await this.store.clear(); this.key = null; this.cfg = null; }

  // ---- Sauvegarde chiffrée ----
  // Le fichier contient les enregistrements tels quels (chiffrés par la clé maître) + la clé maître
  // enveloppée par une clé dérivée d'un mot de passe de sauvegarde distinct (PBKDF2 600 000).
  async exportBackup(password) {
    this.requireUnlocked();
    if (!password || password.length < 8) throw new VaultError('BACKUP_PW');
    const salt = C.randomBytes(16);
    const kek = await C.deriveKeyFromPin(password, salt, this.iterations);
    const wrap = await C.wrapDataKey(this.key, kek, C.AAD_BACKUP);
    const enc = (r) => ({ id: r.id, ts: r.ts, iv: C.b64(r.iv), ct: C.b64(r.ct) });
    const parts = [JSON.stringify({
      format: 'coffre-fort-backup', version: 1, created: new Date().toISOString(),
      kdf: { alg: 'PBKDF2-SHA256', salt: C.b64(salt), iterations: this.iterations },
      wrap: { iv: C.b64(wrap.iv), ct: C.b64(wrap.ct) }
    }).slice(0, -1)];
    parts.push(',"items":[');
    (await this.store.getAll('items')).forEach((r, i) => parts.push((i ? ',' : '') + JSON.stringify(enc(r))));
    parts.push('],"blobs":[');
    const ids = (await this.store.getAll('items')).map(r => r.id);
    let first = true;
    for (const id of ids) {
      const b = await this.store.get('blobs', id);
      if (b) { parts.push((first ? '' : ',') + JSON.stringify(enc(b))); first = false; }
    }
    parts.push(']}');
    return parts; // tableau de chaînes, à passer à new Blob(parts)
  }

  async importBackup(text, password) {
    this.requireUnlocked();
    let data;
    try { data = JSON.parse(text); } catch { throw new VaultError('BACKUP_FORMAT'); }
    if (data?.format !== 'coffre-fort-backup') throw new VaultError('BACKUP_FORMAT');
    const kek = await C.deriveKeyFromPin(password, C.unb64(data.kdf.salt), data.kdf.iterations);
    let bkey;
    try { bkey = await C.unwrapDataKey({ iv: C.unb64(data.wrap.iv), ct: C.unb64(data.wrap.ct) }, kek, C.AAD_BACKUP); }
    catch { throw new VaultError('BACKUP_PW_BAD'); }
    const dbox = (r) => ({ iv: C.unb64(r.iv), ct: C.unb64(r.ct) });
    const blobs = new Map(data.blobs.map(b => [b.id, b]));
    let added = 0;
    for (const r of data.items) {
      if (await this.store.get('items', r.id)) continue; // déjà présent
      const meta = await C.decryptJSON(bkey, dbox(r), 'item:' + r.id);
      if (blobs.has(r.id)) {
        const bytes = await C.decryptBytes(bkey, dbox(blobs.get(r.id)), 'blob:' + r.id);
        const b = await C.encryptBytes(this.key, bytes, 'blob:' + r.id);
        await this.store.put('blobs', { id: r.id, iv: b.iv, ct: b.ct });
      }
      const box = await C.encryptJSON(this.key, meta, 'item:' + r.id);
      await this.store.put('items', { id: r.id, ts: r.ts, iv: box.iv, ct: box.ct });
      added++;
    }
    return added;
  }
}

// Stockage en mémoire (tests).
export class MemoryStore {
  constructor() { this.meta = new Map(); this.s = { items: new Map(), blobs: new Map() }; }
  async getMeta(k) { return this.meta.get(k); }
  async setMeta(k, v) { this.meta.set(k, structuredClone(v)); }
  async getAll(st) { return [...this.s[st].values()].map(v => structuredClone(v)); }
  async get(st, id) { const v = this.s[st].get(id); return v && structuredClone(v); }
  async put(st, rec) { this.s[st].set(rec.id, structuredClone(rec)); }
  async del(st, id) { this.s[st].delete(id); }
  async clear() { this.meta.clear(); this.s.items.clear(); this.s.blobs.clear(); }
}
