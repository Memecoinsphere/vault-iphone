// Coffre-fort — primitives cryptographiques (WebCrypto uniquement, aucune dépendance).
// AES-GCM 256 avec IV aléatoire de 96 bits par chiffrement ; PBKDF2-SHA256 pour le code ;
// HKDF-SHA256 pour la sortie PRF WebAuthn.
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600000;
export const FORMAT_VERSION = 1;

export function randomBytes(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) globalThis.crypto.getRandomValues(b.subarray(i, i + 65536));
  return b;
}

export function b64(buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(str) {
  const s = atob(str);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}

// Clé de données maître : aléatoire, extractible uniquement pour pouvoir être ré-enveloppée.
export async function generateDataKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function deriveKeyFromPin(pin, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function deriveKeyFromPrf(prfOutput, salt) {
  const base = await subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('coffre-fort/prf-kek/v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Chiffrement brut : renvoie { iv, ct } (Uint8Array). aad lie le chiffré à son contexte.
export async function encryptBytes(key, data, aad = '') {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: 128 }, key, data));
  return { iv, ct };
}
export async function decryptBytes(key, box, aad = '') {
  return new Uint8Array(await subtle.decrypt(
    { name: 'AES-GCM', iv: box.iv, additionalData: enc.encode(aad), tagLength: 128 }, key, box.ct));
}
export async function encryptJSON(key, obj, aad = '') {
  return encryptBytes(key, enc.encode(JSON.stringify(obj)), aad);
}
export async function decryptJSON(key, box, aad = '') {
  return JSON.parse(dec.decode(await decryptBytes(key, box, aad)));
}

// Enveloppement de la clé maître (AES-GCM sur la clé brute) par une clé d'enveloppement (KEK).
export async function wrapDataKey(dataKey, kek, aad) {
  const raw = new Uint8Array(await subtle.exportKey('raw', dataKey));
  try { return await encryptBytes(kek, raw, aad); } finally { raw.fill(0); }
}
export async function unwrapDataKey(box, kek, aad) {
  const raw = await decryptBytes(kek, box, aad); // lève une exception si KEK incorrecte ou données altérées
  try {
    return await subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  } finally { raw.fill(0); }
}

export const AAD_PIN = 'coffre-fort/dk/pin/v1';
export const AAD_PRF = 'coffre-fort/dk/prf/v1';
export const AAD_BACKUP = 'coffre-fort/dk/backup/v1';

// Générateur de mot de passe : tirage uniforme par rejet.
export const CHARSETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!@#$%&*+-=?_.:;'
};
export function generatePassword(length = 20, opts = { lower: true, upper: true, digits: true, symbols: true }) {
  const sets = Object.keys(CHARSETS).filter(k => opts[k]).map(k => CHARSETS[k]);
  if (!sets.length) sets.push(CHARSETS.lower);
  const all = sets.join('');
  const pick = (alphabet) => {
    const lim = 256 - (256 % alphabet.length);
    for (;;) { const r = randomBytes(1)[0]; if (r < lim) return alphabet[r % alphabet.length]; }
  };
  for (;;) {
    const chars = Array.from({ length }, () => pick(all));
    // garantit au moins un caractère de chaque famille choisie
    if (length < sets.length || sets.every(s => chars.some(c => s.includes(c)))) return chars.join('');
  }
}
export function passwordEntropyBits(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return Math.round(pw.length * Math.log2(Math.max(pool, 1)));
}
