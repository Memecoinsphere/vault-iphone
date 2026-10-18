// Coffre-fort — interface. Aucune requête réseau : tout reste sur l'appareil.
import { Vault, VaultError } from './vault.js';
import { IdbStore } from './db.js';
import * as C from './crypto.js';
import * as WA from './webauthn.js';

export const APP_VERSION = '1.0.0';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const app = $('#app');
const sheetRoot = $('#sheet-root');

const store = new IdbStore();
const vault = new Vault(store);
window.__vault = undefined; // jamais exposé

const S = { items: [], tab: 'passwords', q: '', qd: '', urls: new Set(), lastAct: Date.now(), suspendUntil: 0, sheets: [], bio: false, pad: null, timers: new Set() };

const ICON = {
  lock: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.7-8.7M17 6l2.5 2.5M14.5 8.5 16.5 10.5"/></svg>',
  photo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 16-5-5-8 8"/></svg>',
  doc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  face: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2M9 9v1M15 9v1M12 9v4h-1M9 16c1.7 1.3 4.3 1.3 6 0"/></svg>',
  plus: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
};

// ---------- Utilitaires ----------
let toastT;
function toast(msg, ms = 2600) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('on');
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), ms);
}
function fmtSize(n) { if (n == null) return ''; const u = ['o', 'Ko', 'Mo', 'Go']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(1).replace('.', ',') : n) + ' ' + u[i]; }
function fmtDate(ts) { return new Date(ts).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function trackURL(blob) { const u = URL.createObjectURL(blob); S.urls.add(u); return u; }
function revokeAll() { for (const u of S.urls) URL.revokeObjectURL(u); S.urls.clear(); }
function suspendBgLock(ms = 180000) { S.suspendUntil = Date.now() + ms; }
function resumeBgLock() { S.suspendUntil = 0; S.lastAct = Date.now(); }
function later(fn, ms) { const t = setTimeout(() => { S.timers.delete(t); fn(); }, ms); S.timers.add(t); return t; }
function clearTimers() { for (const t of S.timers) clearTimeout(t); S.timers.clear(); }
const bioLabel = 'Face ID / Touch ID';

// ---------- Pavé numérique ----------
function pinPad({ onSubmit, min = 6, max = 12 }) {
  const wrap = document.createElement('div');
  wrap.className = 'padwrap';
  wrap.innerHTML = `<div class="dots" aria-label="Code saisi"></div>
    <div class="keypad">${[1, 2, 3, 4, 5, 6, 7, 8, 9].map(n => `<button data-k="${n}" aria-label="${n}">${n}</button>`).join('')}
    <button class="fn" data-k="del">Effacer</button><button data-k="0" aria-label="0">0</button><button class="fn" data-k="ok" disabled>Valider</button></div>`;
  const pad = { pin: '', busy: false, disabled: false, el: wrap };
  const dots = $('.dots', wrap), ok = $('[data-k=ok]', wrap);
  pad.render = () => {
    const n = Math.max(min, pad.pin.length);
    dots.innerHTML = Array.from({ length: n }, (_, i) => `<span class="${i < pad.pin.length ? 'on' : ''}"></span>`).join('');
    ok.disabled = pad.pin.length < min || pad.busy || pad.disabled;
  };
  pad.reset = (shake) => { pad.pin = ''; pad.render(); if (shake) { dots.classList.remove('shake'); void dots.offsetWidth; dots.classList.add('shake'); } };
  pad.press = async (k) => {
    if (pad.busy || pad.disabled) return;
    if (k === 'del') pad.pin = pad.pin.slice(0, -1);
    else if (k === 'ok') { if (pad.pin.length >= min) { const p = pad.pin; pad.busy = true; pad.render(); try { await onSubmit(p, pad); } finally { pad.busy = false; pad.render(); } } return; }
    else if (/^\d$/.test(k) && pad.pin.length < max) pad.pin += k;
    pad.render();
  };
  wrap.addEventListener('click', (e) => { const b = e.target.closest('[data-k]'); if (b) pad.press(b.dataset.k); });
  pad.render();
  S.pad = pad;
  return pad;
}
document.addEventListener('keydown', (e) => {
  const pad = S.pad; if (!pad || !pad.el.isConnected) return;
  if (e.target.matches?.('input,textarea,select')) return;
  if (/^\d$/.test(e.key)) pad.press(e.key);
  else if (e.key === 'Backspace') pad.press('del');
  else if (e.key === 'Enter') pad.press('ok');
});

// ---------- Mise en route / verrouillage ----------
async function init() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => {});
  S.bio = await WA.platformAuthenticatorAvailable();
  if (await vault.exists()) showLock(); else showSetup();
}

function authScreen(title, sub) {
  app.innerHTML = `<section class="auth"><div class="logo-big"></div><h1>${esc(title)}</h1><p class="sub">${esc(sub)}</p>
    <div class="padslot"></div><p class="msg"></p><div class="alt"></div>
    <p class="note">Chiffrement AES-256 sur l'appareil. Aucune donnée ne quitte votre iPhone.</p></section>`;
  return { slot: $('.padslot', app), msg: $('.msg', app), alt: $('.alt', app), h1: $('h1', app), sub: $('.sub', app) };
}

function showSetup() {
  closeAllSheets();
  const ui = authScreen('Créer votre coffre-fort', 'Choisissez un code de 6 à 12 chiffres. Il chiffre vos données : sans lui (ou Face ID), elles sont irrécupérables.');
  const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone;
  if (!standalone && /iPhone|iPad|iPod/.test(navigator.userAgent)) {
    ui.alt.innerHTML = '<p class="sub">Conseil : installez d\'abord l\'app (Partager › « Sur l\'écran d\'accueil »), puis créez le coffre depuis l\'icône. Safari et l\'app installée ont des stockages séparés.</p>';
  }
  let first = null;
  const pad = pinPad({
    onSubmit: async (pin, p) => {
      if (!first) {
        if (/^(\d)\1+$/.test(pin) || '0123456789012'.includes(pin) || '9876543210987'.includes(pin)) {
          ui.msg.textContent = 'Code trop simple, choisissez-en un autre.'; ui.msg.className = 'msg err'; p.reset(true); return;
        }
        first = pin; p.reset(); ui.h1.textContent = 'Confirmez le code'; ui.sub.textContent = 'Saisissez-le une seconde fois.'; ui.msg.textContent = ''; return;
      }
      if (pin !== first) { first = null; ui.h1.textContent = 'Créer votre coffre-fort'; ui.sub.textContent = 'Les codes ne correspondent pas. Recommencez.'; p.reset(true); return; }
      ui.msg.className = 'msg'; ui.msg.innerHTML = '<span class="spinner"></span>';
      await vault.create(pin);
      requestPersist();
      S.items = [];
      if (S.bio) offerBiometrics(); else enterMain();
    }
  });
  ui.slot.append(pad.el);
}

function offerBiometrics() {
  app.innerHTML = `<section class="auth"><div class="logo-big"></div><h1>Activer ${bioLabel} ?</h1>
    <p class="sub">Déverrouillez le coffre d'un regard. La biométrie libère réellement la clé de chiffrement (extension WebAuthn PRF) ; le code reste toujours utilisable.</p>
    <div class="alt"><button class="btn-ghost" id="b-yes">${ICON.face} Activer ${bioLabel}</button><button class="btn-ghost" id="b-no">Plus tard</button></div><p class="msg"></p></section>`;
  $('#b-yes').onclick = () => enableBiometrics({ onDone: enterMain, msgEl: $('.msg', app) });
  $('#b-no').onclick = enterMain;
}

let rlTimer;
function showLock(message = '') {
  closeAllSheets(); clearInterval(rlTimer);
  const ui = authScreen('Coffre-fort verrouillé', 'Saisissez votre code pour déverrouiller.');
  ui.msg.textContent = message;
  const pad = pinPad({
    onSubmit: async (pin, p) => {
      ui.msg.className = 'msg'; ui.msg.innerHTML = '<span class="spinner"></span>';
      try { await vault.unlockWithPin(pin); await enterMain(); }
      catch (e) { p.reset(true); handlePinError(e, ui.msg, pad); }
    }
  });
  ui.slot.append(pad.el);
  if (vault.cfg?.prf) {
    const b = document.createElement('button'); b.className = 'btn-ghost'; b.id = 'bio-unlock';
    b.innerHTML = `${ICON.face} ${bioLabel}`; b.setAttribute('aria-label', `Déverrouiller avec ${bioLabel}`);
    b.onclick = async () => {
      ui.msg.className = 'msg'; ui.msg.textContent = '';
      try { await biometricUnlock(); await enterMain(); }
      catch (e) { if (e.code === 'WIPED') { wiped(); return; } bioError(e, ui.msg, pad); }
    };
    ui.alt.append(b);
    if (vault.cfg.settings.wipeAfter) ui.alt.insertAdjacentHTML('beforeend', `<p class="sub small-warn">Effacement après ${vault.cfg.settings.wipeAfter} échecs actif : annuler Face ID compte aussi comme un échec.</p>`);
  }
  rateLimitUI(ui.msg, pad);
}

function rateLimitUI(msgEl, pad) {
  clearInterval(rlTimer);
  const tick = () => {
    const st = vault.lockStatus();
    if (st.waitMs > 0) { pad.disabled = true; msgEl.className = 'msg err'; msgEl.textContent = `Trop d'essais. Réessayez dans ${Math.ceil(st.waitMs / 1000)} s.`; }
    else { if (pad.disabled) { pad.disabled = false; msgEl.textContent = ''; } clearInterval(rlTimer); }
    pad.render();
  };
  tick(); if (pad.disabled) rlTimer = setInterval(tick, 1000);
}

function handlePinError(e, msgEl, pad) {
  msgEl.className = 'msg err';
  if (e.code === 'WIPED') { wiped(); return; }
  if (e.code === 'BAD_PIN') {
    msgEl.textContent = 'Code incorrect.' + (e.remaining != null ? ` ${e.remaining} essai(s) avant effacement.` : '');
    if (e.waitMs > 0) rateLimitUI(msgEl, pad);
  } else if (e.code === 'RATE_LIMIT') rateLimitUI(msgEl, pad);
  else msgEl.textContent = 'Erreur : ' + (e.message || e);
}

// Déverrouillage Face ID : uniquement sur appui du bouton (jamais lancé automatiquement).
async function biometricUnlock() {
  await vault.beginBiometricAttempt(); // compte l'essai avant l'invite si l'effacement est activé
  let out;
  try { out = await WA.evaluatePrf(vault.cfg.prf.credentialId, vault.cfg.prf.prfSalt); }
  catch (e) { const r = await vault.biometricFailed(); throw Object.assign(e, { bio: r }); }
  try { await vault.unlockWithPrf(out); }
  catch (e) { const r = await vault.biometricFailed(); throw Object.assign(e, { bio: r }); }
}
function bioError(e, msgEl, pad) {
  msgEl.className = 'msg err';
  if (e.code === 'RATE_LIMIT') { rateLimitUI(msgEl, pad); return; }
  const base = e.code === 'BAD_PRF' ? 'Clé biométrique invalide.' : e.name === 'NotAllowedError' ? 'Face ID non reconnu ou annulé.' : 'Biométrie indisponible.';
  const r = e.bio;
  msgEl.textContent = base + (r?.counted ? ` Compté comme un échec : ${r.remaining} essai(s) avant effacement.` : ' Utilisez le code.');
  if (r?.waitMs > 0) rateLimitUI(msgEl, pad);
}

// Effacement immédiat (sans dialogue ni délai) : retour direct à l'écran de création.
function wiped() {
  clearInterval(rlTimer); clearTimers(); revokeAll(); closeAllSheets(); S.items = [];
  showSetup();
  const m = $('.msg', app); if (m) { m.className = 'msg err'; m.textContent = "Trop d'échecs consécutifs (code ou Face ID) : le coffre a été effacé."; }
}

function lockNow(msg) {
  if (!vault.unlocked) return;
  vault.lock(); S.items = []; S.q = ''; S.qd = ''; clearTimers(); revokeAll(); closeAllSheets();
  app.innerHTML = ''; $('#toast').classList.remove('on');
  showLock(msg);
}

// Verrouillage automatique : inactivité + passage en arrière-plan.
['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(ev => addEventListener(ev, () => { S.lastAct = Date.now(); }, { passive: true, capture: true }));
setInterval(() => {
  if (!vault.unlocked || Date.now() < S.suspendUntil) return;
  const lim = (vault.cfg?.settings.autoLockMin ?? 2) * 60000;
  if (Date.now() - S.lastAct > lim) lockNow('Verrouillé après inactivité.');
}, 2000);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && Date.now() >= S.suspendUntil) lockNow();
});
addEventListener('pagehide', () => lockNow());

async function requestPersist() {
  try { if (navigator.storage?.persist && !(await navigator.storage.persisted())) return await navigator.storage.persist(); return true; } catch { return false; }
}

// ---------- Feuilles ----------
function openSheet({ title, left = { label: 'Fermer' }, right, body, full = false, cls = '' }) {
  const bd = document.createElement('div'); bd.className = 'backdrop';
  bd.innerHTML = `<div class="sheet ${full ? 'full' : ''} ${cls}" role="dialog" aria-label="${esc(title)}"><div class="sh-h">
    <button class="l">${esc(left?.label || '')}</button><h2>${esc(title)}</h2><button class="r">${esc(right?.label || '')}</button></div><div class="sh-b"></div></div>`;
  const b = $('.sh-b', bd);
  if (typeof body === 'string') b.innerHTML = body; else if (body) b.append(body);
  const sh = { el: bd, body: b, close: () => { bd.remove(); S.sheets = S.sheets.filter(x => x !== sh); sh.onclose?.(); } };
  $('.l', bd).onclick = () => (left?.fn ? left.fn(sh) : sh.close());
  const rb = $('.r', bd); if (right) rb.onclick = () => right.fn(sh); else rb.disabled = true;
  bd.addEventListener('click', (e) => { if (e.target === bd && !full) sh.close(); });
  sheetRoot.append(bd); S.sheets.push(sh);
  return sh;
}
function closeAllSheets() { [...S.sheets].forEach(s => s.close()); sheetRoot.innerHTML = ''; }

// Ré-authentification (export, changement de code, effacement…)
function reauth(reason) {
  return new Promise((resolve) => {
    const body = document.createElement('div');
    body.innerHTML = `<div class="auth"><p class="sub">${esc(reason)}</p><div class="padslot"></div><p class="msg"></p><div class="alt"></div></div>`;
    const sh = openSheet({ title: 'Confirmez votre identité', body, cls: 'reauth', left: { label: 'Annuler', fn: (s) => { s.close(); resolve(false); } } });
    const msg = $('.msg', body);
    const prev = S.pad;
    const pad = pinPad({
      onSubmit: async (pin, p) => {
        msg.className = 'msg'; msg.innerHTML = '<span class="spinner"></span>';
        try { await vault.checkPin(pin); sh.close(); S.pad = prev; resolve(true); }
        catch (e) { p.reset(true); if (e.code === 'WIPED') { wiped(); return; } handlePinError(e, msg, pad); }
      }
    });
    $('.padslot', body).append(pad.el);
    rateLimitUI(msg, pad);
    if (vault.cfg.prf) {
      const b = document.createElement('button'); b.className = 'btn-ghost'; b.innerHTML = `${ICON.face} Utiliser ${bioLabel}`;
      b.onclick = async () => {
        msg.className = 'msg'; msg.textContent = '';
        try { suspendBgLock(60000); await biometricUnlock(); resumeBgLock(); sh.close(); S.pad = prev; resolve(true); }
        catch (e) { resumeBgLock(); if (e.code === 'WIPED') { wiped(); resolve(false); return; } bioError(e, msg, pad); }
      };
      $('.alt', body).append(b);
    }
  });
}

// ---------- Application principale ----------
async function enterMain() {
  clearInterval(rlTimer);
  S.items = await vault.listItems();
  S.lastAct = Date.now();
  S.pad = null;
  app.innerHTML = `<div class="main"><header class="top"><h1 id="ttl"></h1><button class="ic" id="lockbtn" aria-label="Verrouiller">${ICON.lock}</button></header>
    <div class="content" id="content"></div>
    <nav class="tabs">
      <button data-tab="passwords">${ICON.key}<span>Mots de passe</span></button>
      <button data-tab="photos">${ICON.photo}<span>Photos</span></button>
      <button data-tab="documents">${ICON.doc}<span>Documents</span></button>
      <button data-tab="settings">${ICON.gear}<span>Réglages</span></button></nav></div>`;
  $('#lockbtn').onclick = () => lockNow();
  $$('nav.tabs button').forEach(b => b.onclick = () => { S.tab = b.dataset.tab; renderTab(); });
  renderTab();
  if (vault.cfg.settings.lastBackup == null && S.items.length >= 3) toast('Pensez à exporter une sauvegarde chiffrée (Réglages).', 3500);
}

function renderTab() {
  $$('nav.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === S.tab));
  const titles = { passwords: 'Mots de passe', photos: 'Photos', documents: 'Documents', settings: 'Réglages' };
  $('#ttl').textContent = titles[S.tab];
  revokeAll();
  ({ passwords: renderPasswords, photos: renderPhotos, documents: renderDocuments, settings: renderSettings })[S.tab]();
}

// ----- Mots de passe -----
function renderPasswords() {
  const c = $('#content');
  c.innerHTML = `<div class="toolbar"><input class="search" id="q" type="search" placeholder="Rechercher" value="${esc(S.q)}" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
    <button class="btn" id="addpw" aria-label="Ajouter">${ICON.plus}</button></div><div id="pwlist"></div>`;
  const draw = () => {
    const q = S.q.trim().toLowerCase();
    const list = S.items.filter(i => i.type === 'password').filter(i => !q || [i.title, i.username, i.url, i.notes].some(v => (v || '').toLowerCase().includes(q)))
      .sort((a, b) => (a.title || '').localeCompare(b.title || '', 'fr'));
    $('#pwlist').innerHTML = list.length ? `<div class="list">${list.map(i => `<button class="row" data-id="${esc(i.id)}"><div class="av">${esc((i.title || '?').trim().charAt(0).toUpperCase())}</div>
      <div class="tx"><div class="t1">${esc(i.title)}</div><div class="t2">${esc(i.username || i.url || '—')}</div></div><span class="chev">›</span></button>`).join('')}</div>`
      : `<div class="empty"><b>${q ? 'Aucun résultat' : 'Aucun mot de passe'}</b>${q ? '' : 'Touchez + pour enregistrer votre premier identifiant.'}</div>`;
    $$('#pwlist .row').forEach(r => r.onclick = () => showPassword(S.items.find(i => i.id === r.dataset.id)));
  };
  $('#q').oninput = (e) => { S.q = e.target.value; draw(); };
  $('#addpw').onclick = () => editPassword();
  draw();
}

let clipT;
async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    const sec = vault.cfg.settings.clipboardSec ?? 30;
    toast(`${label} copié. Effacement du presse-papiers dans ${sec} s (si l'app reste ouverte).`, 3000);
    clearTimeout(clipT);
    clipT = setTimeout(async () => { try { await navigator.clipboard.writeText(''); } catch {} }, sec * 1000);
  } catch { toast('Copie impossible sur ce navigateur.'); }
}

function showPassword(it) {
  if (!it) return;
  const body = document.createElement('div'); body.className = 'detail';
  const f = (lab, val, opts = {}) => val ? `<div class="field"><label>${lab}</label><div class="in"><div class="val ${opts.mono ? 'mono' : ''} ${opts.cls || ''}" ${opts.id ? `id="${opts.id}"` : ''}>${opts.html ?? esc(val)}</div>${opts.btns || ''}</div></div>` : '';
  const safeUrl = /^https?:\/\//i.test(it.url || '') ? it.url : (it.url && !/^[a-z]+:/i.test(it.url) ? 'https://' + it.url : null);
  body.innerHTML = f('Identifiant', it.username, { btns: '<button class="mini" data-c="u">Copier</button>' })
    + f('Mot de passe', it.password, { mono: true, id: 'pwv', html: '••••••••••••', btns: '<button class="mini" data-c="show">Afficher</button><button class="mini" data-c="p">Copier</button>' })
    + f('Site web', it.url, { html: safeUrl ? `<a href="${esc(safeUrl)}" target="_blank" rel="noopener noreferrer">${esc(it.url)}</a>` : esc(it.url) })
    + f('Notes', it.notes, { cls: 'notes' })
    + `<p class="meta">Ajouté le ${fmtDate(it.ts)}${it.updated ? ' · modifié le ' + fmtDate(it.updated) : ''}</p>
      <div class="actions"><button class="btn danger" id="del">Supprimer</button></div>`;
  const sh = openSheet({ title: it.title, body, right: { label: 'Modifier', fn: (s) => { s.close(); editPassword(it); } } });
  body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-c]'); if (!b) return;
    if (b.dataset.c === 'u') copy(it.username, 'Identifiant');
    if (b.dataset.c === 'p') copy(it.password, 'Mot de passe');
    if (b.dataset.c === 'show') { const v = $('#pwv', body); const shown = b.textContent === 'Masquer'; v.textContent = shown ? '••••••••••••' : it.password; b.textContent = shown ? 'Afficher' : 'Masquer'; }
  });
  $('#del', body).onclick = async () => {
    if (!confirm(`Supprimer « ${it.title} » ?`)) return;
    await vault.deleteItem(it.id); S.items = S.items.filter(i => i.id !== it.id); sh.close(); renderTab(); toast('Supprimé.');
  };
}

function editPassword(it = null) {
  const body = document.createElement('form'); body.autocomplete = 'off';
  body.innerHTML = `
    <div class="field"><label>Titre *</label><input name="title" required maxlength="200" value="${esc(it?.title)}" placeholder="ex. Banque, Messagerie…"></div>
    <div class="field"><label>Identifiant</label><input name="username" autocapitalize="off" autocorrect="off" spellcheck="false" value="${esc(it?.username)}" placeholder="adresse e-mail ou nom d'utilisateur"></div>
    <div class="field"><label>Mot de passe</label><div class="in"><input name="password" type="password" autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="new-password" value="${esc(it?.password)}">
      <button type="button" class="mini" id="tg">Afficher</button><button type="button" class="mini" id="gen">Générer</button></div>
      <div class="meter"><i></i></div><small class="strength"></small></div>
    <div class="gen hidden" id="genp">
      <div class="r"><span>Longueur <b id="lenv">20</b></span><input type="range" id="len" min="8" max="64" value="20"></div>
      <div class="chk"><label><input type="checkbox" id="g-lower" checked>a-z</label><label><input type="checkbox" id="g-upper" checked>A-Z</label><label><input type="checkbox" id="g-digits" checked>0-9</label><label><input type="checkbox" id="g-symbols" checked>!@#</label></div>
      <div class="r"><button type="button" class="btn sec block" id="regen">Nouveau mot de passe</button></div></div>
    <div class="field"><label>Site web (URL)</label><input name="url" type="url" inputmode="url" autocapitalize="off" autocorrect="off" value="${esc(it?.url)}" placeholder="https://"></div>
    <div class="field"><label>Notes</label><textarea name="notes">${esc(it?.notes)}</textarea></div>`;
  const pw = body.elements.password;
  const meter = () => {
    const bits = pw.value ? C.passwordEntropyBits(pw.value) : 0;
    const pct = Math.min(100, bits / 1.28), i = $('.meter i', body);
    i.style.width = pct + '%'; i.style.background = bits < 50 ? 'var(--danger)' : bits < 80 ? '#d68c1e' : 'var(--ok)';
    $('.strength', body).textContent = pw.value ? (bits < 50 ? 'Faible' : bits < 80 ? 'Correct' : 'Robuste') + ` (~${bits} bits)` : '';
  };
  const gen = () => {
    const opts = { lower: $('#g-lower', body).checked, upper: $('#g-upper', body).checked, digits: $('#g-digits', body).checked, symbols: $('#g-symbols', body).checked };
    pw.value = C.generatePassword(+$('#len', body).value, opts); pw.type = 'text'; $('#tg', body).textContent = 'Masquer'; meter();
  };
  $('#tg', body).onclick = () => { const t = pw.type === 'password'; pw.type = t ? 'text' : 'password'; $('#tg', body).textContent = t ? 'Masquer' : 'Afficher'; };
  $('#gen', body).onclick = () => { $('#genp', body).classList.remove('hidden'); gen(); };
  $('#regen', body).onclick = gen;
  $('#len', body).oninput = (e) => { $('#lenv', body).textContent = e.target.value; gen(); };
  $$('.chk input', body).forEach(x => x.onchange = gen);
  pw.oninput = meter; meter();
  const save = async (sh) => {
    const d = Object.fromEntries(['title', 'username', 'password', 'url', 'notes'].map(k => [k, body.elements[k].value.trim() === '' ? '' : (k === 'password' ? body.elements[k].value : body.elements[k].value.trim())]));
    if (!d.title) { body.elements.title.focus(); toast('Le titre est obligatoire.'); return; }
    if (it) {
      const meta = { ...it, ...d, type: 'password', updated: Date.now() }; delete meta.id; delete meta.ts;
      await vault.updateItem(it.id, meta); Object.assign(it, d, { updated: meta.updated });
    } else {
      S.items.unshift(await vault.addItem({ type: 'password', ...d }));
    }
    sh.close(); renderTab(); toast('Enregistré et chiffré.');
  };
  body.onsubmit = (e) => { e.preventDefault(); save(sh); };
  const sh = openSheet({ title: it ? 'Modifier' : 'Nouveau mot de passe', body, full: true, left: { label: 'Annuler' }, right: { label: 'Enregistrer', fn: save } });
  if (!it) setTimeout(() => body.elements.title.focus(), 250);
}

// ----- Fichiers (photos / documents) -----
function pickFiles({ accept = '', capture = null, multiple = true }) {
  return new Promise((resolve) => {
    const inp = document.createElement('input'); inp.type = 'file'; inp.className = 'fileinput';
    if (accept) inp.accept = accept; if (capture) inp.setAttribute('capture', capture); if (multiple) inp.multiple = true;
    document.body.append(inp);
    suspendBgLock();
    const done = (files) => { inp.remove(); resumeBgLock(); resolve(files); };
    inp.addEventListener('change', () => done([...inp.files]), { once: true });
    inp.addEventListener('cancel', () => done([]), { once: true });
    inp.click();
  });
}

async function makeThumb(blob) {
  try {
    let src, w, h;
    try { src = await createImageBitmap(blob); w = src.width; h = src.height; }
    catch {
      src = await new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = rej; im.src = URL.createObjectURL(blob); });
      w = src.naturalWidth; h = src.naturalHeight; URL.revokeObjectURL(src.src);
    }
    const max = 360, r = Math.min(1, max / Math.max(w, h));
    const cv = document.createElement('canvas'); cv.width = Math.round(w * r); cv.height = Math.round(h * r);
    cv.getContext('2d').drawImage(src, 0, 0, cv.width, cv.height);
    src.close?.();
    return { thumb: cv.toDataURL('image/jpeg', 0.78), width: w, height: h };
  } catch { return {}; }
}

const MAX_FILE = 250 * 1024 * 1024;
async function importFiles(files, kind) {
  if (!files.length) return;
  let n = 0;
  for (const f of files) {
    if (f.size > MAX_FILE) { toast(`« ${f.name} » dépasse 250 Mo, ignoré.`); continue; }
    toast(`Chiffrement ${n + 1}/${files.length}…`, 60000);
    const bytes = new Uint8Array(await f.arrayBuffer());
    const isImg = (f.type || '').startsWith('image/');
    let name = f.name || 'fichier';
    if (kind === 'photo' && /^image\.(jpe?g|heic|png)$/i.test(name)) name = 'Photo du ' + fmtDate(Date.now()).replace(/[/:]/g, '-') + '.' + name.split('.').pop();
    const meta = { type: kind, name, mime: f.type || guessMime(name), lastModified: f.lastModified || Date.now(), ...(isImg ? await makeThumb(f) : {}) };
    S.items.unshift(await vault.addItem(meta, bytes));
    bytes.fill(0); n++;
  }
  renderTab();
  toast(`${n} élément(s) ajouté(s) et chiffré(s).`);
}
function guessMime(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return ({ pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', heic: 'image/heic', gif: 'image/gif', webp: 'image/webp', txt: 'text/plain', csv: 'text/csv', json: 'application/json', md: 'text/markdown', mp4: 'video/mp4', mov: 'video/quicktime', mp3: 'audio/mpeg', m4a: 'audio/mp4' })[ext] || 'application/octet-stream';
}

function renderPhotos() {
  const c = $('#content');
  const photos = S.items.filter(i => i.type === 'photo');
  c.innerHTML = `<div class="toolbar"><button class="btn block" id="lib">${ICON.photo} Photothèque</button><button class="btn sec block" id="cam">Appareil photo</button></div>
    ${photos.length ? `<div class="grid">${photos.map(p => `<button data-id="${esc(p.id)}" aria-label="${esc(p.name)}">${p.thumb ? `<img alt="" src="${esc(p.thumb)}">` : ''}</button>`).join('')}</div>`
      : '<div class="empty"><b>Aucune photo</b>Importez depuis la photothèque ou prenez une photo : elle est chiffrée sur l\'appareil. Pensez ensuite à la supprimer de la pellicule si nécessaire.</div>'}`;
  $('#lib').onclick = async () => importFiles(await pickFiles({ accept: 'image/*' }), 'photo');
  $('#cam').onclick = async () => importFiles(await pickFiles({ accept: 'image/*', capture: 'environment', multiple: false }), 'photo');
  $$('.grid button', c).forEach(b => b.onclick = () => viewFile(S.items.find(i => i.id === b.dataset.id)));
}

function renderDocuments() {
  const c = $('#content');
  c.innerHTML = `<div class="toolbar"><input class="search" id="qd" type="search" placeholder="Rechercher un document" value="${esc(S.qd)}" autocomplete="off">
    <button class="btn" id="adddoc" aria-label="Importer">${ICON.plus}</button></div><div id="doclist"></div>`;
  const draw = () => {
    const q = S.qd.trim().toLowerCase();
    const docs = S.items.filter(i => i.type === 'document' && (!q || i.name.toLowerCase().includes(q)));
    $('#doclist').innerHTML = docs.length ? `<div class="list">${docs.map(d => `<button class="row" data-id="${esc(d.id)}"><div class="av doc">${esc((d.name.split('.').pop() || 'FIC').slice(0, 4).toUpperCase())}</div>
      <div class="tx"><div class="t1">${esc(d.name)}</div><div class="t2">${fmtSize(d.size)} · ${fmtDate(d.ts)}</div></div><span class="chev">›</span></button>`).join('')}</div>`
      : `<div class="empty"><b>${q ? 'Aucun résultat' : 'Aucun document'}</b>${q ? '' : 'Touchez + pour importer un PDF ou tout autre fichier depuis Fichiers.'}</div>`;
    $$('#doclist .row').forEach(r => r.onclick = () => viewFile(S.items.find(i => i.id === r.dataset.id)));
  };
  $('#qd').oninput = (e) => { S.qd = e.target.value; draw(); };
  $('#adddoc').onclick = async () => importFiles(await pickFiles({}), 'document');
  draw();
}

async function viewFile(it) {
  if (!it) return;
  const body = document.createElement('div'); body.className = 'viewer';
  body.innerHTML = '<div class="meta">Déchiffrement…</div>';
  const sh = openSheet({ title: it.name, body, full: true });
  sh.onclose = () => { for (const u of sh.urls || []) { URL.revokeObjectURL(u); S.urls.delete(u); } };
  let bytes;
  try { bytes = await vault.getBlob(it.id); } catch { body.innerHTML = '<div class="meta">Impossible de déchiffrer ce fichier (données altérées ?).</div>'; return; }
  const mime = it.mime || guessMime(it.name);
  const blob = new Blob([bytes], { type: mime });
  const url = trackURL(blob); sh.urls = [url];
  body.innerHTML = '';
  const isPdf = mime === 'application/pdf' || /\.pdf$/i.test(it.name);
  if (mime.startsWith('image/')) { const im = new Image(); im.alt = it.name; im.src = url; body.append(im); }
  else if (isPdf) await renderPdf(bytes, body, url);
  else if (mime.startsWith('video/')) { const v = document.createElement('video'); v.src = url; v.controls = true; v.playsInline = true; v.style.width = '100%'; body.append(v); }
  else if (mime.startsWith('audio/')) { const a = document.createElement('audio'); a.src = url; a.controls = true; a.style.width = '100%'; body.append(a); }
  else if ((mime.startsWith('text/') || /json|xml/.test(mime)) && bytes.length < 2e6) { const pre = document.createElement('pre'); pre.textContent = new TextDecoder().decode(bytes); body.append(pre); }
  else body.insertAdjacentHTML('beforeend', '<div class="empty"><b>Aperçu indisponible</b>Ce type de fichier ne peut pas être affiché dans le coffre. Utilisez « Exporter ».</div>');
  body.insertAdjacentHTML('beforeend', `<p class="meta">${esc(fmtSize(it.size))} · ajouté le ${fmtDate(it.ts)}</p>
    <div class="actions"><button class="btn sec" id="exp">Exporter (déchiffré)</button><button class="btn danger" id="del">Supprimer</button></div>`);
  $('#exp', body).onclick = () => exportPlain(blob, it.name);
  $('#del', body).onclick = async () => {
    if (!confirm(`Supprimer définitivement « ${it.name} » du coffre ?`)) return;
    await vault.deleteItem(it.id); S.items = S.items.filter(i => i.id !== it.id); sh.close(); renderTab(); toast('Supprimé.');
  };
}

let pdfjs;
async function renderPdf(bytes, body, url) {
  const box = document.createElement('div'); box.className = 'pages'; body.append(box);
  try {
    if (!pdfjs) { pdfjs = await import('./vendor/pdfjs/pdf.min.mjs'); pdfjs.GlobalWorkerOptions.workerSrc = new URL('./vendor/pdfjs/pdf.worker.min.mjs', import.meta.url).href; }
    const doc = await pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, enableXfa: false, disableAutoFetch: true }).promise;
    const width = Math.min(box.clientWidth || 360, 900), dpr = Math.min(devicePixelRatio || 1, 2);
    const N = Math.min(doc.numPages, 60);
    const info = document.createElement('p'); info.className = 'meta'; info.textContent = `${doc.numPages} page(s)`; body.insertBefore(info, box);
    for (let p = 1; p <= N; p++) {
      if (!box.isConnected) break;
      const page = await doc.getPage(p);
      const vp0 = page.getViewport({ scale: 1 }), vp = page.getViewport({ scale: width / vp0.width * dpr });
      const cv = document.createElement('canvas'); cv.width = vp.width; cv.height = vp.height; box.append(cv);
      await page.render({ canvasContext: cv.getContext('2d'), viewport: vp }).promise;
    }
    if (doc.numPages > N) box.insertAdjacentHTML('beforeend', `<p class="meta">Aperçu limité aux ${N} premières pages.</p>`);
    doc.destroy();
  } catch (e) {
    box.innerHTML = '';
    const fr = document.createElement('iframe'); fr.src = url; fr.title = 'Aperçu PDF'; box.append(fr);
  }
}

async function exportPlain(blob, name) {
  if (!confirm('Le fichier exporté ne sera plus chiffré. Continuer ?')) return;
  await shareOrDownload(new File([blob], name, { type: blob.type }));
}
async function shareOrDownload(file) {
  suspendBgLock(300000);
  try {
    if (navigator.canShare?.({ files: [file] })) { await navigator.share({ files: [file], title: file.name }); return; }
  } catch (e) { if (e.name === 'AbortError') return; }
  finally { resumeBgLock(); }
  const a = document.createElement('a'); a.href = URL.createObjectURL(file); a.download = file.name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 60000);
}

// ----- Réglages -----
async function renderSettings() {
  const c = $('#content'), st = vault.cfg.settings;
  const opt = (vals, cur) => vals.map(([v, l]) => `<option value="${v}" ${String(v) === String(cur) ? 'selected' : ''}>${l}</option>`).join('');
  const lb = st.lastBackup;
  c.innerHTML = `
    <div class="section-t">Sécurité</div><div class="list">
      <label class="set"><span class="lb">${bioLabel}<small id="bio-sub">${S.bio ? (vault.cfg.prf ? 'Activé — la biométrie déchiffre la clé (PRF)' : 'Désactivé') : 'Non disponible sur cet appareil/navigateur'}</small></span>
        <span class="switch"><input type="checkbox" id="bio" ${vault.cfg.prf ? 'checked' : ''} ${S.bio || vault.cfg.prf ? '' : 'disabled'}><span></span></span></label>
      <button class="set" id="chpin"><span class="lb">Changer le code</span><span class="chev">›</span></button>
      <div class="set"><span class="lb">Verrouillage automatique<small>Et immédiatement en arrière-plan</small></span><select id="al">${opt([[0.5, '30 s'], [1, '1 min'], [2, '2 min'], [5, '5 min'], [10, '10 min']], st.autoLockMin)}</select></div>
      <div class="set"><span class="lb">Effacer après échecs<small>Efface tout après N échecs consécutifs : code erroné ou Face ID non abouti. Attention : annuler Face ID compte aussi comme un échec.</small></span><select id="wa">${opt([[0, 'Désactivé'], [2, '2 essais'], [5, '5 essais'], [10, '10 essais'], [20, '20 essais']], st.wipeAfter)}</select></div>
      <div class="set"><span class="lb">Effacer le presse-papiers</span><select id="cb">${opt([[15, '15 s'], [30, '30 s'], [60, '60 s'], [120, '2 min']], st.clipboardSec ?? 30)}</select></div>
    </div>
    <div class="section-t">Sauvegarde</div><div class="list">
      <button class="set" id="exp"><span class="lb">Exporter une sauvegarde chiffrée<small>${lb ? 'Dernière : ' + fmtDate(lb) : 'Aucune sauvegarde pour l\'instant'}</small></span>${!lb || Date.now() - lb > 30 * 864e5 ? '<span class="badge warn">Conseillé</span>' : '<span class="badge ok">À jour</span>'}</button>
      <button class="set" id="imp"><span class="lb">Importer une sauvegarde<small>Fusionne avec le contenu actuel</small></span><span class="chev">›</span></button>
    </div>
    <p class="info">Enregistrez le fichier dans Fichiers (iCloud Drive ou clé USB) ou sur un ordinateur. Il est chiffré par un mot de passe de sauvegarde distinct : sans lui, il est illisible.</p>
    <div class="section-t">Stockage sur l'appareil</div><div class="list">
      <div class="set"><span class="lb">Contenu<small>${S.items.filter(i => i.type === 'password').length} mot(s) de passe · ${S.items.filter(i => i.type === 'photo').length} photo(s) · ${S.items.filter(i => i.type === 'document').length} document(s)</small></span></div>
      <div class="set"><span class="lb">Espace utilisé<small id="usage">…</small></span></div>
      <button class="set" id="persist"><span class="lb">Stockage persistant<small id="pers-sub">…</small></span><span class="badge" id="pers">…</span></button>
      <div class="set"><span class="lb">Mode<small>${matchMedia('(display-mode: standalone)').matches || navigator.standalone ? 'Application installée sur l\'écran d\'accueil' : 'Navigateur — installez l\'app sur l\'écran d\'accueil pour protéger vos données de l\'effacement automatique de Safari'}</small></span></div>
    </div>
    <div class="section-t">Zone sensible</div><div class="list"><button class="set red" id="wipe"><span class="lb">Effacer tout le coffre</span></button></div>
    <p class="info">Coffre-fort v${APP_VERSION} · chiffrement AES-GCM 256, clé maître aléatoire enveloppée par PBKDF2-SHA256 (${vault.cfg.kdf.iterations.toLocaleString('fr-FR')} itérations) et par WebAuthn PRF. Aucune donnée n'est envoyée sur Internet : pas de compte, pas d'analyse, pas de serveur.</p>`;
  $('#al').onchange = (e) => vault.setSettings({ autoLockMin: +e.target.value });
  $('#cb').onchange = (e) => vault.setSettings({ clipboardSec: +e.target.value });
  $('#wa').onchange = async (e) => {
    const v = +e.target.value;
    if (v && !confirm(`Après ${v} échecs consécutifs, TOUT le coffre sera effacé immédiatement et définitivement, sans délai ni confirmation.\n\nUn échec = un code erroné OU une tentative Face ID qui n'aboutit pas. Attention : annuler Face ID (ou fermer l'invite) compte aussi comme un échec.${v === 2 ? '\n\nMode 2 essais : un code faux puis un Face ID annulé suffisent à tout effacer.' : ''}\n\nActiver ?`)) { e.target.value = st.wipeAfter; return; }
    await vault.setSettings({ wipeAfter: v }); toast(v ? 'Effacement automatique activé.' : 'Effacement automatique désactivé.');
  };
  $('#bio').onchange = async (e) => {
    if (e.target.checked) {
      e.target.checked = false;
      enableBiometrics({ onDone: () => renderTab(), msgEl: $('#bio-sub') });
    } else {
      if (!confirm(`Désactiver ${bioLabel} ? Seul le code permettra d'ouvrir le coffre.`)) { e.target.checked = true; return; }
      await vault.disablePrf(); renderTab(); toast(`${bioLabel} désactivé. Vous pouvez supprimer la clé d'accès « Coffre-fort » dans Réglages › Mots de passe.`, 5000);
    }
  };
  $('#chpin').onclick = changePin;
  $('#exp').onclick = exportBackup;
  $('#imp').onclick = importBackup;
  $('#wipe').onclick = async () => {
    if (!confirm('Effacer définitivement TOUT le contenu du coffre ? Cette action est irréversible.')) return;
    if (!(await reauth('Saisissez votre code pour effacer le coffre.'))) return;
    await vault.wipe(); location.reload();
  };
  $('#persist').onclick = async () => { const ok = await requestPersist(); toast(ok ? 'Stockage persistant accordé.' : 'Safari n\'a pas accordé la persistance (installez l\'app sur l\'écran d\'accueil).', 4000); refreshStorage(); };
  refreshStorage();
}
async function refreshStorage() {
  try { const e = await navigator.storage.estimate(); $('#usage') && ($('#usage').textContent = `${fmtSize(e.usage)} (quota estimé ${fmtSize(e.quota)})`); } catch { $('#usage') && ($('#usage').textContent = 'Inconnu'); }
  let p = false; try { p = await navigator.storage.persisted(); } catch {}
  const b = $('#pers'); if (!b) return;
  b.textContent = p ? 'Accordé' : 'Non accordé'; b.className = 'badge ' + (p ? 'ok' : 'warn');
  $('#pers-sub').textContent = p ? 'Safari ne doit pas effacer ces données automatiquement' : 'Touchez pour demander la persistance';
}

async function enableBiometrics({ onDone, msgEl }) {
  const setMsg = (t, err) => { if (msgEl) { msgEl.textContent = t; msgEl.classList?.toggle('err', !!err); } };
  suspendBgLock(120000);
  try {
    const reg = await WA.registerPasskey();
    let out = reg.prfOutput;
    if (!out) {
      // iOS ne renvoie parfois la sortie PRF qu'à l'authentification : une seconde validation est requise.
      resumeBgLock();
      out = await new Promise((resolve, reject) => {
        const body = document.createElement('div');
        body.innerHTML = `<p class="info">Clé d'accès créée. Confirmez une dernière fois avec ${bioLabel} pour lier la biométrie au chiffrement.</p><button class="btn block" id="cf">${ICON.face} Confirmer</button>`;
        const sh = openSheet({ title: bioLabel, body, left: { label: 'Annuler', fn: (s) => { s.close(); reject(new Error('cancel')); } } });
        $('#cf', body).onclick = async () => { suspendBgLock(60000); try { const o = await WA.evaluatePrf(reg.credentialId, reg.prfSalt); sh.close(); resolve(o); } catch (e) { sh.close(); reject(e); } finally { resumeBgLock(); } };
      });
    }
    await vault.enablePrf({ credentialId: reg.credentialId, prfSalt: reg.prfSalt, prfOutput: out });
    toast(`${bioLabel} activé.`);
    onDone?.();
  } catch (e) {
    if (e instanceof WA.PrfUnsupported) { setMsg('Extension PRF non prise en charge (iOS 18 ou plus récent requis). Le code reste votre clé.', true); alert('Ce navigateur ne prend pas en charge WebAuthn PRF : la biométrie ne peut pas déchiffrer le coffre ici. Le déverrouillage par code reste actif. (iOS 18 / Safari 18 minimum.)'); }
    else if (e?.name === 'NotAllowedError' || e?.message === 'cancel') setMsg('Activation annulée.', true);
    else setMsg('Échec : ' + (e?.message || e), true);
    if (!vault.cfg?.prf && onDone && app.querySelector('#b-yes')) { /* reste sur l'écran d'offre */ }
  } finally { resumeBgLock(); }
}

async function changePin() {
  if (!(await reauth('Saisissez votre code actuel.'))) return;
  const body = document.createElement('div');
  body.innerHTML = '<div class="auth"><p class="sub">Nouveau code (6 à 12 chiffres)</p><div class="padslot"></div><p class="msg"></p></div>';
  const sh = openSheet({ title: 'Nouveau code', body, cls: 'reauth', left: { label: 'Annuler' } });
  let first = null;
  const pad = pinPad({
    onSubmit: async (pin, p) => {
      const sub = $('.sub', body);
      if (!first) { first = pin; p.reset(); sub.textContent = 'Confirmez le nouveau code'; return; }
      if (pin !== first) { first = null; sub.textContent = 'Différent — recommencez (6 à 12 chiffres)'; p.reset(true); return; }
      $('.msg', body).innerHTML = '<span class="spinner"></span>';
      await vault.changePin(pin); sh.close(); toast('Code modifié.');
    }
  });
  $('.padslot', body).append(pad.el);
}

async function exportBackup() {
  if (!(await reauth('Confirmez pour exporter une sauvegarde chiffrée.'))) return;
  const body = document.createElement('form');
  body.innerHTML = `<p class="info">Choisissez un <b>mot de passe de sauvegarde</b> (10 caractères minimum, idéalement une phrase). Il sera demandé pour restaurer. Notez-le en lieu sûr : sans lui, la sauvegarde est inutilisable.</p>
    <div class="field"><label>Mot de passe de sauvegarde</label><input type="password" name="p1" autocomplete="new-password" minlength="10"></div>
    <div class="field"><label>Confirmation</label><input type="password" name="p2" autocomplete="new-password"></div><p class="msg info"></p>`;
  const go = async (sh) => {
    const p1 = body.elements.p1.value, p2 = body.elements.p2.value, m = $('.msg', body);
    if (p1.length < 10) { m.textContent = 'Au moins 10 caractères.'; return; }
    if (p1 !== p2) { m.textContent = 'Les mots de passe ne correspondent pas.'; return; }
    m.textContent = 'Chiffrement de la sauvegarde…';
    const parts = await vault.exportBackup(p1);
    const d = new Date(), name = `coffre-fort-sauvegarde-${d.toISOString().slice(0, 10)}.json`;
    const file = new File(parts, name, { type: 'application/json' });
    await vault.setSettings({ lastBackup: Date.now() });
    sh.close();
    await shareOrDownload(file);
    toast('Sauvegarde chiffrée créée.'); if (S.tab === 'settings') renderTab();
  };
  body.onsubmit = (e) => { e.preventDefault(); go(sh); };
  const sh = openSheet({ title: 'Sauvegarde chiffrée', body, full: true, left: { label: 'Annuler' }, right: { label: 'Exporter', fn: go } });
}

async function importBackup() {
  const [file] = await pickFiles({ multiple: false });
  if (!file) return;
  const body = document.createElement('form');
  body.innerHTML = `<p class="info">Fichier : <b>${esc(file.name)}</b> (${fmtSize(file.size)})</p>
    <div class="field"><label>Mot de passe de la sauvegarde</label><input type="password" name="p" autocomplete="off"></div><p class="msg info"></p>`;
  const go = async (sh) => {
    const m = $('.msg', body); m.textContent = 'Déchiffrement…';
    try {
      const n = await vault.importBackup(await file.text(), body.elements.p.value);
      S.items = await vault.listItems(); sh.close(); renderTab(); toast(`${n} élément(s) restauré(s).`);
    } catch (e) { m.textContent = e.code === 'BACKUP_PW_BAD' ? 'Mot de passe incorrect.' : e.code === 'BACKUP_FORMAT' ? 'Ce fichier n\'est pas une sauvegarde de coffre-fort.' : 'Sauvegarde corrompue ou altérée.'; }
  };
  body.onsubmit = (e) => { e.preventDefault(); go(sh); };
  const sh = openSheet({ title: 'Importer', body, left: { label: 'Annuler' }, right: { label: 'Importer', fn: go } });
}

init().catch(e => { app.innerHTML = `<div class="empty"><b>Erreur au démarrage</b>${esc(e.message)}</div>`; });
