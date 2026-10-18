// Stockage IndexedDB (local à l'appareil). Tous les contenus y sont déjà chiffrés.
const DB_NAME = 'coffre-fort', VERSION = 1;
function req(r) { return new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
export class IdbStore {
  async open() {
    if (this.db) return this.db;
    const r = indexedDB.open(DB_NAME, VERSION);
    r.onupgradeneeded = () => {
      const db = r.result;
      for (const s of ['meta', 'items', 'blobs']) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s, { keyPath: s === 'meta' ? 'k' : 'id' });
    };
    this.db = await req(r);
    return this.db;
  }
  async tx(st, mode, fn) {
    const db = await this.open();
    const t = db.transaction(st, mode);
    const out = await req(fn(t.objectStore(st)));
    await new Promise((res, rej) => { t.oncomplete = res; t.onerror = () => rej(t.error); t.onabort = () => rej(t.error); });
    return out;
  }
  async getMeta(k) { const v = await this.tx('meta', 'readonly', s => s.get(k)); return v?.v; }
  setMeta(k, v) { return this.tx('meta', 'readwrite', s => s.put({ k, v })); }
  getAll(st) { return this.tx(st, 'readonly', s => s.getAll()); }
  get(st, id) { return this.tx(st, 'readonly', s => s.get(id)); }
  put(st, rec) { return this.tx(st, 'readwrite', s => s.put(rec)); }
  del(st, id) { return this.tx(st, 'readwrite', s => s.delete(id)); }
  async clear() {
    const db = await this.open();
    const t = db.transaction(['meta', 'items', 'blobs'], 'readwrite');
    for (const s of ['meta', 'items', 'blobs']) t.objectStore(s).clear();
    await new Promise((res, rej) => { t.oncomplete = res; t.onerror = () => rej(t.error); });
  }
}
