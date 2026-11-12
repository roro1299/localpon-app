// LocalPON - servidor Express + MySQL: cuentas, sincronización entre dispositivos y archivos de la PWA
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

// Carga opcional de un archivo .env (sin dependencias). Las variables ya definidas en el sistema tienen prioridad.
// Los valores de ejemplo de .env.example se ignoran para que nunca queden credenciales conocidas en producción.
const PLACEHOLDERS = new Set(['CAMBIA-ESTA-CLAVE-123', 'CAMBIA-ESTE-CODIGO', 'escribe-aqui-un-texto-largo-y-aleatorio']);
try {
  const ignored = [];
  for (const line of fs.readFileSync(__dirname + '/.env', 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    const val = m[2].replace(/^(['"])(.*)\1$/, '$2');
    if (PLACEHOLDERS.has(val)) { ignored.push(m[1]); continue; }
    if (process.env[m[1]] === undefined) process.env[m[1]] = val;
  }
  if (ignored.length) console.warn('El archivo .env tiene valores de ejemplo sin cambiar (se ignoran): ' + ignored.join(', '));
} catch (e) { /* no hay .env */ }
if (!process.env.JWT_SECRET) console.warn('Aviso: JWT_SECRET no está definido. Define uno propio y largo antes de publicar el servidor.');

const app = express();
const SECRET = process.env.JWT_SECRET || 'localpon-dev-secret-cambiar-en-produccion';
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname + '/public'));
// Registro (log) de cada petición a la API: fecha, método, ruta, código de respuesta y duración. Nunca guarda contraseñas ni tokens.
app.use('/api', (req, res, next) => {
  const t0 = Date.now();
  res.on('finish', () => {
    const lvl = res.statusCode >= 500 ? 'ERROR' : res.statusCode >= 400 ? 'AVISO' : 'INFO';
    console.log(`${new Date().toISOString()} ${lvl} ${req.method} ${req.originalUrl.split('?')[0]} ${res.statusCode} ${Date.now() - t0}ms ip=${req.ip}`);
  });
  next();
});

/* ---------- Código secreto para crear al administrador ---------- */
const CODE_FROM_ENV = !!(process.env.ADMIN_CODE || '').trim();
const SETUP_CODE = CODE_FROM_ENV ? process.env.ADMIN_CODE.trim() : crypto.randomBytes(4).toString('hex').toUpperCase().replace(/(.{4})(.{4})/, '$1-$2');
const norm = t => String(t || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const sameCode = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(norm(a)).digest(), crypto.createHash('sha256').update(norm(b)).digest());
// Limitador por IP para los endpoints que aceptan códigos: 5 fallos => 15 minutos de bloqueo.
app.set('trust proxy', 1);
const attempts = new Map();
const blocked = k => { const a = attempts.get(k); return !!a && a.until > Date.now(); };
const failed = k => { const a = attempts.get(k) || { n: 0, until: 0 }; if (++a.n >= 5) { a.n = 0; a.until = Date.now() + 15 * 60 * 1000; } attempts.set(k, a); };
const passed = k => attempts.delete(k);
/* ---------- Administrador inicial ---------- */
// Cuenta de administrador por defecto: existe para que la app funcione sin registrarse.
// Se crea sola cuando la base está vacía. Si defines ADMIN_EMAIL y ADMIN_PASSWORD en el servidor, se usan esas en lugar de estas.
// AVISO DE SEGURIDAD: estas credenciales están en el código, así que son públicas para quien lo lea.
// Por eso la cuenta nace con "must_change": la primera vez que entra, la app obliga a cambiar la contraseña.
const DEFAULT_ADMIN = { email: 'admin@localpon.app', password: 'LocalPON#2026', name: 'Administrador' };
async function seedAdmin(p) {
  const fromEnv = !!(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD);
  const email = String(fromEnv ? process.env.ADMIN_EMAIL : DEFAULT_ADMIN.email).trim().toLowerCase();
  const pw = String(fromEnv ? process.env.ADMIN_PASSWORD : DEFAULT_ADMIN.password);
  const name = String(fromEnv ? (process.env.ADMIN_NAME || 'Administrador') : DEFAULT_ADMIN.name).trim().slice(0, 80);
  const bad = validate(email, pw);
  if (bad) { console.warn('ADMIN_EMAIL / ADMIN_PASSWORD no son válidos, no se creó el administrador:', bad); return false; }
  const [r] = await p.query("INSERT INTO usuarios (email,nombre,hash,rol,must_change) VALUES (?,?,?,'admin',?)", [email, name, bcrypt.hashSync(pw, 10), fromEnv ? 0 : 1]);
  await p.query('UPDATE usuarios SET owner_id=id WHERE id=?', [r.insertId]);
  console.log(fromEnv ? `Cuenta de administrador creada: ${email}` : `Cuenta de administrador por defecto creada: ${email} / ${pw}  (la app pedirá cambiar la contraseña al entrar)`);
  return true;
}

/* ---------- Base de datos ---------- */
let pool = null, warned = false;
async function initDb() {
  const cfg = {
    host: process.env.DB_HOST || process.env.MYSQLHOST || 'localhost',
    port: +(process.env.DB_PORT || process.env.MYSQLPORT || 3306),
    user: process.env.DB_USER || process.env.MYSQLUSER || 'root',
    password: process.env.DB_PASS ?? process.env.MYSQLPASSWORD ?? '',
    // Bases en la nube (TiDB, Aiven...) exigen conexión cifrada: define DB_SSL=true
    ...(process.env.DB_SSL === 'true' ? { ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true } } : {}),
    enableKeepAlive: true
  };
  const name = process.env.DB_NAME || process.env.MYSQLDATABASE || 'localpon';
  try { const c = await mysql.createConnection(cfg); await c.query(`CREATE DATABASE IF NOT EXISTS \`${name}\``); await c.end(); } catch (e) {}
  const p = mysql.createPool({ ...cfg, database: name, decimalNumbers: true });
  await p.query(`CREATE TABLE IF NOT EXISTS usuarios (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(120) UNIQUE, nombre VARCHAR(80), hash VARCHAR(100), rol VARCHAR(10) NOT NULL DEFAULT 'admin', owner_id INT NULL, pwd_ver INT NOT NULL DEFAULT 0, priv_ver VARCHAR(10) NULL, priv_at BIGINT NULL, must_change TINYINT NOT NULL DEFAULT 0)`);
  // Migración para bases creadas con la versión anterior: las cuentas existentes quedan como administradores de su propio negocio.
  for (const sql of ["ALTER TABLE usuarios ADD COLUMN rol VARCHAR(10) NOT NULL DEFAULT 'admin'", "ALTER TABLE usuarios ADD COLUMN owner_id INT NULL", "ALTER TABLE usuarios ADD COLUMN pwd_ver INT NOT NULL DEFAULT 0"]) {
    try { await p.query(sql); } catch (e) { if (e.code !== 'ER_DUP_FIELDNAME') throw e; }
  }
  await p.query('UPDATE usuarios SET owner_id=id WHERE owner_id IS NULL');
  await p.query(`CREATE TABLE IF NOT EXISTS productos (user_id INT, sku VARCHAR(40), name VARCHAR(120), cat VARCHAR(60), price DECIMAL(10,2), qty INT, updated BIGINT, deleted TINYINT DEFAULT 0, PRIMARY KEY (user_id, sku))`);
  await p.query(`CREATE TABLE IF NOT EXISTS ventas (uid VARCHAR(40) PRIMARY KEY, user_id INT, ts BIGINT, sku VARCHAR(40), name VARCHAR(120), qty INT, total DECIMAL(10,2), pago VARCHAR(10), cliente VARCHAR(80), seller_email VARCHAR(120) NULL, seller_name VARCHAR(80) NULL, INDEX (user_id))`);
  for (const sql of ["ALTER TABLE ventas ADD COLUMN seller_email VARCHAR(120) NULL", "ALTER TABLE ventas ADD COLUMN seller_name VARCHAR(80) NULL", "ALTER TABLE usuarios ADD COLUMN priv_ver VARCHAR(10) NULL", "ALTER TABLE usuarios ADD COLUMN priv_at BIGINT NULL", "ALTER TABLE usuarios ADD COLUMN must_change TINYINT NOT NULL DEFAULT 0"]) {
    try { await p.query(sql); } catch (e) { if (e.code !== 'ER_DUP_FIELDNAME') throw e; }
  }
  pool = p;
  console.log('MySQL conectado');
  let [cnt] = await p.query('SELECT COUNT(*) AS n FROM usuarios');
  if (cnt[0].n === 0 && !!process.env.ADMIN_EMAIL !== !!process.env.ADMIN_PASSWORD) console.warn('Para crear el administrador automáticamente hacen falta ADMIN_EMAIL y ADMIN_PASSWORD (solo está una).');
  if (cnt[0].n === 0 && await seedAdmin(p)) cnt = [{ n: 1 }];
  if (!CODE_FROM_ENV) console.log(`Código secreto del servidor (solo para recuperar al administrador): ${SETUP_CODE}   (cambia en cada reinicio; define ADMIN_CODE para fijarlo)`);
}
(function boot() {
  initDb().catch(e => {
    pool = null;
    if (!warned) { warned = true; console.warn('MySQL no disponible (la app sigue en modo local):', e.message); }
    setTimeout(boot, 15000);
  });
})();

/* ---------- Utilidades ---------- */
const need = (req, res, next) => pool ? next() : res.status(503).json({ ok: false, error: 'Base de datos no disponible' });
const auth = async (req, res, next) => {
  try {
    const t = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const [rows] = await pool.query('SELECT id,rol,owner_id,pwd_ver,email,nombre,must_change FROM usuarios WHERE id=?', [t.uid]);
    if (!rows[0]) throw new Error('usuario eliminado');
    if ((t.v || 0) !== (rows[0].pwd_ver || 0)) throw new Error('contraseña cambiada');
    if (rows[0].must_change && !/^\/api\/me\/(password|privacy)/.test(req.originalUrl)) return res.status(403).json({ ok: false, code: 'must_change', error: 'Debes cambiar la contraseña antes de continuar.' });
    req.uid = rows[0].id; req.rol = rows[0].rol; req.owner = rows[0].owner_id || rows[0].id; req.pwdVer = rows[0].pwd_ver || 0; req.email = rows[0].email; req.nombre = rows[0].nombre;
    next();
  } catch { res.status(401).json({ ok: false, error: 'Sesión inválida' }); }
};
const adminOnly = (req, res, next) => req.rol === 'admin' ? next() : res.status(403).json({ ok: false, error: 'Solo el administrador puede hacer esto.' });
const userOut = (u, email) => ({ name: u.nombre, email, rol: u.rol, owner: u.owner_id || u.id, priv: u.priv_ver || null, mustChange: !!u.must_change });
const token = (id, v = 0) => jwt.sign({ uid: id, v }, SECRET, { expiresIn: '60d' });
const num = v => Number.isFinite(+v) ? Math.max(0, +v) : 0;

async function snapshot(owner, req) {
  const [products] = await pool.query('SELECT sku,name,cat,price,qty,updated,deleted FROM productos WHERE user_id=?', [owner]);
  const cols = 'uid,ts,sku,name,qty,total,pago,cliente,seller_email,seller_name';
  const [rows] = req.rol === 'admin'
    ? await pool.query(`SELECT ${cols} FROM ventas WHERE user_id=? ORDER BY ts DESC LIMIT 5000`, [owner])
    : await pool.query(`SELECT ${cols} FROM ventas WHERE user_id=? AND seller_email=? ORDER BY ts DESC LIMIT 5000`, [owner, req.email]);
  const sales = rows.map(r => ({ uid: r.uid, ts: Number(r.ts), sku: r.sku, name: r.name, qty: r.qty, total: r.total, pago: r.pago, cliente: r.cliente, by: r.seller_email || null, byName: r.seller_name || null }));
  return { products, sales };
}

/* ---------- Rutas ---------- */
app.get('/api/ping', (req, res) => res.json({ ok: true, db: !!pool }));

app.get('/api/setup', async (req, res) => {
  if (!pool) return res.json({ ok: true, db: false, needsSetup: false });
  try { const [r] = await pool.query('SELECT COUNT(*) AS n FROM usuarios'); res.json({ ok: true, db: true, needsSetup: false }); }
  catch (e) { res.json({ ok: true, db: false, needsSetup: false }); }
});

const validate = (email, pw) => {
  if (!/^\S+@\S+\.\S+$/.test(email)) return 'Correo no válido.';
  if (pw.length < 6) return 'La contraseña debe tener 6 o más caracteres.';
  return null;
};

app.post('/api/login', need, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  try {
    const [rows] = await pool.query('SELECT id,nombre,hash,rol,owner_id,pwd_ver,priv_ver,must_change FROM usuarios WHERE email=?', [email]);
    const u = rows[0];
    if (!u || !bcrypt.compareSync(pw, u.hash)) return res.status(401).json({ ok: false, error: 'Correo o contraseña incorrectos.' });
    res.json({ ok: true, token: token(u.id, u.pwd_ver), user: userOut(u, email) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Gestión de cuentas: solo el administrador. Las cuentas que crea comparten el inventario y las ventas de su negocio.
app.get('/api/users', need, auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id,email,nombre,rol FROM usuarios WHERE owner_id=? ORDER BY rol, nombre', [req.owner]);
    res.json({ ok: true, users: rows.map(u => ({ id: u.id, email: u.email, name: u.nombre, rol: u.rol })) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/users', need, auth, adminOnly, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  const name = String(req.body.name || '').trim().slice(0, 80) || email.split('@')[0];
  const bad = validate(email, pw);
  if (bad) return res.status(400).json({ ok: false, error: bad });
  try {
    const [r] = await pool.query("INSERT INTO usuarios (email,nombre,hash,rol,owner_id) VALUES (?,?,?,'empleado',?)", [email, name, bcrypt.hashSync(pw, 10), req.owner]);
    res.json({ ok: true, user: { id: r.insertId, email, name, rol: 'empleado' } });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ ok: false, error: 'Ese correo ya tiene cuenta.' });
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.delete('/api/users/:id', need, auth, adminOnly, async (req, res) => {
  try {
    const [r] = await pool.query("DELETE FROM usuarios WHERE id=? AND owner_id=? AND rol='empleado'", [+req.params.id, req.owner]);
    if (!r.affectedRows) return res.status(404).json({ ok: false, error: 'No se encontró esa cuenta.' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Registra que la persona aceptó una versión del aviso de privacidad (evidencia del consentimiento).
app.post('/api/me/privacy', need, auth, async (req, res) => {
  const v = String(req.body.version || '').trim().slice(0, 10);
  if (!v) return res.status(400).json({ ok: false, error: 'Falta la versión del aviso.' });
  try { await pool.query('UPDATE usuarios SET priv_ver=?, priv_at=? WHERE id=?', [v, Date.now(), req.uid]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Cambiar la propia contraseña (administrador o empleado). Cierra las demás sesiones y devuelve un token nuevo para esta.
app.post('/api/me/password', need, auth, async (req, res) => {
  const k = 'pw:' + req.uid;
  if (blocked(k)) return res.status(429).json({ ok: false, error: 'Demasiados intentos. Espera unos minutos.' });
  const cur = String(req.body.current || '');
  const pw = String(req.body.password || '');
  if (pw.length < 6) return res.status(400).json({ ok: false, error: 'La contraseña nueva debe tener 6 o más caracteres.' });
  if (pw === cur) return res.status(400).json({ ok: false, error: 'La contraseña nueva debe ser distinta a la actual.' });
  try {
    const [rows] = await pool.query('SELECT hash FROM usuarios WHERE id=?', [req.uid]);
    if (!rows[0] || !bcrypt.compareSync(cur, rows[0].hash)) { failed(k); return res.status(403).json({ ok: false, error: 'La contraseña actual no es correcta.' }); }
    await pool.query('UPDATE usuarios SET hash=?, pwd_ver=pwd_ver+1, must_change=0 WHERE id=?', [bcrypt.hashSync(pw, 10), req.uid]);
    passed(k);
    res.json({ ok: true, token: token(req.uid, req.pwdVer + 1) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Restablecer contraseña de un empleado (solo administrador). Cierra las sesiones abiertas de esa cuenta.
app.post('/api/users/:id/password', need, auth, adminOnly, async (req, res) => {
  const pw = String(req.body.password || '');
  if (pw.length < 6) return res.status(400).json({ ok: false, error: 'La contraseña debe tener 6 o más caracteres.' });
  try {
    const [r] = await pool.query("UPDATE usuarios SET hash=?, pwd_ver=pwd_ver+1 WHERE id=? AND owner_id=? AND rol='empleado'", [bcrypt.hashSync(pw, 10), +req.params.id, req.owner]);
    if (!r.affectedRows) return res.status(404).json({ ok: false, error: 'No se encontró esa cuenta.' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Recuperar al administrador: requiere el código secreto del servidor (ADMIN_CODE o el que imprime la terminal).
app.post('/api/recover', need, async (req, res) => {
  const k = 'rec:' + req.ip;
  if (blocked(k)) return res.status(429).json({ ok: false, error: 'Demasiados intentos con código incorrecto. Espera unos minutos.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  if (pw.length < 6) return res.status(400).json({ ok: false, error: 'La contraseña debe tener 6 o más caracteres.' });
  if (!sameCode(req.body.code, SETUP_CODE)) { failed(k); return res.status(403).json({ ok: false, error: 'Código secreto incorrecto.' }); }
  try {
    const [r] = await pool.query("UPDATE usuarios SET hash=?, pwd_ver=pwd_ver+1, must_change=0 WHERE email=? AND rol='admin'", [bcrypt.hashSync(pw, 10), email]);
    if (!r.affectedRows) return res.status(404).json({ ok: false, error: 'No hay un administrador con ese correo.' });
    passed(k);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Recibe productos/ventas del dispositivo, los mezcla (gana el cambio más reciente) y devuelve todo lo de la cuenta.
app.post('/api/sync', need, auth, async (req, res) => {
  try {
    const products = Array.isArray(req.body.products) ? req.body.products.slice(0, 5000) : [];
    const sales = Array.isArray(req.body.sales) ? req.body.sales.slice(0, 5000) : [];
    for (const p of products) {
      if (!p.sku) continue;
      await pool.query(
        `INSERT INTO productos (user_id,sku,name,cat,price,qty,updated,deleted) VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           name=IF(VALUES(updated)>updated,VALUES(name),name),
           cat=IF(VALUES(updated)>updated,VALUES(cat),cat),
           price=IF(VALUES(updated)>updated,VALUES(price),price),
           qty=IF(VALUES(updated)>updated,VALUES(qty),qty),
           deleted=IF(VALUES(updated)>updated,VALUES(deleted),deleted),
           updated=GREATEST(updated,VALUES(updated))`,
        [req.owner, String(p.sku).slice(0, 40), String(p.name || '').slice(0, 120), String(p.cat || 'Otros').slice(0, 60), num(p.price), Math.round(num(p.qty)), Math.round(num(p.updated)), p.deleted ? 1 : 0]);
    }
    for (const s of sales) {
      if (!s.uid) continue;
      await pool.query('INSERT IGNORE INTO ventas (uid,user_id,ts,sku,name,qty,total,pago,cliente,seller_email,seller_name) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        [String(s.uid).slice(0, 40), req.owner, Math.round(num(s.ts)), String(s.sku || '').slice(0, 40), String(s.name || '').slice(0, 120), Math.round(num(s.qty)), num(s.total), s.pago === 'fiado' ? 'fiado' : 'efectivo', String(s.cliente || '').slice(0, 80), req.email, req.nombre]);
    }
    res.json({ ok: true, ...(await snapshot(req.owner, req)) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`LocalPON en http://localhost:${PORT}`));
