const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config(); // 👈 carga las variables del .env
// Centralizar la inicialización del pool de Postgres en lib/db.js
const db = require('./lib/db');
let pgPool = db.getPool();
let stripe = null;
try {
  if (process.env.STRIPE_SECRET_KEY) {
    const Stripe = require('stripe');
    stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  } else {
    console.log('STRIPE_SECRET_KEY no encontrada — Stripe no estará disponible (modo desarrollo)');
  }
} catch (e) {
  console.warn('No se pudo inicializar Stripe:', e.message);
  stripe = null;
}
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  console.warn('nodemailer no está instalado — las funciones de email estarán deshabilitadas.');
  nodemailer = null;
}

// Web Push (optional) - try to require web-push if installed
let webpush = null;
try {
  webpush = require('web-push');
} catch (e) {
  console.warn('web-push no está instalado — Web Push estará deshabilitado. Para habilitar, npm install web-push');
  webpush = null;
}

let bcrypt = null;
try {
  bcrypt = require('bcrypt');
} catch (e) {
  console.warn('bcrypt no está instalado — la comparación de contraseñas seguras no estará disponible.');
}

let OAuth2Client = null;
let googleClient = null;
try {
  ({ OAuth2Client } = require('google-auth-library'));
  if (process.env.GOOGLE_CLIENT_ID) {
    googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }
} catch (e) {
  console.warn('google-auth-library no está instalada — Google Sign-In estará deshabilitado.');
}

function getGoogleClient() {
  if (!OAuth2Client) return null;
  if (!googleClient && process.env.GOOGLE_CLIENT_ID) {
    googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }
  return googleClient;
}

const session = require('express-session');
const app = express();
// Forzar uso exclusivo de la base de datos si se define esta variable de entorno
const USE_DB_ONLY = process.env.USE_DB_ONLY === 'true' || process.env.FORCE_DB === 'true';
// Inicializar Pool de Postgres si 'pg' fue cargado y existe DATABASE_URL
if (pgPool) {
  app.locals.db = pgPool;
} else {
  console.log('Postgres no inicializado (pg ausente o DATABASE_URL no definida) — usando JSON local.');
}
app.use(cors());
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    // store raw body for Stripe webhook verification when the route is /webhook
    if (req.originalUrl && req.originalUrl.startsWith('/webhook')) {
      req.rawBody = buf;
    }
  }
}));

// Session middleware (para administración)
app.use(session({
  secret: process.env.SESSION_SECRET || 'bigfoodadmin2025',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Protección simple para la ruta /admin.html: redirige a login si no autenticado
const ADMIN_PUBLIC_API = new Set(['/api/admin/login', '/api/admin/logout', '/api/admin/session']);

app.use((req, res, next) => {
  try {
    const pathReq = req.path || req.originalUrl || '/';

    if (pathReq === '/admin-login.html') {
      return next();
    }

    if (pathReq.startsWith('/api/admin')) {
      if (!req.session || !req.session.isAuthenticated) {
        if (ADMIN_PUBLIC_API.has(pathReq)) return next();
        return res.status(401).json({ error: 'No autenticado' });
      }
      return next();
    }

    if (pathReq === '/admin.html' || (pathReq.startsWith('/admin') && pathReq !== '/admin-login.html')) {
      if (!req.session || !req.session.isAuthenticated) {
        return res.redirect('/admin-login.html');
      }
    }
  } catch (e) { /* ignore */ }
  next();
});

// Middleware: filtrado básico de palabras prohibidas / intentos simples de inyección
// Rechaza cualquier petición cuya URL, query, params o body contenga palabras/fragmentos en la lista.
{
  const BANNED = [
    'mierda', 'hijo de puta', 'puta madre', 'puta', 'cabron', 'fuck', 'shit','tula', 'pichula', 'weon', 'webon', 'conchetumare', 'conchetumadre', 'putito', 'pablo', 'brian', 'pene', 'culo', 'raja', 'tetita','milf',
    'drop database', 'drop table', 'delete from', 'truncate', 'insert', 'update', 'alter table', 'exec ', 'union select', 'or 1=1', '--', '/**/', 
  ];
  // Safely escape all regex metacharacters. Use a standard character class that
  // includes backslash and the common metacharacters. This prevents tokens like
  // `*` or `+` from producing "Nothing to repeat" when the parts are joined.
  const esc = s => String(s).replace(/[\\^$.*+?()\[\]{}|]/g, '\\$&');
  const BANNED_RE = new RegExp(BANNED.map(esc).join('|'), 'i');

  function scanValue(v) {
    if (!v) return false;
    if (typeof v === 'string') return BANNED_RE.test(v.toLowerCase());
    if (typeof v === 'number' || typeof v === 'boolean') return false;
    if (Array.isArray(v)) return v.some(scanValue);
    if (typeof v === 'object') return Object.values(v).some(scanValue);
    return false;
  }

  app.use((req, res, next) => {
    try {
      const urlPart = String(req.originalUrl || req.url || '').toLowerCase();
      if (BANNED_RE.test(urlPart)) {
        console.warn('[FILTER] Rechazando petición por URL con contenido prohibido:', req.originalUrl);
        return res.status(400).json({ error: 'Contenido prohibido detectado en URL' });
      }
      if (scanValue(req.query) || scanValue(req.params) || scanValue(req.body)) {
        console.warn('[FILTER] Rechazando petición por cuerpo/params/query con contenido prohibido:', { path: req.path });
        return res.status(400).json({ error: 'Contenido prohibido detectado en la petición' });
      }
    } catch (e) { /* ignore */ }
    next();
  });
}

// Servir archivos estáticos (ahora después de haber añadido sesiones y middleware de protección)
app.use(express.static(path.join(__dirname)));

// Si se exige DB-only, bloquear las rutas /api si no hay pool configurado
if (USE_DB_ONLY) {
  app.use('/api', (req, res, next) => {
    if (!app.locals.db) return res.status(503).json({ error: 'Database required but not configured. Set DATABASE_URL or unset USE_DB_ONLY.' });
    next();
  });
}

// Determinar dinámicamente DATA_DIR: preferimos una carpeta `data` con products.json completo
function chooseDataDir() {
  const candidates = [
    path.join(__dirname, 'data'),
    path.join(__dirname, '..', 'data'),
    path.join(__dirname, '..', '..', 'data'),
    path.join(__dirname, 'totemDeCafeteria', 'data'),
    path.join(__dirname, '..', 'totemDeCafeteria', 'data'),
    path.join(__dirname, '..', '..', 'totemDeCafeteria', 'data'),
    path.join(__dirname, 'totemDeCafeteria.V2', 'totemDeCafeteria', 'data'),
    path.join(__dirname, '..', 'totemDeCafeteria.V2', 'totemDeCafeteria', 'data')
  ];

  let best = null;
  let bestSize = 0;
  for (const cand of candidates) {
    try {
      const prodFile = path.join(cand, 'products.json');
      if (fs.existsSync(prodFile)) {
        const st = fs.statSync(prodFile);
        if (st.size > bestSize) { bestSize = st.size; best = cand; }
      }
    } catch (e) {
      // ignore
    }
  }
  // si encontramos una carpeta con productos razonables, la usamos
  if (best) return best;
  // fallback: crear data en __dirname/data
  return path.join(__dirname, 'data');
}

const DATA_DIR = chooseDataDir();
const PEDIDOS_FILE = path.join(DATA_DIR, 'pedidos.json');
// Nuevo directorio para archivos de pedidos diarios
const ARCHIVE_DIR = path.join(DATA_DIR, 'pedidos_archivados');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ARCHIVE_DIR)) fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
if (!fs.existsSync(PEDIDOS_FILE)) fs.writeFileSync(PEDIDOS_FILE, JSON.stringify([]));

function leerPedidos() {
  try {
    const raw = fs.readFileSync(PEDIDOS_FILE);
    return JSON.parse(raw);
  } catch (e) {
    console.error('Error leyendo pedidos:', e);
    return [];
  }
}

function guardarPedidos(pedidos) {
  fs.writeFileSync(PEDIDOS_FILE, JSON.stringify(pedidos, null, 2));
}

// ------------------------------------------------------------------
// NUEVA FUNCIÓN: Archivar pedidos del día y limpiar la lista principal
// ------------------------------------------------------------------
function archivarYLimpiarPedidos(archived_by = 'system') {
  const pedidosActuales = leerPedidos();
  if (pedidosActuales.length === 0) {
    console.log('No hay pedidos para archivar.');
    return { archivar: false, count: 0 };
  }

  // Generar nombre de archivo con la fecha actual (ej: 2025-10-27.json)
  const fecha = new Date().toISOString().split('T')[0];
  const archivoArchivado = path.join(ARCHIVE_DIR, `${fecha}.json`);

  // Guardar los pedidos actuales en el archivo diario junto a metadatos
  const payload = {
    archived_at: new Date().toISOString(),
    archived_by: archived_by || 'system',
    orders: pedidosActuales
  };
  fs.writeFileSync(archivoArchivado, JSON.stringify(payload, null, 2));

  // Limpiar el archivo de pedidos principal
  guardarPedidos([]);
  console.log(`Archivados ${pedidosActuales.length} pedidos en ${archivoArchivado} y limpiada la lista principal.`);
  return { archivar: true, count: pedidosActuales.length, archivo: archivoArchivado, payload };
}


// ------------------------------------------------------------------
// Productos: archivo, lectura/escritura y endpoints REST
// (código de productos sin cambios)
// ------------------------------------------------------------------
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
if (!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, JSON.stringify({ nextId: 1, products: [] }, null, 2));

// Si el products.json actual es muy pequeño (placeholder), intentar copiar uno "real" desde el repo
function findSourceProductsFile() {
  const candidates = [
    path.join(__dirname, 'data', 'products.json'),
    path.join(__dirname, '..', 'data', 'products.json'),
    path.join(__dirname, '..', '..', 'data', 'products.json'),
    path.join(__dirname, 'totemDeCafeteria', 'data', 'products.json'),
    path.join(__dirname, '..', 'totemDeCafeteria', 'data', 'products.json'),
    path.join(__dirname, '..', '..', 'totemDeCafeteria', 'data', 'products.json'),
    path.join(__dirname, 'totemDeCafeteria.V2', 'totemDeCafeteria', 'data', 'products.json'),
    path.join(__dirname, '..', 'totemDeCafeteria.V2', 'totemDeCafeteria', 'data', 'products.json')
  ];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) {
        const st = fs.statSync(c);
        if (st.size && st.size > 200) return c;
      }
    } catch (e) { /* ignore */ }
  }
  return null;
}

try {
  const currentStat = fs.existsSync(PRODUCTS_FILE) ? fs.statSync(PRODUCTS_FILE) : null;
  const currentSize = currentStat ? currentStat.size : 0;
  if (currentSize < 200) {
    const src = findSourceProductsFile();
    if (src) {
      console.log('[INIT] products.json parece pequeño (', currentSize, 'bytes). Copiando desde', src);
      try {
        const content = fs.readFileSync(src);
        fs.writeFileSync(PRODUCTS_FILE, content);
        console.log('[INIT] Copia completada a', PRODUCTS_FILE);
      } catch (e) {
        console.warn('[INIT] No se pudo copiar products.json desde', src, e.message);
      }
    } else {
      console.log('[INIT] No se encontró products.json fuente más grande en candidatos');
    }
  }
} catch (e) {
  console.warn('[INIT] Error comprobando products.json:', e.message);
}

function leerProducts() {
  try {
    const raw = fs.readFileSync(PRODUCTS_FILE);
    return JSON.parse(raw);
  } catch (e) {
    console.error('Error leyendo products:', e);
    return { nextId: 1, products: [] };
  }
}

function guardarProducts(data) {
  fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(data, null, 2));
}

// Listar productos o filtrar por categoría
app.get('/api/products', (req, res) => {
  const pool = app.locals.db;
  const categoria = req.query.categoria;
  if (pool) {
    const sql = categoria ? 'SELECT * FROM products WHERE category = $1 ORDER BY id' : 'SELECT * FROM products ORDER BY id';
    const params = categoria ? [categoria] : [];
    return pool.query(sql, params)
      .then(r => {
        const rows = r.rows.map(row => ({
          id: row.id,
          nombre: row.name || null,
          categoria: row.category || null,
          precio: typeof row.price !== 'undefined' ? Number(row.price) : null,
          disponible: typeof row.available !== 'undefined' ? row.available : true,
          variantes: row.metadata && row.metadata.variantes ? row.metadata.variantes : null,
          img: row.image || null,
          description: row.description || null
        }));
        res.json(rows);
      })
      .catch(err => {
        console.error('[API] Error consultando products en DB:', err);
        res.status(500).json({ error: 'Error consultando products en DB', detail: err.message });
      });
  }

  // Fallback a JSON local
  try {
    console.log('[API] GET /api/products -> using local JSON PRODUCTS_FILE=', PRODUCTS_FILE, 'exists=', fs.existsSync(PRODUCTS_FILE));
    const data = leerProducts();
    if (categoria) {
      return res.json(data.products.filter(p => p.categoria === categoria));
    }
    return res.json(data.products);
  } catch (e) {
    console.error('[API] Error leyendo products:', e);
    res.status(500).json({ error: 'Error leyendo products', detail: e.message });
  }
});

// Endpoint de diagnóstico rápido para verificar paths/archivos en el entorno (útil en Render)
app.get('/api/health', (req, res) => {
  try {
    const productsExists = fs.existsSync(PRODUCTS_FILE);
    const pedidosExists = fs.existsSync(PEDIDOS_FILE);
    const productsStat = productsExists ? fs.statSync(PRODUCTS_FILE) : null;
    const pedidosStat = pedidosExists ? fs.statSync(PEDIDOS_FILE) : null;
    res.json({
      ok: true,
      env: {
        PORT: process.env.PORT || null,
        BASE_URL: process.env.BASE_URL || null,
        STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ? '***SET***' : null,
        STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY ? '***SET***' : null
      },
      server: {
        __dirname,
        dataDir: DATA_DIR,
        productsFile: PRODUCTS_FILE,
        productsExists,
        productsStat: productsStat && { size: productsStat.size, mtime: productsStat.mtime },
        pedidosFile: PEDIDOS_FILE,
        pedidosExists,
        pedidosStat: pedidosStat && { size: pedidosStat.size, mtime: pedidosStat.mtime }
      }
    });
  } catch (err) {
    console.error('Error en /api/health', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Endpoint simple para comprobar si la conexión a Postgres está activa
app.get('/api/dbtest', async (req, res) => {
  const pool = app.locals.db;
  if (!pool) return res.json({ ok: true, db: false, message: 'DB no inicializada (fallback JSON activo)' });
  try {
    const r = await pool.query('SELECT 1 AS ok');
    if (r && r.rows && r.rows.length) return res.json({ ok: true, db: true });
    return res.json({ ok: true, db: false });
  } catch (err) {
    console.error('Error en /api/dbtest:', err.message || err);
    return res.status(500).json({ ok: false, db: false, error: err.message });
  }
});


// ------------------------------------------------------------------
// Endpoints para archivar pedidos (admin)
// ------------------------------------------------------------------

// POST /api/admin/archive-today
// Si existe pool (Postgres), movemos las órdenes del día a archived_orders y las borramos de orders.
// Si no, usamos el fallback de archivos JSON (archivarYLimpiarPedidos).
app.post('/api/admin/archive-today', async (req, res) => {
  const pool = app.locals.db;
    if (!pool) {
    try {
      const actor = req.session && req.session.admin ? (req.session.admin.name || req.session.admin.email || 'admin') : 'admin';
      const result = archivarYLimpiarPedidos(actor);
      return res.json({ ok: true, method: 'file', result });
    } catch (e) {
      console.error('Error archivando pedidos (file):', e);
      return res.status(500).json({ ok: false, error: e.message });
    }
  }

  // DB path
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Select orders from today
    const selectSql = `SELECT * FROM orders WHERE DATE(created_at) = CURRENT_DATE`;
    const r = await client.query(selectSql);
    if (!r.rows || r.rows.length === 0) {
      await client.query('COMMIT');
      return res.json({ ok: true, archived: 0, message: 'No hay pedidos del día para archivar' });
    }

    const now = new Date();
    const insertSql = `INSERT INTO archived_orders (original_order_id, items, total, archived_at, metadata)
      VALUES ($1, $2::jsonb, $3, $4, $5) RETURNING id`;

    let count = 0;
    for (const row of r.rows) {
      // To avoid foreign-key constraint violations (archived_orders.original_order_id -> orders.id)
      // we store the original order id inside metadata and pass NULL for original_order_id.
      const actor = req.session && req.session.admin ? (req.session.admin.name || req.session.admin.email || 'admin') : 'admin';
      const metadataObj = Object.assign({}, row.metadata || {}, { archived_by: actor, original_order_id: row.id });
      const params = [null, JSON.stringify(row.items || []), row.total || 0, now.toISOString(), JSON.stringify(metadataObj)];
      await client.query(insertSql, params);
      count++;
    }

    // Delete archived orders from orders table
    const ids = r.rows.map(x => x.id);
    const delSql = `DELETE FROM orders WHERE id = ANY($1::int[])`;
    await client.query(delSql, [ids]);

    await client.query('COMMIT');
    return res.json({ ok: true, archived: count, archived_at: now.toISOString() });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('Error archivando pedidos (db):', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  } finally {
    client.release();
  }
});


// GET /api/admin/archives
// Lista las fechas de archivos disponibles y la cantidad de pedidos por fecha
app.get('/api/admin/archives', async (req, res) => {
  const pool = app.locals.db;
  if (!pool) {
    // file-based: leer archivos en ARCHIVE_DIR
    try {
      const files = fs.readdirSync(ARCHIVE_DIR).filter(f => f.endsWith('.json'));
      const list = files.map(f => {
        try {
          const raw = fs.readFileSync(path.join(ARCHIVE_DIR, f));
          const obj = JSON.parse(raw);
          const orders = Array.isArray(obj.orders) ? obj.orders : [];
          return { date: f.replace(/\.json$/, ''), count: orders.length, archived_by: obj.archived_by || 'system', archived_at: obj.archived_at || null, file: f };
        } catch (e) { return { date: f.replace(/\.json$/, ''), count: 0, archived_by: null, file: f }; }
      }).sort((a,b)=> b.date.localeCompare(a.date));
      return res.json({ ok: true, method: 'file', archives: list });
    } catch (e) { return res.status(500).json({ ok: false, error: e.message }); }
  }

  // DB-based: agrupar archived_orders por fecha
  try {
    const q = `SELECT to_char(archived_at::date, 'YYYY-MM-DD') AS date, count(*)::int AS count
      FROM archived_orders GROUP BY date ORDER BY date DESC`;
    const r = await pool.query(q);
    // try to enrich with archived_by if possible
    const augmented = r.rows.map(row => Object.assign({}, row, { archived_by: null }));
    try {
      const detailsQ = `SELECT archived_at, metadata FROM archived_orders WHERE DATE(archived_at) = $1 LIMIT 1`;
      for (const a of augmented) {
        const det = await pool.query(detailsQ, [a.date]);
        if (det && det.rows && det.rows[0]) {
          a.archived_at = det.rows[0].archived_at;
          a.archived_by = det.rows[0].metadata && det.rows[0].metadata.archived_by ? det.rows[0].metadata.archived_by : null;
        }
      }
    } catch (e) { /* ignore details enrichment errors */ }
    return res.json({ ok: true, method: 'db', archives: augmented });
  } catch (e) { console.error('Error listando archives:', e.message || e); return res.status(500).json({ ok:false, error: e.message }); }
});


// GET /api/admin/archives/:date (YYYY-MM-DD)
app.get('/api/admin/archives/:date', async (req, res) => {
  const pool = app.locals.db;
  const date = String(req.params.date || '').trim();
  if (!date.match(/^\d{4}-\d{2}-\d{2}$/)) return res.status(400).json({ ok:false, error: 'Formato de fecha inválido, usar YYYY-MM-DD' });

  if (!pool) {
    const filePath = path.join(ARCHIVE_DIR, `${date}.json`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ ok:false, error: 'Archivo de archive no encontrado' });
    try {
      const raw = fs.readFileSync(filePath);
      const obj = JSON.parse(raw);
      const orders = Array.isArray(obj.orders) ? obj.orders : [];
      return res.json({ ok: true, method: 'file', date, archived_at: obj.archived_at || null, archived_by: obj.archived_by || null, orders });
    } catch (e) { return res.status(500).json({ ok:false, error: e.message }); }
  }

  try {
    const q = `SELECT id, original_order_id, items, total, archived_at, metadata FROM archived_orders WHERE DATE(archived_at) = $1 ORDER BY archived_at DESC`;
    const r = await pool.query(q, [date]);
    return res.json({ ok: true, method: 'db', date, archived_at: date, archived_by: null, orders: r.rows });
  } catch (e) { console.error('Error obteniendo archive date:', e.message || e); return res.status(500).json({ ok:false, error: e.message }); }
});


// DELETE /api/admin/archives/:date -> elimina archivo o filas archivadas para esa fecha
app.delete('/api/admin/archives/:date', async (req, res) => {
  const pool = app.locals.db;
  const date = String(req.params.date || '').trim();
  if (!date.match(/^\d{4}-\d{2}-\d{2}$/)) return res.status(400).json({ ok:false, error: 'Formato de fecha inválido, usar YYYY-MM-DD' });

  if (!pool) {
    const filePath = path.join(ARCHIVE_DIR, `${date}.json`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ ok:false, error: 'Archivo de archive no encontrado' });
    try {
      fs.unlinkSync(filePath);
      return res.json({ ok: true, method: 'file', date, message: 'Archivo archivado eliminado' });
    } catch (e) { return res.status(500).json({ ok:false, error: e.message }); }
  }

  try {
    const delQ = `DELETE FROM archived_orders WHERE DATE(archived_at) = $1`;
    const r = await pool.query(delQ, [date]);
    return res.json({ ok: true, method: 'db', date, deleted: r.rowCount });
  } catch (e) { console.error('Error eliminando archived_orders:', e.message || e); return res.status(500).json({ ok:false, error: e.message }); }
});

// Crear nuevo producto
app.post('/api/products', (req, res) => {
  const body = req.body;
  if (!body || !body.nombre || !body.categoria || typeof body.precio === 'undefined') {
    return res.status(400).json({ error: 'Producto inválido. Requiere nombre, categoria y precio.' });
  }
  const pool = app.locals.db;
  if (pool) {
    // Insertar en DB
    const sql = `INSERT INTO products (name, category, price, image, available, metadata, description)
                 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`;
    const metadata = body.variantes ? { variantes: body.variantes } : null;
    const params = [body.nombre, body.categoria, body.precio, body.img || null, typeof body.disponible !== 'undefined' ? body.disponible : true, metadata, body.description || null];
    return pool.query(sql, params)
      .then(r => {
        const row = r.rows[0];
        const producto = { id: row.id, nombre: row.name, categoria: row.category, precio: Number(row.price), disponible: row.available, variantes: row.metadata && row.metadata.variantes ? row.metadata.variantes : null, img: row.image };
        res.json({ status: 'ok', product: producto });
      })
      .catch(err => {
        console.error('[API] Error insertando product en DB:', err);
        res.status(500).json({ error: 'Error insertando product en DB', detail: err.message });
      });
  }

  // Fallback a JSON
  const data = leerProducts();
  const id = data.nextId || 1;
  data.nextId = id + 1;
  const producto = { id, disponible: true, ...body };
  data.products.push(producto);
  guardarProducts(data);
  res.json({ status: 'ok', product: producto });
});

// Actualizar producto (poner disponible, cambiar precio/variantes, etc.)
app.put('/api/products/:id', (req, res) => {
  const id = Number(req.params.id);
  const pool = app.locals.db;
  if (pool) {
    const fields = [];
    const params = [];
    let i = 1;
    if (req.body.nombre) { fields.push(`name = $${i++}`); params.push(req.body.nombre); }
    if (req.body.categoria) { fields.push(`category = $${i++}`); params.push(req.body.categoria); }
    if (typeof req.body.precio !== 'undefined') { fields.push(`price = $${i++}`); params.push(req.body.precio); }
    if (typeof req.body.disponible !== 'undefined') { fields.push(`available = $${i++}`); params.push(req.body.disponible); }
    if (req.body.img) { fields.push(`image = $${i++}`); params.push(req.body.img); }
    if (req.body.description) { fields.push(`description = $${i++}`); params.push(req.body.description); }
    if (req.body.variantes) { fields.push(`metadata = jsonb_set(COALESCE(metadata,'{}'), '{variantes}', $${i++}::jsonb)`); params.push(JSON.stringify(req.body.variantes)); }
    if (fields.length === 0) return res.status(400).json({ error: 'Nada que actualizar' });
    const sql = `UPDATE products SET ${fields.join(', ')} WHERE id = $${i} RETURNING *`;
    params.push(id);
    return pool.query(sql, params)
      .then(r => {
        if (!r.rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
        const row = r.rows[0];
        const producto = { id: row.id, nombre: row.name, categoria: row.category, precio: Number(row.price), disponible: row.available, variantes: row.metadata && row.metadata.variantes ? row.metadata.variantes : null, img: row.image };
        res.json({ status: 'ok', product: producto });
      })
      .catch(err => {
        console.error('[API] Error actualizando product en DB:', err);
        res.status(500).json({ error: 'Error actualizando product en DB', detail: err.message });
      });
  }

  const data = leerProducts();
  const idx = data.products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Producto no encontrado' });
  data.products[idx] = { ...data.products[idx], ...req.body };
  guardarProducts(data);
  res.json({ status: 'ok', product: data.products[idx] });
});

// Eliminar producto
app.delete('/api/products/:id', (req, res) => {
  const id = Number(req.params.id);
  const pool = app.locals.db;
  if (pool) {
    return pool.query('DELETE FROM products WHERE id = $1 RETURNING *', [id])
      .then(r => {
        if (!r.rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
        const row = r.rows[0];
        const removed = { id: row.id, nombre: row.name };
        res.json({ status: 'ok', removed });
      })
      .catch(err => {
        console.error('[API] Error eliminando product en DB:', err);
        res.status(500).json({ error: 'Error eliminando product en DB', detail: err.message });
      });
  }

  const data = leerProducts();
  const idx = data.products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Producto no encontrado' });
  const removed = data.products.splice(idx, 1)[0];
  guardarProducts(data);
  res.json({ status: 'ok', removed });
});

// transporter de nodemailer (código sin cambios)
let mailTransport = null;
(async () => {
  try {
    if (!nodemailer) {
      console.log('nodemailer no disponible — saltando configuración de transporte de correo.');
      return;
    }
    if (process.env.SMTP_USER && process.env.SMTP_PASS) {
      // Configuración de transporte de Nodemailer mejorada
      const transportOptions = {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 465,
        secure: process.env.SMTP_SECURE !== 'false',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
        // Tiempos de espera más cortos para evitar bloqueos largos
        connectionTimeout: 8000, // 8 segundos
        greetingTimeout: 5000, // 5 segundos
        socketTimeout: 10000, // 10 segundos
      };

      // Si se usa Gmail, es mejor especificar el 'service'
      if (transportOptions.host === 'smtp.gmail.com') {
        transportOptions.service = 'gmail';
      }

      mailTransport = nodemailer.createTransport(transportOptions);
      
      console.log('Verificando configuración de SMTP...');
      await mailTransport.verify();
      console.log('SMTP transport configurado y verificado correctamente. Host:', transportOptions.host);

    } else {
      console.log('SMTP credentials not found — creating Ethereal test account for email preview.');
      const testAccount = await nodemailer.createTestAccount();
      mailTransport = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass }
      });
      console.log('Ethereal test account created. Emails will be visible via nodemailer preview URL in logs when sent.');
    }
  } catch (e) {
    console.error('Error setting up mail transport:', e);
    mailTransport = null;
  }
})();

app.get('/api/auth/config', (req, res) => {
  res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || null });
});

// Rutas de administración: login con Google Sign-In y sesiones
app.post('/api/admin/login', async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) {
      return res.status(400).json({ error: 'Token de Google requerido' });
    }

    const client = getGoogleClient();
    if (!client || !process.env.GOOGLE_CLIENT_ID) {
      console.error('[admin] Google Sign-In no está configurado correctamente.');
      return res.status(500).json({ error: 'Autenticación con Google no está configurada' });
    }

    let payload;
    try {
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      payload = ticket.getPayload();
    } catch (err) {
      console.error('[admin] Error verificando token de Google:', err.message || err);
      return res.status(401).json({ error: 'Token de Google inválido' });
    }

    const email = payload && payload.email ? String(payload.email).toLowerCase() : null;
    if (!email) {
      return res.status(401).json({ error: 'Token de Google inválido' });
    }

    const pool = app.locals.db;
    if (!pool) {
      console.error('[admin] Intento de login sin base de datos configurada.');
      return res.status(503).json({ error: 'Servicio de autenticación no disponible (DB no configurada)' });
    }

    let user = null;
    try {
      const primary = await pool.query('SELECT id, email, nombre FROM usuarios WHERE email = $1 LIMIT 1', [email]);
      if (primary.rows && primary.rows.length) {
        user = primary.rows[0];
      } else {
        const fallback = await pool.query('SELECT id, email FROM users WHERE email = $1 LIMIT 1', [email]).catch(() => ({ rows: [] }));
        if (fallback.rows && fallback.rows.length) {
          user = fallback.rows[0];
        }
      }
    } catch (dbErr) {
      console.error('[admin] Error de DB al validar usuario Google:', dbErr.message || dbErr);
      return res.status(500).json({ error: 'Error de base de datos durante la verificación' });
    }

    if (!user) {
      return res.status(401).json({ error: 'La cuenta asociada a Google no está registrada en nuestra base de datos.' });
    }

    const sessionAdmin = {
      id: user.id || null,
      email,
      name: payload && payload.name ? payload.name : null,
      picture: payload && payload.picture ? payload.picture : null
    };

    await new Promise((resolve, reject) => {
      req.session.regenerate(err => {
        if (err) return reject(err);
        req.session.isAuthenticated = true;
        req.session.admin = sessionAdmin;
        resolve();
      });
    });

    return res.json({ status: 'ok', admin: req.session.admin });
  } catch (err) {
    console.error('[admin] Unexpected error during Google login:', err);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/admin/session', (req, res) => {
  if (req.session && req.session.isAuthenticated && req.session.admin) {
    return res.json({ authenticated: true, admin: req.session.admin });
  }
  return res.status(401).json({ authenticated: false, error: 'No autenticado' });
});

app.post('/api/admin/logout', (req, res) => {
  if (!req.session) return res.json({ status: 'ok' });
  const adminEmail = req.session.admin && req.session.admin.email ? req.session.admin.email : null;
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Error al cerrar sesión' });
    res.clearCookie('connect.sid');
    if (adminEmail) console.log(`[admin] Sesión finalizada para ${adminEmail}`);
    res.json({ status: 'ok' });
  });
});

// Endpoint para crear pedido (código sin cambios)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'inicioSesion.html'));
});

// Crear pedido
app.post('/api/pedidos', async (req, res) => {
  const body = req.body;
  console.log('\n[API] POST /api/pedidos recibida. Body:', JSON.stringify(body));
  if (!body || !body.cliente || !Array.isArray(body.items) || body.items.length === 0) {
    return res.status(400).json({ error: 'Formato de pedido inválido. Requiere cliente e items.' });
  }

  const total = body.items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0);
  let estado = 'pendiente';
  if (body.metodoPago && (body.metodoPago === 'efectivo' || body.metodoPago === 'junaeb')) {
    if (body.paymentIntentId) estado = 'Garantizado - Pendiente de Retiro'; else estado = 'pendiente_pago';
  } else if (body.metodoPago && body.metodoPago === 'tarjeta') {
    estado = 'pendiente';
  }

  const pool = app.locals.db;
  if (pool) {
    try {
      const metadata = {
        email: body.email || null,
        metodoPago: body.metodoPago || null,
        nota: body.nota || null,
        paymentIntentId: body.paymentIntentId || null,
        sessionId: body.sessionId || null
      };
      const sql = `INSERT INTO orders (external_id, items, total, status, customer_name, metadata)
                   VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`;
      const params = [body.sessionId || null, JSON.stringify(body.items), total, estado, body.cliente, metadata];
      const r = await pool.query(sql, params);
      const row = r.rows[0];
      const pedido = {
        id: row.id,
        cliente: row.customer_name,
        email: row.metadata && row.metadata.email ? row.metadata.email : (body.email || ''),
        items: row.items,
        total: Number(row.total),
        metodoPago: row.metadata && row.metadata.metodoPago ? row.metadata.metodoPago : (body.metodoPago || 'tarjeta'),
        nota: row.metadata && row.metadata.nota ? row.metadata.nota : (body.nota || ''),
        estado: row.status,
        paymentIntentId: row.metadata && row.metadata.paymentIntentId ? row.metadata.paymentIntentId : (body.paymentIntentId || null),
        sessionId: row.external_id || null,
        fecha: row.created_at
      };
      console.log(`[API] Pedido creado en DB id=${pedido.id} estado=${pedido.estado}`);
      return res.json({ status: 'ok', pedido });
    } catch (err) {
      console.error('[API] Error insertando pedido en DB:', err);
      return res.status(500).json({ error: 'Error insertando pedido en DB', detail: err.message });
    }
  }

  // Fallback a JSON file
  const pedidos = leerPedidos();
  const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
  const pedido = {
    id,
    cliente: body.cliente,
    email: body.email || '',
    items: body.items,
    total,
    metodoPago: body.metodoPago || 'tarjeta',
    nota: body.nota || '',
    estado,
    paymentIntentId: body.paymentIntentId || null,
    fecha: new Date().toISOString()
  };
  pedidos.push(pedido);
  guardarPedidos(pedidos);
  console.log(`[API] Pedido creado id=${pedido.id} estado=${pedido.estado} (fallback JSON)`);
  res.json({ status: 'ok', pedido });
});


// Endpoint para crear PaymentIntent en modo 'manual' (código sin cambios)
app.post('/api/create-payment-intent', async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe no configurado en este entorno' });
    const { amount, currency = 'CLP', orderId, metadata } = req.body;
    console.log('[API] /api/create-payment-intent request body:', JSON.stringify(req.body));
    if (!amount || Number(amount) <= 0) return res.status(400).json({ error: 'Amount inválido' });

    // CLP no usa decimales: pasar monto entero en pesos
    const pi = await stripe.paymentIntents.create({
      amount: Math.round(Number(amount)),
      currency: (currency || 'clp').toLowerCase(),
      // Al eliminar capture_method: 'manual', se usará el comportamiento por defecto de Stripe
      description: `Garantía orden ${orderId || 'n/a'}`,
      metadata: Object.assign({}, metadata || {}, { orderId: orderId || '' }),
      payment_method_types: ['card']
    });

    console.log('[API] PaymentIntent creado:', pi.id, 'amount=', pi.amount, 'currency=', pi.currency);
    res.json({ clientSecret: pi.client_secret, paymentIntentId: pi.id });
  } catch (err) {
    console.error('create-payment-intent error', err);
    res.status(500).json({ error: err.message });
  }
});


  // --- ¡NUEVO ENDPOINT PARA LA APLICACIÓN MÓVIL! ---
  // Este endpoint es exclusivo para la app y no afectará a la web.
  app.post('/api/create-payment-intent-mobile', async (req, res) => {
    try {
      const { amount } = req.body;

      // 1. Validación robusta del monto
      if (amount == null || amount <= 0) {
        console.log("MOBILE: Solicitud rechazada: El monto es inválido o nulo:", amount);
        return res.status(400).json({ error: 'Monto inválido.' });
      }

      console.log(`MOBILE: Creando PaymentIntent para el monto: ${amount}`);

      // 2. Creación del PaymentIntent con la moneda correcta para la app
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount), // Aseguramos que sea un número entero
        currency: 'clp',            // Moneda específica para la app móvil
        automatic_payment_methods: {
          enabled: true,
        },
      });

      console.log("MOBILE: PaymentIntent creado con éxito.");
      res.json({
        clientSecret: paymentIntent.client_secret
      });

    } catch (error) {
      console.error("MOBILE: Error al crear PaymentIntent:", error.message);
      res.status(500).json({ error: 'Error interno del servidor al contactar a Stripe.' });
    }
  });

// Endpoint simple para exponer la publishable key al frontend (código sin cambios)
app.get('/api/config', (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || 'pk_test_51SGsL4E06U1NNw23MU9zuqRK2hu2y5pEAWwSdGNOug8gQpvLP3yJ2WcsfYO77MEcuQfvxC7WRCVicP1zVzJQc1AP00Nv7qFCgD' });
});

// Endpoint para capturar un PaymentIntent (código sin cambios)
app.post('/api/capture-payment-intent', async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe no configurado en este entorno' });
    const { paymentIntentId, amount_to_capture } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'paymentIntentId requerido' });

    const params = {};
    if (amount_to_capture) params.amount_to_capture = Math.round(Number(amount_to_capture));

    const pi = await stripe.paymentIntents.capture(paymentIntentId, params);
    res.json({ status: pi.status, paymentIntent: pi });
  } catch (err) {
    console.error('capture error', err);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint para cancelar un PaymentIntent (código sin cambios)
app.post('/api/cancel-payment-intent', async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe no configurado en este entorno' });
    const { paymentIntentId, cancellation_reason } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'paymentIntentId requerido' });

    const pi = await stripe.paymentIntents.cancel(paymentIntentId, { cancellation_reason });
    res.json({ status: pi.status, paymentIntent: pi });
  } catch (err) {
    console.error('cancel error', err);
    res.status(500).json({ error: err.message });
  }
});

// === ENDPOINT EXCLUSIVO PARA APP MÓVIL: CREAR PAYMENT INTENT ===
app.post('/api/create-payment-intent-mobile-app', async (req, res) => {
  try {
    // 1. EXTRAER EL CUERPO COMPLETO DE LA SOLICITUD
    // `req.body` ahora contiene { clientName, amount, items, ... } enviado desde el móvil.
    const orderData = req.body;
    const { amount } = orderData; // Extraemos solo el `amount` para el PaymentIntent.

    // ¡VERIFICACIÓN IMPORTANTE!
    console.log("Datos del pedido recibidos en /create-payment-intent-mobile-app:", orderData);

    const customer = await stripe.customers.create();
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customer.id },
      { apiVersion: '2020-08-27' }
    );

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Stripe usa centavos.
      currency: 'clp',
      customer: customer.id,
      payment_method_types: ['card'],
      // 2. ASIGNACIÓN DE METADATA
      // Serializamos el objeto completo del pedido a un string JSON.
      // El webhook NO puede leer objetos anidados, debe ser un string.
      metadata: {
        pedido: JSON.stringify(orderData)
      }
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      ephemeralKey: ephemeralKey.secret,
      customer: customer.id,
      publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    });
  } catch (error) {
    console.error('Error al crear el Payment Intent (móvil):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// === ENDPOINT EXCLUSIVO PARA APP MÓVIL: STRIPE WEBHOOK ===
app.post('/stripe-webhook-mobile-app', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`❌ Error en la firma del webhook (móvil): ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Manejar el evento payment_intent.succeeded
  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    console.log('✅ PaymentIntent exitoso (móvil):', intent.id);

    // --- DIAGNÓSTICO DEL WEBHOOK ---
    // 1. REGISTRO DE DATOS CRUDOS DE METADATA
    console.log("Metadata cruda recibida en el webhook (móvil):", intent.metadata);
    console.log("Contenido de intent.metadata.pedido:", intent.metadata.pedido);
    let orderDetails;
    try {
      // 2. INTENTO DE PARSEAR LA METADATA
      if (!intent.metadata.pedido) {
          throw new Error("La metadata 'pedido' está vacía o no existe.");
      }
      orderDetails = JSON.parse(intent.metadata.pedido);
      console.log("Metadata parseada correctamente (móvil):", orderDetails);

      // Verificación de campos esenciales
      if (!orderDetails.clientName || !orderDetails.items || !orderDetails.amount) {
          throw new Error("Faltan datos esenciales en la metadata (clientName, items, o amount).");
      }

      // 3. BLOQUE TRY...CATCH PARA LA BASE DE DATOS
      // Toda la lógica de inserción va aquí dentro.
      const queryText = `
        INSERT INTO pedidos (client_name, items, total, payment_intent_id, status)
        VALUES ($1, $2, $3, $4, 'pagado')
        RETURNING id;
      `;
      const values = [
        orderDetails.clientName,
        JSON.stringify(orderDetails.items), // Guardamos los items como un string JSON en la BD.
        orderDetails.amount,
        intent.id
      ];

      const result = await pgPool.query(queryText, values);
      console.log(`🎉 Pedido #${result.rows[0].id} guardado exitosamente en la base de datos (móvil).`);

    } catch (dbError) {
      // 4. MANEJO EXPLÍCITO DE ERRORES (tanto de parseo como de BD)
      console.error('❌ ¡FALLO CRÍTICO! No se pudo guardar el pedido en la base de datos (móvil).');
      console.error('Error Detallado:', dbError.message);
      console.error('Detalles del Pedido que falló:', orderDetails || intent.metadata.pedido);
      // Aquí podrías añadir una alerta (ej. enviar un email) para notificar del fallo.
    }
  }

  res.json({ received: true });
});

// Endpoint para listar pedidos
app.get('/api/pedidos', async (req, res) => {
  const pool = app.locals.db;
  console.log('[API] GET /api/pedidos query:', req.query);
  if (pool) {
    try {
      const clauses = [];
      const params = [];
      let i = 1;
      if (req.query.estado) { clauses.push(`status = $${i++}`); params.push(req.query.estado); }
      if (req.query.sessionId) { clauses.push(`(external_id = $${i} OR (metadata->> 'sessionId') = $${i})`); params.push(req.query.sessionId); i++; }
      const sql = `SELECT * FROM orders ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY created_at DESC`;
      const r = await pool.query(sql, params);
      const rows = r.rows.map(row => ({
        id: row.id,
        cliente: row.customer_name,
        email: row.metadata && row.metadata.email ? row.metadata.email : null,
        items: row.items,
        total: Number(row.total),
        metodoPago: row.metadata && row.metadata.metodoPago ? row.metadata.metodoPago : null,
        nota: row.metadata && row.metadata.nota ? row.metadata.nota : null,
        estado: row.status,
        paymentIntentId: row.metadata && row.metadata.paymentIntentId ? row.metadata.paymentIntentId : null,
        sessionId: row.external_id || (row.metadata && row.metadata.sessionId ? row.metadata.sessionId : null),
        fecha: row.created_at
      }));
      return res.json(rows);
    } catch (err) {
      console.error('[API] Error consultando pedidos en DB:', err);
      return res.status(500).json({ error: 'Error consultando pedidos en DB', detail: err.message });
    }
  }

  // fallback a JSON
  const pedidos = leerPedidos();
  if (req.query.estado) {
    const filtered = pedidos.filter(p => p.estado === req.query.estado);
    console.log('[API] returning', filtered.length, 'pedidos for estado=', req.query.estado);
    return res.json(filtered);
  }
  if (req.query.sessionId) {
    const filtered = pedidos.filter(p => p.sessionId === req.query.sessionId);
    console.log('[API] returning', filtered.length, 'pedidos for sessionId=', req.query.sessionId);
    return res.json(filtered);
  }
  console.log('[API] returning', pedidos.length, 'total pedidos');
  res.json(pedidos);
});

// Obtener pedido por id
app.get('/api/pedidos/:id', async (req, res) => {
  const id = Number(req.params.id);
  const pool = app.locals.db;
  if (pool) {
    try {
      const r = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
      if (!r.rows.length) return res.status(404).json({ error: 'Pedido no encontrado' });
      const row = r.rows[0];
      const pedido = {
        id: row.id,
        cliente: row.customer_name,
        email: row.metadata && row.metadata.email ? row.metadata.email : null,
        items: row.items,
        total: Number(row.total),
        metodoPago: row.metadata && row.metadata.metodoPago ? row.metadata.metodoPago : null,
        nota: row.metadata && row.metadata.nota ? row.metadata.nota : null,
        estado: row.status,
        paymentIntentId: row.metadata && row.metadata.paymentIntentId ? row.metadata.paymentIntentId : null,
        sessionId: row.external_id || (row.metadata && row.metadata.sessionId ? row.metadata.sessionId : null),
        fecha: row.created_at
      };
      return res.json(pedido);
    } catch (err) {
      console.error('[API] Error consultando pedido por id en DB:', err);
      return res.status(500).json({ error: 'Error consultando pedido en DB', detail: err.message });
    }
  }

  const pedidos = leerPedidos();
  const pedido = pedidos.find(p => p.id === id);
  console.log('[API] GET /api/pedidos/' + id + ' found=', Boolean(pedido));
  if (!pedido) return res.status(404).json({ error: 'Pedido no encontrado' });
  res.json(pedido);
});

// Endpoint de prueba para simular pago (código sin cambios)
app.post('/admin/simulate-payment', async (req, res) => {
  const { sessionId, metadata, items } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  // Simular el comportamiento del webhook
  const fakeEvent = { type: 'checkout.session.completed', data: { object: { id: sessionId, metadata: metadata || {} } } };
  // Reusar la lógica del webhook: crear pedido si no existe
  try {
    const session = fakeEvent.data.object;
    const metadata = session.metadata || {};
    let resolvedItems = items || [];
    let total = resolvedItems.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0);
    const pedidos = leerPedidos();
    const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
    const pedido = {
      id,
      cliente: metadata.cliente || 'Cliente Simulado',
      email: metadata.email || '',
      items: resolvedItems,
      total,
      estado: 'pagado',
      fecha: new Date().toISOString(),
      fechaPago: new Date().toISOString(),
      sessionId
    };
    pedidos.push(pedido);
    guardarPedidos(pedidos);

    // enviar correo si es posible
    if (mailTransport && pedido.email) {
      const html = `<h2>Comprobante de pago - Pedido #${pedido.id}</h2><p>Cliente: ${pedido.cliente}</p><ul>${pedido.items.map(i=>`<li>${i.cantidad} x ${i.nombre} - $${i.precio * i.cantidad}</li>`).join('')}</ul><p><strong>Total: $${pedido.total}</strong></p>`;
      const info = await mailTransport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@example.com', to: pedido.email, subject: `Comprobante de pago - Pedido #${pedido.id}`, html });
  console.log('Simulated payment mail sent:', info.messageId);
  if (nodemailer && nodemailer.getTestMessageUrl) console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
            if (nodemailer && nodemailer.getTestMessageUrl) console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
    }

    return res.json({ status: 'ok', pedido });
  } catch (e) {
    console.error('Error simulating payment:', e);
    return res.status(500).json({ error: 'error' });
  }
});

// Endpoint para actualizar estado (código sin cambios)
app.patch('/api/pedidos/:id', async (req, res) => {
  const id = Number(req.params.id);
  const pool = app.locals.db;
  const update = req.body || {};

  // If we have a database pool, update the DB record so GET /api/pedidos returns the same state
  if (pool) {
    try {
      const found = await pool.query('SELECT * FROM orders WHERE id = $1 LIMIT 1', [id]);
      if (!found.rows.length) return res.status(404).json({ error: 'Pedido no encontrado' });
      const row = found.rows[0];

      // Determine new values (fall back to existing DB values when not provided)
      const newStatus = update.estado || update.status || row.status;
      const newCustomer = update.cliente || row.customer_name;
      const newItems = typeof update.items !== 'undefined' ? update.items : row.items;
      const newTotal = typeof update.total !== 'undefined' ? update.total : row.total;
      const existingMetadata = row.metadata || {};
      const metadataUpdate = Object.assign({}, existingMetadata);
      if (typeof update.email !== 'undefined') metadataUpdate.email = update.email;
      if (typeof update.metodoPago !== 'undefined') metadataUpdate.metodoPago = update.metodoPago;
      if (typeof update.nota !== 'undefined') metadataUpdate.nota = update.nota;
      if (typeof update.paymentIntentId !== 'undefined') metadataUpdate.paymentIntentId = update.paymentIntentId;
      if (typeof update.sessionId !== 'undefined') metadataUpdate.sessionId = update.sessionId;

      const sql = `UPDATE orders SET status = $1, customer_name = $2, items = $3, total = $4, metadata = $5 WHERE id = $6 RETURNING *`;
      // Ensure JSON columns are passed as JSON (string) to avoid invalid input syntax
      let itemsParam = newItems;
      let metadataParam = metadataUpdate;
      try {
        // If items is already a string (bad data), try to parse it; otherwise stringify
        if (typeof newItems === 'string') {
          try { itemsParam = JSON.parse(newItems); } catch (e) { /* keep as string, will stringify below */ }
        }
        itemsParam = JSON.stringify(itemsParam);
      } catch (e) {
        itemsParam = JSON.stringify([]);
      }
      try {
        if (typeof metadataUpdate === 'string') {
          try { metadataParam = JSON.parse(metadataUpdate); } catch (e) { /* keep as string */ }
        }
        metadataParam = JSON.stringify(metadataParam);
      } catch (e) {
        metadataParam = JSON.stringify({});
      }

      const params = [newStatus, newCustomer, itemsParam, newTotal, metadataParam, id];
      let r;
      try {
        r = await pool.query(sql, params);
      } catch (err) {
        console.error('[API] Error actualizando pedido en DB:', err && err.message ? err.message : err);
        console.error('[API] UPDATE params:', { id, newStatus, newCustomer, itemsParam, newTotal, metadataParam });
        throw err;
      }
      const row2 = r.rows[0];
      const pedido = {
        id: row2.id,
        cliente: row2.customer_name,
        email: row2.metadata && row2.metadata.email ? row2.metadata.email : null,
        items: row2.items,
        total: Number(row2.total),
        metodoPago: row2.metadata && row2.metadata.metodoPago ? row2.metadata.metodoPago : null,
        nota: row2.metadata && row2.metadata.nota ? row2.metadata.nota : null,
        estado: row2.status,
        paymentIntentId: row2.metadata && row2.metadata.paymentIntentId ? row2.metadata.paymentIntentId : null,
        sessionId: row2.external_id || (row2.metadata && row2.metadata.sessionId ? row2.metadata.sessionId : null),
        fecha: row2.created_at
      };
      return res.json({ status: 'ok', pedido });
    } catch (err) {
      console.error('[API] Error actualizando pedido en DB:', err && err.message ? err.message : err);
      return res.status(500).json({ error: 'Error actualizando pedido en DB' });
    }
  }

  // Fallback to JSON file if no DB pool
  try {
    const pedidos = leerPedidos();
    const idx = pedidos.findIndex(p => p.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Pedido no encontrado' });
    pedidos[idx] = { ...pedidos[idx], ...update };
    guardarPedidos(pedidos);
    res.json({ status: 'ok', pedido: pedidos[idx] });
  } catch (e) {
    console.error('[API] Error actualizando pedido (fallback):', e);
    res.status(500).json({ error: 'Error actualizando pedido' });
  }
});

// Endpoint para notificar por correo que un pedido está listo
app.post('/api/pedidos/:id/notify', async (req, res) => {
  const id = Number(req.params.id);
  const pool = app.locals.db;
  let pedido = null;
  try {
    if (pool) {
      try {
        const r = await pool.query('SELECT * FROM orders WHERE id = $1 LIMIT 1', [id]);
        if (r.rows && r.rows.length) {
          const row = r.rows[0];
          pedido = {
            id: row.id,
            cliente: row.customer_name,
            email: row.metadata && row.metadata.email ? row.metadata.email : null,
            estado: row.status
          };
        }
      } catch (e) {
        // ignore DB lookup error and fallback to file
        console.error('Error DB lookup for notify:', e.message || e);
      }
    }
    if (!pedido) {
      const pedidos = leerPedidos();
      const found = pedidos.find(p => Number(p.id) === id);
      if (found) pedido = found;
    }

    if (!pedido) return res.status(404).json({ error: 'Pedido no encontrado' });

    if (!pedido.email) return res.status(400).json({ error: 'Pedido no tiene email asociado' });

    if (!mailTransport) return res.status(503).json({ error: 'Servicio de correo no disponible' });

    const subject = `Tu pedido #${pedido.id} está listo`;
    const text = `Hola ${pedido.cliente || ''},\n\nTu pedido #${pedido.id} ya está listo para retiro.\n\nSaludos,\nEl equipo de la cafetería`;
    const html = `<p>Hola ${pedido.cliente || ''},</p><p>Tu pedido <strong>#${pedido.id}</strong> ya está <strong>listo</strong> para retiro.</p><p>Saludos,<br/>Equipo de la cafetería</p>`;

    try {
      const info = await mailTransport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@example.com', to: pedido.email, subject, text, html });
      const preview = nodemailer && nodemailer.getTestMessageUrl ? nodemailer.getTestMessageUrl(info) : null;
      // Also attempt to send a Web Push notification to the user (if available)
      try {
        if (webpush && process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
          try {
            webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
            // Build payload
            const payload = JSON.stringify({ title: '🎉 ¡Tu Pedido está Listo!', body: `El pedido #${pedido.id} ha sido completado y está listo para ser recogido.`, url: `/success.html?pedidoId=${pedido.id}` });
            // Attempt to fetch subscription from DB/file and send (helper defined below)
            await sendNotificationByUserId(pedido.email, payload);
          } catch (wpErr) {
            console.warn('WebPush send attempt failed:', wpErr && wpErr.message ? wpErr.message : wpErr);
          }
        }
      } catch (e) {
        console.warn('Error intentando enviar Web Push (silenciado):', e && e.message ? e.message : e);
      }
      return res.json({ status: 'ok', messageId: info && info.messageId ? info.messageId : null, preview: preview });
    } catch (err) {
      console.error('Error sending notify email:', err && err.message ? err.message : err);
      return res.status(500).json({ error: 'Error enviando correo' });
    }
  } catch (err) {
    console.error('Unexpected error in notify:', err);
    return res.status(500).json({ error: 'Error interno' });
  }
});

// --- Web Push helper functions and endpoints ---
// Store subscriptions either in Postgres table `user_subscriptions` (user_id TEXT PRIMARY KEY, subscription JSON) or in a local file
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'user_subscriptions.json');
if (!fs.existsSync(SUBSCRIPTIONS_FILE)) fs.writeFileSync(SUBSCRIPTIONS_FILE, JSON.stringify({}));

async function saveSubscription(userId, subscription) {
  const pool = app.locals.db;
  if (pool) {
    try {
      // Try to create table if not exists (safe to run repeatedly)
      await pool.query(`CREATE TABLE IF NOT EXISTS user_subscriptions (user_id TEXT PRIMARY KEY, subscription JSONB, created_at TIMESTAMP DEFAULT NOW())`);
      await pool.query(`INSERT INTO user_subscriptions(user_id, subscription, created_at) VALUES($1,$2,NOW()) ON CONFLICT (user_id) DO UPDATE SET subscription = EXCLUDED.subscription, created_at = NOW()`, [String(userId), subscription]);
      return true;
    } catch (e) {
      console.warn('saveSubscription DB failed, falling back to file:', e.message || e);
    }
  }
  // fallback to file
  try {
    const raw = fs.readFileSync(SUBSCRIPTIONS_FILE, 'utf8');
    const map = JSON.parse(raw || '{}');
    map[String(userId)] = subscription;
    fs.writeFileSync(SUBSCRIPTIONS_FILE, JSON.stringify(map, null, 2));
    return true;
  } catch (e) {
    console.error('saveSubscription file write failed:', e.message || e);
    return false;
  }
}

async function getSubscription(userId) {
  const pool = app.locals.db;
  if (pool) {
    try {
      const r = await pool.query('SELECT subscription FROM user_subscriptions WHERE user_id = $1 LIMIT 1', [String(userId)]);
      if (r.rows && r.rows.length) return r.rows[0].subscription;
    } catch (e) {
      console.warn('getSubscription DB failed, falling back to file:', e.message || e);
    }
  }
  try {
    const raw = fs.readFileSync(SUBSCRIPTIONS_FILE, 'utf8');
    const map = JSON.parse(raw || '{}');
    return map[String(userId)] || null;
  } catch (e) {
    console.error('getSubscription file read failed:', e.message || e);
    return null;
  }
}

async function deleteSubscription(userId) {
  const pool = app.locals.db;
  if (pool) {
    try {
      await pool.query('DELETE FROM user_subscriptions WHERE user_id = $1', [String(userId)]);
      return true;
    } catch (e) {
      console.warn('deleteSubscription DB failed, falling back to file:', e.message || e);
    }
  }
  try {
    const raw = fs.readFileSync(SUBSCRIPTIONS_FILE, 'utf8');
    const map = JSON.parse(raw || '{}');
    delete map[String(userId)];
    fs.writeFileSync(SUBSCRIPTIONS_FILE, JSON.stringify(map, null, 2));
    return true;
  } catch (e) {
    console.error('deleteSubscription file write failed:', e.message || e);
    return false;
  }
}

async function sendNotificationByUserId(userId, payload) {
  if (!webpush) throw new Error('web-push not available');
  const sub = await getSubscription(userId);
  if (!sub) throw new Error('No subscription for user');
  try {
    await webpush.sendNotification(sub, payload);
    return true;
  } catch (e) {
    // if subscription is expired or invalid, remove it
    const code = e && e.statusCode ? e.statusCode : null;
    if (code === 410 || code === 404) {
      await deleteSubscription(userId);
    }
    throw e;
  }
}

// Endpoint to expose the VAPID public key to clients
app.get('/api/vapidPublicKey', (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) return res.status(404).json({ error: 'VAPID_PUBLIC_KEY not set' });
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// Save subscription
app.post('/api/subscribe', async (req, res) => {
  try {
    const { user_id, subscription } = req.body || {};
    if (!user_id || !subscription) return res.status(400).json({ error: 'user_id and subscription required' });
    const ok = await saveSubscription(user_id, subscription);
    if (!ok) return res.status(500).json({ error: 'Could not save subscription' });
    return res.json({ status: 'ok' });
  } catch (e) {
    console.error('/api/subscribe error', e.message || e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Trigger send notification to a specific user (internal use)
app.post('/api/send-notification/:user_id', async (req, res) => {
  try {
    if (!webpush || !process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) return res.status(501).json({ error: 'WebPush not configured' });
    const userId = req.params.user_id;
    const payload = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : JSON.stringify({ title: 'Notificación', body: 'Tienes una notificación' });
    webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
    try {
      await sendNotificationByUserId(userId, payload);
      return res.json({ status: 'ok' });
    } catch (e) {
      console.error('Error sending notification to', userId, e && e.message ? e.message : e);
      return res.status(500).json({ error: 'Error sending notification', detail: e && e.message ? e.message : String(e) });
    }
  } catch (e) {
    console.error('/api/send-notification error', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// === NUEVO ENDPOINT PARA ARCHIVAR Y LIMPIAR PEDIDOS ===
app.post('/api/pedidos/archivar', (req, res) => {
  const actor = req.session && req.session.admin ? (req.session.admin.name || req.session.admin.email || 'admin') : 'admin';
  const resultado = archivarYLimpiarPedidos(actor);
  if (resultado.archivar) {
    return res.json({
      status: 'ok',
      mensaje: `Archivados ${resultado.count} pedidos. Lista principal limpiada.`,
      archivo: path.basename(resultado.archivo),
      archived_by: resultado.payload && resultado.payload.archived_by ? resultado.payload.archived_by : null,
      archived_at: resultado.payload && resultado.payload.archived_at ? resultado.payload.archived_at : null
    });
  }
  res.json({ status: 'ok', mensaje: 'No había pedidos para archivar. Lista vacía.' });
});

// === NUEVA RUTA PARA CREAR SESIÓN DE STRIPE === (código sin cambios)
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { cliente, items, email } = req.body;

    if (!cliente || !items || !Array.isArray(items) || !email) {
      return res.status(400).json({ error: 'Faltan datos del pedido' });
    }

    // Calcular total en pesos
    const total = items.reduce((sum, item) => sum + (item.precio * item.cantidad), 0);

    // Crear sesión de pago en Stripe
    if (!stripe) return res.status(500).json({ error: 'Stripe no configurado en este entorno' });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: items.map(item => ({
        price_data: {
          currency: 'clp',
          product_data: { name: item.nombre },
          unit_amount: Math.round(Number(item.precio)), // CLP usa montos enteros. Se redondea para asegurar que sea un entero.
        },
        quantity: item.cantidad,
      })),
      mode: 'payment',
      success_url: `${process.env.BASE_URL || 'http://localhost:3000'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL || 'http://localhost:3000'}/cancel.html`,
      metadata: { cliente, email, items: JSON.stringify(items) },
    });

    // Guardar un pedido provisional en nuestro sistema (estado: 'esperando_pago')
    try {
      const pool = app.locals.db;
      // intentamos recuperar items desde la petición (si el cliente las envía en metadata) o dejamos vacías
      let items = [];
      try { if (req.body.items) items = req.body.items; } catch (e) { items = []; }
      const provisionalTotal = items.length ? items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0) : (req.body.total || 0);

      if (pool) {
        // Guardar provisional en la DB (orders.external_id = session.id)
        try {
          const metadata = { email: req.body.email || null, metodoPago: req.body.metodoPago || null, nota: req.body.nota || null, sessionId: session.id };
          const sql = `INSERT INTO orders (external_id, items, total, status, customer_name, metadata)
                       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`;
          const params = [session.id, JSON.stringify(items), provisionalTotal, 'esperando_pago', req.body.cliente || (req.body.metadata && req.body.metadata.cliente) || 'Cliente', metadata];
          const r = await pool.query(sql, params);
          const row = r.rows[0];
          console.log('[API] Pedido provisional creado en DB para Checkout session:', session.id, 'pedidoId=', row.id);
        } catch (err) {
          console.warn('[API] No se pudo crear pedido provisional en DB:', err.message);
        }
      } else {
        // Fallback JSON: crear pedido provisional en archivo
        const pedidos = leerPedidos();
        const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
        const pedido = {
          id,
          cliente: req.body.cliente || (req.body.metadata && req.body.metadata.cliente) || 'Cliente',
          email: req.body.email || (req.body.metadata && req.body.metadata.email) || '',
          items,
          total: provisionalTotal,
          estado: 'esperando_pago',
          fecha: new Date().toISOString(),
          sessionId: session.id
        };
        pedidos.push(pedido);
        guardarPedidos(pedidos);
        console.log('[API] Pedido provisional creado para Checkout session (fallback):', session.id, 'pedidoId=', pedido.id);
      }
    } catch (e) {
      console.warn('No se pudo crear pedido provisional:', e.message);
    }

    // Devolver la URL de Checkout
    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creando sesión de pago:', error);
    res.status(500).json({ error: 'No se pudo crear la sesión de pago' });
  }
});

// Endpoint para recibir webhooks de Stripe (código sin cambios)
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event = null;
  try {
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      const raw = req.rawBody || req.body;
      event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } else {
      // si no hay webhook secret, parsea el body directo (útil en desarrollo si no usas signing)
      event = req.body;
    }
  } catch (err) {
    console.error('Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const sessionId = session.id;
    const metadata = session.metadata || {};

    // Creamos el pedido definitivo al confirmarse el pago.
    // Intentamos recuperar los items desde la sesión de Stripe (si stripe está disponible)
    (async () => {
      try {
        let items = [];
        let total = 0;
        if (stripe) {
          // recuperar la sesión completa y sus line_items
          const sess = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
          if (sess && sess.line_items && sess.line_items.data) {
            items = sess.line_items.data.map(li => ({ nombre: li.description || li.price.product, cantidad: li.quantity, precio: li.price.unit_amount }));
            total = items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0);
          }
        } else {
          // si no hay Stripe (modo desarrollo), intentamos usar metadata que envió el cliente
          if (metadata.items) {
            try { items = JSON.parse(metadata.items); } catch (e) { items = []; }
            total = items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0);
          }
        }

        const pool = app.locals.db;
        // mantenemos una referencia al pedido final que usaremos para el email/envíos
        let finalPedido = null;

        if (pool) {
          try {
            // buscar pedido existente por external_id o metadata.sessionId
            const findSql = `SELECT * FROM orders WHERE external_id = $1 OR (metadata->> 'sessionId') = $1 LIMIT 1`;
            const found = await pool.query(findSql, [sessionId]);
            const metadataFromSession = Object.assign({}, metadata || {}, { sessionId });

            if (found.rows.length) {
              const existing = found.rows[0];
              // actualizar pedido existente
              const updateSql = `UPDATE orders SET items = $1, total = $2, status = $3, customer_name = $4, metadata = $5 WHERE id = $6 RETURNING *`;
              const params = [items, total || existing.total || (session.amount_total || 0), 'pagado', metadataFromSession.cliente || session.customer_details?.name || existing.customer_name, metadataFromSession, existing.id];
              const rUp = await pool.query(updateSql, params);
              const row = rUp.rows[0];
              finalPedido = {
                id: row.id,
                cliente: row.customer_name,
                email: row.metadata && row.metadata.email ? row.metadata.email : (metadataFromSession.email || session.customer_details?.email || ''),
                items: row.items,
                total: Number(row.total),
                metodoPago: row.metadata && row.metadata.metodoPago ? row.metadata.metodoPago : null,
                nota: row.metadata && row.metadata.nota ? row.metadata.nota : null,
                estado: row.status,
                paymentIntentId: row.metadata && row.metadata.paymentIntentId ? row.metadata.paymentIntentId : null,
                sessionId: row.external_id || (row.metadata && row.metadata.sessionId ? row.metadata.sessionId : null),
                fecha: row.created_at,
                fechaPago: new Date().toISOString()
              };
              console.log('[API] Pedido provisional actualizado a pagado en DB para sessionId=', sessionId, 'pedidoId=', finalPedido.id);
            } else {
              // insertar nuevo pedido en DB
              const insertSql = `INSERT INTO orders (external_id, items, total, status, customer_name, metadata) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`;
              const params = [sessionId, JSON.stringify(items), total || (session.amount_total || 0), 'pagado', metadata.cliente || session.customer_details?.name || 'Cliente', metadataFromSession];
              const rIns = await pool.query(insertSql, params);
              const row = rIns.rows[0];
              finalPedido = {
                id: row.id,
                cliente: row.customer_name,
                email: row.metadata && row.metadata.email ? row.metadata.email : (metadata.email || session.customer_details?.email || ''),
                items: row.items,
                total: Number(row.total),
                metodoPago: row.metadata && row.metadata.metodoPago ? row.metadata.metodoPago : null,
                nota: row.metadata && row.metadata.nota ? row.metadata.nota : null,
                estado: row.status,
                paymentIntentId: row.metadata && row.metadata.paymentIntentId ? row.metadata.paymentIntentId : null,
                sessionId: row.external_id || (row.metadata && row.metadata.sessionId ? row.metadata.sessionId : null),
                fecha: row.created_at,
                fechaPago: new Date().toISOString()
              };
              console.log('[API] Pedido creado desde webhook en DB para sessionId=', sessionId, 'pedidoId=', finalPedido.id);
            }
          } catch (e) {
            console.error('[API] Error creando/actualizando pedido en DB desde webhook:', e);
          }
        }

        // Si no se pudo usar DB, usamos el fallback JSON actual
        if (!finalPedido) {
          try {
            const pedidos = leerPedidos();
            const existingIdx = pedidos.findIndex(p => p.sessionId === sessionId);
            if (existingIdx !== -1) {
              pedidos[existingIdx] = {
                ...pedidos[existingIdx],
                cliente: metadata.cliente || session.customer_details?.name || pedidos[existingIdx].cliente,
                email: metadata.email || session.customer_details?.email || pedidos[existingIdx].email,
                items: items.length ? items : pedidos[existingIdx].items,
                total: total || pedidos[existingIdx].total || (session.amount_total || 0),
                estado: 'pagado',
                fechaPago: new Date().toISOString()
              };
              guardarPedidos(pedidos);
              finalPedido = pedidos[existingIdx];
              console.log('[API] Pedido provisional actualizado a pagado (fallback) para sessionId=', sessionId, 'pedidoId=', finalPedido.id);
            } else {
              const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
              const pedido = {
                id,
                cliente: metadata.cliente || session.customer_details?.name || 'Cliente',
                email: metadata.email || session.customer_details?.email || '',
                items,
                total: total || (session.amount_total || 0),
                estado: 'pagado',
                fecha: new Date().toISOString(),
                fechaPago: new Date().toISOString(),
                sessionId
              };
              pedidos.push(pedido);
              guardarPedidos(pedidos);
              finalPedido = pedido;
              console.log('[API] Pedido creado desde webhook (fallback) para sessionId=', sessionId, 'pedidoId=', pedido.id);
            }
          } catch (e) {
            console.error('Error creando pedido desde webhook (fallback):', e);
          }
        }

        // enviar correo al cliente con comprobante si está configurado
        const itemsHtml = (finalPedido.items || []).map(i => `<li>${i.cantidad} x ${i.nombre} - $${(i.precio * i.cantidad)}</li>`).join('');
        const html = `
          <h2>Comprobante de pago - Pedido #${finalPedido.id}</h2>
          <p>Cliente: ${finalPedido.cliente}</p>
          <p>Fecha: ${new Date(finalPedido.fechaPago || new Date()).toLocaleString()}</p>
          <ul>${itemsHtml}</ul>
          <p><strong>Total: $${finalPedido.total}</strong></p>
        `;

        if (mailTransport && process.env.SMTP_USER && finalPedido.email) {
          // Intentar generar PDF como comprobante si pdfkit está disponible
          const attachments = [];
          try {
            const PDFDocument = require('pdfkit');
            const doc = new PDFDocument({ margin: 40 });
            const buffers = [];
            doc.on('data', buffers.push.bind(buffers));
            const pdfEnd = new Promise((resolve) => doc.on('end', () => resolve(Buffer.concat(buffers))));

            doc.fontSize(18).text(`Comprobante de pago - Pedido #${finalPedido.id}`, { align: 'center' });
            doc.moveDown();
            doc.fontSize(12).text(`Cliente: ${finalPedido.cliente}`);
            if (finalPedido.email) doc.text(`Email: ${finalPedido.email}`);
            doc.text(`Fecha: ${new Date(finalPedido.fechaPago || new Date()).toLocaleString()}`);
            doc.moveDown();
            doc.text('Detalle de items:', { underline: true });
            (finalPedido.items || []).forEach(i => {
              doc.moveDown(0.2);
              doc.text(`${i.cantidad} x ${i.nombre} - $${(i.precio * i.cantidad)}`);
            });
            doc.moveDown();
            doc.fontSize(14).text(`Total: $${finalPedido.total}`, { bold: true });
            doc.end();

            const pdfBuffer = await pdfEnd;
            attachments.push({ filename: `comprobante_pedido_${finalPedido.id}.pdf`, content: pdfBuffer });
          } catch (e) {
            console.warn('No se pudo generar PDF (pdfkit no instalado?):', e.message);
          }

          // Enviar correo con adjunto si existe
          const mailOptions = { from: process.env.SMTP_FROM || process.env.SMTP_USER, to: finalPedido.email, subject: `Comprobante de pago - Pedido #${finalPedido.id}`, html };
          if (attachments.length) mailOptions.attachments = attachments;

          mailTransport.sendMail(mailOptions)
            .then(() => console.log('Correo enviado a', finalPedido.email))
            .catch(err => console.error('Error enviando correo:', err));
        }

      } catch (e) {
        console.error('Error creando pedido desde webhook:', e);
      }
    })();
  }

  res.json({ received: true });
});

// Servir app (código sin cambios)
// Si el puerto 3000 está ocupado en el entorno, permitimos fallback a 3001 para pruebas locales
const PORT = process.env.PORT || 3000;
if (process.env.FORCE_PORT_3001 === 'true') {
  process.env.PORT = '3001';
}
app.listen(PORT, () => {
  console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});