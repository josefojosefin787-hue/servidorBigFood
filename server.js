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
  (async () => {
    try {
      await pgPool.query(`CREATE TABLE IF NOT EXISTS order_archives (
        archive_key text PRIMARY KEY,
        archive_date date NOT NULL,
        archived_at timestamptz NOT NULL,
        archived_by text,
        orders jsonb NOT NULL,
        summary jsonb
      )`);
      await pgPool.query(`ALTER TABLE order_archives ADD COLUMN IF NOT EXISTS archive_key text`);
      await pgPool.query(`ALTER TABLE order_archives ADD COLUMN IF NOT EXISTS archive_date date`);
      await pgPool.query(`UPDATE order_archives SET archive_key = COALESCE(archive_key, archive_date::text)`);
      await pgPool.query(`ALTER TABLE order_archives ALTER COLUMN archive_key SET NOT NULL`);
      await pgPool.query(`DO $$
        BEGIN
          ALTER TABLE order_archives DROP CONSTRAINT IF EXISTS order_archives_pkey;
        EXCEPTION
          WHEN undefined_object THEN NULL;
        END $$;`);
      await pgPool.query(`ALTER TABLE order_archives ADD CONSTRAINT order_archives_pkey PRIMARY KEY (archive_key)`);
      await pgPool.query(`CREATE INDEX IF NOT EXISTS order_archives_date_idx ON order_archives (archive_date DESC)`);
      console.log('[INIT] Tabla order_archives verificada y normalizada.');
    } catch (e) {
      console.error('[INIT] No se pudo verificar/crear order_archives:', e.message || e);
    }
  })();
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

const ARCHIVE_TIMEZONE = process.env.ARCHIVE_TZ || 'America/Santiago';
const archiveDateFormatter = new Intl.DateTimeFormat('en-CA', {
  timeZone: ARCHIVE_TIMEZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit'
});

function normalizeArchiveDate(inputDate) {
  if (inputDate && /^\d{4}-\d{2}-\d{2}$/.test(String(inputDate))) return String(inputDate);
  const baseDate = inputDate ? new Date(inputDate) : new Date();
  return archiveDateFormatter.format(baseDate);
}

function generateArchiveKey(baseDateInput = null, reference = new Date()) {
  const baseDate = normalizeArchiveDate(baseDateInput);
  const safeStamp = reference.toISOString().replace(/[-:]/g, '').replace('T', '').replace('Z', '');
  return `${baseDate}_${safeStamp}`;
}

function deriveArchiveDateFromKey(key) {
  const match = String(key || '').match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : normalizeArchiveDate();
}

function resolveArchiveFile(identifier) {
  if (!identifier) return null;
  const direct = path.join(ARCHIVE_DIR, `${identifier}.json`);
  if (fs.existsSync(direct)) return direct;
  if (/^\d{4}-\d{2}-\d{2}$/.test(identifier)) {
    try {
      const files = fs.readdirSync(ARCHIVE_DIR)
        .filter(f => f.startsWith(identifier) && f.endsWith('.json'))
        .sort();
      if (files.length) return path.join(ARCHIVE_DIR, files[files.length - 1]);
    } catch (e) {
      return null;
    }
  }
  return null;
}

// ------------------------------------------------------------------
// NUEVA FUNCIÓN: Archivar pedidos del día y limpiar la lista principal
// ------------------------------------------------------------------
function asNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizeItemList(rawItems) {
  if (!rawItems) return [];
  let items = rawItems;
  if (typeof items === 'string') {
    try { items = JSON.parse(items); }
    catch (e) { return []; }
  }
  if (!Array.isArray(items)) return [];
  return items.map(it => {
    if (!it || typeof it !== 'object') return { cantidad: 1, nombre: String(it), precio: 0 };
    const cantidad = asNumber(it.cantidad ?? it.qty ?? it.quantity ?? 1, 1);
    const nombre = it.nombre || it.name || it.product_name || it.product_code || 'Producto';
    const precio = asNumber(it.precio ?? it.price ?? it.valor ?? 0, 0);
    return { cantidad, nombre, precio };
  });
}

function deriveFinancialFields(orderLike = {}) {
  const items = normalizeItemList(orderLike.items || []);
  const metadata = orderLike.metadata && typeof orderLike.metadata === 'object' ? orderLike.metadata : {};
  const subtotal = items.reduce((sum, item) => sum + (item.precio * item.cantidad), 0);
  const explicitSubtotal = asNumber(metadata.subtotal, subtotal);
  const taxAmount = asNumber(metadata.tax_amount ?? metadata.tax ?? metadata.iva ?? metadata.impuestos, 0);
  const discountAmount = asNumber(metadata.discount_amount ?? metadata.descuento ?? metadata.discount, 0);
  const explicitTotal = asNumber(orderLike.total ?? metadata.total ?? metadata.monto ?? subtotal + taxAmount - discountAmount, subtotal + taxAmount - discountAmount);
  const paymentMethod = metadata.metodoPago || metadata.payment_method || orderLike.metodoPago || orderLike.payment_method || null;
  const profitFromMeta = asNumber(metadata.profit ?? metadata.utilidad ?? metadata.margin, 0);
  const costOfGoods = asNumber(metadata.cost_of_goods ?? metadata.costo, null);
  const computedProfit = profitFromMeta || (Number.isFinite(costOfGoods) ? explicitTotal - costOfGoods : 0);
  const itemsCount = items.reduce((sum, item) => sum + item.cantidad, 0);
  return {
    items,
    subtotal: Number(explicitSubtotal.toFixed(2)),
    tax_amount: Number(taxAmount.toFixed(2)),
    discount_amount: Number(discountAmount.toFixed(2)),
    total: Number(explicitTotal.toFixed(2)),
    payment_method: paymentMethod,
    profit: Number(computedProfit.toFixed(2)),
    items_count: itemsCount,
    metadata
  };
}

function snapshotOrderData(orderRow = {}) {
  const metadata = orderRow.metadata && typeof orderRow.metadata === 'object'
    ? orderRow.metadata
    : {};

  const base = {
    id: orderRow.id || orderRow.original_order_id || null,
    external_id: orderRow.external_id || metadata.sessionId || null,
    cliente: orderRow.customer_name || orderRow.cliente || metadata.cliente || metadata.customer_name || null,
    email: orderRow.email || metadata.email || null,
    items: orderRow.items,
    total: Number(orderRow.total || orderRow.monto || metadata.total || 0),
    estado: orderRow.status || orderRow.estado || metadata.estado || 'pendiente',
    metodoPago: metadata.metodoPago || orderRow.metodoPago || null,
    payment_method: metadata.payment_method || metadata.metodoPago || orderRow.metodoPago || null,
    nota: metadata.nota || orderRow.nota || null,
    source: metadata.source || orderRow.source || null,
    paymentIntentId: metadata.paymentIntentId || orderRow.paymentIntentId || null,
    created_at: orderRow.created_at || orderRow.fecha || null,
    updated_at: orderRow.updated_at || null,
    metadata
  };

  const financials = deriveFinancialFields(base);
  return Object.assign({}, base, financials);
}

function summarizeOrders(orders = []) {
  const summary = {
    totalOrders: orders.length,
    totalAmount: 0,
    subtotal: 0,
    taxAmount: 0,
    discountAmount: 0,
    profit: 0,
    itemsSold: 0,
    byStatus: {},
    byPaymentMethod: {},
    bySource: {},
    topProducts: []
  };
  const productTotals = new Map();

  orders.forEach(order => {
    const total = asNumber(order.total, 0);
    const subtotal = asNumber(order.subtotal, total);
    const tax = asNumber(order.tax_amount, 0);
    const discount = asNumber(order.discount_amount, 0);
    const profit = asNumber(order.profit, 0);
    const itemsCount = asNumber(order.items_count, (order.items || []).reduce((sum, item) => sum + asNumber(item.cantidad || item.qty || 1, 1), 0));
    summary.totalAmount += total;
    summary.subtotal += subtotal;
    summary.taxAmount += tax;
    summary.discountAmount += discount;
    summary.profit += profit;
    summary.itemsSold += itemsCount;
    const status = (order.estado || 'desconocido').toLowerCase();
    summary.byStatus[status] = (summary.byStatus[status] || 0) + 1;
    const metodo = (order.metodoPago || order.payment_method || 'desconocido').toLowerCase();
    summary.byPaymentMethod[metodo] = (summary.byPaymentMethod[metodo] || 0) + 1;
    const source = (order.source || 'desconocido').toLowerCase();
    summary.bySource[source] = (summary.bySource[source] || 0) + 1;

    (order.items || []).forEach(item => {
      const key = (item.nombre || item.name || item.product_code || 'sin_nombre').toLowerCase();
      const qty = asNumber(item.cantidad || item.qty || 1, 1);
      const amount = asNumber(item.precio || item.price || 0, 0) * qty;
      const existing = productTotals.get(key) || { nombre: key, cantidad: 0, total: 0 };
      existing.cantidad += qty;
      existing.total += amount;
      existing.nombre = item.nombre || item.name || key;
      productTotals.set(key, existing);
    });
  });

  summary.topProducts = Array.from(productTotals.values())
    .sort((a, b) => b.cantidad - a.cantidad)
    .slice(0, 10);

  summary.totalAmount = Number(summary.totalAmount.toFixed(2));
  summary.subtotal = Number(summary.subtotal.toFixed(2));
  summary.taxAmount = Number(summary.taxAmount.toFixed(2));
  summary.discountAmount = Number(summary.discountAmount.toFixed(2));
  summary.profit = Number(summary.profit.toFixed(2));
  summary.itemsSold = Number(summary.itemsSold.toFixed(2));
  return summary;
}

function startOfDay(date) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  return d;
}

function endOfDay(date) {
  const d = new Date(date);
  d.setHours(23, 59, 59, 999);
  return d;
}

function parseRangeDays(input) {
  if (!input) return 30;
  if (/^\d+$/.test(input)) return Math.max(1, Math.min(365, Number(input)));
  const match = String(input).match(/^(\d+)([dDwWmMyY])$/);
  if (!match) return 30;
  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  if (unit === 'w') return value * 7;
  if (unit === 'm') return value * 30;
  if (unit === 'y') return value * 365;
  return value;
}

function resolveDateRange(query = {}) {
  const now = new Date();
  const toDate = query.to ? new Date(query.to) : now;
  let fromDate;
  if (query.from) {
    fromDate = new Date(query.from);
  } else {
    const days = parseRangeDays(query.range || query.days || query.period || '30');
    fromDate = new Date(toDate);
    fromDate.setDate(fromDate.getDate() - (days - 1));
  }
  if (isNaN(fromDate) || isNaN(toDate)) {
    throw new Error('Rango inválido. Usa fechas ISO (YYYY-MM-DD) o range=30d');
  }
  return { from: startOfDay(fromDate), to: endOfDay(toDate) };
}

function readArchivedOrdersFromFiles() {
  if (!fs.existsSync(ARCHIVE_DIR)) return [];
  const files = fs.readdirSync(ARCHIVE_DIR).filter(f => f.endsWith('.json'));
  const collected = [];
  for (const filename of files) {
    try {
      const raw = fs.readFileSync(path.join(ARCHIVE_DIR, filename));
      const obj = JSON.parse(raw);
      const archiveKey = obj.archive_key || filename.replace(/\.json$/, '');
      const archiveDate = obj.archive_date || deriveArchiveDateFromKey(archiveKey);
      const archivedAt = obj.archived_at || null;
      const orders = Array.isArray(obj.orders) ? obj.orders : [];
      orders.forEach(order => {
        const enriched = Object.assign({}, order, {
          archived_at: order.archived_at || archivedAt,
          metadata: Object.assign({}, order.metadata || {}, { archive_date: archiveDate, archive_key: archiveKey })
        });
        collected.push(snapshotOrderData(enriched));
      });
    } catch (e) {
      console.warn('[ARCHIVE] No se pudo leer archivo', filename, e.message || e);
    }
  }
  return collected;
}

function getOrderTimestamp(order) {
  const raw = order && (order.archived_at || order.created_at || order.fecha || (order.metadata && (order.metadata.archived_at || order.metadata.created_at)));
  const date = raw ? new Date(raw) : new Date();
  return isNaN(date) ? new Date() : date;
}

function detectItemCategory(item) {
  if (!item || typeof item !== 'object') return 'Sin categoría';
  return (item.categoria || item.category || item.cat || (item.metadata && (item.metadata.categoria || item.metadata.category)) || 'Sin categoría').trim() || 'Sin categoría';
}

function archivarYLimpiarPedidos(archived_by = 'system', archiveDateInput = null) {
  const pedidosActuales = leerPedidos();
  if (pedidosActuales.length === 0) {
    console.log('No hay pedidos para archivar.');
    return { archivar: false, count: 0 };
  }

  const fecha = normalizeArchiveDate(archiveDateInput);
  const now = new Date();
  const archiveKey = generateArchiveKey(fecha, now);
  const archivoArchivado = path.join(ARCHIVE_DIR, `${archiveKey}.json`);
  const ordersSnapshot = pedidosActuales.map(p => snapshotOrderData(p));
  const summary = summarizeOrders(ordersSnapshot);
  const payload = {
    archive_date: fecha,
    archive_key: archiveKey,
    archived_at: now.toISOString(),
    archived_by: archived_by || 'system',
    orders: ordersSnapshot,
    summary
  };
  fs.writeFileSync(archivoArchivado, JSON.stringify(payload, null, 2));

  guardarPedidos([]);
  console.log(`Archivados ${ordersSnapshot.length} pedidos en ${archivoArchivado} y limpiada la lista principal.`);
  return { archivar: true, count: ordersSnapshot.length, archivo: archivoArchivado, payload };
}

async function archiveOrdersInDb(pool, actor, archiveDate) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const selectSql = `SELECT * FROM orders ORDER BY created_at ASC`;
    const r = await client.query(selectSql);
    if (!r.rows || r.rows.length === 0) {
      await client.query('ROLLBACK');
      return { archived: 0, archive_date: archiveDate, archived_at: null, summary: null };
    }

    const now = new Date();
    const archivedAt = now.toISOString();
    const archiveKey = generateArchiveKey(archiveDate, now);
    const ordersSnapshot = r.rows.map(row => snapshotOrderData(row));
    const summary = summarizeOrders(ordersSnapshot);
    const insertSql = `INSERT INTO archived_orders (
        original_order_id,
        items,
        subtotal,
        tax_amount,
        discount_amount,
        total,
        profit,
        payment_method,
        metadata,
        archived_at
      ) VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)`;

    for (const snap of ordersSnapshot) {
      const metadataObj = Object.assign({}, snap.metadata || {}, {
        archived_by: actor,
        original_order_id: snap.id,
        archive_date: archiveDate,
        archive_key: archiveKey,
        order_snapshot: snap
      });
      const params = [
        null,
        JSON.stringify(snap.items || []),
        snap.subtotal || 0,
        snap.tax_amount || 0,
        snap.discount_amount || 0,
        snap.total || 0,
        snap.profit || 0,
        snap.payment_method || null,
        JSON.stringify(metadataObj),
        archivedAt
      ];
      await client.query(insertSql, params);
    }

    const upsertArchiveList = `INSERT INTO order_archives (archive_key, archive_date, archived_at, archived_by, orders, summary)
      VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)
      ON CONFLICT (archive_key)
      DO UPDATE SET archive_date = EXCLUDED.archive_date, archived_at = EXCLUDED.archived_at, archived_by = EXCLUDED.archived_by,
        orders = EXCLUDED.orders, summary = EXCLUDED.summary`;
    await client.query(upsertArchiveList, [archiveKey, archiveDate, archivedAt, actor, JSON.stringify(ordersSnapshot), JSON.stringify(summary)]);

    await client.query('DELETE FROM orders');
    await client.query('COMMIT');

    return { archived: ordersSnapshot.length, archive_date: archiveDate, archive_key: archiveKey, archived_at: archivedAt, summary };
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    throw e;
  } finally {
    client.release();
  }
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

  const normalizeBool = (value) => {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      const v = value.trim().toLowerCase();
      if (['true', '1', 'yes', 'si', 'on'].includes(v)) return true;
      if (['false', '0', 'no', 'off'].includes(v)) return false;
    }
    return null;
  };
  const availabilityFilter = (() => {
    const explicit = normalizeBool(req.query.available);
    if (explicit !== null) return explicit;
    const onlyAvailable = normalizeBool(req.query.onlyAvailable);
    if (onlyAvailable === true) return true;
    return null;
  })();

  if (pool) {
    const conditions = [];
    const params = [];
    let idx = 1;
    if (categoria) {
      conditions.push(`category = $${idx++}`);
      params.push(categoria);
    }
    if (availabilityFilter !== null) {
      conditions.push(`available = $${idx++}`);
      params.push(availabilityFilter);
    }
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `SELECT * FROM products ${whereClause} ORDER BY id`;
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
    let list = data.products || [];
    if (categoria) {
      list = list.filter(p => p.categoria === categoria);
    }
    if (availabilityFilter !== null) {
      list = list.filter(p => {
        const value = typeof p.disponible === 'undefined' ? true : !!p.disponible;
        return value === availabilityFilter;
      });
    }
    return res.json(list);
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
  const requestedDate = req.body && req.body.date ? String(req.body.date) : null;
  const archiveDate = normalizeArchiveDate(requestedDate);
  const actor = req.session && req.session.admin ? (req.session.admin.name || req.session.admin.email || 'admin') : 'admin';

  if (!pool) {
    try {
      const result = archivarYLimpiarPedidos(actor, archiveDate);
      return res.json({ ok: true, method: 'file', archive_date: archiveDate, archived_at: result.payload.archived_at, archived: result.count, summary: result.payload.summary });
    } catch (e) {
      console.error('Error archivando pedidos (file):', e);
      return res.status(500).json({ ok: false, error: e.message });
    }
  }

  try {
    const result = await archiveOrdersInDb(pool, actor, archiveDate);
    if (!result.archived) return res.json({ ok: true, archived: 0, archive_date: archiveDate, message: 'No hay pedidos activos para archivar' });
    return res.json({ ok: true, ...result });
  } catch (e) {
    console.error('Error archivando pedidos (db):', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
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
          return {
            date: f.replace(/\.json$/, ''),
            count: orders.length,
            archived_by: obj.archived_by || 'system',
            archived_at: obj.archived_at || null,
            summary: obj.summary || null,
            file: f
          };
        } catch (e) {
          return { date: f.replace(/\.json$/, ''), count: 0, archived_by: null, file: f };
        }
      }).sort((a,b)=> b.date.localeCompare(a.date));
      return res.json({ ok: true, method: 'file', archives: list });
    } catch (e) { return res.status(500).json({ ok: false, error: e.message }); }
  }

  // DB-based: preferir tabla order_archives con snapshot completo
  try {
    const q = `SELECT archive_date::text AS date, archived_at, archived_by, jsonb_array_length(orders)::int AS count, summary
      FROM order_archives ORDER BY archive_date DESC`;
    const r = await pool.query(q);
    return res.json({ ok: true, method: 'db', archives: r.rows });
  } catch (e) {
    console.error('Error listando order_archives, intentando fallback en archived_orders:', e.message || e);
    try {
      const fallbackQ = `SELECT to_char(archived_at::date, 'YYYY-MM-DD') AS date, count(*)::int AS count
        FROM archived_orders GROUP BY date ORDER BY date DESC`;
      const r = await pool.query(fallbackQ);
      const fallbackArchives = r.rows.map(row => ({
        archive_key: row.date,
        date: row.date,
        count: row.count,
        archived_at: null,
        archived_by: null,
        summary: null
      }));
      return res.json({ ok: true, method: 'db-fallback', archives: fallbackArchives });
    } catch (err) {
      console.error('Error listando archives (fallback):', err.message || err);
      return res.status(500).json({ ok:false, error: err.message });
    }
  }
});


// GET /api/admin/archives/:id (acepta clave completa o fecha base)
app.get('/api/admin/archives/:id', async (req, res) => {
  const pool = app.locals.db;
  const identifier = String(req.params.id || '').trim();
  if (!identifier) return res.status(400).json({ ok:false, error: 'Identificador de archivo requerido' });
  const isDateOnly = /^\d{4}-\d{2}-\d{2}$/.test(identifier);

  if (!pool) {
    const filePath = resolveArchiveFile(identifier);
    if (!filePath) return res.status(404).json({ ok:false, error: 'Archivo de archive no encontrado' });
    try {
      const raw = fs.readFileSync(filePath);
      const obj = JSON.parse(raw);
      const orders = Array.isArray(obj.orders) ? obj.orders : [];
      const archiveKey = obj.archive_key || identifier;
      const archiveDate = obj.archive_date || deriveArchiveDateFromKey(archiveKey);
      return res.json({ ok: true, method: 'file', archive_key: archiveKey, date: archiveDate, archived_at: obj.archived_at || null, archived_by: obj.archived_by || null, summary: obj.summary || null, orders });
    } catch (e) { return res.status(500).json({ ok:false, error: e.message }); }
  }

  try {
    const baseQuery = `SELECT archive_key, archive_date::text AS date, archived_at, archived_by, orders, summary FROM order_archives`;
    let row = null;
    const byKey = await pool.query(`${baseQuery} WHERE archive_key = $1 LIMIT 1`, [identifier]);
    if (byKey.rows && byKey.rows.length) {
      row = byKey.rows[0];
    } else if (isDateOnly) {
      const byDate = await pool.query(`${baseQuery} WHERE archive_date = $1 ORDER BY archived_at DESC LIMIT 1`, [identifier]);
      if (byDate.rows && byDate.rows.length) row = byDate.rows[0];
    }
    if (row) {
      return res.json({ ok: true, method: 'db', archive_key: row.archive_key, date: row.date, archived_at: row.archived_at, archived_by: row.archived_by, summary: row.summary || null, orders: row.orders || [] });
    }
    // fallback to archived_orders if order_archives entry missing
    const fallbackParams = isDateOnly ? [identifier] : [identifier];
    const fallbackQ = isDateOnly
      ? `SELECT original_order_id, items, total, archived_at, metadata FROM archived_orders WHERE DATE(archived_at) = $1 ORDER BY archived_at DESC`
      : `SELECT original_order_id, items, total, archived_at, metadata FROM archived_orders WHERE metadata->>'archive_key' = $1 ORDER BY archived_at DESC`;
    const fallbackRows = await pool.query(fallbackQ, fallbackParams);
    if (!fallbackRows.rows.length) {
      return res.status(404).json({ ok:false, error: 'Archivo no encontrado' });
    }
    const archiveDate = isDateOnly ? identifier : deriveArchiveDateFromKey(identifier);
    const orders = fallbackRows.rows.map(row => {
      if (row.metadata && row.metadata.order_snapshot) return row.metadata.order_snapshot;
      return snapshotOrderData({
        id: row.original_order_id,
        items: row.items,
        total: row.total,
        status: row.metadata && row.metadata.status,
        customer_name: row.metadata && row.metadata.customer_name,
        metadata: Object.assign({}, row.metadata, { archive_key: row.metadata?.archive_key || identifier, archive_date: archiveDate }),
        created_at: row.archived_at
      });
    });
    return res.json({ ok: true, method: 'db-fallback', archive_key: identifier, date: archiveDate, archived_at: orders[0]?.archived_at || null, archived_by: null, orders });
  } catch (e) { console.error('Error obteniendo archive date:', e.message || e); return res.status(500).json({ ok:false, error: e.message }); }
});


// DELETE /api/admin/archives/:id -> elimina archivo o filas archivadas para esa clave
app.delete('/api/admin/archives/:id', async (req, res) => {
  const pool = app.locals.db;
  const identifier = String(req.params.id || '').trim();
  if (!identifier) return res.status(400).json({ ok:false, error: 'Identificador requerido' });
  const isDateOnly = /^\d{4}-\d{2}-\d{2}$/.test(identifier);

  if (!pool) {
    const filePath = resolveArchiveFile(identifier);
    if (!filePath || !fs.existsSync(filePath)) return res.status(404).json({ ok:false, error: 'Archivo de archive no encontrado' });
    try {
      fs.unlinkSync(filePath);
      return res.json({ ok: true, method: 'file', id: identifier, message: 'Archivo archivado eliminado' });
    } catch (e) { return res.status(500).json({ ok:false, error: e.message }); }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let deletedKeys = [];
    const delByKey = await client.query('DELETE FROM order_archives WHERE archive_key = $1 RETURNING archive_key, archive_date', [identifier]);
    deletedKeys = delByKey.rows.map(row => row.archive_key);
    if (!deletedKeys.length && isDateOnly) {
      const delByDate = await client.query('DELETE FROM order_archives WHERE archive_date = $1 RETURNING archive_key', [identifier]);
      deletedKeys = delByDate.rows.map(row => row.archive_key);
    }
    let delOrders;
    if (deletedKeys.length) {
      delOrders = await client.query('DELETE FROM archived_orders WHERE metadata->>archive_key = ANY($1)', [deletedKeys]);
    } else if (isDateOnly) {
      delOrders = await client.query('DELETE FROM archived_orders WHERE DATE(archived_at) = $1', [identifier]);
    } else {
      delOrders = { rowCount: 0 };
    }
    await client.query('COMMIT');
    return res.json({ ok: true, method: 'db', id: identifier, deleted_lists: deletedKeys.length, deleted_orders: delOrders.rowCount || 0 });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('Error eliminando archived_orders/order_archives:', e.message || e);
    return res.status(500).json({ ok:false, error: e.message });
  } finally {
    client.release();
  }
});


// ------------------------------------------------------------------
// Estadísticas para el panel de administración
// ------------------------------------------------------------------
app.get('/api/admin/stats/overview', async (req, res) => {
  let range;
  try {
    range = resolveDateRange(req.query || {});
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  const pool = app.locals.db;
  const fromISO = range.from.toISOString();
  const toISO = range.to.toISOString();

  if (!pool) {
    const orders = readArchivedOrdersFromFiles();
    const filtered = orders.filter(order => {
      const when = new Date(order.archived_at || order.created_at || order.fecha || order.metadata?.archived_at || Date.now());
      return when >= range.from && when <= range.to;
    });
    const summary = summarizeOrders(filtered);
    const paymentMap = new Map();
    const ordersByDayMap = new Map();
    filtered.forEach(order => {
      const method = (order.payment_method || order.metodoPago || 'desconocido').toLowerCase();
      const current = paymentMap.get(method) || { payment_method: method, orders: 0, total: 0 };
      current.orders += 1;
      current.total += asNumber(order.total, 0);
      paymentMap.set(method, current);
      const dateKey = new Date(order.archived_at || order.created_at || order.fecha || Date.now()).toISOString().slice(0, 10);
      const dayRow = ordersByDayMap.get(dateKey) || { date: dateKey, orders: 0, total: 0, items: 0 };
      dayRow.orders += 1;
      dayRow.total += asNumber(order.total, 0);
      dayRow.items += asNumber(order.items_count, (order.items || []).length);
      ordersByDayMap.set(dateKey, dayRow);
    });
    const overview = {
      ordersCount: summary.totalOrders,
      totalRevenue: summary.totalAmount,
      subtotal: summary.subtotal,
      taxAmount: summary.taxAmount,
      discountAmount: summary.discountAmount,
      profit: summary.profit,
      itemsSold: summary.itemsSold
    };
    const paymentBreakdown = Array.from(paymentMap.values()).sort((a, b) => b.total - a.total);
    const ordersByDay = Array.from(ordersByDayMap.values()).sort((a, b) => a.date.localeCompare(b.date));
    return res.json({ ok: true, method: 'file', range: { from: fromISO, to: toISO }, overview, paymentBreakdown, ordersByDay });
  }

  try {
    const overviewSql = `
      SELECT
        COALESCE(SUM(subtotal),0) AS subtotal,
        COALESCE(SUM(tax_amount),0) AS tax_amount,
        COALESCE(SUM(discount_amount),0) AS discount_amount,
        COALESCE(SUM(total),0) AS total_revenue,
        COALESCE(SUM(profit),0) AS profit,
        COALESCE(SUM(items_count),0) AS items_sold,
        COUNT(*)::int AS orders_count
      FROM archived_orders
      WHERE archived_at BETWEEN $1 AND $2
    `;
    const paymentSql = `
      SELECT
        COALESCE(NULLIF(payment_method, ''), 'desconocido') AS payment_method,
        COUNT(*)::int AS orders,
        COALESCE(SUM(total),0) AS total
      FROM archived_orders
      WHERE archived_at BETWEEN $1 AND $2
      GROUP BY 1
      ORDER BY total DESC
    `;
    const ordersByDaySql = `
      SELECT
        COALESCE(order_date, archived_at::date)::text AS date,
        COUNT(*)::int AS orders,
        COALESCE(SUM(total),0) AS total,
        COALESCE(SUM(items_count),0) AS items
      FROM archived_orders
      WHERE archived_at BETWEEN $1 AND $2
      GROUP BY 1
      ORDER BY date
    `;

    const [overviewRes, paymentRes, dayRes] = await Promise.all([
      pool.query(overviewSql, [fromISO, toISO]),
      pool.query(paymentSql, [fromISO, toISO]),
      pool.query(ordersByDaySql, [fromISO, toISO])
    ]);

    const overviewRow = overviewRes.rows[0] || {};
    const overview = {
      ordersCount: Number(overviewRow.orders_count || 0),
      totalRevenue: Number(overviewRow.total_revenue || 0),
      subtotal: Number(overviewRow.subtotal || 0),
      taxAmount: Number(overviewRow.tax_amount || 0),
      discountAmount: Number(overviewRow.discount_amount || 0),
      profit: Number(overviewRow.profit || 0),
      itemsSold: Number(overviewRow.items_sold || 0)
    };

    const paymentBreakdown = paymentRes.rows.map(row => ({
      payment_method: row.payment_method || 'desconocido',
      orders: Number(row.orders || 0),
      total: Number(row.total || 0)
    }));

    const ordersByDay = dayRes.rows.map(row => ({
      date: row.date,
      orders: Number(row.orders || 0),
      total: Number(row.total || 0),
      items: Number(row.items || 0)
    }));

    return res.json({ ok: true, method: 'db', range: { from: fromISO, to: toISO }, overview, paymentBreakdown, ordersByDay });
  } catch (e) {
    console.error('Error obteniendo stats overview:', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || 'Error obteniendo estadísticas' });
  }
});

app.get('/api/admin/stats/top-products', async (req, res) => {
  let range;
  try {
    range = resolveDateRange(req.query || {});
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 50);
  const fromISO = range.from.toISOString();
  const toISO = range.to.toISOString();
  const pool = app.locals.db;

  if (!pool) {
    const orders = readArchivedOrdersFromFiles().filter(order => {
      const when = new Date(order.archived_at || order.created_at || order.fecha || Date.now());
      return when >= range.from && when <= range.to;
    });
    const productMap = new Map();
    orders.forEach(order => {
      (order.items || []).forEach(item => {
        const key = (item.nombre || item.name || 'Sin nombre').toLowerCase();
        const current = productMap.get(key) || { nombre: item.nombre || item.name || 'Sin nombre', cantidad: 0, total: 0 };
        const qty = asNumber(item.cantidad || item.qty || 1, 1);
        const price = asNumber(item.precio || item.price || 0, 0);
        current.cantidad += qty;
        current.total += qty * price;
        productMap.set(key, current);
      });
    });
    const products = Array.from(productMap.values())
      .sort((a, b) => b.total - a.total)
      .slice(0, limit)
      .map(p => ({ nombre: p.nombre, cantidad: Number(p.cantidad.toFixed(2)), total: Number(p.total.toFixed(2)) }));
    return res.json({ ok: true, method: 'file', range: { from: fromISO, to: toISO }, products });
  }

  const priceRegex = '^[-+]?[0-9]*\\.?[0-9]+$';
  try {
    const sql = `
      SELECT
        COALESCE(NULLIF(TRIM(item->>'nombre'), ''), 'Sin nombre') AS nombre,
        SUM(
          CASE WHEN (item->>'cantidad') ~ '${priceRegex}'
            THEN (item->>'cantidad')::numeric
            ELSE 1
          END
        )::float AS cantidad,
        SUM(
          (CASE WHEN (item->>'cantidad') ~ '${priceRegex}' THEN (item->>'cantidad')::numeric ELSE 1 END) *
          (CASE WHEN (item->>'precio') ~ '${priceRegex}' THEN (item->>'precio')::numeric ELSE 0 END)
        )::float AS total
      FROM archived_orders ao,
        LATERAL jsonb_array_elements(ao.items) AS item
      WHERE ao.archived_at BETWEEN $1 AND $2
      GROUP BY 1
      ORDER BY total DESC
      LIMIT $3
    `;
    const r = await pool.query(sql, [fromISO, toISO, limit]);
    const products = r.rows.map(row => ({
      nombre: row.nombre,
      cantidad: Number(row.cantidad || 0),
      total: Number(row.total || 0)
    }));
    return res.json({ ok: true, method: 'db', range: { from: fromISO, to: toISO }, products });
  } catch (e) {
    console.error('Error obteniendo top products:', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || 'Error obteniendo top products' });
  }
});

app.get('/api/admin/stats/hourly-sales', async (req, res) => {
  let range;
  try {
    range = resolveDateRange(req.query || {});
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  const pool = app.locals.db;
  const fromISO = range.from.toISOString();
  const toISO = range.to.toISOString();

  if (!pool) {
    const orders = readArchivedOrdersFromFiles().filter(order => {
      const when = getOrderTimestamp(order);
      return when >= range.from && when <= range.to;
    });
    const bucketMap = new Map();
    orders.forEach(order => {
      const when = getOrderTimestamp(order);
      when.setMinutes(0, 0, 0);
      const key = when.toISOString();
      const bucket = bucketMap.get(key) || { hour: key, orders: 0, total: 0, items: 0 };
      bucket.orders += 1;
      bucket.total += asNumber(order.total, 0);
      bucket.items += asNumber(order.items_count, (order.items || []).length);
      bucketMap.set(key, bucket);
    });
    const buckets = Array.from(bucketMap.values()).sort((a, b) => new Date(a.hour) - new Date(b.hour));
    return res.json({ ok: true, method: 'file', range: { from: fromISO, to: toISO }, buckets });
  }

  try {
    const sql = `
      SELECT
        date_trunc('hour', archived_at) AS bucket,
        COUNT(*)::int AS orders,
        COALESCE(SUM(total),0) AS total,
        COALESCE(SUM(items_count),0) AS items
      FROM archived_orders
      WHERE archived_at BETWEEN $1 AND $2
      GROUP BY 1
      ORDER BY bucket
    `;
    const r = await pool.query(sql, [fromISO, toISO]);
    const buckets = r.rows.map(row => ({
      hour: row.bucket ? new Date(row.bucket).toISOString() : null,
      orders: Number(row.orders || 0),
      total: Number(row.total || 0),
      items: Number(row.items || 0)
    }));
    return res.json({ ok: true, method: 'db', range: { from: fromISO, to: toISO }, buckets });
  } catch (e) {
    console.error('Error obteniendo hourly sales:', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || 'Error obteniendo ventas por hora' });
  }
});

app.get('/api/admin/stats/category-sales', async (req, res) => {
  let range;
  try {
    range = resolveDateRange(req.query || {});
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  const pool = app.locals.db;
  const fromISO = range.from.toISOString();
  const toISO = range.to.toISOString();
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);

  if (!pool) {
    const orders = readArchivedOrdersFromFiles().filter(order => {
      const when = getOrderTimestamp(order);
      return when >= range.from && when <= range.to;
    });
    const catMap = new Map();
    orders.forEach(order => {
      (order.items || []).forEach(item => {
        const category = detectItemCategory(item);
        const entry = catMap.get(category) || { categoria: category, unidades: 0, total: 0, pedidos: 0 };
        const qty = asNumber(item.cantidad || item.qty || 1, 1);
        const price = asNumber(item.precio || item.price || 0, 0);
        entry.unidades += qty;
        entry.total += qty * price;
        entry.pedidos += 1;
        catMap.set(category, entry);
      });
    });
    const categories = Array.from(catMap.values())
      .sort((a, b) => b.total - a.total)
      .slice(0, limit)
      .map(row => ({
        categoria: row.categoria,
        unidades: Number(row.unidades.toFixed(2)),
        total: Number(row.total.toFixed(2)),
        pedidos: row.pedidos
      }));
    return res.json({ ok: true, method: 'file', range: { from: fromISO, to: toISO }, categories });
  }

  const numberRegex = '^[-+]?[0-9]*\\.?[0-9]+$';
  try {
    const sql = `
      WITH expanded AS (
        SELECT
          ao.id,
          ao.archived_at,
          COALESCE(NULLIF(TRIM(COALESCE(
            item->>'categoria', item->>'category', item->>'cat'
          )), ''), 'Sin categoría') AS categoria,
          CASE WHEN (item->>'cantidad') ~ '${numberRegex}' THEN (item->>'cantidad')::numeric ELSE 1 END AS qty,
          CASE WHEN (item->>'precio') ~ '${numberRegex}' THEN (item->>'precio')::numeric ELSE 0 END AS price
        FROM archived_orders ao
        CROSS JOIN LATERAL jsonb_array_elements(ao.items) AS item
        WHERE ao.archived_at BETWEEN $1 AND $2
      )
      SELECT
        categoria,
        COUNT(DISTINCT id)::int AS pedidos,
        SUM(qty)::float AS unidades,
        SUM(qty * price)::float AS total
      FROM expanded
      GROUP BY categoria
      ORDER BY total DESC
      LIMIT $3
    `;
    const r = await pool.query(sql, [fromISO, toISO, limit]);
    const categories = r.rows.map(row => ({
      categoria: row.categoria,
      pedidos: Number(row.pedidos || 0),
      unidades: Number(row.unidades || 0),
      total: Number(row.total || 0)
    }));
    return res.json({ ok: true, method: 'db', range: { from: fromISO, to: toISO }, categories });
  } catch (e) {
    console.error('Error obteniendo category sales:', e.message || e);
    return res.status(500).json({ ok: false, error: e.message || 'Error obteniendo ventas por categoría' });
  }
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
      // Marcar origen por defecto como 'web' para pedidos creados desde la interfaz web
      metadata.source = metadata.source || 'web';
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
    source: 'web',
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
    // Si la petición incluye metadata con datos de pedido (ej. desde la app móvil),
    // crear un registro de pedido provisional en la misma tabla/lista que usa la web
    try {
      const pedidoMeta = metadata || {};
      // metadata may include a serialized `pedido` or fields like clientName/items
      let cliente = pedidoMeta.clientName || pedidoMeta.cliente || null;
      let items = pedidoMeta.items || pedidoMeta.pedido || null;
      // items might be a JSON string
      if (typeof items === 'string') {
        try { items = JSON.parse(items); } catch(e) { /* keep as string if not JSON */ }
      }
      const totalFromReq = Number(amount) || (pedidoMeta.amount ? Number(pedidoMeta.amount) : null);

      function normalizeItems(arr) {
        if (!Array.isArray(arr)) return [];
        return arr.map(it => {
          if (it && typeof it === 'object') {
            const qty = it.cantidad || it.qty || it.quantity || it.quantity || 1;
            const name = it.nombre || it.name || (it.product && (it.product.nombre || it.product.name)) || '';
            const price = Number(it.precio || it.price || (it.product && it.product.precio) || (it.product && it.product.price) || 0);
            return { cantidad: Number(qty), nombre: name, precio: price };
          }
          return { cantidad: 1, nombre: String(it), precio: 0 };
        });
      }

      if ((cliente || items) && totalFromReq != null) {
        const pool = app.locals.db;
        const estado = 'pendiente';
        const externalId = pedidoMeta.orderId || orderId || null;
        const metadataToStore = Object.assign({}, pedidoMeta, { paymentIntentId: pi.id });
        // marcar origen como móvil
        metadataToStore.source = metadataToStore.source || 'mobile';
        const normalizedItems = normalizeItems(items || []);
        if (pool) {
          try {
            const sql = `INSERT INTO orders (external_id, items, total, status, customer_name, metadata) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`;
            const params = [externalId, JSON.stringify(normalizedItems), totalFromReq, estado, cliente, metadataToStore];
            const r = await pool.query(sql, params);
            const row = r.rows[0];
            console.log('[API] Pedido provisional creado desde create-payment-intent en DB id=', row.id);
            // optionally attach to response
            req.createdPedido = {
              id: row.id,
              cliente: row.customer_name,
              items: row.items,
              total: Number(row.total),
              estado: row.status,
              paymentIntentId: metadataToStore.paymentIntentId,
              fecha: row.created_at
            };
          } catch (e) { console.warn('No se pudo crear pedido provisional en DB desde create-payment-intent:', e.message || e); }
        } else {
          // fallback to file-based pedidos
          try {
            const pedidos = leerPedidos();
            const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
            const pedido = {
              id,
              cliente: cliente || '',
              email: pedidoMeta.email || '',
              items: normalizedItems,
              total: totalFromReq,
              metodoPago: pedidoMeta.metodoPago || 'tarjeta',
              nota: pedidoMeta.nota || '',
              estado,
              paymentIntentId: pi.id,
              fecha: new Date().toISOString()
            };
            pedidos.push(pedido);
            guardarPedidos(pedidos);
            console.log('[API] Pedido provisional creado (fallback) id=', pedido.id);
            req.createdPedido = pedido;
          } catch (e) { console.warn('No se pudo crear pedido provisional en archivo desde create-payment-intent:', e.message || e); }
        }
      }
    } catch (e) { console.warn('Error procesando metadata para crear pedido provisional:', e && e.message ? e.message : e); }
    // Return createdPedido if available to help client/UI show the provisional order
    const resp = { clientSecret: pi.client_secret, paymentIntentId: pi.id };
    if (req.createdPedido) resp.pedido = req.createdPedido;
    res.json(resp);
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
      const pool = app.locals.db || pgPool;
      function normalizeItems(arr) {
        if (!Array.isArray(arr)) return [];
        return arr.map(it => {
          if (it && typeof it === 'object') {
            const qty = it.cantidad || it.qty || it.quantity || 1;
            const name = it.nombre || it.name || (it.product && (it.product.nombre || it.product.name)) || '';
            const price = Number(it.precio || it.price || (it.product && it.product.precio) || (it.product && it.product.price) || 0);
            return { cantidad: Number(qty), nombre: name, precio: price };
          }
          return { cantidad: 1, nombre: String(it), precio: 0 };
        });
      }

      if (pool) {
        try {
          // Check if a provisional order with this paymentIntent already exists
          const qCheck = `SELECT * FROM orders WHERE (metadata->>'paymentIntentId' = $1 OR metadata->>'payment_intent_id' = $1) LIMIT 1`;
          const chk = await pool.query(qCheck, [intent.id]);
          if (chk && chk.rows && chk.rows.length) {
            const existing = chk.rows[0];
            const updateSql = `UPDATE orders SET status = $1, updated_at = now(), metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{paymentIntentId}', to_jsonb($2::text), true) WHERE id = $3 RETURNING *`;
            const up = await pool.query(updateSql, ['completed', intent.id, existing.id]);
            console.log(`🎉 Pedido existente #${existing.id} actualizado a pagado (webhook móvil).`);
          } else {
            const normalized = normalizeItems(orderDetails.items || []);
            const sql = `INSERT INTO orders (external_id, items, total, status, customer_name, metadata) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`;
            const params = [orderDetails.orderId || null, JSON.stringify(normalized), orderDetails.amount, 'completed', orderDetails.clientName, { paymentIntentId: intent.id, source: 'mobile' }];
            const result = await pool.query(sql, params);
            console.log(`🎉 Pedido #${result.rows[0].id} guardado exitosamente en la base de datos (móvil webhook).`);
          }
        } catch (e) {
          console.error('Error guardando pedido desde webhook en DB:', e && e.message ? e.message : e);
        }
      } else {
        // fallback to file-based: check existing by paymentIntentId
        try {
          const pedidos = leerPedidos();
          const existing = pedidos.find(p => p.paymentIntentId === intent.id);
          if (existing) {
            existing.estado = 'pagado';
            existing.fecha = new Date().toISOString();
            guardarPedidos(pedidos);
            console.log(`🎉 Pedido (fallback) #${existing.id} actualizado a pagado desde webhook móvil.`);
          } else {
            const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
            const pedido = {
              id,
              cliente: orderDetails.clientName || '',
              email: '',
              items: orderDetails.items || [],
              total: orderDetails.amount || 0,
              metodoPago: 'tarjeta',
              nota: '',
              estado: 'pagado',
              paymentIntentId: intent.id,
              source: 'mobile',
              fecha: new Date().toISOString()
            };
            pedidos.push(pedido);
            guardarPedidos(pedidos);
            console.log(`🎉 Pedido (fallback) #${pedido.id} guardado desde webhook móvil.`);
          }
        } catch (e) {
          console.error('Error guardando pedido desde webhook (fallback):', e && e.message ? e.message : e);
        }
      }

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
        fecha: row.created_at,
        source: row.metadata && row.metadata.source ? row.metadata.source : null,
        metadata: row.metadata || {}
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
app.post('/api/pedidos/archivar', async (req, res) => {
  const actor = req.session && req.session.admin ? (req.session.admin.name || req.session.admin.email || 'admin') : 'admin';
  const archiveDate = normalizeArchiveDate(req.body && req.body.date ? req.body.date : null);
  const pool = app.locals.db;

  if (pool) {
    try {
      const result = await archiveOrdersInDb(pool, actor, archiveDate);
      if (!result.archived) return res.json({ status: 'ok', mensaje: 'No hay pedidos activos para archivar.' });
      return res.json({ status: 'ok', mensaje: `Archivados ${result.archived} pedidos.`, archive_date: result.archive_date, archived_at: result.archived_at, summary: result.summary });
    } catch (e) {
      console.error('/api/pedidos/archivar error (db):', e.message || e);
      return res.status(500).json({ error: 'Error archivando pedidos en DB', detail: e.message });
    }
  }

  const resultado = archivarYLimpiarPedidos(actor, archiveDate);
  if (resultado.archivar) {
    return res.json({
      status: 'ok',
      mensaje: `Archivados ${resultado.count} pedidos. Lista principal limpiada.`,
      archivo: path.basename(resultado.archivo),
      archive_date: resultado.payload.archive_date,
      archived_by: resultado.payload && resultado.payload.archived_by ? resultado.payload.archived_by : null,
      archived_at: resultado.payload && resultado.payload.archived_at ? resultado.payload.archived_at : null,
      summary: resultado.payload.summary || null
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