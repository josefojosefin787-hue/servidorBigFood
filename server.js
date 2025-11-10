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

let bcrypt = null;
try {
  bcrypt = require('bcrypt');
} catch (e) {
  console.warn('bcrypt no está instalado — la comparación de contraseñas seguras no estará disponible.');
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
app.use((req, res, next) => {
  try {
    const pathReq = req.path || req.originalUrl || '/';
    if (pathReq === '/admin.html' || pathReq.startsWith('/admin') || pathReq.startsWith('/api/admin')) {
      // permitir acceso a endpoints de login/verify/logout sin auth
      if (pathReq.startsWith('/api/admin') || pathReq === '/admin-login.html' || pathReq === '/verify.html') return next();
      if (!req.session || !req.session.isAuthenticated) return res.redirect('/admin-login.html');
    }
  } catch (e) { /* ignore */ }
  next();
});

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
function archivarYLimpiarPedidos() {
  const pedidosActuales = leerPedidos();
  if (pedidosActuales.length === 0) {
    console.log('No hay pedidos para archivar.');
    return { archivar: false, count: 0 };
  }

  // Generar nombre de archivo con la fecha actual (ej: 2025-10-27.json)
  const fecha = new Date().toISOString().split('T')[0];
  const archivoArchivado = path.join(ARCHIVE_DIR, `${fecha}.json`);

  // Guardar los pedidos actuales en el archivo diario
  fs.writeFileSync(archivoArchivado, JSON.stringify(pedidosActuales, null, 2));

  // Limpiar el archivo de pedidos principal
  guardarPedidos([]);
  console.log(`Archivados ${pedidosActuales.length} pedidos en ${archivoArchivado} y limpiada la lista principal.`);
  return { archivar: true, count: pedidosActuales.length, archivo: archivoArchivado };
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
      const transportOptions = {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: Number(process.env.SMTP_PORT) || 465,
        secure: process.env.SMTP_SECURE !== 'false', // Default to true unless explicitly set to 'false'
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        },
        connectionTimeout: 15000, // 15 segundos
        greetingTimeout: 10000 // 10 segundos
      };
      mailTransport = nodemailer.createTransport(transportOptions);
      console.log('SMTP transport configured with host:', transportOptions.host, 'port:', transportOptions.port, 'secure:', transportOptions.secure);
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

// Rutas de administración: login con verificación por código (2FA) usando sesiones
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y password son requeridos' });
    }
    const pool = app.locals.db;

    // --- Database Authentication ---
    if (pool) {
      try {
        const q = await pool.query('SELECT * FROM usuarios WHERE email = $1 LIMIT 1', [email]);
        let user = q.rows && q.rows.length ? q.rows[0] : null;

        if (!user) {
          const q2 = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]).catch(() => ({ rows: [] }));
          user = q2.rows && q2.rows.length ? q2.rows[0] : null;
        }

        if (user) {
          // User found, validate password
          let valid = false;
          try {
            const bcrypt = require('bcrypt');
            if (user.password) valid = await bcrypt.compare(password, user.password);
          } catch (e) {
            valid = (String(user.password || '') === String(password));
          }

          if (valid) {
            // Password is valid for DB user
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            req.session.pendingVerification = { code: verificationCode, timestamp: Date.now(), email, userId: user.id };
            
            // Send email without blocking the response
            if (mailTransport) {
              const mailOptions = { from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@example.com', to: user.email, subject: 'Código de verificación - Admin Panel', text: `Tu código de verificación es: ${verificationCode}` };
              mailTransport.sendMail(mailOptions)
                .then(info => console.log(`[mail] Verification code sent to ${user.email}. Message ID: ${info.messageId}`))
                .catch(err => console.error(`[mail] Failed to send verification code to ${user.email}:`, err.message || err));
            } else {
              console.warn(`[mail] mailTransport no configurado: code for ${email} is ${verificationCode}`);
            }
            
            return res.json({ status: 'ok', message: 'Código de verificación enviado' });
          } else {
            // IMPORTANT: If user exists in DB but password is wrong, fail immediately.
            return res.status(401).json({ error: 'Credenciales inválidas' });
          }
        }
        // If user is not found in the DB, proceed to fallback...
      } catch (e) {
        console.error('[admin] DB error during login:', e.message);
        return res.status(500).json({ error: 'Error de base de datos durante el login' });
      }
    }

    // --- Fallback Authentication (if DB not configured or user not found in DB) ---
    if (email === 'admin@gmail.com' && password === '1234') {
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      req.session.pendingVerification = { code: verificationCode, timestamp: Date.now(), email };
      
      // Send email without blocking the response
      if (mailTransport) {
        const mailOptions = { from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@example.com', to: process.env.SMTP_USER || 'ssalasg@alumnos.ceduc.cl', subject: 'Código de verificación - Admin Panel', text: `Tu código de verificación es: ${verificationCode}` };
        mailTransport.sendMail(mailOptions)
          .then(info => console.log(`[mail] Fallback verification code sent. Message ID: ${info.messageId}`))
          .catch(err => console.error('[mail] error enviando mail fallback:', err.message || err));
      } else {
        console.log(`[admin] Verification code (dev fallback): ${verificationCode}`);
      }
      return res.json({ status: 'ok', message: 'Código de verificación enviado' });
    }

    // --- All checks failed ---
    return res.status(401).json({ error: 'Credenciales inválidas' });

  } catch (err) {
    console.error('[admin] Unexpected error during login:', err);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/admin/verify', (req, res) => {
  const { code } = req.body || {};
  if (!req.session || !req.session.pendingVerification) return res.status(400).json({ error: 'No hay verificación pendiente' });
  const { code: storedCode, timestamp } = req.session.pendingVerification;
  if (Date.now() - timestamp > 10 * 60 * 1000) { delete req.session.pendingVerification; return res.status(400).json({ error: 'El código ha expirado' }); }
  if (String(code) === String(storedCode)) {
    req.session.isAuthenticated = true;
    // opcional: almacenar info del admin en sesión
    req.session.admin = { email: req.session.pendingVerification.email, id: req.session.pendingVerification.userId || null };
    delete req.session.pendingVerification;
    return res.json({ status: 'ok' });
  }
  return res.status(401).json({ error: 'Código inválido' });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Error al cerrar sesión' });
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
      capture_method: 'manual',
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
app.patch('/api/pedidos/:id', (req, res) => {
  const id = Number(req.params.id);
  const pedidos = leerPedidos();
  const idx = pedidos.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Pedido no encontrado' });
  const update = req.body;
  pedidos[idx] = { ...pedidos[idx], ...update };
  guardarPedidos(pedidos);
  res.json({ status: 'ok', pedido: pedidos[idx] });
});

// === NUEVO ENDPOINT PARA ARCHIVAR Y LIMPIAR PEDIDOS ===
app.post('/api/pedidos/archivar', (req, res) => {
  const resultado = archivarYLimpiarPedidos();
  if (resultado.archivar) {
    return res.json({
      status: 'ok',
      mensaje: `Archivados ${resultado.count} pedidos. Lista principal limpiada.`,
      archivo: path.basename(resultado.archivo)
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