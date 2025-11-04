const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config(); // 👈 carga las variables del .env
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

const app = express();
app.use(cors());
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    // store raw body for Stripe webhook verification when the route is /webhook
    if (req.originalUrl && req.originalUrl.startsWith('/webhook')) {
      req.rawBody = buf;
    }
  }
}));
app.use(express.static(path.join(__dirname)));

const DATA_DIR = path.join(__dirname, 'data');
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
  try {
    console.log('[API] GET /api/products -> PRODUCTS_FILE=', PRODUCTS_FILE, 'exists=', fs.existsSync(PRODUCTS_FILE));
    const data = leerProducts();
    const categoria = req.query.categoria;
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

// Crear nuevo producto
app.post('/api/products', (req, res) => {
  const body = req.body;
  if (!body || !body.nombre || !body.categoria || typeof body.precio === 'undefined') {
    return res.status(400).json({ error: 'Producto inválido. Requiere nombre, categoria y precio.' });
  }
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
      mailTransport = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
      console.log('SMTP transport configured.');
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

// Endpoint para crear pedido (código sin cambios)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'inicioSesion.html'));
});

app.post('/api/pedidos', (req, res) => {
  const body = req.body;
  console.log('\n[API] POST /api/pedidos recibida. Body:', JSON.stringify(body));
  if (!body || !body.cliente || !Array.isArray(body.items) || body.items.length === 0) {
    return res.status(400).json({ error: 'Formato de pedido inválido. Requiere cliente e items.' });
  }
  const pedidos = leerPedidos();
  const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
  const total = body.items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0);
  // soportar metodoPago (efectivo, junaeb, tarjeta), nota y email
  // Si viene paymentIntentId significa que se autorizó una tarjeta de garantía (capture_method: manual)
  let estado = 'pendiente';
  if (body.metodoPago && (body.metodoPago === 'efectivo' || body.metodoPago === 'junaeb')) {
    if (body.paymentIntentId) {
      estado = 'Garantizado - Pendiente de Retiro';
    } else {
      estado = 'pendiente_pago';
    }
  } else if (body.metodoPago && body.metodoPago === 'tarjeta') {
    estado = 'pendiente';
  }

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
  console.log(`[API] Pedido creado id=${pedido.id} estado=${pedido.estado} paymentIntentId=${pedido.paymentIntentId || ''}`);
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

// Endpoint para listar pedidos (código sin cambios)
app.get('/api/pedidos', (req, res) => {
  const pedidos = leerPedidos();
  console.log('[API] GET /api/pedidos query:', req.query);
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

// Obtener pedido por id (código sin cambios)
app.get('/api/pedidos/:id', (req, res) => {
  const id = Number(req.params.id);
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
          unit_amount: item.precio, // CLP usa montos enteros
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
      const pedidos = leerPedidos();
      const id = pedidos.length ? (pedidos[pedidos.length - 1].id + 1) : 1;
      // intentamos recuperar items desde la petición (si el cliente las envía en metadata) o dejamos vacías
      let items = [];
      try { if (req.body.items) items = req.body.items; } catch (e) { items = []; }
      const total = items.length ? items.reduce((s, it) => s + (Number(it.precio || 0) * Number(it.cantidad || 1)), 0) : (req.body.total || 0);
      const pedido = {
        id,
        cliente: req.body.cliente || (req.body.metadata && req.body.metadata.cliente) || 'Cliente',
        email: req.body.email || (req.body.metadata && req.body.metadata.email) || '',
        items,
        total,
        estado: 'esperando_pago',
        fecha: new Date().toISOString(),
        sessionId: session.id
      };
      pedidos.push(pedido);
      guardarPedidos(pedidos);
      console.log('[API] Pedido provisional creado para Checkout session:', session.id, 'pedidoId=', pedido.id);
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

        const pedidos = leerPedidos();
        // Si existe un pedido provisional con la misma sessionId, lo actualizamos
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
          console.log('[API] Pedido provisional actualizado a pagado para sessionId=', sessionId, 'pedidoId=', pedidos[existingIdx].id);
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
          console.log('[API] Pedido creado desde webhook para sessionId=', sessionId, 'pedidoId=', pedido.id);
        }

        // enviar correo al cliente con comprobante si está configurado
        const itemsHtml = pedido.items.map(i => `<li>${i.cantidad} x ${i.nombre} - $${(i.precio * i.cantidad)}</li>`).join('');
        const html = `
          <h2>Comprobante de pago - Pedido #${pedido.id}</h2>
          <p>Cliente: ${pedido.cliente}</p>
          <p>Fecha: ${new Date(pedido.fechaPago).toLocaleString()}</p>
          <ul>${itemsHtml}</ul>
          <p><strong>Total: $${pedido.total}</strong></p>
        `;

        if (mailTransport && process.env.SMTP_USER && pedido.email) {
          // Intentar generar PDF como comprobante si pdfkit está disponible
          const attachments = [];
          try {
            const PDFDocument = require('pdfkit');
            const doc = new PDFDocument({ margin: 40 });
            const buffers = [];
            doc.on('data', buffers.push.bind(buffers));
            const pdfEnd = new Promise((resolve) => doc.on('end', () => resolve(Buffer.concat(buffers))));

            doc.fontSize(18).text(`Comprobante de pago - Pedido #${pedido.id}`, { align: 'center' });
            doc.moveDown();
            doc.fontSize(12).text(`Cliente: ${pedido.cliente}`);
            if (pedido.email) doc.text(`Email: ${pedido.email}`);
            doc.text(`Fecha: ${new Date(pedido.fechaPago).toLocaleString()}`);
            doc.moveDown();
            doc.text('Detalle de items:', { underline: true });
            pedido.items.forEach(i => {
              doc.moveDown(0.2);
              doc.text(`${i.cantidad} x ${i.nombre} - $${(i.precio * i.cantidad)}`);
            });
            doc.moveDown();
            doc.fontSize(14).text(`Total: $${pedido.total}`, { bold: true });
            doc.end();

            const pdfBuffer = await pdfEnd;
            attachments.push({ filename: `comprobante_pedido_${pedido.id}.pdf`, content: pdfBuffer });
          } catch (e) {
            console.warn('No se pudo generar PDF (pdfkit no instalado?):', e.message);
          }

          // Enviar correo con adjunto si existe
          const mailOptions = { from: process.env.SMTP_FROM || process.env.SMTP_USER, to: pedido.email, subject: `Comprobante de pago - Pedido #${pedido.id}`, html };
          if (attachments.length) mailOptions.attachments = attachments;

          mailTransport.sendMail(mailOptions)
            .then(() => console.log('Correo enviado a', pedido.email))
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