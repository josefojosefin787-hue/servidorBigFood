// Script para importar products.json y pedidos.json a la base de datos.
// Uso: node scripts/import_json_to_db.js
// Requiere: DATABASE_URL en el entorno y que las tablas 'products' y 'orders' existan.
const fs = require('fs');
const path = require('path');
async function main() {
  const conn = process.env.DATABASE_URL;
  if (!conn) {
    console.error('Por favor define DATABASE_URL en el entorno.');
    process.exit(1);
  }
  const pg = require('pg');
  const Pool = pg.Pool;
  const pool = new Pool({ connectionString: conn, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
  try {
    const dataDirCandidates = [
      path.join(__dirname, '..', 'data'),
      path.join(__dirname, '..', '..', 'data'),
      path.join(__dirname, 'data')
    ];
    let dataDir = null;
    for (const c of dataDirCandidates) {
      const p1 = path.join(c, 'products.json');
      if (fs.existsSync(p1)) { dataDir = c; break; }
    }
    if (!dataDir) {
      console.error('No se encontró data/products.json. Ajusta dataDirCandidates o copia products.json en la carpeta data.');
      process.exit(2);
    }
    const productsPath = path.join(dataDir, 'products.json');
    const pedidosPath = path.join(dataDir, 'pedidos.json');

    // Importar products
    if (fs.existsSync(productsPath)) {
      const raw = fs.readFileSync(productsPath, 'utf8');
      const parsed = JSON.parse(raw);
      const products = parsed.products || [];
      console.log(`Importando ${products.length} productos desde ${productsPath}`);
      for (const p of products) {
        const metadata = p.variantes ? { variantes: p.variantes } : null;
        try {
          await pool.query(
            `INSERT INTO products (name, category, price, image, available, metadata, description)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
            [p.nombre || p.name || null, p.categoria || p.category || null, p.precio || p.price || 0, p.img || p.image || null, typeof p.disponible === 'undefined' ? true : p.disponible, metadata, p.description || null]
          );
        } catch (err) {
          console.warn('Error insertando producto:', p.nombre || p.name, err.message);
        }
      }
      console.log('Importación de productos completada.');
    } else {
      console.log('No existe', productsPath);
    }

    // Importar pedidos
    if (fs.existsSync(pedidosPath)) {
      const raw2 = fs.readFileSync(pedidosPath, 'utf8');
      const pedidos = JSON.parse(raw2);
      console.log(`Importando ${pedidos.length} pedidos desde ${pedidosPath}`);
      for (const ped of pedidos) {
        try {
          const items = ped.items || [];
          const total = ped.total || items.reduce((s, it) => s + (Number(it.precio || it.price || 0) * Number(it.cantidad || it.qty || 1)), 0);
          const metadata = { nota: ped.nota || null, metodoPago: ped.metodoPago || null, paymentIntentId: ped.paymentIntentId || null, sessionId: ped.sessionId || null, email: ped.email || null };
          await pool.query(
            `INSERT INTO orders (external_id, items, total, status, customer_name, metadata, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
            [ped.sessionId || null, items, total, ped.estado || 'pendiente', ped.cliente || null, metadata, ped.fecha ? new Date(ped.fecha) : new Date()]
          );
        } catch (err) {
          console.warn('Error insertando pedido id=', ped.id, err.message);
        }
      }
      console.log('Importación de pedidos completada.');
    } else {
      console.log('No existe', pedidosPath);
    }

    console.log('Importación finalizada. Revisa la base de datos para validar.');
  } catch (err) {
    console.error('Error en el proceso:', err);
    process.exit(3);
  } finally {
    await pool.end();
  }
}

main();
