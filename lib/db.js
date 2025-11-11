const { existsSync } = require('fs');
let poolInstance = null;

function initPool() {
  if (poolInstance) return poolInstance;
  const connectionString = process.env.DATABASE_URL;
  // En producción, es obligatorio que exista DATABASE_URL
  if (!connectionString) {
    if (process.env.NODE_ENV === 'production') {
      console.error('lib/db: NODE_ENV=production pero DATABASE_URL no definida. Abortando arranque.');
      // Forzamos la terminación para que el despliegue falle y se pueda corregir la variable en Render
      process.exit(1);
    }
    console.log('lib/db: DATABASE_URL no definida — no se inicializa pool (modo desarrollo, usar fallback JSON).');
    return null;
  }
  let pg;
  try {
    pg = require('pg');
  } catch (e) {
    console.log('lib/db: paquete pg no instalado — las funciones de DB estarán deshabilitadas.');
    return null;
  }
  const { Pool } = pg;
  try {
    poolInstance = new Pool({
      connectionString,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    console.log('lib/db: Pool de Postgres inicializado.');
    return poolInstance;
  } catch (err) {
    console.error('lib/db: Error inicializando Pool:', err && err.message ? err.message : err);
    poolInstance = null;
    return null;
  }
}

function getPool() {
  if (!poolInstance) return initPool();
  return poolInstance;
}

module.exports = { initPool, getPool };
