const { existsSync } = require('fs');
let poolInstance = null;

function initPool() {
  if (poolInstance) return poolInstance;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.log('lib/db: DATABASE_URL no definida — no se inicializa pool.');
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
