// Uso: node scripts/run_sql_file.js ./ruta/al/archivo.sql
// Requiere: exportar DATABASE_URL o pasar la conexión como primer argumento
const fs = require('fs');
const path = require('path');
async function main() {
  const connArg = process.argv[2];
  const fileArg = process.argv[3];
  const connectionString = connArg && connArg.startsWith('postgres') ? connArg : process.env.DATABASE_URL;
  const sqlFile = fileArg || connArg;
  if (!connectionString) {
    console.error('Falta la conexión. Exporta DATABASE_URL o pasa la connection string como primer argumento.');
    process.exit(1);
  }
  if (!sqlFile) {
    console.error('Falta la ruta al archivo SQL.');
    process.exit(1);
  }
  const pg = require('pg');
  const Pool = pg.Pool;
  const pool = new Pool({ connectionString, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
  try {
    const sql = fs.readFileSync(path.resolve(sqlFile), 'utf8');
    console.log('Ejecutando SQL desde', sqlFile);
    await pool.query(sql);
    console.log('SQL ejecutado correctamente.');
  } catch (err) {
    console.error('Error ejecutando SQL:', err);
    process.exit(2);
  } finally {
    await pool.end();
  }
}

main();
