import EmbeddedPostgres from 'embedded-postgres';
import path from 'path';

const dbDir = path.resolve('.pgdata');

const pg = new EmbeddedPostgres({
  port: 5432,
  databaseDir: dbDir,
  user: 'ciphervault',
  password: 'ciphervault',
  database: 'ciphervault',
});

console.log('Initializing embedded PostgreSQL in', dbDir);
try {
  await pg.initialise();
} catch (e) {
  // Already initialized is fine
}

console.log('Starting PostgreSQL server on port 5432...');
await pg.start();
console.log('PostgreSQL is running at localhost:5432 with database ciphervault');

try {
  await pg.createDatabase('ciphervault');
  console.log('Database ciphervault created or confirmed');
} catch (e) {
  // already exists
}

// Keep process running
process.on('SIGINT', async () => {
  console.log('Stopping PostgreSQL...');
  await pg.stop();
  process.exit(0);
});
