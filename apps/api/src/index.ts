import { app } from './app';

const PORT = parseInt(process.env.API_PORT || '4000', 10);
const HOST = '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  // Production safe logging
  process.stdout.write(`CipherVault API server running on http://${HOST}:${PORT}\n`);
});

const gracefulShutdown = (signal: string) => {
  process.stdout.write(`Received ${signal}. Shutting down gracefully...\n`);
  server.close(() => {
    process.stdout.write('Closed out remaining connections. Exiting process.\n');
    process.exit(0);
  });

  // Force close if graceful shutdown takes too long
  setTimeout(() => {
    process.stderr.write('Could not close connections in time, forcefully shutting down\n');
    process.exit(1);
  }, 10000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
