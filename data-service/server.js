const express = require('express');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Middlewares
const verifyInternalTokenMiddleware = require('./middlewares/verifyInternalToken');

// Configuration
const app = express();
app.use(express.json());

const PORT = process.env.PORT_DATA || 3001;
const LOG_FILE = path.join(__dirname, 'data-service.log');

// Logging
function log(level, message, metadata = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    message,
    ...metadata
  };
  const logLine = JSON.stringify(logEntry);
  console.log(logLine);
  fs.appendFileSync(LOG_FILE, logLine + '\n');
}

const logger = {
  info: (message, metadata) => log('INFO', message, metadata),
  warn: (message, metadata) => log('WARN', message, metadata),
  error: (message, metadata) => log('ERROR', message, metadata)
};

// Endpoint protégé - Accepte UNIQUEMENT les tokens internes
app.get('/internal/data',
  verifyInternalTokenMiddleware(logger),
  (req, res) => {
    try {
      const { sub: userId, jti } = req.internalPayload;

      logger.info('Internal data accédé', { 
        userId, 
        jti,
        timestamp: new Date().toISOString()
      });

      res.json({
        secure: true,
        message: 'Données sécurisées du microservice',
        userId,
        jti,
        timestamp: new Date().toISOString(),
        data: {
          internalCall: true,
          service: 'data-service'
        }
      });
    } catch (err) {
      logger.error('Erreur internal data', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  }
);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'data-service' });
});

// Démarrage serveur
app.listen(PORT, () => {
  logger.info('Data-service démarré', { port: PORT });
  console.log(`Data-service listening on port ${PORT}`);
});

module.exports = app;
