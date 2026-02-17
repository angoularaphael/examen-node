const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Middlewares
const { authMiddleware, verifyJWT: verifyJWTUtil, base64UrlEncode, getSigningKey } = require('./middlewares/auth');
const rateLimiter = require('./middlewares/rateLimiter');
const powMiddleware = require('./middlewares/pow');

// Configuration
const app = express();
app.use(express.json());
const SECRET = process.env.SECRET;
const PEPPER_MAIN = process.env.PEPPER_MAIN;
const TOKEN_EXPIRY = 5 * 60; 
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; 
const PORT = process.env.PORT_AUTH || 3000;
const LOG_FILE = path.join(__dirname, 'auth.log');

// Logging - Sauvegarde des logs en fichier
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

// Blacklist - Tokens invalidés
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');

function loadBlacklist() {
  try {
    if (fs.existsSync(BLACKLIST_FILE)) {
      const data = fs.readFileSync(BLACKLIST_FILE, 'utf8');
      return new Set(JSON.parse(data));
    }
  } catch (err) {
    logger.error('Erreur chargement blacklist', { error: err.message });
  }
  return new Set();
}

function saveBlacklist(blacklist) {
  try {
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([...blacklist], null, 2));
  } catch (err) {
    logger.error('Erreur sauvegarde blacklist', { error: err.message });
  }
}

let tokenBlacklist = loadBlacklist();
logger.info('Blacklist chargée', { count: tokenBlacklist.size });

// Encodage Base64 URL-safe
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Création JWT
function createJWT(userId, type = 'access') {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = type === 'refresh' ? REFRESH_TOKEN_EXPIRY : TOKEN_EXPIRY;
  
  const payload = {
    sub: userId,
    iat: now,
    exp: now + expiresIn,
    jti: crypto.randomUUID(),
    type: type 
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const hmac = crypto.createHmac('sha256', SECRET + PEPPER_MAIN);
  hmac.update(signatureInput);
  const signature = base64UrlEncode(hmac.digest());
  const token = `${encodedHeader}.${encodedPayload}.${signature}`;

  return {
    token,
    payload
  };
}

// Vérification JWT
function verifyJWT(token) {
  return verifyJWTUtil(token, tokenBlacklist);
}

// Endpoints
app.post('/auth/login', (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      logger.warn('Login échoué - userId manquant', { ip: req.ip });
      return res.status(400).json({ error: 'Le ID de l utilisateur est requis' });
    }
    
    const { token: accessToken, payload: accessPayload } = createJWT(userId, 'access');
    const { token: refreshToken, payload: refreshPayload } = createJWT(userId, 'refresh');
    
    logger.info('Login réussi', { userId, accessJti: accessPayload.jti, refreshJti: refreshPayload.jti });
    
    res.json({
      accessToken,
      refreshToken,
      accessExpiresIn: TOKEN_EXPIRY,
      refreshExpiresIn: REFRESH_TOKEN_EXPIRY,
      jti: accessPayload.jti
    });
  } catch (err) {
    logger.error('Erreur login', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Vérification du token
app.get('/verify', authMiddleware(tokenBlacklist, logger), (req, res) => {
  try {
    res.json({ valid: true, payload: req.userPayload });
  } catch (err) {
    logger.error('Erreur verify', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Rotation de token
app.post('/auth/rotate', authMiddleware(tokenBlacklist, logger), (req, res) => {
  try {
    const { jti, sub } = req.userPayload;

    tokenBlacklist.add(jti);
    saveBlacklist(tokenBlacklist);
    const { token: newToken, payload: newPayload } = createJWT(sub, 'access');

    logger.info('Token roté', { oldJti: jti, newJti: newPayload.jti, userId: sub });

    res.json({
      token: newToken,
      expiresIn: TOKEN_EXPIRY,
      jti: newPayload.jti,
      message: 'Token rotated successfully'
    });
  } catch (err) {
    logger.error('Erreur rotation', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Refresh token
app.post('/auth/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      logger.warn('Refresh échoué - Token manquant', { ip: req.ip });
      return res.status(401).json({ error: 'Refresh token requis' });
    }

    const verifyResult = verifyJWT(refreshToken);

    if (!verifyResult.valid) {
      logger.warn('Refresh échoué', { error: verifyResult.error });
      return res.status(401).json({ error: verifyResult.error });
    }

    const { type, sub } = verifyResult.payload;

    if (type !== 'refresh') {
      logger.warn('Refresh échoué - Type incorrect', { userId: sub, type });
      return res.status(403).json({ error: 'Seul un refresh token peut être utilisé' });
    }

    const { token: newAccessToken, payload: newPayload } = createJWT(sub, 'access');

    logger.info('Access token rafraîchi', { userId: sub, newJti: newPayload.jti });

    res.json({
      accessToken: newAccessToken,
      expiresIn: TOKEN_EXPIRY,
      jti: newPayload.jti
    });
  } catch (err) {
    logger.error('Erreur refresh', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Route protégée - Auth + Rate Limit + Proof of Work
app.get('/secure-data',
  authMiddleware(tokenBlacklist, logger),
  rateLimiter(logger),
  powMiddleware(logger),
  (req, res) => {
    try {
      res.json({ 
        secure: true,
        userId: req.userPayload.sub,
        jti: req.userPayload.jti,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      logger.error('Erreur secure-data', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  }
);

// Démarrage serveur
app.listen(PORT, ()=> {
  logger.info('Serveur démarré', { port: PORT, tokenExpiry: TOKEN_EXPIRY, refreshExpiry: REFRESH_TOKEN_EXPIRY });
});
