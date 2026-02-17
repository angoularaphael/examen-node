const crypto = require('crypto');

const SECRET = process.env.SECRET;
const PEPPER_MAIN = process.env.PEPPER_MAIN;

// Recupere la cle de signature
function getSigningKey() {
  return SECRET + PEPPER_MAIN;
}

// Encodage Base64 URL-safe
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Decodage Base64 URL-safe
function base64UrlDecode(str) {
  return Buffer.from(str + '==', 'base64').toString();
}

// Verifie un JWT avec signature HMAC
function verifyJWT(token, tokenBlacklist) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Format invalide' };
    }

    const [encodedHeader, encodedPayload, receivedSignature] = parts;
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const hmac = crypto.createHmac('sha256', getSigningKey());
    hmac.update(signatureInput);
    const calculatedSignature = base64UrlEncode(hmac.digest());
    if (!crypto.timingSafeEqual(
      Buffer.from(receivedSignature),
      Buffer.from(calculatedSignature)
    )) {
      return { valid: false, error: 'Signature invalide' };
    }
    const payloadJson = base64UrlDecode(encodedPayload);
    const payload = JSON.parse(payloadJson);
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { valid: false, error: 'Token expiré' };
    }
    if (tokenBlacklist.has(payload.jti)) {
      return { valid: false, error: 'Token invalidé' };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// Middleware pour verifier JWT
function authMiddleware(tokenBlacklist, logger) {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn('Auth échouée - Token manquant', { ip: req.ip });
        return res.status(401).json({ error: 'Token manquant' });
      }

      const token = authHeader.slice(7);
      const result = verifyJWT(token, tokenBlacklist);

      if (!result.valid) {
        logger.warn('Auth échouée', { error: result.error, ip: req.ip });
        return res.status(401).json({ error: result.error });
      }
      req.userPayload = result.payload;
      logger.info('Token vérifié', { userId: result.payload.sub, jti: result.payload.jti });

      next();
    } catch (err) {
      logger.error('Erreur lors de la vérification', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  };
}

module.exports = {
  verifyJWT,
  authMiddleware,
  base64UrlEncode,
  base64UrlDecode,
  getSigningKey
};
