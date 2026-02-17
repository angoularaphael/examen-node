const crypto = require('crypto');

const SECRET = process.env.SECRET;
const PEPPER_SECONDARY = process.env.PEPPER_SECONDARY;

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

// Récupère la clé de signature pour les tokens internes
function getInternalSigningKey() {
  return SECRET + PEPPER_SECONDARY;
}

// Crée un token interne pour la communication inter-microservices
function createInternalToken(userId, expiresIn = 300) {
  try {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    const now = Math.floor(Date.now() / 1000);
    
    const payload = {
      sub: userId,
      iat: now,
      exp: now + expiresIn,
      jti: crypto.randomUUID(),
      internal: true
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    const hmac = crypto.createHmac('sha256', getInternalSigningKey());
    hmac.update(signatureInput);
    const signature = base64UrlEncode(hmac.digest());

    const token = `${encodedHeader}.${encodedPayload}.${signature}`;

    return {
      token,
      payload
    };
  } catch (err) {
    throw new Error(`Erreur création token interne: ${err.message}`);
  }
}

// Vérifie un token interne
function verifyInternalToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Format invalide' };
    }

    const [encodedHeader, encodedPayload, receivedSignature] = parts;
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    const hmac = crypto.createHmac('sha256', getInternalSigningKey());
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

    if (!payload.internal) {
      return { valid: false, error: 'Token non interne - accès refusé' };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

module.exports = {
  createInternalToken,
  verifyInternalToken,
  base64UrlEncode,
  base64UrlDecode,
  getInternalSigningKey
};
