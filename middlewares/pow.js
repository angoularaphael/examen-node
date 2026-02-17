const crypto = require('crypto');

// Middleware de Proof of Work
function powMiddleware(logger) {
  return (req, res, next) => {
    try {
      const nonce = req.headers['x-pow-nonce'];
      const authHeader = req.headers.authorization;

      if (!nonce) {
        logger.warn('PoW - Nonce manquant', { ip: req.ip });
        return res.status(403).json({ error: 'X-POW-Nonce manquant' });
      }
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.error('PoW - Token manquant');
        return res.status(401).json({ error: 'Token manquant' });
      }
      const token = authHeader.slice(7);
      const hash = crypto.createHash('sha256')
        .update(token + nonce)
        .digest('hex');
      const difficulty = '0000';

      if (!hash.startsWith(difficulty)) {
        logger.warn('PoW - Proof of Work incorrect', { 
          hash: hash.substring(0, 10), 
          difficulty,
          nonce
        });
        return res.status(403).json({ 
          error: 'Proof of Work invalide',
          hint: `Le hash doit commencer par "${difficulty}"`
        });
      }

      logger.info('PoW - Validé', { 
        hash: hash.substring(0, 10),
        jti: req.userPayload?.jti
      });

      next();
    } catch (err) {
      logger.error('Erreur Proof of Work', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  };
}

// Utilitaire pour genérer un nonce valide
function findValidNonce(token, difficulty = '0000') {
  let nonce = 0;
  let hash;

  while (true) {
    hash = crypto.createHash('sha256')
      .update(token + nonce)
      .digest('hex');

    if (hash.startsWith(difficulty)) {
      return { nonce, hash };
    }

    nonce++;
    if (nonce > 10000000) {
      throw new Error('Nonce non trouvé après 10M tentatives');
    }
  }
}

module.exports = powMiddleware;
module.exports.findValidNonce = findValidNonce;
