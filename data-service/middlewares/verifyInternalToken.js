const { verifyInternalToken } = require('../utils/internalToken');

// Middleware pour vérifier les tokens internes (inter-microservices uniquement)
function verifyInternalTokenMiddleware(logger) {
  return (req, res, next) => {
    try {
      const internalToken = req.headers['x-internal-token'];

      if (!internalToken) {
        logger.warn('Token interne manquant', { ip: req.ip });
        return res.status(401).json({ error: 'X-INTERNAL-TOKEN manquant' });
      }

      const result = verifyInternalToken(internalToken);

      if (!result.valid) {
        logger.warn('Vérification token interne échouée', { 
          error: result.error, 
          ip: req.ip 
        });
        return res.status(401).json({ error: result.error });
      }

      req.internalPayload = result.payload;
      logger.info('Token interne vérifié', { 
        userId: result.payload.sub, 
        jti: result.payload.jti 
      });

      next();
    } catch (err) {
      logger.error('Erreur lors de la vérification interne', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  };
}

module.exports = verifyInternalTokenMiddleware;
