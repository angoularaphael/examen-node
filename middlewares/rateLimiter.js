const rateLimitMap = new Map();

// Middleware de rate limiting
function rateLimiterMiddleware(logger) {
  return (req, res, next) => {
    try {
      const jti = req.userPayload?.jti; 
      
      if (!jti) {
        logger.error('Rate Limiter - JTI absent du payload');
        return res.status(401).json({ error: 'JTI absent du token' });
      }

      const now = Date.now();
      const windowMs = 30 * 1000;
      const limit = 10;

      if (!rateLimitMap.has(jti)) {
        rateLimitMap.set(jti, { count: 1, resetTime: now + windowMs });
        logger.info('Rate limit - Première requête', { jti });
        return next();
      }

      const data = rateLimitMap.get(jti);
      if (now > data.resetTime) {
        data.count = 1;
        data.resetTime = now + windowMs;
        logger.info('Rate limit - Fenêtre réinitialisée', { jti });
        return next();
      }
      data.count++;
      
      if (data.count > limit) {
        logger.warn('Rate limit - Dépassement', { 
          jti, 
          count: data.count, 
          limit 
        });
        return res.status(429).json({ 
          error: 'Trop de requêtes - limite atteinte',
          retryAfter: Math.ceil((data.resetTime - now) / 1000)
        });
      }

      logger.info('Rate limit - Requête acceptée', { jti, count: data.count });
      next();
    } catch (err) {
      logger.error('Erreur rate limiter', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  };
}

// Nettoyage automatique des entrées expirées
function cleanupExpiredEntries() {
  const now = Date.now();
  for (const [jti, data] of rateLimitMap.entries()) {
    if (now > data.resetTime + 60000) {
      rateLimitMap.delete(jti);
    }
  }
}

setInterval(cleanupExpiredEntries, 60 * 60 * 1000);

module.exports = rateLimiterMiddleware;
