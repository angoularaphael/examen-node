
const rateLimitMap = new Map();

module.exports = (req, res, next) => {
    const jti = req.userPayload?.jti; 
    
    if (!jti) return res.status(401).json({ error: "JTI absent" });

    const now = Date.now();
    const windowMs = 30 * 1000;
    const limit = 10;

    if (!rateLimitMap.has(jti)) {
        rateLimitMap.set(jti, { count: 1, resetTime: now + windowMs });
        return next();
    }

    const data = rateLimitMap.get(jti);

    if (now > data.resetTime) {
        data.count = 1;
        data.resetTime = now + windowMs;
        return next();
    }

    data.count++;
    if (data.count > limit) {
        return res.status(429).json({ error: "Rate limit exceeded" }); // HTTP 429 [cite: 60]
    }

    next();
};