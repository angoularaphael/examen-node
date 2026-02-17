const crypto = require('crypto');
module.exports = (req, res, next) => {
    const nonce = req.headers['x-pow-nonce']; 
    const token = req.headers.authorization?.split(' ')[1];

    if (!nonce || !token) {
        return res.status(403).json({ error: "Nonce ou Token manquant" });
    }

    const hash = crypto.createHash('sha256')
                       .update(token + nonce)
                       .digest('hex');

    const difficulty = "0000"; 
    if (!hash.startsWith(difficulty)) {
        return res.status(403).json({ error: "Proof of Work incorrect" }); 
    }

    next();
};