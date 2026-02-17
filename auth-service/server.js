const rateLimiter = require('./middlewares/rateLimiter');
const pow = require('./middlewares/pow');
const { verifyJWT } = require('./middlewares/auth');

app.get('/secure-data', 
    verifyJWT,    
    rateLimiter,   
    pow,           
    (req, res) => { 
        res.json({ secure: true });
    }
);