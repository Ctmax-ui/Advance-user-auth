const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    handler: (req, res) => {
        const timeUntilReset = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'You have exceeded the maximum number of login attempts. Please try again later.',
            remainingTime: timeUntilReset
        });
    }
});

module.exports = { loginLimiter }