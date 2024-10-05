const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
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

const logoutLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
    max: 500, // limit each IP to 5 login requests per windowMs
    handler: (req, res) => {
        const timeUntilReset = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'You have exceeded the maximum number of login attempts. Please try again later.',
            remainingTime: timeUntilReset
        });
    }
});

const registerLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
    max: 7, // limit each IP to 5 login requests per windowMs
    handler: (req, res) => {
        const timeUntilReset = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'You have exceeded the maximum number of login attempts. Please try again later.',
            remainingTime: timeUntilReset
        });
    }
});
            
const passwordResetLinkLimit = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes.
    max: 5, // limit each IP to 5 login requests per windowMs.
    handler: (req, res) => {
        const timeUntilReset = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'Too many attempts. Please try again later.',
            remainingTime: timeUntilReset
        });
    }
});

const passwordResetAndUpdateLimit = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes.
    max: 5, // limit each IP to 5 login requests per windowMs.
    handler: (req, res) => {
        const timeUntilReset = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).json({
            success: false,
            message: 'too meny attempts, try again later.',
            remainingTime: timeUntilReset
        });
    }
});



module.exports = { loginLimiter, logoutLimiter,registerLimiter,passwordResetLinkLimit, passwordResetAndUpdateLimit }