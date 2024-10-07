const asyncHandler = require('express-async-handler');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const JWT_REFRESH_KEY = process.env.JWT_REFRESH_KEY;

const authMiddleware = (req, res, next) => {
    try {
        const { accessToken } = req.body;
        const { refreshToken } = req.cookies; // Accessing refresh token from cookies


        if (!accessToken && !refreshToken) {
            return res.status(400).json({ success: false, message: "Unauthorized. Missing authentication tokens." });
        }

        jwt.verify(refreshToken, JWT_REFRESH_KEY, (err, decodedRefresh) => {
            if (err) {
                // console.error("Refresh token verification failed:", err);
                return res.status(401).json({ success: false,access:false, message: "Unauthorized, ref token" });
            }

            jwt.verify(accessToken, JWT_REFRESH_KEY, (err, decodedAccess) => {
                if (err) {
                    // console.error("Access token verification failed:", err);
                    return res.status(401).json({ success: false,access:false, message: "Unauthorized, acc token" });
                }
                req.user = decodedAccess; // Attach user info to request
                next(); // Call next middleware
            });
        });
    } catch (error) {
        // console.error("Error in auth middleware:", error);
        return res.status(400).json({ success: false, error: "Unauthorized" });
    }
};

module.exports = { authMiddleware };
