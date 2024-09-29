const asyncHandler = require('express-async-handler');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
require('dotenv').config();


const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const JWT_REFRESH_KEY = process.env.JWT_REFRESH_KEY

const authMiddleware = (req, res, next) => {
    console.log(req.cookies);
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) return res.status(401).json({ success: false, message: "Unauthorized" });

        jwt.verify(refreshToken, JWT_SECRET_KEY, (err, user) => {
            if (err) return res.status(403).json({ success: false, message: "Forbidden" });

            req.user = user;
            console.log(req.user);
            next();
        });
    } catch (error) {
        console.log(error);
        res.status(400).json({success:false, error: "unauthorize"})
    }
};

module.exports = { authMiddleware }