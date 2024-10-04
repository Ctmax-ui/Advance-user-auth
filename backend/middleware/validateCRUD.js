const jwt = require("jsonwebtoken");
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY


// for creating user validation middleware
const validateCreateUserInput = (req, res, next) => {
    const { userName, userEmail, password, } = req.body;

    if (!userName || userName.trim() === '') {
        return res.status(400).json({ error: "User Name is required." });
    };
    if (!userEmail || userEmail.trim() === '') {
        return res.status(400).json({ error: "User Email is required." });
    };
    if (userEmail && !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(userEmail.trim())) {
        return res.status(400).json({ error: "please recheck the input email" })
    }
    if (!password || password.trim() === '') {
        return res.status(400).json({ error: "Password is required." });
    };


    next();
}

// for user login validation
const validateLoginUserInput = (req, res, next) => {
    const {userEmail, password, } = req.body;
    if (!userEmail || userEmail.trim() === '') {
        return res.status(400).json({ error: "User Email is required." });
    };
    if (userEmail && !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(userEmail.trim())) {
        return res.status(400).json({ error: "please recheck the input email" })
    }
    if (!password || password.trim() === '') {
        return res.status(400).json({ error: "Password is required." });
    };
    
    next()
}


// authenticate user update token
const authenticateUserUpdateToken = (req, res, next) => {
    const token = req.body.userUpdateToken;
    console.log(req.body);
    
    if (!token) return res.status(401).json({ error: "Access denied. No token provided." });


    try {
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.user = decoded; // Add user details to the request object
        next();
    } catch (err) {
        res.status(401).json({ error: "Invalid token. Please Genarate token again" });
    }
};

// for updating user validation middleware
const validateUpdateUserInput = (req, res, next) => {

    const { userName, userEmail, password } = req.body;

    if (userName && userName.length > 15) return res.status(400).json({ error: "User name is too long." });

    if (password && password.length > 30) {
        return res.status(400).json({ error: "Bro calm down, your password is way to secure within 30 characters." })
    } else if (password && password.length < 4) {
        return res.status(400).json({ error: "Your password is too short." })
    };

    if (userEmail && !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(userEmail.trim())) res.status(400).json({ error: "User email is invalid, check the Email." });

    next();
};

module.exports = { validateCreateUserInput, validateLoginUserInput, validateUpdateUserInput, authenticateUserUpdateToken }
