const jwt = require("jsonwebtoken");
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY

// for creating user validation middleware
const validateCreateUserInput = (req, res, next) => {
    const { userName, userEmail, password, passwordConfirm } = req.body;

    if (!userName || userName.trim() === '') {
        return res.status(400).send("User Name is required.");
    }
    if (!userEmail || userEmail.trim() === '') {
        return res.status(400).send("User Email is required.");
    }
    if (!password || password.trim() === '') {
        return res.status(400).send("Password is required.");
    }
    if (!passwordConfirm || passwordConfirm.trim() === '') {
        return res.status(400).send("Confirmation password is required.");
    }
    
    if (password !== passwordConfirm) {
        return res.status(400).send("Password and confirmation password do not match.");
    }

    next()
}

// authenticate user update token
const authenticateUserUpdateToken = (req, res, next) => {
    const token = req.body.userUpdateToken;
    if (!token) return res.status(401).send("Access denied. No token provided.");

    try {
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.user = decoded; // Add user details to the request object
        next();
    } catch (err) {
        res.status(401).send("Invalid token. Please log in again.");
    }
};

// for updating user validation middleware
const validateUpdateUserInput = (req,res,next)=>{

    // const {userId, userName, userEmail, password, sessionToken } = req.body;

    // if (!userId || userId.trim()===''){
    //     return res.status(400).send("User Id is required.");
    // }
    // if (!password || password.trim() === '') {
    //     return res.status(400).send("Password is required.");
    // }
    // if (!userName || userName.trim() === '') {
    //     return res.status(400).send("User Name is required.");
    // }
    // if (!userEmail || userEmail.trim() === '') {
    //     return res.status(400).send("User Email is required.");
    // }
    // // if (!sessionToken || sessionToken.trim() === '') {
    // //     return res.status(400).send("Confirmation password is required.");
    // // }
    next()
}

module.exports = {validateCreateUserInput, validateUpdateUserInput, authenticateUserUpdateToken}
