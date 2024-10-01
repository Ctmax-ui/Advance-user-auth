const userScema = require("../model/userScema");
const asyncHandler = require('express-async-handler');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const JWT_REFRESH_KEY = process.env.JWT_REFRESH_KEY

// @ for creating user {"userName":"jitu", "userEmail":"jitu@gmail.com","password":"hi","passwordConfirm":"hi"}
const setUser = asyncHandler(async (req, res) => {
    try {
        const { userName, userEmail, password } = req.body;

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt)
        const newUser = await userScema.create({
            username: userName,
            email: userEmail,
            password: hashedPassword
        });
        res.status(201).json({
            success: true,
            message: "Registered successfully!",
            user: { id: newUser._id, username: newUser.username, email: newUser.email }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Server error." });
    }
})

// @ for login user
const loginUser = asyncHandler(async (req, res) => {
    try {
        const { userEmail, password } = req.body;

        const foundUser = await userScema.findOne({ email: userEmail });
        if (!foundUser) {
            return res.status(400).json({ success: false, message: "User email or password is incorrect." });
        }

        // Check if the account is locked
        if (foundUser.lockoutUntil && foundUser.lockoutUntil > Date.now()) {
            const remainingTime = Math.ceil((foundUser.lockoutUntil - Date.now()) / 1000);
            return res.status(403).json({ success: false,remainingTime: remainingTime, message: 'Account is locked. Please try again later.' });
        }

        const isPasswordMatch = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordMatch) {
            foundUser.failedLoginAttempts = (foundUser.failedLoginAttempts || 0) + 1;

            // Lock the account if attempts exceed limit
            if (foundUser.failedLoginAttempts >= 5) {
                foundUser.lockoutUntil = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
            }

            await foundUser.save(); // Save the updated user info
            return res.status(400).json({ success: false, message: "User email or password is incorrect." });
        }

        // Reset failed attempts on successful login
        foundUser.failedLoginAttempts = 0;
        foundUser.lockoutUntil = null;
        await foundUser.save();

        const refreshToken = jwt.sign({ userId: foundUser._id }, JWT_REFRESH_KEY, { expiresIn: '7d' });

        // Save in local storage
        const accessToken = jwt.sign({ userId: foundUser._id }, JWT_REFRESH_KEY, { expiresIn: '15m' });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,     // Must be true to protect against XSS attacks
            secure: false,      // Set to true in production if using HTTPS
            sameSite: 'Strict', // Strict mode for better security
            maxAge: 24 * 60 * 60 * 1000, // One day
            path: "/",
        });

        res.status(200).json({ success: true, accessToken: accessToken });
    } catch (err) {
        console.error(err); // Log the error for debugging
        res.status(500).json({ success: false, error: "Server error." });
    }
});


// for genarating access token
const refreshToken = (req, res) => {
    // console.log(req);
    const { refreshToken } = req.cookies;
    try {
        if (!refreshToken) return res.status(401).json({ error: "Unauthorized" });

        jwt.verify(refreshToken, JWT_REFRESH_KEY, (err, user) => {
            if (err) return res.status(403).json({ success: false, error: "Invalid refresh token" });

            const newAccessToken = jwt.sign({ userId: user.userId, password: user.password }, JWT_REFRESH_KEY, { expiresIn: '20s' });

            res.json({ success: true, accessToken: newAccessToken });
        });
    } catch (error) {

    }
};

// for logout user
const logout = (req, res) => {
    // console.log(res, "line 84");
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: false,
        sameSite: 'Strict',
        path: "/"
    });

    res.status(200).json({ success: true, message: "Logged out successfully" });
};


const userHasAccess = (req, res) => {
    res.json({success:true,message:"you has access", access:true})
}



// @ for genarating user update token with it user can update their email pass or name
const getUserUpdateAuthToken = asyncHandler(async (req, res) => {
    const { userId, password } = req.body;

    try {
        if (!userId) return res.status(400).json({ error: "User ID is required." });

        const foundUser = await userScema.findById(userId);
        if (!foundUser) return res.status(404).json({ message: "User not found." });

        const isPasswordMatch = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordMatch) return res.status(403).json({ message: "Access denied. Incorrect password." });

        const token = jwt.sign({ userId: userId }, JWT_SECRET_KEY, { expiresIn: '30m' }); // Expires in 20 seconds
        res.status(200).json({ message: "Authentication successful.", token });

    } catch (err) {
        // console.error("Error during user validation:", err.message);
        res.status(500).json({ error: "Server error." });

    }
});

//  @ it will update the user in database
const updateUser = asyncHandler(async (req, res) => {
    try {
        const { userName, userEmail, password } = req.body;

        const userId = req.user.userId;

        const foundUser = await userScema.findById(userId);
        if (!foundUser) return res.status(404).json({ message: "User not found." });

        if (userName) foundUser.username = userName;
        if (userEmail) foundUser.email = userEmail;
        if (password) {
            const salt = await bcrypt.genSalt(10);
            foundUser.password = await bcrypt.hash(password, salt);
        }

        await foundUser.save();
        res.status(200).json({ message: `User updated successfully.` });
    } catch (err) {
        res.status(500).json({ error: "Server error." });
    }
})

module.exports = { setUser, loginUser, logout, refreshToken, updateUser, getUserUpdateAuthToken , userHasAccess}