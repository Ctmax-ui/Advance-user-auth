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
    console.log(req.body);
    try {
        const { userEmail, password } = req.body;

        const foundUser = await userScema.findOne({ email: userEmail });
        if (!foundUser) return res.status(400).json({ success: false, message: "Useremail or password is incorrect." });


        const isPasswordMatch = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordMatch) return res.status(400).json({ success: false, message: "Useremail or password is incorrect." });

        const accessToken = jwt.sign({ userId: foundUser._id }, JWT_SECRET_KEY, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: foundUser._id }, JWT_REFRESH_KEY, { expiresIn: '7d' });


        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 24 * 60 * 60 * 1000, //one day
        });

        res.status(200).json({ success: true, accessToken: accessToken, });

    } catch (err) {
        res.status(400).json({ success: false, error: "Server error." });
    }
});


const refreshToken = (req, res) => {
    const { refreshToken } = req.cookies;
    try {
        if (!refreshToken) return res.status(401).json({ error: "Unauthorized" });

        jwt.verify(refreshToken, JWT_REFRESH_KEY, (err, user) => {
            if (err) return res.status(403).json({ success: false, error: "Invalid refresh token" });

            const newAccessToken = jwt.sign({ userId: user.userId, password: user.password }, JWT_SECRET_KEY, { expiresIn: '15m' });

            res.json({ success: true, accessToken: newAccessToken });
        });
    } catch (error) {

    }
};


const logout = (req, res) => {
    res.clearCookie('refreshToken');
    res.json({ message: "Logged out successfully" });
};





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

module.exports = { setUser, loginUser, logout, refreshToken, updateUser, getUserUpdateAuthToken }