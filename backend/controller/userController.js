const userScema = require("../model/userScema");
const asyncHandler = require('express-async-handler');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

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
        const {userEmail, password } = req.body;
        
        const foundUser = await userScema.findOne({ email:userEmail});
        if (!foundUser) return res.status(400).json({ success:false, message: "Useremail or password is incorrect." });


        const isPasswordMatch = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordMatch) return res.status(400).json({ success:false, message: "Useremail or password is incorrect." });

        const token = jwt.sign({ userId: foundUser.id, userPass:foundUser.password }, JWT_SECRET_KEY, { expiresIn: '30m' });

        res.status(201).json({success:true, sessionKey: token, });

    } catch (err) {
        res.status(400).json({ success: false, error: "Server error." });
    }
})

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

module.exports = { setUser,loginUser, updateUser, getUserUpdateAuthToken }