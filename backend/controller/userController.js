const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY

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
            message: "User registered successfully!",
            user: { id: newUser._id, username: newUser.username, email: newUser.email }
        });
    } catch (err) {
        res.status(500).send("Server error.");
    }
})

// for genarating user update token

const getUserUpdateAuthToken = asyncHandler(async (req, res) => {
    const { userId, password } = req.body;
    console.log(req.body);

    try {
        if (!userId) return res.status(400).send("User ID is required.");

        const foundUser = await userScema.findById(userId);
        if (!foundUser) return res.status(404).send("User not found.");

        const isPasswordMatch = await bcrypt.compare(password, foundUser.password);
        if (!isPasswordMatch) return res.status(403).send("Access denied. Incorrect password.");

        const token = jwt.sign({ userId: userId }, JWT_SECRET_KEY, { expiresIn: '20s' }); // Expires in 20 seconds
        res.status(200).json({ message: "Authentication successful.", token });
    } catch (err) {
        console.error("Error during user validation:", err.message);
        res.status(500).send("Server error.");
    }
});


const updateUser = asyncHandler(async (req, res) => {
    try {
        const { userName, userEmail, password } = req.body;

        // Get user ID from JWT Token
        const userId = req.user.userId;

        // Find the user
        const foundUser = await userScema.findById(userId);
        if (!foundUser) return res.status(404).send("User not found.");

        // Update only provided fields, keep the rest unchanged
        if (userName) foundUser.username = userName;
        if (userEmail) foundUser.email = userEmail;
        if (password) {
            
            const salt = await bcrypt.genSalt(10);
            foundUser.password = await bcrypt.hash(password, salt);
        }

        // Save updated user details
        await foundUser.save();
        res.status(200).send(`User updated successfully.`);
    } catch (err) {
        console.error("Error during user update:", err.message);
        res.status(500).send("Server error.");
    }
})

module.exports = { setUser, updateUser, getUserUpdateAuthToken }