const mongoose = require('mongoose');

const createUserScema = new mongoose.Schema({
    username: { type: String, required: [true, 'Name cannot be empty'] },


    email: { type: String, required: [true, 'Email cannot be empty'] },
    emailVerified: { type: Boolean, default: false },
    emailVerificationOTP: { type: String, default: null },

    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date, default: null },

    twoFactorAuthentication: { type: Boolean, default: false },

    password: { type: String, required: [true, 'Password cannot be empty'] },
    resetPasswordToken: { type: String, default: "" },
    resetPasswordExpires: { type: Date, default: "" },

    connectedDevices: [
        {
            _id: false,
            deviceName: { type: String, },
            ipAddress: { type: String, required: true },
            loginTime: { type: Date, default: Date.now },
        },
    ],

}, {
    timestamps: true,
    collection: 'user'
})

const userScema = mongoose.model("user", createUserScema)


module.exports = userScema