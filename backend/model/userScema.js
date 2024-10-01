const mongoose = require('mongoose');

const createUserScema = new mongoose.Schema({
    username: { type: String, required: [true, 'Name cannot be empty'] },


    email: { type: String, required: [true, 'Email cannot be empty'] },
    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, default: null },

    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date, default: null },

    twoFactorAuthentication: {type: Boolean, default: false},

    password: { type: String, required: [true, 'Password cannot be empty'] },
    passwordResetToken: { type: String, default: null },
    passwordResetOTP: { type: String, default: null }
}, {
    timestamps: true,
    collection: 'user'
})

const userScema = mongoose.model("user", createUserScema)


module.exports = userScema