const mongoose = require('mongoose');

const createUserScema = new mongoose.Schema({
    username: { type: String, required: [true, 'Name cannot be empty'] },

    
    email: { type: String, required: [true, 'Email cannot be empty'] },
    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, default:null},
    
    password: { type: String, required: [true, 'Password cannot be empty'] },
    passwordResetToken:{type:String, }
}, {
    timestamps: true,
    collection: 'user'
})

const userScema = mongoose.model("user", createUserScema)


module.exports = userScema