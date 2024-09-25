const mongoose = require('mongoose');

const createUserScema = new mongoose.Schema({
    name: { type: String, required: [true, 'Name cannot be empty'] },
    email: { type: String, required: [true, 'Email cannot be empty'] },
    password: { type: String, required: [true, 'Password cannot be empty'] },
    verified: {}
}, {
    timestamps: true,
    collection: 'user'
})

const userScema = mongoose.model("user", createUserScema)


module.exports = userScema