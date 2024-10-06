const mongoose = require('mongoose');
require('dotenv').config()

async function connect() {
    try {
        const conn = await mongoose.connect(process.env.MONGO_CONNECTION_URL)
        console.log('enstablish db connection on',conn?.connection?.host);
    } catch (error) {
     console.log(error);   
     process.exit(1)
    }
}

module.exports = connect