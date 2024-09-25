const mongoose = require('mongoose');

async function connect() {
    try {
        const conn = await mongoose.connect('mongodb://127.0.0.1:27017/user?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+2.3.1')
        console.log('enstablish db connection on',conn?.connection?.host);
    } catch (error) {
     console.log(error);   
     process.exit(1)
    }
}

module.exports = connect