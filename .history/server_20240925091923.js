const express = require('express');
const app = express()
const connect = require('./backend/db/dbConnect')
const cors = require('cors')
const createUser = require("./backend/controller/userController")
const userRoutes = require('./routes/userRoutes');
connect()



app.use(cors()); 
app.use('/api',userRoutes )


app.listen(3000, ()=>{console.log('server on http://localhost:3000');})