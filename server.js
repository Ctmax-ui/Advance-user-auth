const express = require('express');
const app = express()
require('dotenv').config
const cors = require('cors');
const cookieParser = require('cookie-parser');
const connect = require('./backend/db/dbConnect')
connect()

app.use(cors({
    origin: process.env.ALLOW_CROS_TO || 'http://localhost:5173',
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());


app.use('/api/v1', require('./backend/routes/route'))

app.listen(process.env.PORT || 3000, () => { console.log(`server on http://localhost:${process.env.PORT || 3000}`); })


/* http://localhost:3000/api/v1/createuser  Post @for creating user



*/