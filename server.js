const express = require('express');
const app = express()
const connect = require('./backend/db/dbConnect')
const cors = require('cors');
const cookieParser = require('cookie-parser');
connect()

app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
})); 
app.use(express.json());
app.use(cookieParser());


app.use('/api/v1', require('./backend/routes/route') )

app.listen(3000, ()=>{console.log('server on http://localhost:3000');})


/* http://localhost:3000/api/v1/user  Post @for creating user.
{"userName":"jitu", "userEmail":"jitu@gmail.com","password":"hi"}
*/


/* http://localhost:3000/api/v1/userupdatetoken Post @for genarating user update Token.
 {"userId":"66f4fd4966bfc50cbacb8511","password":"his"}


 http://localhost:3000/api/v1/user  Put @for updating user.
 {"userUpdateToken": "", "userName": "luck", "userEmail": "loggy"}
*/


// http://localhost:3000/api/v1/loginuser post @for login user.


// http://localhost:3000/api/v1/deleteuser @for delete user.