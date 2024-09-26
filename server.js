const express = require('express');
const app = express()
const connect = require('./backend/db/dbConnect')
const cors = require('cors')
const createUser = require("./backend/controller/userController")
connect()

app.use(cors()); 
app.use(express.json());

app.use('/api/v1', require('./backend/routes/route') )

app.listen(3000, ()=>{console.log('server on http://localhost:3000');})


/* http://localhost:3000/api/v1/user  Post @for creating user
{"userName":"jitu", "userEmail":"jitu@gmail.com","password":"hi","passwordConfirm":"hi"}
*/


/* http://localhost:3000/api/v1/userupdatetoken Post @for genarating user update Token
 {"userId":"66f4fd4966bfc50cbacb8511","password":"his"}

 http://localhost:3000/api/v1/user  Put @for creating user
 {"userUpdateToken": "", "userName": "luck", "userEmail": "loggy"}
*/


// http://localhost:3000/api/v1/loginuser @for login user





// http://localhost:3000/api/v1/deleteuser @for delete user