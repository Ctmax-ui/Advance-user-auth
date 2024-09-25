const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const setUser = asyncHandler(async (req, res) => {
    let error= null;
    try {

        console.log(req);

        let userName= null;
        let userEmail=null
        let password=''
        let confirmPassword=null;

        if(username)
        const cUser = await userScema.create({
            name:userName,
            email: userEmail,
            password: password
        })
        res.status(201).send(cUser)

    }catch(err){
        error = err.message
        res.status(400).send(error)
    }
})





module.exports = {setUser}