const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const setUser = asyncHandler(async (req, res) => {
    let error= null;
    try {
        const cUser = await userScema.create({
            name:'',
            email: "gg@g.com",
            password: "gg"
        })
        res.status(201).send(cUser)
    }catch(err){
        console.log(err);
        error = 
        res.status(400).send(err.message)
    }
})





module.exports = {setUser}