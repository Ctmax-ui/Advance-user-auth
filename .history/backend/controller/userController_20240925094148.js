const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const setUser = asyncHandler(async (req, res) => {
    let error= null;
    try {

        console.log(req);

        let userName= '';
        let user


        const cUser = await userScema.create({
            name:'',
            email: "gg@g.com",
            password: "gg"
        })
        res.status(201).send(cUser)

    }catch(err){
        error = err.message
        res.status(400).send(error)
    }
})





module.exports = {setUser}