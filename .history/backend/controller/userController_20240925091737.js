const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const ssetUser = asyncHandler(async (req, res) => {
    try {
        const cUser = await userScema.create({
            name:'',
            email: "gg@g.com",
            password: "gg"
        })
        res.status(200).send(cUser)
    }catch(err){
        console.log(err._message);
        res.status(200).send(err._message)
    }
})





module.exports = {setUser}