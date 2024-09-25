const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const setUser = asyncHandler(async (req, res) => {
    let error = null;
    try {

        console.log(req.body);

        let userName = req.body.userName || null;
        let userEmail = req.body.userEmail || null
        let password =req.body.password || null
        let confirmPassword =req.body.confirmPassword || null;

        if


        if (userName && userEmail && password && (password == confirmPassword)) {
            const cUser = await userScema.create({
                name: userName,
                email: userEmail,
                password: password
            })
            res.status(201).send(cUser)
        }
        res.status(400).send(error)
    } catch (err) {
        error = err.message
        res.status(400).send(error)
    }
})





module.exports = { setUser }