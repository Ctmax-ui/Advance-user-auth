const userScema = require("../model/userScema")
const asyncHandler = require('express-async-handler');

// @ for creating user
const setUser = asyncHandler(async (req, res) => {
    let error = null;
    try {

        console.log(req.body);

        let userName = req.body.userName || null;
        let userEmail = req.body.userEmail || null
        let password = req.body.password || null
        let confirmPassword = req.body.confirmPassword || null;

        if (userName == null || userName == "") {
            error = "User Name is required."
        } else if (userEmail == null || userEmail == "") {
            error = "User Email is required."
        } else if (password == null || password == "") {
            error = "Password required."
        } else if (confirmPassword == null || confirmPassword == "") {
            error = "confirmPass required."
        }else if(password == confirmpass){
            error= "Password and confirm password dose not match."
        }


        if (userName && userEmail && password) {
            const cUser = await userScema.create({
                username: userName,
                email: userEmail,
                password: password
            })
            res.status(201).send(cUser)
            return
        }
        res.status(400).send(error)
    } catch (err) {
        error = err.message
        res.status(400).send(error)
    }
})





module.exports = { setUser }