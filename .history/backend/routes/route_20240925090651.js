const express = require('express')
const { setUser } = require('../controller/userController')
const router = express.Router()



router.route('/').post(setUser)