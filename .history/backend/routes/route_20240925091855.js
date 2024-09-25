const express = require('express')
const { setUser } = require('../controller/userController')
const router = express.Router()
const userRoutes = require('./routes/userRoutes');


router.route('/').get(setUser);