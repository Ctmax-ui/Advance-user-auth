const express = require('express')
const { setUser } = require('../controller/')
const router = express.Router()



router.route('/').get(setUser);