const express = require('express')
const { setUser } = require('../')
const router = express.Router()



router.route('/').get(setUser);