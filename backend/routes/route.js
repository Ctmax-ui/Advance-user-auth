const express = require('express')
const { setUser, updateUser, getUserUpdateAuthToken } = require('../controller/userController')
const { validateCreateUserInput, validateUpdateUserInput, authenticateUserUpdateToken } = require('../middleware/validateCRUD')
const router = express.Router()

router.route('/user')
    .post(validateCreateUserInput, setUser)
    .put(authenticateUserUpdateToken,validateUpdateUserInput, updateUser);

router.route("/userupdatetoken").post(getUserUpdateAuthToken)

module.exports = router