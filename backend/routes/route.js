const express = require('express');
const { setUser, loginUser, updateUser, getUserUpdateAuthToken } = require('../controller/userController');
const { validateCreateUserInput, validateLoginUserInput, validateUpdateUserInput, authenticateUserUpdateToken } = require('../middleware/validateCRUD');
const router = express.Router();

// for user creating and updating
router.route('/user')
    .post(validateCreateUserInput, setUser)
    .put(authenticateUserUpdateToken, validateUpdateUserInput, updateUser);

// for user login
router.route('/login').post(validateLoginUserInput, loginUser)

// for user updating auth token
router.route("/userupdatetoken").post(getUserUpdateAuthToken);

module.exports = router