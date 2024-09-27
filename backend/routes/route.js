const express = require('express');
const { setUser, updateUser, getUserUpdateAuthToken } = require('../controller/userController');
const { validateCreateUserInput, validateUpdateUserInput, authenticateUserUpdateToken } = require('../middleware/validateCRUD');
const router = express.Router();

// for user creating and updating
router.route('/user')
    .post(validateCreateUserInput, setUser)
    .put(authenticateUserUpdateToken, validateUpdateUserInput, updateUser);

// for user updating auth token
router.route("/userupdatetoken").post(getUserUpdateAuthToken);

module.exports = router