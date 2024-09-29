const express = require('express');
const { setUser, loginUser, logout, refreshToken, updateUser, getUserUpdateAuthToken } = require('../controller/userController');
const { validateCreateUserInput, validateLoginUserInput, validateUpdateUserInput, authenticateUserUpdateToken } = require('../middleware/validateCRUD');
const { authMiddleware } = require('../middleware/authMidleware');
const router = express.Router();

// for user creating and updating
router.route('/user')
    .post(validateCreateUserInput, setUser)
    .put(authenticateUserUpdateToken, validateUpdateUserInput, updateUser);


// for user login
router.route('/login').post(validateLoginUserInput, loginUser);


// for refresh token
router.route('/refreshtoken').post(refreshToken);

router.use(authMiddleware)

// for logout
router.route('/logout').get(logout);


// for user updating auth token
router.route("/userupdatetoken").post(getUserUpdateAuthToken);

module.exports = router