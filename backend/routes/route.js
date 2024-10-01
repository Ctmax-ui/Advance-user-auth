const express = require('express');
const { setUser,
    loginUser,
    logout,
    refreshToken,
    updateUser,
    getUserUpdateAuthToken,
    userHasAccess } = require('../controller/userController');

const { validateCreateUserInput,
    validateLoginUserInput,
    validateUpdateUserInput,
    authenticateUserUpdateToken } = require('../middleware/validateCRUD');

const { authMiddleware } = require('../middleware/authMidleware');
const { loginLimiter } = require('../middleware/limiterMiddleware')




const router = express.Router();

// for user creating and updating
router.route('/createuser')
    .post(validateCreateUserInput, setUser);



// for user login
router.route('/login').post(loginLimiter,validateLoginUserInput, loginUser);


// for refresh token
router.route('/refreshtoken').post(refreshToken);


// for logout
router.route('/logout').post(logout);

router.use(authMiddleware);

router.route('/userhasaccess').post(userHasAccess);



// for user updating auth token
router.route("/updateuser").post(authenticateUserUpdateToken, validateUpdateUserInput, updateUser);
router.route("/userupdatetoken").post(getUserUpdateAuthToken);

module.exports = router