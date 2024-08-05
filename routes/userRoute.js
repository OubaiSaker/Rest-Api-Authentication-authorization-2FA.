const express = require('express');
const router = express.Router();

const userController = require('../controllers/usersController')
const authAccessToken = require('../middleware/authAccessToken');
const isAdmin = require('../middleware/admin');
const isModerator = require('../middleware/moderator');
const authRefreshToken = require('../middleware/authRefreshToken');

router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);
router.get('/2fa/generate', authRefreshToken, userController.genrate2fa);
router.post('/2fa/validate', authRefreshToken, userController.validate2fa);
router.post('/login/2fa', userController.twoFactorMethod);
router.get('/current', authRefreshToken, userController.getCurrentUser);
router.get('/admin', [authRefreshToken, isAdmin], userController.getAdmin);
router.get('/moderator', [authRefreshToken, isModerator], userController.getModerator);
router.post('/refresh-token', authRefreshToken, userController.postRefreshToken);
router.post('/logout', authRefreshToken, userController.logoutUser);

module.exports = router;