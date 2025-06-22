const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');


router.post('/login', userController.loginUser);
router.post('/register', userController.registerUser);
router.post('/refresh', userController.refreshToken);
router.post('/logout', userController.logoutUser);
router.get('/:email/profile', userController.getUserProfile);
router.put('/:email/profile', userController.updateUserProfile);



module.exports = router;
