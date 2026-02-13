//login register verify logout reverify otp resendOTP forgotPassword otpVerification changePassword
import express from "express";
import { changePassword, forgotPassword, identifyUser, login, logout, logoutAll, refreshToken, register, resendOTP, reVerify, updateUser, verify, verifyOtp } from "../controllers/authController.js";
import { isAuthenticated } from "../middleware/isAuthenticated.js";
import {singleUpload} from "../middleware/multer.js";
const router = express.Router();

router.post('/register', register);
router.post('/verify', verify);
router.post('/reverify', reVerify);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/resend-otp', resendOTP);
router.post('/otp-verify', verifyOtp);
router.post('/change-password', changePassword);
router.post('/refresh', refreshToken);
router.post('/logout', logout);
router.post('/logout-all', isAuthenticated, logoutAll);
router.get('/me', isAuthenticated, identifyUser);
router.put('/update/:id',isAuthenticated,singleUpload,updateUser);



export default router