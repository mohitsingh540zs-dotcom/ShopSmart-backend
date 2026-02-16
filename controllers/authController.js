//login register verify logout reverify
import { Users } from "../models/usersSchema.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { verificationMail, otpMail, successMail } from "../services/emailService.js";
import { Session } from "../models/session.js";
import { MaxAttempts, UserBlockedUntil } from "../config/Constrants.js";
import { refreshExpiry } from "../utils/refreshExpiry.js";
import { generateOTP, getOtpExpiry } from "../utils/GenerateOtp.js"
import cloudinary from "../utils/Cloudinary.js";


//register
export const register = async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        //basic validation
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must me 8 characters"
            });
        }

        //checks if a user already exists?
        const user = await Users.findOne({ email });

        if (user) {
            return res.status(400).json({
                success: false,
                message: "User already registered, Go to login page"
            });
        }
        //hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // create user
        const newUser = await Users.create({
            firstName,
            lastName,
            email,
            password: hashedPassword
        });

        //generate token
        const token = jwt.sign({ id: newUser._id },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '30m' }
        );

        try {
            await verificationMail(email, token);
        } catch (error) {
            console.log("Error occured for sending mail to the user", error);
        }

        newUser.token = token;
        await newUser.save();

        //user created successfully
        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            newUser
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        })
    }
}
//verify
export const verify = async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        //check is the params contain the bearer token

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(400).json({
                success: false,
                message: "token is invalid or missing"
            });
        }

        //check 
        //if bearer exists extract the token

        const token = authHeader.split(" ")[1];

        let decoded;

        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        } catch (error) {
            if (error.name === "TokenExpiredError") {
                return res.status(400).json({
                    success: false,
                    message: "Token expired"
                });
            }
        }

        //find the user by id 
        const user = await Users.findById(decoded.id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        //find if user is already verified
        if (user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "User already verified"
            });
        }

        try {
            await successMail(user.firstName, user.email);
        } catch (error) {
            console.log(error.message);
        }

        user.isVerified = true;
        user.token = null;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "User Verified successfully"
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}
//reVerify
export const reVerify = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "email required"
            })
        }

        const user = await Users.findOne({ email });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "User is already verified."
            });
        }

        //if user founded then generate new token and send it to mail
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "30m" }
        )

        verificationMail(email, token);

        user.token = token;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Reverification email sent successfully",
            token: user.token
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }

}
//login
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // basic validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        // find user (explicitly include password)
        const user = await Users.findOne({ email }).select("+password");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User doesn't exist"
            });
        }

        // password check
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // verification check
        if (!user.isVerified) {
            return res.status(400).json({
                success: false,
                code: "Email_Not_Verified",
                message: "Please verify your email first"
            });
        }

        // generate tokens

        //Access token(Short life tokens only for access protected routes)
        const accessToken = jwt.sign(
            { id: user._id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: "15m" }
        );
        //Refresh token(long life tokens only for recreating access token)
        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: "7d" }
        );

        const hashToken = crypto.createHash("sha256").update(refreshToken).digest("hex");

        await user.save();

        // remove old session (single device login)
        await Session.findOneAndDelete({ userId: user._id });

        // create new session
        await Session.create({
            userId: user._id,
            refreshTokenHash: hashToken,
            expiresAt: refreshExpiry()
        });

        //  remove sensitive fields before sending
        const { password: pwd, token, ...safeUser } = user._doc;

        const isProduction = process.env.NODE_ENV === "production";

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProduction, // true on Render
            sameSite: isProduction ? "None" : "Lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        }).json({
            success: true,
            message: `Login successful, welcome ${safeUser.firstName}`,
            user: safeUser,
            accessToken
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
//forget-password
export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // 1️ Basic validation
        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        // 2️ Check if user exists
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User does not exist"
            });
        }

        // 3️ User must be verified
        if (!user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "Please verify your email first"
            });
        }

        // 4️ Prevent OTP spam (cooldown)
        if (user.otpExpiry && user.otpExpiry > Date.now()) {
            return res.status(429).json({
                success: false,
                message: "OTP already sent. Please wait before requesting again"
            });
        }

        // 5️ Generate OTP (6 digit)
        const otp = generateOTP();

        const hashedOTP = await bcrypt.hash(String(otp), 10);

        const otpExpiry = getOtpExpiry(); // 10 minutes

        // 6️ Save OTP info
        user.otp = hashedOTP;
        user.otpExpiry = otpExpiry;
        user.otpAttempts = 0;
        user.otpBlockedUntil = null;

        await user.save();

        // 7️ Create OTP verification token (contains email)
        const otpToken = jwt.sign(
            { email },
            process.env.OTP_SECRET,
            { expiresIn: "30m" }
        );

        // 8️ Send OTP email
        await otpMail(email, otp);

        return res.status(200).json({
            success: true,
            message: "OTP sent to your email",
            otpToken
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
//otpVerification
export const verifyOtp = async (req, res) => {
    try {
        const { otp, otpToken } = req.body;

        // 1️ Basic validation
        if (!otp || !otpToken) {
            return res.status(400).json({
                success: false,
                message: "OTP and token are required"
            });
        }

        // 2️ Verify OTP token (contains email)
        let decoded;
        try {
            decoded = jwt.verify(otpToken, process.env.OTP_SECRET);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "OTP token is invalid or expired"
            });
        }

        const { email } = decoded;

        // 3️ Find user
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // 4️ Block check
        if (user.otpBlockedUntil && user.otpBlockedUntil > Date.now()) {
            return res.status(429).json({
                success: false,
                message: "Too many attempts. Try again later."
            });
        }

        // 5️ OTP existence check
        if (!user.otp || !user.otpExpiry) {
            return res.status(400).json({
                success: false,
                message: "No OTP request found"
            });
        }

        // 6️ OTP expiry check (IMPORTANT: before bcrypt)
        if (user.otpExpiry < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP expired. Please request a new one"
            });
        }

        // 7️ Compare OTP
        const isOtpValid = await bcrypt.compare(otp, user.otp);
        if (!isOtpValid) {
            user.otpAttempts += 1;

            if (user.otpAttempts >= MaxAttempts) {
                user.otpBlockedUntil = new Date(Date.now() + UserBlockedUntil);
                user.otpAttempts = 0;
            }

            await user.save();

            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        }

        // 8️ Generate password reset token
        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedResetToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        user.resetToken = hashedResetToken;
        user.resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000);

        // 9️ Clear OTP data
        user.otp = null;
        user.otpExpiry = null;
        user.otpAttempts = 0;
        user.otpBlockedUntil = null;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "OTP verified successfully. You can now reset your password.",
            resetToken
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
//resend otp 
export const resendOTP = async (req, res) => {
    try {
        const { otpToken } = req.body;

        // 1. Verify token
        let decoded;
        try {
            decoded = jwt.verify(otpToken, process.env.OTP_SECRET);
        } catch (error) {
            if (error.name === "TokenExpiredError") {
                return res.status(401).json({
                    success: false,
                    message: "Session expired. Please request OTP again."
                });
            }
            return res.status(400).json({
                success: false,
                message: error.message
            });
        }

        const { email } = decoded;

        // 2. Check user
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User does not exist"
            });
        }

        // 3. Block resend if OTP is still valid
        if (user.otpExpiry && user.otpExpiry > Date.now()) {
            return res.status(429).json({
                success: false,
                message: "Please wait before requesting another OTP"
            });
        }


        // 4. Generate NEW OTP
        const otp = generateOTP(); // e.g. 6-digit
        const hashedotp = await bcrypt.hash(String(otp), 10);   // IMPORTANT: hash it
        const otpExpiry = getOtpExpiry();

        user.otp = hashedotp;
        user.otpExpiry = otpExpiry;
        user.otpAttempts = 0;
        user.otpBlockedUntil = null;


        await user.save();

        // 5. Send OTP email
        await otpMail(email, otp);

        return res.status(200).json({
            success: true,
            message: "New OTP has been sent"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};
//change password
export const changePassword = async (req, res) => {
    try {
        const { resetToken, newPassword, confirmPassword } = req.body;

        if (!resetToken || !newPassword || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

        const user = await Users.findOne({
            resetToken: hashedToken,
            resetTokenExpiry: { $gt: Date.now() }
        }).select("+password");

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid user or Expired reset token"
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be greater then 8 characters."
            })
        }

        const isSamePassword = await bcrypt.compare(newPassword, user.password);

        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: "New password must be different from old password"
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords are not matching"
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully."
        });


    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });

    }
}
//logout
export const logout = async (req, res) => {

    try {
        const refreshToken = req.cookies?.refreshToken;

        if (refreshToken) {
            const hashToken = crypto
                .createHash("sha256")
                .update(refreshToken)
                .digest("hex");

            await Session.findOneAndDelete({ refreshTokenHash: hashToken });
        }

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: false,
            sameSite: "lax"
        });

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
};
//logout-All sessions
export const logoutAll = async (req, res) => {
    try {
        const userId = req.user.id; // from auth middleware

        // delete ALL sessions of this user
        await Session.deleteMany({ userId });

        // clear refresh token cookie from current device
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
        });

        return res.status(200).json({
            success: true,
            message: "Logged out from all devices",
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
};
//refreshToken
export const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        const refreshTokenHash = crypto
            .createHash("sha256")
            .update(refreshToken)
            .digest("hex");

        const session = await Session.findOne({
            userId: decoded.id,
            refreshTokenHash,
            expiresAt: { $gt: new Date() }
        });

        if (!session) {
            return res.status(401).json({ message: "Invalid session" });
        }

        const newAccessToken = jwt.sign(
            { id: decoded.id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: "15m" }
        );

        return res.status(200).json({
            success: true,
            accessToken: newAccessToken
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
};
/* /user/me   for RBACs needed everytime*/
export const identifyUser = async (req, res) => {
    try {
        const user = req.user;

        return res.status(200).json({
            success: true,
            message: "User is authenticated",
            user
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Unauthorized"
        });
    }
}

/**Admin handlers **/

//Admin access of get all users
export const getUsers = async (_, res) => {
    try {
        //the requester is admin or not 

        const users = await Users.find({});

        return res.status(200).json({
            success: true,
            message: "Users fetched successfully",
            userCount: users.length,
            users
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}
//Update user's role by id 
export const updateUser = async (req, res) => {
    try {
        const userIdtoUpdate = req.params.id;
        const loggedIn = req.user;

        const { firstName, lastName, address, city, zipcode, phoneNo, role } = req.body;

        // Correct permission check
        if (loggedIn.id !== userIdtoUpdate && loggedIn.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to update this user"
            });
        }

        const user = await Users.findById(userIdtoUpdate);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        let profilePicUrl = user.profilePic;
        let profilePicPublicId = user.profilePicPublicId;

        // file upload working
        if (req.file) {
            if (profilePicPublicId) {
                await cloudinary.uploader.destroy(profilePicPublicId);
            }

            const uploadResult = await new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream(
                    { folder: "profile" },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );
                stream.end(req.file.buffer);
            });

            profilePicUrl = uploadResult.secure_url;
            profilePicPublicId = uploadResult.public_id;
        }

        // safe field updates
        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.address = address || user.address;
        user.city = city || user.city;
        user.zipcode = zipcode || user.zipcode;
        user.phoneNo = phoneNo || user.phoneNo;

        if (role) user.role = role;

        user.profilePic = profilePicUrl;
        user.profilePicPublicId = profilePicPublicId;

        const updatedUser = await user.save();

        return res.status(200).json({
            success: true,
            message: "User Updated Successfully",
            updatedUser
        });

    } catch (error) {
        console.error("UPDATE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
};
//delete users
export const deleteUser = async (req, res) => {
    try {
        const { id } = req.params;

        //validation if user not exists 
        const user = await Users.findById(id);

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User doesn't exists"
            });
        }

        if (req.user.id === id && req.user.role === 'admin') {
            return res.status(400).json({
                success: false,
                message: "you can't delete yourself, you're admin"
            });
        }

        /// but if user exists 
        const deletedUser = await Users.findByIdAndDelete(id);
        return res.status(200).json({
            success: true,
            message: "User Deleted Successfully"
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });

    }
}
