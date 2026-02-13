import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true,
        maxLength: 10
    },
    lastName: {
        type: String,
        required: true,
        trim: true,
        maxLength: 10
    },
    profilePic: {
        type: String,
        default: ""
    },
    profilePicPublicId: {
        type: String,
        default: ""
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        index: true
    },
    password: {
        type: String,
        trim: true,
        minLength: 8,
        select: false
    },
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    },
    token: {
        type: String,
        default: null
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,
        default: null
    },
    otpExpiry: {
        type: Date,
        default: null
    },
    otpAttempts: {
        type: Number,
        default: 0
    },
    otpBlockedUntil: {
        type: Date,
        default: null
    },
    resetToken: {
        type: String,
        default: null
    },
    resetTokenExpiry: {
        type: Date,
        default: null
    },
    address:{
        type:String,
        default:""
    },
    city:{
        type:String,
        default:""
    },
    zipcode:{
        type:String,
        default:""
    },
    phoneNo:{
        type:String,
        default:""
    }

},
    {
        timestamps: true,
        versionKey: false,
        collection: "Users"
    });

export const Users = mongoose.model("Users", userSchema);