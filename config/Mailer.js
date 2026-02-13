// server/email/Mailer.js
import nodemailer from "nodemailer";

export const getTransporter = () => {
    return nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS
        }
    });
};
