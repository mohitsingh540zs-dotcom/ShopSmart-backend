// server/email/Mailer.js
import nodemailer from "nodemailer";

export const getTransporter = () => {
    return nodemailer.createTransport({
        host: "smtp-relay.brevo.com",
        port: 587,
        secure:false,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS
        },
        tls:{
            rejectUnauthorized: false
        }
    });
};
