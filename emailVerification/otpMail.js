import { getTransporter } from "../config/Mailer.js";

export const OtpMail = async (otp, email) => {
    try {
        const transporter = getTransporter();

        const mailOptions = {
            from: `AuthSystem <${process.env.MAIL_USER}>`,
            to: email,
            subject: 'OTP email',
            html: `<p>${otp}, This is your otp please do not share your otp with anyone.</p>`
        }

        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.log(error);
    }
}