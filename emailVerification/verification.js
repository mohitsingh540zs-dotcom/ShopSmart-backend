import { getTransporter } from "../config/Mailer.js";

export const verificationMail = async (email, token) => {

    try {
        const transporter = getTransporter();

        const mailOptions = {
            from: `AuthSystem <${process.env.MAIL_USER}>`,
            to: email,
            subject: 'Verification email',
            html: `<p>This is the verification link <br/> https://shop-smart-frontend-nine.vercel.app/verify/${token}</p>`
        };

        await transporter.sendMail(mailOptions);
        console.log("Verification mail was sended to user's email.");

    } catch (error) {
        console.log("error occured:",error.message);
    }


}