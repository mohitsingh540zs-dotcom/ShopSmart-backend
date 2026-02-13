import { getTransporter } from "../config/Mailer.js";

export const SuccessMail = async (firstName, email) => {
    try {
        const transporter = getTransporter();


        const mailOptions = {
            from: `AuthSystem <${process.env.MAIL_USER}>`,
            to: email,
            subject: 'Success Verification email',
            html: `<p>${firstName}, Your Account is successfully verified.</p>`
        };

        await transporter.sendMail(mailOptions);
        console.log("Success mail sended");


    } catch (error) {
        console.log("Mail error:",error.message);

    }
}