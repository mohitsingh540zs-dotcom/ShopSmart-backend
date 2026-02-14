import sendEmail from "../utils/sendEmail.js";

export const verificationMail = async (email, token) => {
  try {
    const verificationLink = `https://shop-smart-frontend-nine.vercel.app/verify/${token}`;

    await sendEmail({
      to: email,
      subject: "Verification Email",
      html: `
        <h2>Welcome to Shopsmart 👋</h2>
        <p>Please verify your account by clicking the link below:</p>
        <a href="${verificationLink}" 
           style="
             display:inline-block;
             padding:10px 20px;
             background-color:#4CAF50;
             color:white;
             text-decoration:none;
             border-radius:5px;
           ">
           Verify Account
        </a>
        <p>If you did not create this account, please ignore this email.</p>
      `,
    });

    console.log("Verification mail sent successfully.");
  } catch (error) {
    console.error("Verification email error:", error.message);
    throw error;
  }
};

export const successMail = async (firstName, email) => {
  try {

    await sendEmail({
      to: email,
      subject: "Success Email",
      html: `
        <h2>Successfully Verified ✅</h2>
        <p><span style="color:green;
        font-weight:bold;
        ">Hi ${firstName}</span>, Your Email Account is Verified Successfully now you can login,</p>
        <p style="color:gray;">and explore the products in our site.</p>
        
      `,
    });

    console.log("Verification mail sent successfully.");
  } catch (error) {
    console.error("Verification email error:", error.message);
    throw error;
  }
};

export const otpMail = async (email, otp) => {
  try {

    await sendEmail({
      to: email,
      subject: "OTP Email",
      html: `
            <h2>Forgot Password </h2>
            <p> ${otp}, This is your otp please do not share your otp with anyone.</p > 
            <p style="
              color:gray;
            ">If you did not initiated this otp, please verify and check your mail.</p>
          `,
    });

    console.log("Verification mail sent successfully.");
  } catch (error) {
    console.error("Verification email error:", error.message);
    throw error;
  }
};