import Brevo from "@getbrevo/brevo";

const sendEmail = async ({ to, subject, html }) => {
    if (!process.env.BREVO_API_KEY) {
        throw new Error("BREVO_API_KEY not found in environment variables");
    }

    const apiInstance = new Brevo.TransactionalEmailsApi();

    apiInstance.setApiKey(
        Brevo.TransactionalEmailsApiApiKeys.apiKey,
        process.env.BREVO_API_KEY
    );

    try {
        const response = await apiInstance.sendTransacEmail({
            sender: {
                email: "mohitsingh540zs@gmail.com",
                name: "Shopsmart",
            },
            to: [{ email: to }],
            subject: subject,
            htmlContent: html,
        });

        console.log("FULL RESPONSE:", JSON.stringify(response, null, 2));

    } catch (error) {
        console.error("Brevo Error:", error.response?.body || error);
        throw new Error("Email sending failed");
    }
};

export default sendEmail;
