import dotenv from "dotenv";

dotenv.config();

const MailSelector = "input#username";
const PasswordSelector = "input#password";
const SubmitSelector = "button[type='submit']";

export async function submitLogin(page) {
  console.log("🌍 Navigating to Login Page...");

  if (
    !process.env.LOGIN_URL ||
    !process.env.USEREMAIL ||
    !process.env.PASSWORD
  ) {
    console.error(
      "❌ Missing environment variables. Ensure .env is properly loaded."
    );
    throw new Error("Missing required environment variables.");
  }

  try {
    console.log(`🔑 Logging in at: ${process.env.LOGIN_URL}`);
    await page.goto(process.env.LOGIN_URL, {
      waitUntil: "networkidle",
      timeout: 60000,
    });

    console.log(`📧 Entering email: ${process.env.USEREMAIL}`);
    await page.fill(MailSelector, process.env.USEREMAIL);

    console.log(`🔒 Entering password.`);
    await page.fill(PasswordSelector, process.env.PASSWORD);
    await page.locator(SubmitSelector).nth(0).click();

    await page.waitForURL(/erp/, { timeout: 60000 });
    // await page.waitForLoadState("networkidle", { timeout: 60000 });
    await page.waitForSelector("div.modal-card", { timeout: 60000 });

    console.log("✅ Authentication successful!");
  } catch (error) {
    console.error("❌ Login failed:", error);
    throw error;
  }
}
