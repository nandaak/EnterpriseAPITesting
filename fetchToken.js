const { chromium } = require('playwright');
const { submitLogin } = require('./submitLogin.js');
const { writeFile }  = require('fs/promises');
const path = require('path');
/**
 * Fetches the authentication token from the ERP system after login
 * and saves it to a local file named 'token.txt'.
 */
async function fetchAndSaveToken() {
  let browser; // Declare outside try block for scope in finally
  const TOKEN_FILE_NAME = "token.txt";
  const TOKEN_STORAGE_KEY = "userToken";
  const filePath = path.resolve(process.cwd(), TOKEN_FILE_NAME);

  console.log("🚀 Starting token retrieval process...");

  try {
    // 1. Launch Browser
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    // 2. Perform Login
    console.log("➡️ Attempting to log in to the ERP system...");
    await submitLogin(page);
    console.log("✅ Login successful.");

    // 3. Retrieve Token from localStorage
    const tokenData = await page.evaluate(
      (key) => localStorage.getItem(key),
      TOKEN_STORAGE_KEY
    );

    if (!tokenData) {
      throw new Error(
        `Token not found in localStorage under key: "${TOKEN_STORAGE_KEY}"`
      );
    }

    // 4. Save Token to File
    await writeFile(filePath, tokenData.trim(), "utf-8"); // .trim() ensures no leading/trailing whitespace

    console.log(`🎉 Token successfully saved to file: ${TOKEN_FILE_NAME}`);
    console.log(`(Full Path: ${filePath})`);
  } catch (error) {
    console.error("❌ An error occurred during the token retrieval process:");
    console.error(error.message);
    process.exit(1); // Exit with a non-zero code to indicate failure
  } finally {
    // 5. Cleanup Resources
    if (browser) {
      await browser.close();
      console.log("🧹 Browser closed. Process finished.");
    }
  }
}

fetchAndSaveToken();
