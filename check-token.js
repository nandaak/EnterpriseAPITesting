// check-token.js

const fs = require("fs");
const path = require("path");

/**
 * @class TokenChecker
 * @description Utility class to check the existence, format, and expiry of a token stored in 'token.txt'.
 */
class TokenChecker {
  constructor() {
    // Determine the absolute path to the token file in the current working directory
    this.tokenFilePath = path.join(process.cwd(), "token.txt");
  }

  /**
   * @method checkTokenFile
   * @description Reads and validates the token file, providing detailed diagnostic output.
   * @returns {object} The token check result object.
   */
  checkTokenFile() {
    console.log("🔍 Checking token status...\n");
    console.log(`Token File Path: ${this.tokenFilePath}`);

    if (!fs.existsSync(this.tokenFilePath)) {
      console.log("❌ Token file not found");
      return {
        exists: false,
        message: "token.txt file does not exist. Ensure token generation was successful.",
      };
    }

    try {
      // Use synchronous file read and trim whitespace/newlines
      const token = fs.readFileSync(this.tokenFilePath, "utf8").trim();

      if (!token) {
        console.log("❌ Token file is empty");
        return {
          exists: true,
          valid: false,
          message: "token.txt exists but is empty",
        };
      }

      console.log(`✅ Token file exists`);
      console.log(`📏 Token length: ${token.length} characters`);

      // Basic length validation
      if (token.length < 50) { // A typical JWT is much longer than 10
        console.log("⚠️ Token appears suspiciously short (less than 50 chars)");
        // continue, but log a warning
      }

      // JWT analysis (Base64 URL-safe encoding)
      const parts = token.split(".");
      if (parts.length === 3) {
        console.log("✅ Token is in standard JWT format (3 parts)");

        try {
          // Decode the Base64url-encoded payload. Replace '-' with '+' and '_' with '/' for standard Base64
          // and pad with '=' if needed before decoding.
          const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
          const padding = (4 - base64.length % 4) % 4;
          const paddedBase64 = base64 + '='.repeat(padding);

          // Decode and parse the JSON payload
          const payload = JSON.parse(Buffer.from(paddedBase64, "base64").toString('utf8'));

          if (payload.exp) {
            const expiresAt = new Date(payload.exp * 1000); // JWT 'exp' is in seconds
            const now = new Date();
            const timeUntilExpiry = expiresAt.getTime() - now.getTime();
            const minutesUntilExpiry = Math.round(timeUntilExpiry / (1000 * 60));

            console.log(`📅 Expires at: ${expiresAt.toISOString()}`);
            console.log(`⏳ Time until expiry: ${minutesUntilExpiry} minutes`);

            if (timeUntilExpiry < 0) {
              console.log("❌ Token has **EXPIRED**");
              return {
                exists: true,
                valid: false,
                expired: true,
                expiresAt,
                message: "Token has expired",
              };
            } else if (minutesUntilExpiry < 5) {
              console.log("⚠️ Token expires **SOON** (less than 5 minutes)");
              return {
                exists: true,
                valid: true,
                expiresSoon: true,
                expiresAt,
                minutesUntilExpiry,
                message: `Token expires in ${minutesUntilExpiry} minutes`,
              };
            } else {
              console.log("✅ Token is valid and fresh");
              return {
                exists: true,
                valid: true,
                expiresAt,
                minutesUntilExpiry,
                message: `Token is valid for ${minutesUntilExpiry} minutes`,
              };
            }
          } else {
            console.log("ℹ️ JWT payload decoded but no **'exp'** (expiry) claim found.");
            return {
              exists: true,
              valid: true, // Cannot validate expiry, assume valid for now
              message: "Token exists, JWT decoded, but no expiry claim ('exp') found",
            };
          }
        } catch (e) {
          console.log(`ℹ️ Token is JWT format but payload couldn't be decoded/parsed: ${e.message}`);
          return {
            exists: true,
            valid: true, // Assume valid if we can't decode, for diagnostic purposes
            length: token.length,
            message: "Token exists but JWT payload couldn't be correctly decoded or parsed",
          };
        }
      } else {
        console.log("ℹ️ Token is not in standard JWT format (expected 3 parts separated by '.')");
        return {
          exists: true,
          valid: true, // Assume valid for non-JWT tokens
          length: token.length,
          message: "Token exists (non-JWT format)",
        };
      }
    } catch (error) {
      console.error("❌ Error reading token file:", error.message);
      return {
        exists: false,
        valid: false,
        error: error.message,
        message: "File read error",
      };
    }
  }
}

// Check if the file is executed directly (CommonJS equivalent to import.meta.url)
if (require.main === module) {
  const checker = new TokenChecker();
  checker.checkTokenFile();
}

// Export the class for use in other files (like debug-token.js's TokenManager)
module.exports = { TokenChecker };