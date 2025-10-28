const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const logger = require("./logger");

class TokenManager {
  static getTokenFilePath() {
    return path.join(process.cwd(), "token.txt");
  }

  static readTokenFromFile() {
    try {
      const tokenPath = this.getTokenFilePath();

      if (!fs.existsSync(tokenPath)) {
        logger.warn(`⚠️ Token file not found at: ${tokenPath}`);
        return null;
      }

      let tokenContent = fs.readFileSync(tokenPath, "utf8").trim();

      if (!tokenContent) {
        logger.warn("⚠️ Token file is empty");
        return null;
      }

      // Clean the token - remove any "Bearer " prefix and quotes
      let cleanToken = tokenContent.replace(/['"]/g, "").trim();

      // Remove "Bearer " prefix if present
      if (cleanToken.startsWith("Bearer ")) {
        cleanToken = cleanToken.substring(7);
        logger.info('🔧 Removed "Bearer " prefix from token');

        // Save the cleaned version back to file
        fs.writeFileSync(tokenPath, cleanToken, "utf8");
        logger.info("💾 Saved cleaned token back to file");
      }

      if (cleanToken.length < 10) {
        logger.error("❌ Token appears to be invalid (too short)");
        return null;
      }

      logger.info(`✅ Token loaded from file (length: ${cleanToken.length})`);
      return cleanToken;
    } catch (error) {
      logger.error(`❌ Failed to read token from file: ${error.message}`);
      return null;
    }
  }

  static saveTokenToFile(token) {
    try {
      const tokenPath = this.getTokenFilePath();

      // Clean the token - remove any "Bearer " prefix and quotes
      let cleanToken = token.replace(/['"]/g, "").trim();

      // Ensure no "Bearer " prefix in stored token
      if (cleanToken.startsWith("Bearer ")) {
        cleanToken = cleanToken.substring(7);
        logger.info('🔧 Removed "Bearer " prefix before saving to file');
      }

      // Save to file
      fs.writeFileSync(tokenPath, cleanToken, "utf8");

      // Verify the file was written
      const fileStats = fs.statSync(tokenPath);

      logger.info(`💾 Token saved to: ${tokenPath}`);
      logger.info(`📄 File size: ${fileStats.size} bytes`);
      logger.info(`🔐 Token length: ${cleanToken.length} characters`);

      return {
        success: true,
        filePath: tokenPath,
        tokenLength: cleanToken.length,
        fileSize: fileStats.size,
      };
    } catch (error) {
      logger.error(`❌ Failed to save token to file: ${error.message}`);
      throw error;
    }
  }

  static validateToken(token) {
    if (!token) return { isValid: false, reason: "Token is empty" };

    try {
      // Check if token is a JWT
      const parts = token.split(".");
      if (parts.length !== 3) {
        return { isValid: false, reason: "Token is not a valid JWT" };
      }

      // Decode payload to check expiration
      const base64Url = parts[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const payload = JSON.parse(Buffer.from(base64, "base64").toString());

      const expiresAt = new Date(payload.exp * 1000);
      const now = new Date();
      const timeUntilExpiry = expiresAt - now;

      if (timeUntilExpiry < 0) {
        return { isValid: false, reason: "Token has expired", expiresAt };
      }

      return {
        isValid: true,
        expiresAt,
        timeUntilExpiry,
        payload,
      };
    } catch (error) {
      return {
        isValid: false,
        reason: `Token validation failed: ${error.message}`,
      };
    }
  }

  // Add this method to your existing TokenManager class
  static formatTokenForHeader(token) {
    if (!token) return "";

    let cleanToken = token.replace(/['"]/g, "").trim();

    // Remove any existing "Bearer " prefix
    if (cleanToken.startsWith("Bearer ")) {
      cleanToken = cleanToken.substring(7);
    }

    // Add "Bearer " prefix for header
    const formattedToken = `Bearer ${cleanToken}`;

    // Validate token length
    if (cleanToken.length < 100) {
      console.warn(
        `⚠️  Warning: Token appears short (${cleanToken.length} chars)`
      );
    }

    return formattedToken;
  }

  static async getValidToken() {
    // First try to read from file
    let token = this.readTokenFromFile();

    if (token) {
      const validation = this.validateToken(token);

      if (validation.isValid) {
        const minutesUntilExpiry = Math.round(
          validation.timeUntilExpiry / (1000 * 60)
        );

        if (minutesUntilExpiry < 5) {
          logger.warn(
            `⚠️ Token expires soon (${minutesUntilExpiry} minutes), attempting refresh...`
          );
          try {
            token = await this.refreshToken();
          } catch (error) {
            logger.warn(
              `⚠️ Token refresh failed, using existing token: ${error.message}`
            );
          }
        } else {
          logger.info(
            `✅ Using valid token from file (expires in ${minutesUntilExpiry} minutes)`
          );
          return token;
        }
      } else {
        logger.warn(
          `⚠️ Token from file is invalid: ${validation.reason}, attempting refresh...`
        );
        try {
          token = await this.refreshToken();
        } catch (error) {
          throw new Error(
            `No valid token available: ${validation.reason} and refresh failed: ${error.message}`
          );
        }
      }
    } else {
      // No token in file, try to refresh
      logger.info(
        "🔄 No token found in file, attempting to fetch new token..."
      );
      try {
        token = await this.refreshToken();
      } catch (error) {
        throw new Error(
          `No token available and refresh failed: ${error.message}`
        );
      }
    }

    return token;
  }

  static async refreshToken() {
    return new Promise((resolve, reject) => {
      logger.info("🔄 Attempting to refresh token...");

      exec("node fetchToken.js", (error, stdout, stderr) => {
        if (error) {
          logger.error(`❌ Failed to refresh token: ${error.message}`);
          reject(error);
          return;
        }

        // Extract token from output - look for token pattern
        const tokenMatch = stdout.match(/(?:TOKEN=)?([^\s]+)/);
        if (tokenMatch && tokenMatch[1]) {
          const newToken = tokenMatch[1].replace(/['"]/g, "").trim();

          if (newToken && newToken.length > 100) {
            logger.info(`✅ New token obtained (length: ${newToken.length})`);

            // Save to token file
            if (this.saveTokenToFile(newToken)) {
              resolve(newToken);
            } else {
              reject(new Error("Failed to save token to file"));
            }
          } else {
            reject(new Error("Invalid token received from fetchToken.js"));
          }
        } else {
          reject(
            new Error("Could not extract token from fetchToken.js output")
          );
        }
      });
    });
  }

  static async ensureValidToken() {
    try {
      const token = await this.getValidToken();
      return token;
    } catch (error) {
      logger.error(`❌ Failed to ensure valid token: ${error.message}`);
      throw error;
    }
  }

  // ADDED: Missing method that was being called in tests
  static async validateAndRefreshToken() {
    try {
      logger.info("🔐 Validating and refreshing token if needed...");

      // First, check if we have a token file
      const tokenPath = this.getTokenFilePath();
      if (!fs.existsSync(tokenPath)) {
        logger.warn("⚠️ No token file found, attempting to fetch new token...");
        try {
          await this.refreshToken();
          return true;
        } catch (error) {
          logger.error(`❌ Failed to fetch initial token: ${error.message}`);
          return false;
        }
      }

      // Read and validate existing token
      const token = this.readTokenFromFile();
      if (!token) {
        logger.warn("⚠️ Token file is empty, attempting to refresh...");
        try {
          await this.refreshToken();
          return true;
        } catch (error) {
          logger.error(`❌ Failed to refresh empty token: ${error.message}`);
          return false;
        }
      }

      // Validate the token
      const validation = this.validateToken(token);

      if (!validation.isValid) {
        logger.warn(
          `⚠️ Token is invalid: ${validation.reason}, attempting refresh...`
        );
        try {
          await this.refreshToken();
          return true;
        } catch (error) {
          logger.error(`❌ Failed to refresh invalid token: ${error.message}`);
          return false;
        }
      }

      // Check if token is about to expire (less than 5 minutes)
      const minutesUntilExpiry = Math.round(
        validation.timeUntilExpiry / (1000 * 60)
      );

      if (minutesUntilExpiry < 5) {
        logger.warn(
          `⚠️ Token expires soon (${minutesUntilExpiry} minutes), attempting refresh...`
        );
        try {
          await this.refreshToken();
          return true;
        } catch (error) {
          logger.warn(
            `⚠️ Token refresh failed but existing token is still valid: ${error.message}`
          );
          // Return true because the existing token is still valid
          return true;
        }
      }

      logger.info(
        `✅ Token is valid (expires in ${minutesUntilExpiry} minutes)`
      );
      return true;
    } catch (error) {
      logger.error(`❌ Token validation and refresh failed: ${error.message}`);
      return false;
    }
  }

  // Enhanced version with more detailed status
  static async validateAndRefreshTokenWithStatus() {
    const result = {
      success: false,
      refreshed: false,
      message: "",
      tokenInfo: null,
    };

    try {
      logger.info("🔐 Comprehensive token validation and refresh...");

      const tokenPath = this.getTokenFilePath();

      // Check if token file exists
      if (!fs.existsSync(tokenPath)) {
        result.message = "No token file found";
        logger.warn(`⚠️ ${result.message}`);

        try {
          await this.refreshToken();
          result.success = true;
          result.refreshed = true;
          result.message = "Successfully fetched new token (no existing token)";
          logger.info(`✅ ${result.message}`);
          return result;
        } catch (error) {
          result.message = `Failed to fetch initial token: ${error.message}`;
          logger.error(`❌ ${result.message}`);
          return result;
        }
      }

      // Read existing token
      const token = this.readTokenFromFile();
      if (!token) {
        result.message = "Token file is empty";
        logger.warn(`⚠️ ${result.message}`);

        try {
          await this.refreshToken();
          result.success = true;
          result.refreshed = true;
          result.message = "Successfully refreshed empty token";
          logger.info(`✅ ${result.message}`);
          return result;
        } catch (error) {
          result.message = `Failed to refresh empty token: ${error.message}`;
          logger.error(`❌ ${result.message}`);
          return result;
        }
      }

      // Validate token
      const validation = this.validateToken(token);
      result.tokenInfo = {
        exists: true,
        isValid: validation.isValid,
        reason: validation.reason,
        expiresAt: validation.expiresAt,
        timeUntilExpiry: validation.timeUntilExpiry,
      };

      if (!validation.isValid) {
        result.message = `Token is invalid: ${validation.reason}`;
        logger.warn(`⚠️ ${result.message}`);

        try {
          await this.refreshToken();
          result.success = true;
          result.refreshed = true;
          result.message = "Successfully refreshed invalid token";
          logger.info(`✅ ${result.message}`);
          return result;
        } catch (error) {
          result.message = `Failed to refresh invalid token: ${error.message}`;
          logger.error(`❌ ${result.message}`);
          return result;
        }
      }

      // Check expiration
      const minutesUntilExpiry = Math.round(
        validation.timeUntilExpiry / (1000 * 60)
      );

      if (minutesUntilExpiry < 5) {
        result.message = `Token expires soon (${minutesUntilExpiry} minutes)`;
        logger.warn(`⚠️ ${result.message}`);

        try {
          await this.refreshToken();
          result.success = true;
          result.refreshed = true;
          result.message = `Successfully refreshed soon-to-expire token`;
          logger.info(`✅ ${result.message}`);
          return result;
        } catch (error) {
          result.success = true; // Still valid, just couldn't refresh
          result.refreshed = false;
          result.message = `Refresh failed but token is still valid for ${minutesUntilExpiry} minutes: ${error.message}`;
          logger.warn(`⚠️ ${result.message}`);
          return result;
        }
      }

      // Token is valid and not expiring soon
      result.success = true;
      result.refreshed = false;
      result.message = `Token is valid for ${minutesUntilExpiry} minutes`;
      logger.info(`✅ ${result.message}`);
      return result;
    } catch (error) {
      result.message = `Unexpected error during token validation: ${error.message}`;
      logger.error(`❌ ${result.message}`);
      return result;
    }
  }

  static getTokenInfo() {
    const token = this.readTokenFromFile();
    if (!token) {
      return { exists: false };
    }

    const validation = this.validateToken(token);
    return {
      exists: true,
      isValid: validation.isValid,
      reason: validation.reason,
      expiresAt: validation.expiresAt,
      timeUntilExpiry: validation.timeUntilExpiry,
      length: token.length,
      source: "token.txt",
      formattedHeader: this.formatTokenForHeader(token),
    };
  }

  // Utility method to check token status without refreshing
  static checkTokenStatus() {
    const token = this.readTokenFromFile();
    if (!token) {
      return {
        exists: false,
        valid: false,
        message: "No token file found",
      };
    }

    const validation = this.validateToken(token);
    const minutesUntilExpiry = validation.timeUntilExpiry
      ? Math.round(validation.timeUntilExpiry / (1000 * 60))
      : 0;

    return {
      exists: true,
      valid: validation.isValid,
      expiresIn: `${minutesUntilExpiry} minutes`,
      expiresAt: validation.expiresAt,
      message: validation.isValid
        ? `Token valid for ${minutesUntilExpiry} minutes`
        : `Token invalid: ${validation.reason}`,
    };
  }
}

module.exports = TokenManager;
