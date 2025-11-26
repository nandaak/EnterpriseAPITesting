// config/api-config.js - Enhanced version
require("dotenv").config();
const TokenManager = require("../utils/token-manager");
const logger = require("../utils/logger");

// Enhanced configuration with better token handling
const getApiConfig = () => {
  // Use ENDPOINT from .env as the primary base URL (dynamic endpoint support)
  const baseURL = process.env.ENDPOINT || process.env.API_BASE_URL || "https://microtecsaudi.com:2032";

  // Get and validate token
  let rawToken = TokenManager.readTokenFromFile();
  let tokenSource = "token.txt";

  // Fallback to environment variables if token file doesn't exist
  if (!rawToken) {
    rawToken = process.env.TOKEN || "";
    tokenSource = "environment";
  }

  // Enhanced token validation
  let authorizationHeader = "";
  let tokenValid = false;
  let tokenExpired = false;

  if (rawToken) {
    authorizationHeader = TokenManager.formatTokenForHeader(rawToken);
    const validation = TokenManager.validateToken(rawToken);
    tokenValid = validation.isValid;
    tokenExpired = validation.reason === "Token has expired";
  }

  // Configuration object
  const config = {
    baseURL: baseURL,
    timeout: 30000,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/plain, */*",
    },
    retryConfig: {
      retries: 3,
      retryDelay: 1000,
    },
    validateStatus: function (status) {
      return status >= 200 && status < 500; // Don't throw on 4xx errors
    },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,

    // Token information for debugging
    tokenInfo: {
      hasToken: !!rawToken,
      tokenLength: rawToken ? rawToken.length : 0,
      isJWT: rawToken ? rawToken.split(".").length === 3 : false,
      isValid: tokenValid,
      isExpired: tokenExpired,
      formattedCorrectly: authorizationHeader.startsWith("Bearer "),
      source: tokenSource,
    },
  };

  // Add Authorization header only if token is present and valid
  if (authorizationHeader && tokenValid && !tokenExpired) {
    config.headers.Authorization = authorizationHeader;

    // Verify token length
    if (authorizationHeader.length < 100) {
      logger.error("🚨 CRITICAL: Authorization header appears truncated!");
    }
  } else {
    logger.warn("⚠️  No valid authorization token available for API config");
  }

  // Enhanced logging
  logger.info("\n🔐 API CONFIGURATION STATUS:");
  logger.info(`   Base URL: ${config.baseURL}`);
  logger.info(`   Token Source: ${config.tokenInfo.source}`);
  logger.info(
    `   Has Token: ${config.tokenInfo.hasToken ? "✅ YES" : "❌ NO"}`
  );
  logger.info(
    `   Token Valid: ${config.tokenInfo.isValid ? "✅ YES" : "❌ NO"}`
  );
  logger.info(
    `   Token Expired: ${config.tokenInfo.isExpired ? "❌ YES" : "✅ NO"}`
  );

  if (config.headers.Authorization) {
    logger.info(`   Authorization Header: ✅ SET`);
    logger.info(
      `   Token Length: ${config.headers.Authorization.length} characters`
    );

    // Security: log preview only
    const preview = config.headers.Authorization.substring(0, 20) + "...";
    logger.info(`   Token Preview: ${preview}`);
  } else {
    logger.error("   Authorization Header: ❌ MISSING");
  }

  return config;
};

// Export the configuration
module.exports = getApiConfig();
