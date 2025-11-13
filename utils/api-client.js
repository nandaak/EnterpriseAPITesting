// utils/api-client.js - Completely fixed version
const axios = require("axios");
const apiConfig = require("../config/api-config");
const logger = require("./logger");
const TokenManager = require("./token-manager");

class ApiClient {
  constructor(customConfig = {}) {
    // Get the base configuration
    const baseConfig =
      typeof apiConfig === "function" ? apiConfig() : apiConfig;

    // Merge configurations with proper header handling
    const config = {
      ...baseConfig,
      ...customConfig,
      headers: {
        ...baseConfig.headers,
        ...customConfig.headers,
      },
    };

    // Enhanced token validation with proper debugging
    this.validateTokenConfiguration(config);

    // Create axios instance with ALL headers including Authorization
    this.client = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout,
      headers: { ...config.headers }, // CRITICAL: Include all headers
      validateStatus: config.validateStatus,
      maxContentLength: config.maxContentLength,
      maxBodyLength: config.maxBodyLength,
    });

    this.setupInterceptors();
  }

  /**
   * Creates a client instance configured to send requests without an Authorization token.
   * @returns {ApiClient} A new client instance.
   */
  static withNoToken() {
    // Assuming a standard configuration utility
    return this.createInstance({ headers: { Authorization: null } });
    // OR, if using Axios directly: return axios.create({ baseURL, headers: { Authorization: null } })
  }

  /**
   * Creates a client instance configured with an invalid Authorization token.
   * @returns {ApiClient} A new client instance.
   */
  static withWrongToken() {
    const invalidToken = "Bearer invalid-token-for-security-test-purposes";
    return this.createInstance({ headers: { Authorization: invalidToken } });
  }

  /**
   * Check if the API client is ready with token
   */
  isReady() {
    return !!(this.token && this.client);
  }

  /**
   * Get token status for debugging
   */
  getTokenStatus() {
    return {
      hasToken: !!this.token,
      tokenLength: this.token ? this.token.length : 0,
      tokenPreview: this.token
        ? this.token.substring(0, 20) + "..."
        : "No token",
      isReady: this.isReady(),
    };
  }

  validateTokenConfiguration(config) {
    const authHeader = config.headers?.Authorization;
    const hasToken = authHeader && authHeader.startsWith("Bearer ");

    logger.info(
      `🔐 API Client Token Status: ${hasToken ? "PRESENT" : "MISSING"}`
    );

    if (hasToken) {
      // Log actual token length for debugging
      logger.debug(
        `🔐 Actual Token Length in Config: ${authHeader.length} characters`
      );

      const tokenPreview =
        authHeader.length > 30
          ? `${authHeader.substring(0, 25)}...${authHeader.substring(
              authHeader.length - 5
            )}`
          : authHeader;

      logger.debug(`🔐 Token Preview: ${tokenPreview}`);
      logger.info(`✅ API Client configured with valid Bearer token`);
    } else {
      logger.error("🚨 API Client configured WITHOUT Authorization token!");
    }
  }

  setupInterceptors() {
    // Request interceptor - FIXED: Don't modify the actual token
    this.client.interceptors.request.use(
      (config) => {
        // Create a safe copy for logging ONLY
        const logConfig = {
          ...config,
          headers: { ...config.headers },
        };

        // Mask token in log copy only
        if (logConfig.headers?.Authorization) {
          const token = logConfig.headers.Authorization;
          const maskedToken =
            token.length > 25
              ? `${token.substring(0, 20)}...${token.substring(
                  token.length - 5
                )}`
              : "***MASKED***";
          logConfig.headers.Authorization = maskedToken;
        }

        logger.info(
          `🌐 Making ${config.method?.toUpperCase()} to: ${config.baseURL}${
            config.url
          }`
        );
        logger.debug(
          `📋 Headers: ${JSON.stringify(logConfig.headers, null, 2)}`
        );

        // Log actual token status without modifying it
        if (config.headers?.Authorization) {
          const actualToken = config.headers.Authorization;
          const hasBearerToken =
            actualToken && actualToken.startsWith("Bearer ");
          logger.info(
            `🔐 Request Auth: ${
              hasBearerToken ? "Bearer Token ✅" : "Invalid Format ❌"
            }`
          );

          if (hasBearerToken) {
            logger.debug(
              `🔐 Actual Token Length in Request: ${actualToken.length}`
            );

            // CRITICAL: Verify token integrity
            if (actualToken.length < 100) {
              logger.error(
                `🚨 CRITICAL: Token appears truncated! Length: ${actualToken.length}`
              );
            } else {
              logger.debug(
                `🔐 Token integrity: ✅ GOOD (${actualToken.length} chars)`
              );
            }
          }
        } else {
          logger.error("🔐 Request Auth: NO AUTHORIZATION HEADER ❌");
        }

        return config; // Return original config, not the logged one
      },
      (error) => {
        logger.error("❌ Request interceptor error:", error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        logger.info(
          `📥 Response: ${response.status} for ${response.config.url}`
        );
        return response;
      },
      (error) => {
        if (error.response?.status === 401) {
          logger.error(`🔐 AUTH FAILED (401) for: ${error.config?.url}`);
          logger.error(`🔐 Method: ${error.config?.method}`);

          // Debug token in failed request
          if (error.config?.headers?.Authorization) {
            const authHeader = error.config.headers.Authorization;
            logger.error(`🔐 Auth Header Present: YES`);
            logger.error(`🔐 Auth Header Length: ${authHeader.length}`);
            logger.error(
              `🔐 Auth Format: ${
                authHeader.startsWith("Bearer ") ? "Bearer ✅" : "Other ❌"
              }`
            );

            if (authHeader.length < 100) {
              logger.error(
                `🚨 SUSPECTED TOKEN TRUNCATION: Length only ${authHeader.length}`
              );
            }
          } else {
            logger.error(`🔐 Auth Header Present: NO`);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // Add this method to your ApiClient class
  async request(config) {
    try {
      const response = await this.client(config);
      return {
        data: response.data,
        status: response.status,
        headers: response.headers,
        config: response.config,
      };
    } catch (error) {
      // Enhanced error logging for debugging
      if (error.response) {
        const { status, data } = error.response;
        logger.error(`🔍 Detailed Error Analysis:`);
        logger.error(`   - Status: ${status}`);
        logger.error(`   - URL: ${error.config?.url}`);
        logger.error(`   - Method: ${error.config?.method}`);

        if (status === 500) {
          logger.error(`   - Server Error: Check payload and server logs`);
          logger.debug(`   - Response data:`, data);
        } else if (status === 404) {
          logger.error(`   - Not Found: Check endpoint URL and resource ID`);
        }
      }

      throw error;
    }
  }

  // Update the get method to use normalized URLs
  async get(url, config = {}) {
    const normalizedUrl = this.normalizeUrl(url);
    return this.request({ method: "GET", url: normalizedUrl, ...config });
  }

  // async get(url, config = {}) {
  //   return this.request({ method: "GET", url, ...config });
  // }

  async post(url, data, config = {}) {
    return this.request({ method: "POST", url, data, ...config });
  }

  async put(url, data, config = {}) {
    return this.request({ method: "PUT", url, data, ...config });
  }

  async delete(url, config = {}) {
    return this.request({ method: "DELETE", url, ...config });
  }

  // Enhanced token testing with detailed diagnostics
  async testTokenValidity() {
    logger.info("🔐 Comprehensive token validity test...");
    const testEndpoint = "/erp-apis/JournalEntry";

    try {
      // First, check current token state
      const currentToken =
        this.client.defaults.headers?.Authorization ||
        this.client.defaults.headers?.common?.Authorization;

      if (!currentToken) {
        logger.error("❌ No token found in client configuration");
        return false;
      }

      logger.info(`🔐 Testing token with length: ${currentToken.length}`);

      if (currentToken.length < 100) {
        logger.error(
          `🚨 Token appears truncated: ${currentToken.length} characters`
        );
        return false;
      }

      const response = await this.get(testEndpoint);

      if (response.status === 200) {
        logger.info("✅ Token is VALID and working");
        return true;
      } else {
        logger.error(`❌ Token test failed with status: ${response.status}`);

        // Additional diagnostics for 401
        if (response.status === 401) {
          logger.error(`🔐 401 Diagnostic Info:`);
          logger.error(`   - Token Length: ${currentToken.length}`);
          logger.error(`   - Endpoint: ${testEndpoint}`);
          logger.error(`   - Base URL: ${this.client.defaults.baseURL}`);
        }

        return false;
      }
    } catch (error) {
      logger.error(`❌ Token test error: ${error.message}`);
      return false;
    }
  }

  // Create client with specific token - FIXED
  withToken(token) {
    // Ensure proper token formatting
    const authHeader = token.startsWith("Bearer ") ? token : `Bearer ${token}`;

    logger.info(
      `🔐 Creating API client with provided token (length: ${authHeader.length})`
    );

    return new ApiClient({
      headers: {
        Authorization: authHeader,
      },
    });
  }

  // Static method to create client with token from file - FIXED
  static async createWithTokenFromFile() {
    try {
      const token = await TokenManager.getValidToken();
      if (!token) {
        throw new Error("No valid token available");
      }

      const authHeader = TokenManager.formatTokenForHeader(token);
      logger.info(
        `🔐 Creating API client with token from file (length: ${authHeader.length})`
      );

      return new ApiClient({
        headers: {
          Authorization: authHeader,
        },
      });
    } catch (error) {
      logger.error(
        `❌ Failed to create API client with token from file: ${error.message}`
      );
      throw error;
    }
  }

  // Add this method to your ApiClient class
  normalizeUrl(url) {
    if (!url) return url;

    const baseUrl = this.client.defaults.baseURL;

    // Remove duplicate base URLs
    if (url.startsWith(baseUrl + baseUrl)) {
      return url.replace(baseUrl, "");
    }

    // Ensure proper URL format
    if (url.startsWith("http")) {
      return url;
    } else {
      return url.startsWith("/") ? url : `/${url}`;
    }
  }
}

// Create and export a default instance
const defaultClient = new ApiClient();

// Export both the class and default instance
module.exports = defaultClient;
module.exports.ApiClient = ApiClient;
