// utils\Security-helpers.js

const fs = require("fs");
const path = require("path");
const apiClient = require("./api-client"); // Assume apiClient is configured (e.g., using axios)
const logger = require("./logger");
const { HTTP_STATUS_CODES, FILE_PATHS } = require("../Constants");
const MALICIOUS_PAYLOADS = require("../test-data/security/malicious-payloads");

/**
 * Utility class containing shared helper functions for API security testing.
 * All functions are refactored to remove Allure dependencies and return structured results.
 */
class SecurityHelpers {
  // ... inside SecurityHelpers class
  /**
   * Fetches pre-defined malicious payloads.
   * NOTE: This relies on the imported MALICIOUS_PAYLOADS.
   * @returns {object} The malicious payloads object.
   */
  static generateMaliciousPayloads() {
    return MALICIOUS_PAYLOADS;
  }

  static generateSQLInjectionPayloads() {
    return MALICIOUS_PAYLOADS.SQL_INJECTION;
  }
  static generateXSSPayloads() {
    return MALICIOUS_PAYLOADS.XSS;
  }

  /**
   * Finds the primary operation (e.g., 'Post', 'PUT', 'GET') endpoint from a module config.
   * @param {object} moduleConfig - The configuration object for the module.
   * @param {string} preferredOperation - The desired operation (e.g., 'Post').
   * @returns {object|null} The operation object containing 'method' and 'path', or null.
   */
  static getModuleOperation(moduleConfig, preferredOperation) {
    if (!moduleConfig || !preferredOperation) return null;

    const operation = moduleConfig[preferredOperation];
    // NOTE: Original code assumed operation to be an object with method/path.
    // Given the test uses moduleConfig.CREATE[0] (a URL string), this helper is likely misaligned.
    // Returning the endpoint array for simplicity, as tests rely on index [0] being the URL.
    if (Array.isArray(operation) && operation[0]) {
      // Return the entire array/config entry
      return operation;
    }
    return null;
  }

  /**
   * Loads a valid JSON payload for a given module/operation.
   * @param {string} fullModuleName - The full module path (e.g., 'Accounting.Transaction.Journal_Entry').
   * @param {string} operation - The operation name (e.g., 'Post').
   * @returns {object|null} The loaded payload, or null if not found.
   */
  static loadPayload(fullModuleName, operation) {
    // Construct the expected file path based on module name and operation
    const parts = fullModuleName.split(".");
    const fileName = `${parts[parts.length - 1]}-${operation}.json`;
    const filePath = path.join(
      FILE_PATHS.INPUT_DATA_ROOT,
      fullModuleName,
      fileName
    );

    if (!fs.existsSync(filePath)) {
      logger.warn(
        `Payload not found for ${fullModuleName} (${operation}): ${filePath}`
      );
      return null;
    }

    try {
      const content = fs.readFileSync(filePath, "utf8");
      return JSON.parse(content);
    } catch (error) {
      logger.error(
        `Failed to read/parse payload for ${fullModuleName}: ${error.message}`
      );
      return null;
    }
  }

  /**
   * Fetches a default test data utility class/object.
   * NOTE: This helper assumes the existence of a TestData utility class/module.
   * Since the definition is external, we will return a placeholder object.
   * @returns {{getPostData: function, getNullRequiredFields: function}}
   */
  static getDefaultTestData() {
    // Placeholder implementation for external dependency (must be provided externally)
    return {
      getPostData: () => ({
        name: "Valid_Name",
        value: 123,
        description: "Test",
      }),
      getNullRequiredFields: () => ({
        name: null,
        value: 123,
        description: "Test",
      }),
    };
  }

  // --- CORE UTILITY FUNCTIONS ---

  /**
   * Make an API call using the appropriate method. Handles errors gracefully.
   * @param {string} url - The endpoint URL.
   * @param {string} method - HTTP method ('POST', 'GET', etc.).
   * @param {object} [data] - Request body data.
   * @param {object} [client=apiClient] - The API client instance to use.
   * @returns {Promise<object>} The response object (status, data, etc.).
   */
  static async makeApiCall(url, method, data = null, client = apiClient) {
    try {
      logger.info(`🌐 Making ${method} request to: ${url}`);
      let response;
      switch (method.toUpperCase()) {
        case "GET":
          response = await client.get(url);
          break;
        case "POST":
          response = await client.post(url, data);
          break;
        case "PUT":
          response = await client.put(url, data);
          break;
        case "DELETE":
          response = await client.delete(url);
          break;
        default:
          throw new Error(`Unsupported method: ${method}`);
      }
      return response;
    } catch (error) {
      // Return a structured error response similar to an Axios response
      return (
        error.response || {
          status: "No response",
          statusText: "Request failed (Network/Timeout)",
          data: null,
          error: error.message,
        }
      );
    }
  }

  // --- SECURITY TESTING FUNCTIONS (Refactored) ---

  /**
   * Advanced SQL Injection Protection Testing (TC-5).
   * Iterates through a set of SQL payloads and posts them to the endpoint.
   * Checks if the request is blocked (4xx/5xx) or if the response leaks SQL error details.
   * @param {object} moduleConfig - The module configuration object.
   * @param {string} moduleName - The name of the module.
   * @returns {Promise<Array<object>>} Array of detailed test results.
   */
  static async testSQLInjectionProtection(moduleConfig, moduleName = "") {
    logger.info(`🛡️ Starting advanced SQL Injection tests for ${moduleName}`);
    const results = [];
    const endpoint = moduleConfig.CREATE;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          test: "SQL Injection Protection",
          skipped: true,
          message: `No POST endpoint available for SQL testing in ${moduleName}`,
          module: moduleName,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    const sqlPayloads = this.generateSQLInjectionPayloads();
    const testData = this.getDefaultTestData();
    const targetUrl = endpoint[0];

    // Iterate through different SQL injection techniques
    for (const [technique, payloads] of Object.entries(sqlPayloads)) {
      // Iterate through fields/parameters to inject into
      for (const [field, sqlPayload] of Object.entries(payloads)) {
        try {
          const baseData = testData.getPostData();
          const maliciousData = { ...baseData };

          // Inject the payload into the field, handling both existing and new fields
          maliciousData[field] = sqlPayload;

          logger.debug(`Injecting SQL (${technique}) into field: ${field}`);

          const response = await apiClient.post(targetUrl, maliciousData);

          const isBlocked = [
            HTTP_STATUS_CODES.BAD_REQUEST, // 400
            422, // Unprocessable Entity
            HTTP_STATUS_CODES.FORBIDDEN, // 403
            HTTP_STATUS_CODES.SERVER_ERROR, // 500
          ].includes(response.status);
          const showsError = this.checkSQLErrorIndicators(response);

          results.push({
            test: `SQL ${technique} - ${field}`,
            expected: "400/422/403/500 or no SQL error leakage",
            actual: response.status,
            success: isBlocked || !showsError,
            blocked: isBlocked,
            errorLeakage: showsError,
            payloadPreview: sqlPayload.substring(0, 50) + "...",
            message: `Result: Status ${response.status}. Blocked: ${isBlocked}, Leakage: ${showsError}`,
            module: moduleName,
            timestamp: new Date().toISOString(),
          });
        } catch (error) {
          logger.error(
            `SQL Injection Test Error (${technique} in ${field}): ${error.message}`
          );
          results.push({
            test: `SQL ${technique} - ${field}`,
            success: false,
            error: error.message,
            module: moduleName,
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    logger.info(
      `🛡️ SQL Injection tests finished. Total tests: ${results.length}`
    );
    return results;
  }

  /**
   * Comprehensive XSS Protection Testing (TC-6).
   * Iterates through XSS payloads and posts them, checking if they are blocked or sanitized.
   * @param {object} moduleConfig - The module configuration object.
   * @param {string} moduleName - The name of the module.
   * @returns {Promise<Array<object>>} Array of detailed test results.
   */
  static async testXSSProtection(moduleConfig, moduleName = "") {
    logger.info(`🕷️ Starting advanced XSS Protection tests for ${moduleName}`);
    const results = [];
    const endpoint = moduleConfig.CREATE;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          test: "XSS Protection",
          skipped: true,
          message: `No POST endpoint available for XSS testing in ${moduleName}`,
          module: moduleName,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    const xssPayloads = this.generateXSSPayloads();
    const testData = this.getDefaultTestData();
    const targetUrl = endpoint[0];

    // Iterate through different XSS vector types
    for (const [vectorType, payloads] of Object.entries(xssPayloads)) {
      // Iterate through fields/parameters to inject into
      for (const [field, xssPayload] of Object.entries(payloads)) {
        try {
          const baseData = testData.getPostData();
          const maliciousData = { ...baseData };

          // Inject the payload into the field, handling both existing and new fields
          maliciousData[field] = xssPayload;

          logger.debug(`Injecting XSS (${vectorType}) into field: ${field}`);

          const response = await apiClient.post(targetUrl, maliciousData);

          const isBlocked = [
            HTTP_STATUS_CODES.BAD_REQUEST, // 400
            422, // Unprocessable Entity
            HTTP_STATUS_CODES.FORBIDDEN, // 403
            HTTP_STATUS_CODES.SERVER_ERROR, // 500
          ].includes(response.status);
          const isSanitized = this.checkXSSSanitization(response, xssPayload);

          results.push({
            test: `XSS ${vectorType} - ${field}`,
            expected: "400/422/403 or sanitized content",
            actual: response.status,
            success: isBlocked || isSanitized,
            blocked: isBlocked,
            sanitized: isSanitized,
            payloadPreview: xssPayload.substring(0, 50) + "...",
            message: `Result: Status ${response.status}. Blocked: ${isBlocked}, Sanitized: ${isSanitized}`,
            module: moduleName,
            timestamp: new Date().toISOString(),
          });
        } catch (error) {
          logger.error(
            `XSS Protection Test Error (${vectorType} in ${field}): ${error.message}`
          );
          results.push({
            test: `XSS ${vectorType} - ${field}`,
            success: false,
            error: error.message,
            module: moduleName,
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    logger.info(
      `🕷️ XSS Protection tests finished. Total tests: ${results.length}`
    );
    return results;
  }

  /**
   * Runs Authorization Security Tests (No Token, Wrong Token).
   * @param {object} moduleConfig - The module configuration object.
   * @param {string} moduleName - The name of the module.
   * @returns {Promise<Array<object>>} Array of test results.
   */
  static async testAuthorizationSecurity(moduleConfig, moduleName = "") {
    logger.info(`🔐 Starting Authorization Security Tests for ${moduleName}`);
    const results = [];
    const endpoint = moduleConfig.CREATE;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          test: "Authorization",
          skipped: true,
          message: `No POST endpoint available`,
          module: moduleName,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    const testData = this.getDefaultTestData();
    const requestData = testData.getPostData();

    // 1. Test: No Token
    try {
      // NOTE: Assumes apiClient.withNoToken() exists and returns a client instance
      const client = apiClient.withNoToken();
      const response = await this.makeApiCall(
        endpoint[0],
        "POST",
        requestData,
        client
      );

      const success = response.status === 401 || response.status === 403;
      results.push({
        test: "No Token Authorization",
        expected: 401,
        actual: response.status,
        success: success,
        message: success
          ? "Passed (401/403 returned)"
          : `Failed: Expected 401/403, got ${response.status}`,
        module: moduleName,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`No Token Test Error: ${error.message}`);
      results.push({
        test: "No Token Authorization",
        success: false,
        error: error.message,
        module: moduleName,
        timestamp: new Date().toISOString(),
      });
    }

    // 2. Test: Wrong Token
    try {
      // NOTE: Assumes apiClient.withWrongToken() exists and returns a client instance
      const client = apiClient.withWrongToken();
      const response = await this.makeApiCall(
        endpoint[0],
        "POST",
        requestData,
        client
      );

      const success = response.status === 401 || response.status === 403;
      results.push({
        test: "Wrong Token Authorization",
        expected: 401,
        actual: response.status,
        success: success,
        message: success
          ? "Passed (401/403 returned)"
          : `Failed: Expected 401/403, got ${response.status}`,
        module: moduleName,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`Wrong Token Test Error: ${error.message}`);
      results.push({
        test: "Wrong Token Authorization",
        success: false,
        error: error.message,
        module: moduleName,
        timestamp: new Date().toISOString(),
      });
    }

    logger.info(
      `🔐 Authorization tests completed: ${
        results.filter((r) => r.success).length
      }/${results.length} passed.`
    );
    return results;
  }

  /**
   * Runs Malicious Payload Tests (SQL Injection, XSS Injection).
   * @param {object} moduleConfig - The module configuration object.
   * @param {string} endpointType - The endpoint type (e.g., 'Post').
   * @param {string} moduleName - The name of the module.
   * @returns {Promise<Array<object>>} Array of test results.
   */
  static async testMaliciousPayloads(
    moduleConfig,
    endpointType = "Post",
    moduleName = ""
  ) {
    logger.info(`🦠 Starting Malicious Payload Tests for ${moduleName}`);
    const results = [];
    const endpoint = moduleConfig[endpointType];

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          test: "Malicious Payloads",
          skipped: true,
          message: `No ${endpointType} endpoint available`,
          module: moduleName,
          timestamp: new Date().toISOString(),
        },
      ];
    }

    const maliciousPayloads = this.generateMaliciousPayloads();
    const testData = this.getDefaultTestData();
    const targetUrl = endpoint[0];

    // SQL Injection Test
    const sqlInjectionPayload = {
      ...testData.getPostData(),
      ...maliciousPayloads.sqlInjection,
    };
    try {
      const response = await this.makeApiCall(
        targetUrl,
        "POST",
        sqlInjectionPayload
      );
      const isSuccess = [400, 422, 500, 403].includes(response.status);
      results.push({
        test: "SQL Injection",
        expected: "400/422/500/403",
        actual: response.status,
        success: isSuccess,
        message: isSuccess
          ? "Passed (Blocked/Errored gracefully)"
          : `Failed: Expected 400/422/500/403, got ${response.status}`,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`SQL Injection Test Error: ${error.message}`);
      results.push({
        test: "SQL Injection",
        success: false,
        error: error.message,
      });
    }

    // XSS Injection Test
    const xssPayload = {
      ...testData.getPostData(),
      ...maliciousPayloads.xss,
    };
    try {
      const response = await this.makeApiCall(targetUrl, "POST", xssPayload);
      const isSuccess = [400, 422, 500, 403].includes(response.status);
      results.push({
        test: "XSS Injection",
        expected: "400/422/500/403",
        actual: response.status,
        success: isSuccess,
        message: isSuccess
          ? "Passed (Blocked/Errored gracefully)"
          : `Failed: Expected 400/422/500/403, got ${response.status}`,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(`XSS Injection Test Error: ${error.message}`);
      results.push({
        test: "XSS Injection",
        success: false,
        error: error.message,
      });
    }

    logger.info(`🦠 Malicious payload tests finished.`);
    return results;
  }

  /**
   * Tests for proper 400 response when required fields are explicitly set to null.
   * @param {object} moduleConfig - The module configuration object.
   * @param {string} endpointType - The endpoint type (e.g., 'Post').
   * @param {string} moduleName - The name of the module.
   * @returns {Promise<object>} The single test result object.
   */
  static async testNullRequiredFields(
    moduleConfig,
    endpointType = "Post",
    moduleName = ""
  ) {
    logger.info(`🗂️ Starting Null Required Fields Test for ${moduleName}`);
    const endpoint = moduleConfig[endpointType];

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return {
        test: "Null Required Fields",
        skipped: true,
        message: `No ${endpointType} endpoint available`,
        module: moduleName,
        timestamp: new Date().toISOString(),
      };
    }

    const testData = this.getDefaultTestData();
    const nullPayload = testData.getNullRequiredFields();

    try {
      const response = await this.makeApiCall(endpoint[0], "POST", nullPayload);

      const success = response.status === HTTP_STATUS_CODES.BAD_REQUEST; // 400
      return {
        test: "Null Required Fields",
        expected: HTTP_STATUS_CODES.BAD_REQUEST,
        actual: response.status,
        success: success,
        message: success
          ? "Passed (400 returned)"
          : `Failed: Expected 400, got ${response.status}`,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error(`Null Required Fields Test Error: ${error.message}`);
      return {
        test: "Null Required Fields",
        success: false,
        error: error.message,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Checks response content for indicators of SQL error leakage.
   * NOTE: This is a simplified check.
   * @param {object} response - The API response object.
   * @returns {boolean} True if error indicators are found.
   */
  static checkSQLErrorIndicators(response) {
    if (!response.data) return false;

    const dataString = JSON.stringify(response.data).toLowerCase();
    const indicators = [
      "sql",
      "syntax error",
      "database error",
      "odbc",
      "db exception",
    ];

    return indicators.some((ind) => dataString.includes(ind));
  }

  /**
   * Checks if response content shows evidence of XSS payload sanitization.
   * NOTE: This is a simplified check for security purposes.
   * @param {object} response - The API response object.
   * @param {string} originalPayload - The XSS payload used.
   * @returns {boolean} True if payload appears to be sanitized or blocked.
   */
  static checkXSSSanitization(response, originalPayload) {
    // If the response status indicates a block, it's considered safe (sanitized=true)
    if ([400, 422, 403].includes(response.status)) return true;

    if (!response.data) return false;

    const dataString = JSON.stringify(response.data);

    // Check if the original payload (e.g., <script>alert(1)</script>)
    // is returned un-modified in the response, which indicates failure (not sanitized)
    if (dataString.includes(originalPayload)) {
      return false; // Not sanitized
    }

    // If the payload is modified or absent, assume it was sanitized or not reflected.
    // This logic is a simplification for a security helper utility.
    return true;
  }

  // --- INTERNAL FUZZING HELPERS ---

  /**
   * Recursively injects a malicious string into all string properties of an object.
   * @param {object} payload - The object to fuzz.
   * @param {string} maliciousString - The string to inject.
   * @returns {object} The fuzzed payload.
   */
  static _fuzzPayload(payload, maliciousString) {
    if (typeof payload !== "object" || payload === null) {
      return payload;
    }

    for (const key in payload) {
      if (payload.hasOwnProperty(key)) {
        const value = payload[key];

        if (typeof value === "string") {
          // Inject the malicious string only if the existing string is not a placeholder for a resource ID
          if (!key.toLowerCase().includes("id") && value.length > 0) {
            payload[key] = maliciousString;
          }
        } else if (Array.isArray(value)) {
          // Recurse into array elements
          payload[key] = value.map((item) =>
            SecurityHelpers._fuzzPayload(item, maliciousString)
          );
        } else if (typeof value === "object" && value !== null) {
          // Recurse into nested objects
          payload[key] = SecurityHelpers._fuzzPayload(value, maliciousString);
        }
      }
    }
    return payload;
  }

  /**
   * Validates if a string is a valid UUID format.
   * @param {string} id - The string to check.
   * @returns {boolean}
   */
  static isValidUUID(id) {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(id);
  }
}

module.exports = SecurityHelpers;
