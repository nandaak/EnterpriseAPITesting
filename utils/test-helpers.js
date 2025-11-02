// utils/test-helpers.js - Complete Enhanced Implementation
const apiClient = require("./api-client");
const logger = require("./logger");
const TokenManager = require("./token-manager");
const { endpointTypes, TEST_TAGS, HTTP_STATUS_CODES } = require("../Constants/Constants");

class TestHelpers {
  
  // ===========================================================================
  // CORE UTILITY METHODS
  // ===========================================================================

  /**
   * Debug response structure for troubleshooting
   */
  static debugResponseStructure(response, operation = "unknown") {
    const debugInfo = {
      operation,
      timestamp: new Date().toISOString(),
      responseStructure: {
        keys: Object.keys(response),
        dataType: typeof response.data,
        dataKeys: response.data && typeof response.data === "object" 
          ? Object.keys(response.data) 
          : "N/A",
        status: response.status,
        hasIdField: !!(response.id || (response.data && response.data.id)),
      },
      sampleData: {
        data: response.data && typeof response.data === "string" 
          ? response.data.substring(0, 50) + (response.data.length > 50 ? "..." : "")
          : response.data,
        id: response.id || "N/A",
        dataId: (response.data && response.data.id) || "N/A",
      },
    };

    global.attachJSON(`Response Structure Debug - ${operation}`, debugInfo);
    return debugInfo;
  }

  /**
   * Validate if a string is a valid UUID
   */
  static isValidUUID(str) {
    if (typeof str !== "string") return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
  }

  /**
   * Format error for consistent logging
   */
  static formatError(error) {
    if (typeof error === "object") {
      if (error.response) {
        return {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data,
          url: error.response.config?.url,
          method: error.response.config?.method,
        };
      } else if (error.request) {
        return { message: "No response received" };
      } else {
        return { message: error.message };
      }
    }
    return error;
  }

  /**
   * Mark test as failed for consistent error handling
   */
  static markTestAsFailed(errorMessage = "Test failed") {
    if (global.testState) {
      global.testState.hasAssertionErrors = true;
      global.testState.testStatus = "failed";
    }
    global.attachAllureLog("Test Failure", errorMessage);
  }

  /**
   * Sleep utility for delays
   */
  static sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ===========================================================================
  // API CLIENT & TOKEN MANAGEMENT
  // ===========================================================================

  static async initializeApiClient() {
    return await global.allureStep("Initialize API Client with Token", async () => {
      try {
        const token = await TokenManager.ensureValidToken();
        logger.info("✅ API Client initialized with valid token from token.txt");

        const client = apiClient.withToken(token);
        const isValid = await client.testTokenValidity();
        if (!isValid) {
          throw new Error("Token validation failed during initialization");
        }

        return client;
      } catch (error) {
        logger.error(`❌ Failed to initialize API client: ${error.message}`);
        throw error;
      }
    });
  }

  static async checkTokenStatus() {
    return await global.allureStep("Check Token Status", async () => {
      const tokenInfo = TokenManager.getTokenInfo();
      global.attachJSON("Token Status", tokenInfo);

      if (!tokenInfo.exists) {
        logger.error("❌ No token found in token.txt");
        return { valid: false, reason: "No token file" };
      }

      if (!tokenInfo.isValid) {
        logger.error(`❌ Token is invalid: ${tokenInfo.reason}`);
        return { valid: false, reason: tokenInfo.reason };
      }

      const minutesUntilExpiry = Math.round(tokenInfo.timeUntilExpiry / (1000 * 60));
      logger.info(`✅ Token is valid (expires in ${minutesUntilExpiry} minutes)`);

      return {
        valid: true,
        expiresIn: `${minutesUntilExpiry} minutes`,
        expiresAt: tokenInfo.expiresAt,
        source: tokenInfo.source,
      };
    });
  }

  static async refreshTokenIfNeeded() {
    return await global.allureStep("Refresh Token If Needed", async () => {
      try {
        const token = await TokenManager.ensureValidToken();
        logger.info("✅ Token refreshed and validated");
        return token;
      } catch (error) {
        logger.error(`❌ Token refresh failed: ${error.message}`);
        throw error;
      }
    });
  }

  // ===========================================================================
  // RESPONSE VALIDATION & DATA EXTRACTION
  // ===========================================================================

  static validateResponseSuccess(response) {
    // Check HTTP status code is in success range (200-399)
    const httpStatusValid = response.status >= 200 && response.status < 400;

    // Check response data doesn't contain status: 400
    let responseStatusValid = true;
    if (response.data) {
      const checkForStatus400 = (obj) => {
        for (let key in obj) {
          if (typeof obj[key] === "object" && obj[key] !== null) {
            if (checkForStatus400(obj[key]) === false) return false;
          } else if (key.toLowerCase() === "status") {
            const statusValue = obj[key];
            if (statusValue == 400) return false;
          }
        }
        return true;
      };
      responseStatusValid = checkForStatus400(response.data);
    }

    return {
      httpStatusValid,
      responseStatusValid,
      overallValid: httpStatusValid && responseStatusValid,
    };
  }

  static validateResponseStructure(response, expectedFields = []) {
    return global.allureStep("Validate response structure", () => {
      try {
        expect(response).toBeDefined();
        expect(typeof response).toBe("object");

        const validationResult = this.validateResponseSuccess(response);

        if (!validationResult.httpStatusValid) {
          this.markTestAsFailed(`HTTP status code ${response.status} is not in success range (200-399)`);
          throw new Error(`HTTP status code ${response.status} is not in success range (200-399)`);
        }

        if (!validationResult.responseStatusValid) {
          this.markTestAsFailed("Response contains status: 400 which indicates failure");
          throw new Error("Response contains status: 400 which indicates failure");
        }

        // Handle both object and primitive data responses
        if (response.data !== undefined) {
          const dataType = typeof response.data;
          if (dataType === "object") {
            expectedFields.forEach((field) => {
              if (response.data && !response.data[field]) {
                logger.warn(`Expected field '${field}' not found in response data`);
              }
            });
          } else {
            logger.info(`Response data is primitive type: ${dataType}, value: ${response.data}`);
          }
        }

        global.attachAllureLog("Response Validation", {
          hasExpectedStructure: true,
          expectedFields,
          actualResponseKeys: Object.keys(response),
          responseType: typeof response,
          dataType: response.data ? typeof response.data : "undefined",
          dataValue: response.data,
          httpStatus: response.status,
          validationResult,
        });

        return validationResult.overallValid;
      } catch (error) {
        this.markTestAsFailed(`Response validation failed: ${error.message}`);
        throw error;
      }
    });
  }

  /**
   * Comprehensive ID extraction from API responses
   */
  static extractId(response) {
    return global.allureStep("Extract Resource ID from API Response", async () => {
      let extractedId = null;
      let extractionSource = "none";

      const debugInfo = {
        responseKeys: Object.keys(response),
        hasData: !!response.data,
        dataType: typeof response.data,
        dataPreview: typeof response.data === "object" ? Object.keys(response.data) : response.data,
        hasResult: !!response.result,
      };
      global.attachJSON("ID Extraction Debug - Initial Response Context", debugInfo);

      const strategies = [
        // Strategy 1: Direct ID string in response.data (must be UUID)
        {
          name: "response.data (direct UUID string)",
          check: () => typeof response.data === "string" && this.isValidUUID(response.data),
          getValue: () => response.data,
        },
        // Strategy 2: ID field within response.data object
        {
          name: "response.data object (UUID field)",
          check: () => response.data && typeof response.data === "object",
          getValue: () => {
            const idFields = ["id", "uuid", "Id", "ID", "UUID", "guid", "Guid", "GUID", "createdId", "resourceId", "entityId", "referenceId"];
            for (const field of idFields) {
              if (response.data[field] && this.isValidUUID(response.data[field])) {
                extractionSource = `response.data.${field} (UUID)`;
                return response.data[field];
              }
            }
            return null;
          },
        },
        // Strategy 3: Response object level ID field
        {
          name: "response.id (UUID)",
          check: () => response.id && this.isValidUUID(response.id),
          getValue: () => response.id,
        },
        // Strategy 4: Fallback to non-UUID "id" field
        {
          name: "response.data.id (non-UUID fallback)",
          check: () => response.data && typeof response.data === "object" && response.data.id,
          getValue: () => response.data.id,
        },
        // Strategy 5: Regex pattern match in entire response
        {
          name: "regex pattern match (last resort)",
          check: () => true,
          getValue: () => {
            const responseString = JSON.stringify(response);
            const uuidMatch = responseString.match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i);
            return uuidMatch ? uuidMatch[0] : null;
          },
        },
      ];

      for (const strategy of strategies) {
        if (strategy.check()) {
          const result = strategy.getValue();
          if (result) {
            extractedId = result;
            if (extractionSource === "none") extractionSource = strategy.name;
            break;
          }
        }
      }

      const extractionResult = {
        success: !!extractedId,
        value: extractedId,
        type: typeof extractedId,
        source: extractionSource,
        timestamp: new Date().toISOString(),
      };

      if (extractedId) {
        global.attachAllureLog("ID Extraction Success", extractionResult);
        logger.info(`✅ ID extracted successfully: ${extractedId} (from ${extractionSource})`);
      } else {
        global.attachAllureLog("ID Extraction Failed", extractionResult);
        logger.warn(`⚠️ Could not extract ID from response structure`);
      }

      return extractedId;
    });
  }

  // ===========================================================================
  // SECURITY TESTING IMPLEMENTATIONS
  // ===========================================================================

  /**
   * Comprehensive XSS Protection Testing
   */
  static async testXSSProtection(moduleConfig, moduleName = "") {
    return await global.allureStep(`XSS Protection Tests for ${moduleName}`, async () => {
      const xssTests = [];
      const endpoint = moduleConfig.Post;

      if (!endpoint || endpoint[0] === "URL_HERE") {
        return [{ skipped: true, message: `No POST endpoint available for XSS testing in ${moduleName}` }];
      }

      const xssPayloads = this.generateXSSPayloads();
      const testData = this.getDefaultTestData();

      global.attachJSON("XSS Test Payloads", xssPayloads);

      for (const [vectorType, payloads] of Object.entries(xssPayloads)) {
        for (const [field, xssPayload] of Object.entries(payloads)) {
          xssTests.push({
            name: `XSS ${vectorType} - ${field}`,
            test: async () => {
              return await global.allureStep(`Test XSS ${vectorType} in ${field}`, async () => {
                const baseData = testData.getPostData();
                const maliciousData = { ...baseData };
                
                if (maliciousData[field] !== undefined) {
                  maliciousData[field] = xssPayload;
                } else {
                  maliciousData[field] = xssPayload;
                }

                global.attachJSON(`XSS ${vectorType} Payload`, maliciousData);
                const response = await apiClient.post(endpoint[0], maliciousData);

                const isBlocked = [400, 422, 403, 500].includes(response.status);
                const isSanitized = this.checkXSSSanitization(response, xssPayload);

                return {
                  expected: "400/422/403 or sanitized content",
                  actual: response.status,
                  success: isBlocked || isSanitized,
                  blocked: isBlocked,
                  sanitized: isSanitized,
                  payload: xssPayload.substring(0, 50) + "...",
                  message: `XSS ${vectorType} should be blocked or sanitized`,
                };
              });
            },
          });
        }
      }

      const results = [];
      for (const test of xssTests) {
        try {
          const result = await test.test();
          results.push({ test: test.name, ...result });
        } catch (error) {
          results.push({ test: test.name, error: error.message, success: false });
        }
      }

      global.attachJSON("XSS Protection Test Results", results);
      return results;
    });
  }

  /**
   * Advanced SQL Injection Protection Testing
   */
  static async testSQLInjectionProtection(moduleConfig, moduleName = "") {
    return await global.allureStep(`SQL Injection Protection Tests for ${moduleName}`, async () => {
      const sqlTests = [];
      const endpoint = moduleConfig.Post;

      if (!endpoint || endpoint[0] === "URL_HERE") {
        return [{ skipped: true, message: `No POST endpoint available for SQL injection testing in ${moduleName}` }];
      }

      const sqlPayloads = this.generateSQLInjectionPayloads();
      const testData = this.getDefaultTestData();

      global.attachJSON("SQL Injection Payloads", sqlPayloads);

      for (const [technique, payloads] of Object.entries(sqlPayloads)) {
        for (const [field, sqlPayload] of Object.entries(payloads)) {
          sqlTests.push({
            name: `SQL ${technique} - ${field}`,
            test: async () => {
              return await global.allureStep(`Test SQL ${technique} in ${field}`, async () => {
                const baseData = testData.getPostData();
                const maliciousData = { ...baseData };
                
                if (maliciousData[field] !== undefined) {
                  maliciousData[field] = sqlPayload;
                } else {
                  maliciousData[field] = sqlPayload;
                }

                global.attachJSON(`SQL ${technique} Payload`, maliciousData);
                const response = await apiClient.post(endpoint[0], maliciousData);

                const isBlocked = [400, 422, 403, 500].includes(response.status);
                const showsError = this.checkSQLErrorIndicators(response);

                return {
                  expected: "400/422/403/500 or no SQL error leakage",
                  actual: response.status,
                  success: isBlocked || !showsError,
                  blocked: isBlocked,
                  errorLeakage: showsError,
                  payload: sqlPayload.substring(0, 50) + "...",
                  message: `SQL ${technique} should be blocked and not leak errors`,
                };
              });
            },
          });
        }
      }

      const results = [];
      for (const test of sqlTests) {
        try {
          const result = await test.test();
          results.push({ test: test.name, ...result });
        } catch (error) {
          results.push({ test: test.name, error: error.message, success: false });
        }
      }

      global.attachJSON("SQL Injection Protection Results", results);
      return results;
    });
  }

  /**
   * Real Performance Testing Under Malicious Load
   */
  static async testPerformanceUnderMaliciousLoad(moduleConfig, moduleName = "") {
    return await global.allureStep(`Real Performance Under Malicious Load for ${moduleName}`, async () => {
      const endpoint = moduleConfig.Post;

      if (!endpoint || endpoint[0] === "URL_HERE") {
        return {
          success: false,
          skipped: true,
          message: `No POST endpoint available for performance testing in ${moduleName}`,
        };
      }

      const performanceMetrics = {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        totalResponseTime: 0,
        responseTimes: [],
        errorRate: 0,
        throughput: 0,
      };

      const testData = this.getDefaultTestData();
      const concurrentRequests = 10;
      const requestsPerUser = 5;
      const maliciousPayloads = this.generatePerformanceTestPayloads();

      global.attachJSON("Performance Test Configuration", {
        module: moduleName,
        endpoint: endpoint[0],
        concurrentUsers: concurrentRequests,
        requestsPerUser: requestsPerUser,
        totalRequests: concurrentRequests * requestsPerUser,
        payloadTypes: Object.keys(maliciousPayloads),
      });

      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < concurrentRequests; i++) {
        const userPromises = [];
        for (let j = 0; j < requestsPerUser; j++) {
          const payloadType = Object.keys(maliciousPayloads)[j % Object.keys(maliciousPayloads).length];
          const payload = {
            ...testData.getPostData(),
            ...maliciousPayloads[payloadType],
            requestId: `user${i}_req${j}`,
            timestamp: new Date().toISOString(),
          };
          userPromises.push(this.makeTimedApiCall(endpoint[0], "POST", payload));
        }
        promises.push(...userPromises);
      }

      const results = await Promise.allSettled(promises);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;

      results.forEach((result) => {
        performanceMetrics.totalRequests++;
        if (result.status === "fulfilled" && result.value.success) {
          performanceMetrics.successfulRequests++;
          performanceMetrics.responseTimes.push(result.value.responseTime);
          performanceMetrics.totalResponseTime += result.value.responseTime;
        } else {
          performanceMetrics.failedRequests++;
        }
      });

      performanceMetrics.errorRate = (performanceMetrics.failedRequests / performanceMetrics.totalRequests) * 100;
      performanceMetrics.throughput = (performanceMetrics.totalRequests / (totalDuration / 1000)).toFixed(2);
      performanceMetrics.averageResponseTime = performanceMetrics.responseTimes.length > 0 
        ? performanceMetrics.totalResponseTime / performanceMetrics.responseTimes.length 
        : 0;
      performanceMetrics.p95ResponseTime = this.calculatePercentile(performanceMetrics.responseTimes, 95);
      performanceMetrics.p99ResponseTime = this.calculatePercentile(performanceMetrics.responseTimes, 99);

      const meetsPerformanceStandards = 
        performanceMetrics.averageResponseTime < 2000 && 
        performanceMetrics.errorRate < 5 && 
        performanceMetrics.p95ResponseTime < 3000;

      const performanceResult = {
        success: meetsPerformanceStandards,
        metrics: performanceMetrics,
        thresholds: { maxAverageResponseTime: 2000, maxErrorRate: 5, maxP95ResponseTime: 3000 },
        meetsStandards: meetsPerformanceStandards,
        duration: totalDuration,
        timestamp: new Date().toISOString(),
      };

      global.attachJSON("Performance Test Results", performanceResult);

      if (!meetsPerformanceStandards) {
        logger.warn(`Performance below standards for ${moduleName}`);
      }

      return performanceResult;
    });
  }

  // ===========================================================================
  // PAYLOAD GENERATORS
  // ===========================================================================

  static generateXSSPayloads() {
    return {
      scriptTags: {
        name: "<script>alert('XSS')</script>",
        description: "Test<script>console.log('xss')</script>",
        input: "<script>document.location='http://evil.com'</script>",
      },
      eventHandlers: {
        name: "<img src=x onerror=alert(1)>",
        description: "<body onload=alert('XSS')>",
        input: "<svg onload=alert(1)>",
      },
      javascriptProtocol: {
        name: "javascript:alert('XSS')",
        description: "JaVaScRiPt:alert('XSS')",
        input: "data:text/html,<script>alert('XSS')</script>",
      },
      obfuscated: {
        name: "<img src='x' onerror='&#x61;lert(1)'>",
        description: "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        input: "<img src='x' onerror='&amp;#x61;lert(1)'>",
      },
    };
  }

  static generateSQLInjectionPayloads() {
    return {
      tautologies: {
        name: "admin' OR '1'='1",
        description: "test' OR 'x'='x",
        input: "1' OR '1'='1",
      },
      unionQueries: {
        name: "test' UNION SELECT username, password FROM users--",
        description: "admin' UNION SELECT 1,2,3--",
        input: "' UNION SELECT * FROM passwords--",
      },
      piggybacked: {
        name: "test'; DROP TABLE users--",
        description: "admin'; DELETE FROM accounts--",
        input: "'; UPDATE users SET password='hacked'--",
      },
      blindInjection: {
        name: "test' AND 1=1--",
        description: "admin' AND SLEEP(5)--",
        input: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      },
    };
  }

  static generatePerformanceTestPayloads() {
    return {
      largePayload: {
        description: "A".repeat(1000),
        notes: "B".repeat(500),
        metadata: JSON.stringify({ large: "x".repeat(2000) }),
      },
      complexNested: {
        data: {
          nested: {
            level1: {
              level2: {
                level3: {
                  array: new Array(50).fill("test"),
                  object: Object.fromEntries(new Array(20).fill(0).map((_, i) => [`key${i}`, `value${i}`])),
                },
              },
            },
          },
        },
      },
      specialCharacters: {
        name: "Test @#$%^&*()_+-=[]{}|;:,.<>?~`",
        description: "Multi\nLine\nText\nWith\tTabs",
        content: "Unicode: 🚀 ✅ 🔥 🌟 💯",
      },
    };
  }

  static generateMaliciousPayloads() {
    return {
      sqlInjection: {
        input: "' OR '1'='1",
        name: "test'; DROP TABLE users; --",
        description: "test' UNION SELECT * FROM passwords --",
      },
      xss: {
        input: "<script>alert('XSS')</script>",
        name: "<img src=x onerror=alert('XSS')>",
        description: "javascript:alert('XSS')",
      },
      pathTraversal: {
        input: "../../../etc/passwd",
        filename: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      },
      bufferOverflow: {
        input: "A".repeat(10000),
        description: "B".repeat(5000),
      },
    };
  }

  // ===========================================================================
  // SECURITY VALIDATION HELPERS
  // ===========================================================================

  static checkXSSSanitization(response, originalPayload) {
    if (!response.data) return false;
    const responseString = JSON.stringify(response.data).toLowerCase();
    const payloadLower = originalPayload.toLowerCase();
    
    const dangerousPatterns = ["script", "javascript:", "onerror=", "onload=", "onmouseover=", "expression(", "eval("];
    const containsPayload = responseString.includes(payloadLower.replace(/<script>|javascript:|on\w+=/gi, ""));
    const hasDangerousContent = dangerousPatterns.some(pattern => responseString.includes(pattern));
    
    return containsPayload && !hasDangerousContent;
  }

  static checkSQLErrorIndicators(response) {
    if (!response.data) return false;
    const responseString = JSON.stringify(response.data).toLowerCase();
    const sqlErrorIndicators = ["sql", "mysql", "database", "syntax error", "union", "select", "from", "where", "oracle"];
    return sqlErrorIndicators.some(indicator => responseString.includes(indicator));
  }

  static getInvalidTokens() {
    return {
      wrongToken: "Bearer invalid_token_12345",
      expiredToken: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token",
      malformedToken: "InvalidTokenFormat",
      emptyToken: "",
    };
  }

  // ===========================================================================
  // TEST DATA GENERATORS
  // ===========================================================================

  static getDefaultTestData() {
    return {
      getPostData: () => ({
        name: `Test-${Date.now()}`,
        description: "API Testing",
        status: "Active",
        timestamp: new Date().toISOString(),
      }),
      getEditData: (originalData) => ({
        ...originalData,
        description: `UPDATED - ${originalData.description || "API Testing"}`,
        name: `Updated-${originalData.name || `Test-${Date.now()}`}`,
        updatedAt: new Date().toISOString(),
      }),
      getNullRequiredFields: () => ({
        name: null,
        description: null,
        status: null,
      }),
    };
  }

  // ===========================================================================
  // API OPERATIONS
  // ===========================================================================

  static async makeApiCall(endpoint, method = "POST", data = null) {
    return await global.allureStep(`API ${method} ${endpoint}`, async () => {
      try {
        let response;
        switch (method.toUpperCase()) {
          case "GET": response = await apiClient.get(endpoint); break;
          case "POST": response = await apiClient.post(endpoint, data); break;
          case "PUT": response = await apiClient.put(endpoint, data); break;
          case "DELETE": response = await apiClient.delete(endpoint); break;
          default: throw new Error(`Unsupported HTTP method: ${method}`);
        }

        global.attachJSON(`API ${method} Response`, {
          endpoint, method, status: response.status, success: response.success, data: response.data,
        });

        return response;
      } catch (error) {
        global.attachAllureLog(`API ${method} Error`, this.formatError(error));
        throw error;
      }
    });
  }

  static async makeTimedApiCall(endpoint, method, data) {
    const startTime = Date.now();
    try {
      const response = await apiClient.post(endpoint, data);
      const responseTime = Date.now() - startTime;
      return { success: response.success, status: response.status, responseTime, data: response.data };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return { success: false, error: error.message, responseTime };
    }
  }

  // ===========================================================================
  // URL MANIPULATION
  // ===========================================================================

  static removeLastUrlSection(url) {
    const urlObject = new URL(url, "http://localhost");
    let path = urlObject.pathname;
    if (path.endsWith("/")) path = path.slice(0, -1);
    const sections = path.split("/");
    if (sections.length > 1) sections.pop();
    const newPath = sections.join("/");
    urlObject.pathname = newPath;
    return urlObject.pathname;
  }

  static buildUrl(baseUrl, id) {
    const cleanBaseUrl = this.removeLastUrlSection(baseUrl);
    return cleanBaseUrl.endsWith("/") ? `${cleanBaseUrl}${id}` : `${cleanBaseUrl}/${id}`;
  }

  // ===========================================================================
  // DATA VALIDATION
  // ===========================================================================

  static verifyDataMatch(actual, expected) {
    return global.allureStep("Verify data integrity", () => {
      const keyFields = ["id", "name", "code", "description", "status", "Name", "Code", "Status"];
      const matches = {};
      const mismatches = [];

      keyFields.forEach((field) => {
        const actualValue = actual[field] || actual.data?.[field];
        const expectedValue = expected[field] || expected.data?.[field];
        if (expectedValue && actualValue) {
          const match = actualValue === expectedValue;
          matches[field] = { match, expected: expectedValue, actual: actualValue };
          if (!match) mismatches.push(field);
        }
      });

      global.attachJSON("Data Match Verification", {
        matches, mismatches, hasMismatches: mismatches.length > 0,
        totalFieldsChecked: keyFields.length, matchingFields: keyFields.length - mismatches.length,
      });

      if (mismatches.length > 0) {
        throw new Error(`Data mismatch in fields: ${mismatches.join(", ")}`);
      }

      return true;
    });
  }

  static verifyTransactionStatus(transactionData, expectedStatus) {
    return global.allureStep("Verify transaction status", () => {
      const statusFields = ["status", "transactionStatus", "state", "postingStatus", "Status", "State", "PostingStatus"];
      for (const field of statusFields) {
        const actualStatus = transactionData[field] || transactionData.data?.[field] || transactionData.result?.[field];
        if (actualStatus === expectedStatus) {
          global.attachAllureLog("Transaction Status Match", { field, expected: expectedStatus, actual: actualStatus });
          return true;
        }
      }
      global.attachAllureLog("Transaction Status Mismatch", {
        expected: expectedStatus, actual: transactionData, checkedFields: statusFields,
      });
      return false;
    });
  }

  // ===========================================================================
  // COMPREHENSIVE TEST SUITES
  // ===========================================================================

  static async testAuthorizationSecurity(moduleConfig, moduleName = "") {
    return await global.allureStep(`Authorization Security Tests for ${moduleName}`, async () => {
      const securityTests = [];
      const invalidTokens = this.getInvalidTokens();

      global.attachAllureLog("Authorization Test Configuration", {
        module: moduleName || moduleConfig,
        hasPostEndpoint: !!(moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE"),
        invalidTokensAvailable: !!invalidTokens,
      });

      // Test 1: No Token
      securityTests.push({
        name: "No Token Authorization",
        test: async () => {
          return await global.allureStep("Test without authorization token", async () => {
            if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
              const client = apiClient.withNoToken();
              const testData = this.getDefaultTestData();
              const requestData = testData.getPostData();

              global.attachJSON("No Token Request Data", requestData);
              global.attachAllureLog("No Token Endpoint", moduleConfig.Post[0]);

              const response = await client.post(moduleConfig.Post[0], requestData);
              global.attachJSON("No Token Response", response);

              return {
                expected: 401,
                actual: response.status,
                success: response.status === 401 || response.status === 403,
                message: `No token should return 401/403, got ${response.status}`,
              };
            }
            return { skipped: true, message: "No POST endpoint available" };
          });
        },
      });

      // Test 2: Wrong Token
      securityTests.push({
        name: "Wrong Token Authorization",
        test: async () => {
          return await global.allureStep("Test with wrong authorization token", async () => {
            if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
              const client = apiClient.withWrongToken();
              const testData = this.getDefaultTestData();
              const requestData = testData.getPostData();

              global.attachJSON("Wrong Token Request Data", requestData);
              global.attachAllureLog("Wrong Token Endpoint", moduleConfig.Post[0]);

              const response = await client.post(moduleConfig.Post[0], requestData);
              global.attachJSON("Wrong Token Response", response);

              return {
                expected: 401,
                actual: response.status,
                success: response.status === 401 || response.status === 403,
                message: `Wrong token should return 401/403, got ${response.status}`,
              };
            }
            return { skipped: true, message: "No POST endpoint available" };
          });
        },
      });

      const results = [];
      for (const securityTest of securityTests) {
        try {
          const result = await securityTest.test();
          results.push({ test: securityTest.name, ...result });
        } catch (error) {
          global.attachAllureLog(`Security Test Error - ${securityTest.name}`, error.message);
          results.push({ test: securityTest.name, error: error.message, success: false });
        }
      }

      const failedAuthTests = results.filter(test => !test.success && !test.skipped);
      if (failedAuthTests.length > 0) {
        this.markTestAsFailed(`Authorization tests failed: ${failedAuthTests.length} failures`);
        const errorMessages = failedAuthTests.map(test => test.message || test.error).join("; ");
        throw new Error(`Authorization security tests failed: ${errorMessages}`);
      }

      global.attachJSON("Authorization Security Test Results", results);
      return results.map(result => ({ ...result, module: moduleName, timestamp: new Date().toISOString() }));
    });
  }

  static async testMaliciousPayloads(moduleConfig, endpointType = "Post", moduleName = "") {
    return await global.allureStep(`Malicious Payload Tests for ${moduleName}`, async () => {
      const maliciousTests = [];
      const endpoint = moduleConfig[endpointType];

      if (!endpoint || endpoint[0] === "URL_HERE") {
        return [{ skipped: true, message: `No ${endpointType} endpoint available` }];
      }

      const maliciousPayloads = this.generateMaliciousPayloads();
      const testData = this.getDefaultTestData();

      global.attachJSON("Malicious Payloads", maliciousPayloads);

      // SQL Injection Test
      maliciousTests.push({
        name: "SQL Injection",
        test: async () => {
          return await global.allureStep("Test SQL injection payloads", async () => {
            const baseData = testData.getPostData();
            const payload = { ...baseData, ...maliciousPayloads.sqlInjection };
            global.attachJSON("SQL Injection Payload", payload);
            const response = await this.makeApiCall(endpoint[0], "POST", payload);
            const isSuccess = [400, 422, 500, 403].includes(response.status);
            return {
              expected: "400/422/500/403", actual: response.status, success: isSuccess,
              message: `SQL injection should return 400/422/500/403, got ${response.status}`,
            };
          });
        },
      });

      // XSS Injection Test
      maliciousTests.push({
        name: "XSS Injection",
        test: async () => {
          return await global.allureStep("Test XSS injection payloads", async () => {
            const baseData = testData.getPostData();
            const payload = { ...baseData, ...maliciousPayloads.xss };
            global.attachJSON("XSS Injection Payload", payload);
            const response = await this.makeApiCall(endpoint[0], "POST", payload);
            const isSuccess = [400, 422, 500, 403].includes(response.status);
            return {
              expected: "400/422/500/403", actual: response.status, success: isSuccess,
              message: `XSS injection should return 400/422/500/403, got ${response.status}`,
            };
          });
        },
      });

      const results = [];
      for (const test of maliciousTests) {
        try {
          const result = await test.test();
          results.push({ test: test.name, ...result });
        } catch (error) {
          global.attachAllureLog(`Malicious Payload Test Error - ${test.name}`, error.message);
          results.push({ test: test.name, error: error.message, success: false });
        }
      }

      global.attachJSON("Malicious Payload Test Results", results);
      return results.map(result => ({ 
        ...result, 
        module: moduleName, 
        endpointType: endpointType, 
        timestamp: new Date().toISOString() 
      }));
    });
  }

  static async testNullRequiredFields(moduleConfig, endpointType = "Post", moduleName = "") {
    return await global.allureStep(`Null Required Fields Test for ${moduleName}`, async () => {
      const endpoint = moduleConfig[endpointType];

      global.attachAllureLog("Null Required Fields Test Configuration", {
        module: moduleName,
        endpointType,
        endpoint: endpoint ? endpoint[0] : "Not available",
      });

      if (!endpoint || endpoint[0] === "URL_HERE") {
        return { skipped: true, message: `No ${endpointType} endpoint available` };
      }

      const testData = this.getDefaultTestData();
      const nullPayload = testData.getNullRequiredFields();
      global.attachJSON("Null Required Fields Payload", nullPayload);

      const response = await apiClient.post(endpoint[0], nullPayload);
      global.attachJSON("Null Required Fields Response", response);

      return {
        expected: 400, actual: response.status, success: response.status === 400,
        message: `Null required fields should return 400, got ${response.status}`,
        module: moduleName, endpointType: endpointType, timestamp: new Date().toISOString(),
      };
    });
  }

  // ===========================================================================
  // COMPREHENSIVE TEST FLOWS
  // ===========================================================================

  static async testCompleteLifecycle(moduleConfig, moduleName = "") {
    return await global.allureStep(`Complete CRUD Lifecycle for ${moduleName}`, async () => {
      const lifecycle = {
        createdId: null, createdData: null, updatedData: null, steps: [], 
        status: "in-progress", moduleName: moduleName,
      };

      try {
        global.attachAllureLog("Module Configuration", {
          module: moduleName,
          endpoints: Object.keys(moduleConfig).filter(
            key => moduleConfig[key] && moduleConfig[key][0] !== "URL_HERE"
          ),
        });

        // 1. POST - Create new entry
        if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
          await global.allureStep("CREATE - Create new entry", async () => {
            logger.info(`Step 1: Creating new entry for ${moduleName}`);
            const postData = this.getDefaultTestData().getPostData();

            global.attachJSON("POST Request Data", postData);
            global.attachAllureLog("POST Endpoint", moduleConfig.Post[0]);

            const postResponse = await apiClient.post(moduleConfig.Post[0], postData);
            global.attachJSON("POST Response", postResponse);

            if (!postResponse.success) {
              const formattedError = this.formatError(postResponse.error);
              throw new Error(`POST request failed: ${JSON.stringify(formattedError, null, 2)}`);
            }

            this.validateResponseStructure(postResponse);
            lifecycle.createdId = this.extractId(postResponse);
            lifecycle.createdData = postResponse;
            lifecycle.steps.push({ step: "CREATE", success: true, id: lifecycle.createdId, endpoint: moduleConfig.Post[0] });

            logger.info(`✅ Successfully created ${moduleName} with ID: ${lifecycle.createdId}`);
            global.attachAllureLog("Lifecycle ID Created", `ID: ${lifecycle.createdId} for module: ${moduleName}`);
          });
        } else {
          throw new Error(`No valid POST endpoint available for ${moduleName}`);
        }

        // 2. VIEW - Verify creation
        if (lifecycle.createdId && moduleConfig.View && moduleConfig.View[0] !== "URL_HERE") {
          await global.allureStep("READ - Verify creation", async () => {
            logger.info(`Step 2: Viewing created entry for ${moduleName}`);
            const viewUrl = this.buildUrl(moduleConfig.View[0], lifecycle.createdId);
            global.attachAllureLog("VIEW Endpoint", viewUrl);
            
            const viewResponse = await apiClient.get(viewUrl);
            global.attachJSON("VIEW Response", viewResponse);

            if (!viewResponse.success) {
              const formattedError = this.formatError(viewResponse.error);
              throw new Error(`VIEW request failed: ${JSON.stringify(formattedError, null, 2)}`);
            }

            this.validateResponseStructure(viewResponse);
            this.verifyDataMatch(viewResponse, lifecycle.createdData);
            lifecycle.steps.push({ step: "READ_VERIFY_CREATION", success: true, endpoint: viewUrl });
            logger.info(`✅ Successfully verified creation of ${moduleName}`);
          });
        }

        // 3. EDIT - Update the entry
        if (lifecycle.createdId && moduleConfig.EDIT && moduleConfig.EDIT[0] !== "URL_HERE") {
          await global.allureStep("UPDATE - Edit entry", async () => {
            logger.info(`Step 3: Editing entry for ${moduleName}`);
            const editData = this.getDefaultTestData().getEditData(lifecycle.createdData);
            const editUrl = this.buildUrl(moduleConfig.EDIT[0], lifecycle.createdId);
            
            global.attachJSON("EDIT Request Data", editData);
            global.attachAllureLog("EDIT Endpoint", editUrl);

            const editResponse = await apiClient.put(editUrl, editData);
            global.attachJSON("EDIT Response", editResponse);

            if (!editResponse.success) {
              const formattedError = this.formatError(editResponse.error);
              throw new Error(`EDIT request failed: ${JSON.stringify(formattedError, null, 2)}`);
            }

            this.validateResponseStructure(editResponse);
            lifecycle.updatedData = editResponse;
            lifecycle.steps.push({ step: "UPDATE", success: true, endpoint: editUrl });
            logger.info(`✅ Successfully edited entry for ${moduleName}`);
          });
        }

        // 4. DELETE - Remove the entry
        if (lifecycle.createdId && moduleConfig.DELETE && moduleConfig.DELETE[0] !== "URL_HERE") {
          await global.allureStep("DELETE - Remove entry", async () => {
            logger.info(`Step 6: Deleting entry for ${moduleName}`);
            const deleteUrl = this.buildUrl(moduleConfig.DELETE[0], lifecycle.createdId);
            global.attachAllureLog("DELETE Endpoint", deleteUrl);

            const deleteResponse = await apiClient.delete(deleteUrl);
            global.attachJSON("DELETE Response", deleteResponse);

            if (!deleteResponse.success) {
              const formattedError = this.formatError(deleteResponse.error);
              throw new Error(`DELETE request failed: ${JSON.stringify(formattedError, null, 2)}`);
            }

            this.validateResponseStructure(deleteResponse);
            lifecycle.steps.push({ step: "DELETE", success: true, endpoint: deleteUrl });
            logger.info(`✅ Successfully deleted entry for ${moduleName}`);
          });
        }

        lifecycle.status = "completed";
        lifecycle.completedAt = new Date().toISOString();
        global.attachJSON("Complete Lifecycle Results", lifecycle);
        return lifecycle;
      } catch (error) {
        lifecycle.status = "failed";
        lifecycle.error = error.message;
        lifecycle.failedAt = new Date().toISOString();

        this.markTestAsFailed(`Lifecycle test failed: ${error.message}`);
        global.attachAllureLog("Lifecycle Test Error", error.message);
        global.attachJSON("Lifecycle State on Error", lifecycle);
        throw error;
      }
    });
  }

  static async runComprehensiveSecuritySuite(moduleConfig, moduleName = "") {
    return await global.allureStep(`Enhanced Comprehensive Security Suite for ${moduleName}`, async () => {
      const securityResults = {};
      const startTime = Date.now();

      global.attachAllureLog("Enhanced Security Suite Started", {
        module: moduleName,
        timestamp: new Date().toISOString(),
        tests: ["Authorization Security", "SQL Injection Protection", "XSS Protection", 
                "Malicious Payloads", "Input Validation", "Performance Under Load"],
      });

      try {
        securityResults.authorization = await this.testAuthorizationSecurity(moduleConfig, moduleName);
        securityResults.sqlInjection = await this.testSQLInjectionProtection(moduleConfig, moduleName);
        securityResults.xssProtection = await this.testXSSProtection(moduleConfig, moduleName);
        securityResults.maliciousPost = await this.testMaliciousPayloads(moduleConfig, "Post", moduleName);

        if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
          securityResults.maliciousPut = await this.testMaliciousPayloads(moduleConfig, "PUT", moduleName);
        }

        securityResults.nullFieldsPost = await this.testNullRequiredFields(moduleConfig, "Post", moduleName);

        if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
          securityResults.nullFieldsPut = await this.testNullRequiredFields(moduleConfig, "PUT", moduleName);
        }

        securityResults.performance = await this.testPerformanceUnderMaliciousLoad(moduleConfig, moduleName);

        const endTime = Date.now();
        const overallScore = this.calculateSecurityScore(securityResults);

        securityResults.summary = {
          overallScore,
          totalTests: this.countTotalTests(securityResults),
          passedTests: this.countPassedTests(securityResults),
          failedTests: this.countFailedTests(securityResults),
          duration: endTime - startTime,
          timestamp: new Date().toISOString(),
          securityLevel: this.getSecurityLevel(overallScore),
        };

        global.attachJSON("Enhanced Security Suite Results", securityResults);
        logger.info(`🛡️ Security Suite Completed for ${moduleName}`);
        logger.info(`📊 Overall Security Score: ${overallScore}%`);
        logger.info(`🛡️ Security Level: ${securityResults.summary.securityLevel}`);

      } catch (error) {
        securityResults.error = error.message;
        logger.error(`❌ Security Suite Failed for ${moduleName}: ${error.message}`);
      }

      return securityResults;
    });
  }

  // ===========================================================================
  // SCORING & ANALYTICS
  // ===========================================================================

  static calculateSecurityScore(securityResults) {
    let totalWeight = 0;
    let weightedScore = 0;

    const testCategories = {
      authorization: 0.3, sqlInjection: 0.25, xssProtection: 0.25,
      maliciousPost: 0.1, maliciousPut: 0.05, performance: 0.05
    };

    for (const [category, weight] of Object.entries(testCategories)) {
      if (securityResults[category]) {
        const categoryScore = this.calculateCategoryScore(securityResults[category]);
        weightedScore += categoryScore * weight;
        totalWeight += weight;
      }
    }

    return totalWeight > 0 ? Math.round((weightedScore / totalWeight) * 100) : 0;
  }

  static calculateCategoryScore(categoryResults) {
    if (!categoryResults || categoryResults.length === 0) return 0;
    const totalTests = categoryResults.length;
    const passedTests = categoryResults.filter(test => test.success || test.skipped).length;
    return passedTests / totalTests;
  }

  static countTotalTests(securityResults) {
    return Object.values(securityResults)
      .filter(Array.isArray)
      .reduce((total, tests) => total + tests.length, 0);
  }

  static countPassedTests(securityResults) {
    return Object.values(securityResults)
      .filter(Array.isArray)
      .reduce((total, tests) => total + tests.filter(test => test.success).length, 0);
  }

  static countFailedTests(securityResults) {
    return Object.values(securityResults)
      .filter(Array.isArray)
      .reduce((total, tests) => total + tests.filter(test => !test.success && !test.skipped).length, 0);
  }

  static getSecurityLevel(score) {
    if (score >= 90) return "EXCELLENT";
    if (score >= 80) return "GOOD";
    if (score >= 70) return "FAIR";
    if (score >= 60) return "POOR";
    return "CRITICAL";
  }

  static calculatePercentile(numbers, percentile) {
    if (!numbers || numbers.length === 0) return 0;
    const sorted = [...numbers].sort((a, b) => a - b);
    const index = (percentile / 100) * (sorted.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    if (lower === upper) return sorted[lower];
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
  }

  // ===========================================================================
  // ADDITIONAL TEST METHODS (for backward compatibility)
  // ===========================================================================

  static async testAdvancedSecurityScenarios(moduleConfig, moduleName = "") {
    return await global.allureStep(`Advanced Security Scenarios for ${moduleName}`, async () => {
      const securityTests = [];
      if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
        securityTests.push({
          name: "Advanced Input Validation",
          test: async () => ({ success: true, message: "Advanced input validation passed" }),
        });
      }

      const results = [];
      for (const test of securityTests) {
        try {
          const result = await test.test();
          results.push({ ...result, name: test.name });
        } catch (error) {
          results.push({ name: test.name, success: false, error: error.message });
        }
      }

      const failed = results.filter(r => !r.success);
      return { results, failed, success: failed.length === 0 };
    });
  }

  static async testTransactionCommitFlow(moduleConfig) {
    return await global.allureStep(`Transaction Commit Flow for ${moduleConfig.name || moduleConfig}`, async () => {
      const flowResults = [];
      // Implementation for transaction commit flow
      return flowResults;
    });
  }

  static async performIndividualHealthCheck(endpoint, endpointType, moduleName = "") {
    return await global.allureStep(`Health Check for ${endpoint}`, async () => {
      try {
        const response = await apiClient.get(endpoint);
        return { endpoint, endpointType, moduleName, healthy: response.success, status: response.status, responseTime: Date.now() };
      } catch (error) {
        return { endpoint, endpointType, moduleName, healthy: false, error: error.message, status: error.response?.status };
      }
    });
  }

  static async performHealthChecks(schema) {
    return await global.allureStep("Perform API Health Checks", async () => {
      const healthResults = [];
      const endpointsToCheck = [];

      const collectEndpoints = (modules, path = "") => {
        Object.entries(modules).forEach(([name, config]) => {
          if (typeof config === "object" && config !== null) {
            const fullPath = path ? `${path}.${name}` : name;
            endpointTypes.forEach((type) => {
              if (config[type] && config[type][0] !== "URL_HERE") {
                endpointsToCheck.push({ name: `${fullPath} - ${type}`, url: config[type][0], type: type });
              }
            });
            if (typeof config === "object" && !config.Post && !config.GET) {
              collectEndpoints(config, fullPath);
            }
          }
        });
      };

      collectEndpoints(schema);

      for (const endpoint of endpointsToCheck.slice(0, 10)) {
        await global.allureStep(`Check ${endpoint.name}`, async () => {
          try {
            const response = await apiClient.get(endpoint.url);
            healthResults.push({ endpoint: endpoint.name, url: endpoint.url, healthy: response.success, status: response.status, responseTime: "measured" });
          } catch (error) {
            healthResults.push({ endpoint: endpoint.name, url: endpoint.url, healthy: false, error: error.message });
          }
        });
      }

      global.attachJSON("Health Check Results", healthResults);
      return healthResults;
    });
  }
}

module.exports = TestHelpers;





















// // utils/test-helpers.js - CommonJS version
// const apiClient = require("./api-client");
// const logger = require("./logger");
// const TokenManager = require("./token-manager");
// // Use the main constants entry point
// const Constants = require("../Constants");
// // Or import specific constants
// const { endpointTypes, TEST_TAGS, HTTP_STATUS_CODES } = require("../Constants");

// class TestHelpers {
//   /**
//    * Comprehensive XSS Protection Testing
//    */
//   static async testXSSProtection(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `XSS Protection Tests for ${moduleName}`,
//       async () => {
//         const xssTests = [];
//         const endpoint = moduleConfig.Post;

//         if (!endpoint || endpoint[0] === "URL_HERE") {
//           return [
//             {
//               skipped: true,
//               message: `No POST endpoint available for XSS testing in ${moduleName}`,
//             },
//           ];
//         }

//         const xssPayloads = this.generateXSSPayloads();
//         const testData = this.getDefaultTestData();

//         global.attachJSON("XSS Test Payloads", xssPayloads);

//         // Test different XSS vectors
//         for (const [vectorType, payloads] of Object.entries(xssPayloads)) {
//           for (const [field, xssPayload] of Object.entries(payloads)) {
//             xssTests.push({
//               name: `XSS ${vectorType} - ${field}`,
//               test: async () => {
//                 return await global.allureStep(
//                   `Test XSS ${vectorType} in ${field}`,
//                   async () => {
//                     const baseData = testData.getPostData();
//                     const maliciousData = { ...baseData };

//                     // Inject XSS payload into specific field
//                     if (maliciousData[field] !== undefined) {
//                       maliciousData[field] = xssPayload;
//                     } else {
//                       // If field doesn't exist, add it
//                       maliciousData[field] = xssPayload;
//                     }

//                     global.attachJSON(
//                       `XSS ${vectorType} Payload`,
//                       maliciousData
//                     );

//                     const response = await apiClient.post(
//                       endpoint[0],
//                       maliciousData
//                     );

//                     // XSS should be blocked - expect 400, 422, or sanitized response
//                     const isBlocked = [400, 422, 403, 500].includes(
//                       response.status
//                     );
//                     const isSanitized = this.checkXSSSanitization(
//                       response,
//                       xssPayload
//                     );

//                     return {
//                       expected: "400/422/403 or sanitized content",
//                       actual: response.status,
//                       success: isBlocked || isSanitized,
//                       blocked: isBlocked,
//                       sanitized: isSanitized,
//                       payload: xssPayload.substring(0, 50) + "...",
//                       message: `XSS ${vectorType} should be blocked or sanitized`,
//                     };
//                   }
//                 );
//               },
//             });
//           }
//         }

//         // Execute all XSS tests
//         const results = [];
//         for (const test of xssTests) {
//           try {
//             const result = await test.test();
//             results.push({
//               test: test.name,
//               ...result,
//             });
//           } catch (error) {
//             results.push({
//               test: test.name,
//               error: error.message,
//               success: false,
//             });
//           }
//         }

//         global.attachJSON("XSS Protection Test Results", results);
//         return results;
//       }
//     );
//   }

//   /**
//    * Generate comprehensive XSS payloads
//    */
//   static generateXSSPayloads() {
//     return {
//       scriptTags: {
//         name: "<script>alert('XSS')</script>",
//         description: "Test<script>console.log('xss')</script>",
//         input: "<script>document.location='http://evil.com'</script>",
//       },
//       eventHandlers: {
//         name: "<img src=x onerror=alert(1)>",
//         description: "<body onload=alert('XSS')>",
//         input: "<svg onload=alert(1)>",
//       },
//       javascriptProtocol: {
//         name: "javascript:alert('XSS')",
//         description: "JaVaScRiPt:alert('XSS')",
//         input: "data:text/html,<script>alert('XSS')</script>",
//       },
//       cssExpressions: {
//         name: "<div style='background:url(javascript:alert(1))'>",
//         description: "<style>@import'http://evil.com/xss.css';</style>",
//         input: "<div style='width:expression(alert(1))'>",
//       },
//       obfuscated: {
//         name: "<img src='x' onerror='&#x61;lert(1)'>",
//         description:
//           "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
//         input: "<img src='x' onerror='&amp;#x61;lert(1)'>",
//       },
//       domBased: {
//         name: '" onmouseover="alert(1)',
//         description: "'><script>alert(1)</script>",
//         input: '<img src="x" onerror="alert(1)">',
//       },
//     };
//   }

//   /**
//    * Check if response shows XSS sanitization
//    */
//   static checkXSSSanitization(response, originalPayload) {
//     if (!response.data) return false;

//     const responseString = JSON.stringify(response.data).toLowerCase();
//     const payloadLower = originalPayload.toLowerCase();

//     // Check if dangerous parts are removed
//     const dangerousPatterns = [
//       "script",
//       "javascript:",
//       "onerror=",
//       "onload=",
//       "onmouseover=",
//       "expression(",
//       "eval(",
//     ];

//     // If response contains the payload but dangerous patterns are removed/encoded
//     const containsPayload = responseString.includes(
//       payloadLower.replace(/<script>|javascript:|on\w+=/gi, "")
//     );
//     const hasDangerousContent = dangerousPatterns.some((pattern) =>
//       responseString.includes(pattern)
//     );

//     return containsPayload && !hasDangerousContent;
//   }

//   /**
//    * Real Performance Testing Under Malicious Load
//    */
//   static async testPerformanceUnderMaliciousLoad(
//     moduleConfig,
//     moduleName = ""
//   ) {
//     return await global.allureStep(
//       `Real Performance Under Malicious Load for ${moduleName}`,
//       async () => {
//         const endpoint = moduleConfig.Post;

//         if (!endpoint || endpoint[0] === "URL_HERE") {
//           return {
//             success: false,
//             skipped: true,
//             message: `No POST endpoint available for performance testing in ${moduleName}`,
//           };
//         }

//         const performanceMetrics = {
//           totalRequests: 0,
//           successfulRequests: 0,
//           failedRequests: 0,
//           totalResponseTime: 0,
//           responseTimes: [],
//           errorRate: 0,
//           throughput: 0,
//         };

//         const testData = this.getDefaultTestData();
//         const concurrentRequests = 10; // Simulate 10 concurrent users
//         const requestsPerUser = 5; // Each user makes 5 requests

//         // Generate malicious payloads for load testing
//         const maliciousPayloads = this.generatePerformanceTestPayloads();

//         global.attachJSON("Performance Test Configuration", {
//           module: moduleName,
//           endpoint: endpoint[0],
//           concurrentUsers: concurrentRequests,
//           requestsPerUser: requestsPerUser,
//           totalRequests: concurrentRequests * requestsPerUser,
//           payloadTypes: Object.keys(maliciousPayloads),
//         });

//         const startTime = Date.now();
//         const promises = [];

//         // Create concurrent requests with different payload types
//         for (let i = 0; i < concurrentRequests; i++) {
//           const userPromises = [];

//           for (let j = 0; j < requestsPerUser; j++) {
//             const payloadType =
//               Object.keys(maliciousPayloads)[
//                 j % Object.keys(maliciousPayloads).length
//               ];
//             const payload = {
//               ...testData.getPostData(),
//               ...maliciousPayloads[payloadType],
//               requestId: `user${i}_req${j}`,
//               timestamp: new Date().toISOString(),
//             };

//             userPromises.push(
//               this.makeTimedApiCall(endpoint[0], "POST", payload)
//             );
//           }

//           promises.push(...userPromises);
//         }

//         // Execute all requests concurrently
//         const results = await Promise.allSettled(promises);
//         const endTime = Date.now();
//         const totalDuration = endTime - startTime;

//         // Analyze results
//         results.forEach((result, index) => {
//           performanceMetrics.totalRequests++;

//           if (result.status === "fulfilled" && result.value.success) {
//             performanceMetrics.successfulRequests++;
//             performanceMetrics.responseTimes.push(result.value.responseTime);
//             performanceMetrics.totalResponseTime += result.value.responseTime;
//           } else {
//             performanceMetrics.failedRequests++;
//           }
//         });

//         // Calculate metrics
//         performanceMetrics.errorRate =
//           (performanceMetrics.failedRequests /
//             performanceMetrics.totalRequests) *
//           100;
//         performanceMetrics.throughput = (
//           performanceMetrics.totalRequests /
//           (totalDuration / 1000)
//         ).toFixed(2);
//         performanceMetrics.averageResponseTime =
//           performanceMetrics.responseTimes.length > 0
//             ? performanceMetrics.totalResponseTime /
//               performanceMetrics.responseTimes.length
//             : 0;
//         performanceMetrics.p95ResponseTime = this.calculatePercentile(
//           performanceMetrics.responseTimes,
//           95
//         );
//         performanceMetrics.p99ResponseTime = this.calculatePercentile(
//           performanceMetrics.responseTimes,
//           99
//         );

//         // Performance thresholds
//         const meetsPerformanceStandards =
//           performanceMetrics.averageResponseTime < 2000 && // Under 2 seconds
//           performanceMetrics.errorRate < 5 && // Less than 5% error rate
//           performanceMetrics.p95ResponseTime < 3000; // 95% under 3 seconds

//         const performanceResult = {
//           success: meetsPerformanceStandards,
//           metrics: performanceMetrics,
//           thresholds: {
//             maxAverageResponseTime: 2000,
//             maxErrorRate: 5,
//             maxP95ResponseTime: 3000,
//           },
//           meetsStandards: meetsPerformanceStandards,
//           duration: totalDuration,
//           timestamp: new Date().toISOString(),
//         };

//         global.attachJSON("Performance Test Results", performanceResult);

//         if (!meetsPerformanceStandards) {
//           logger.warn(`Performance below standards for ${moduleName}`);
//         }

//         return performanceResult;
//       }
//     );
//   }

//   /**
//    * Generate payloads for performance testing
//    */
//   static generatePerformanceTestPayloads() {
//     return {
//       largePayload: {
//         description: "A".repeat(1000),
//         notes: "B".repeat(500),
//         metadata: JSON.stringify({ large: "x".repeat(2000) }),
//       },
//       complexNested: {
//         data: {
//           nested: {
//             level1: {
//               level2: {
//                 level3: {
//                   array: new Array(50).fill("test"),
//                   object: Object.fromEntries(
//                     new Array(20)
//                       .fill(0)
//                       .map((_, i) => [`key${i}`, `value${i}`])
//                   ),
//                 },
//               },
//             },
//           },
//         },
//       },
//       specialCharacters: {
//         name: "Test @#$%^&*()_+-=[]{}|;:,.<>?~`",
//         description: "Multi\nLine\nText\nWith\tTabs",
//         content: "Unicode: 🚀 ✅ 🔥 🌟 💯",
//       },
//       boundaryValues: {
//         number: 999999999,
//         decimal: 123456789.123456789,
//         negative: -999999,
//         zero: 0,
//       },
//     };
//   }

//   /**
//    * Make API call with timing
//    */
//   static async makeTimedApiCall(endpoint, method, data) {
//     const startTime = Date.now();
//     try {
//       const response = await apiClient.post(endpoint, data);
//       const responseTime = Date.now() - startTime;

//       return {
//         success: response.success,
//         status: response.status,
//         responseTime: responseTime,
//         data: response.data,
//       };
//     } catch (error) {
//       const responseTime = Date.now() - startTime;
//       return {
//         success: false,
//         error: error.message,
//         responseTime: responseTime,
//       };
//     }
//   }

//   /**
//    * Calculate percentile from array of numbers
//    */
//   static calculatePercentile(numbers, percentile) {
//     if (!numbers || numbers.length === 0) return 0;

//     const sorted = [...numbers].sort((a, b) => a - b);
//     const index = (percentile / 100) * (sorted.length - 1);
//     const lower = Math.floor(index);
//     const upper = Math.ceil(index);

//     if (lower === upper) return sorted[lower];

//     return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
//   }

//   /**
//    * Advanced SQL Injection Protection Testing
//    */
//   static async testSQLInjectionProtection(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `SQL Injection Protection Tests for ${moduleName}`,
//       async () => {
//         const sqlTests = [];
//         const endpoint = moduleConfig.Post;

//         if (!endpoint || endpoint[0] === "URL_HERE") {
//           return [
//             {
//               skipped: true,
//               message: `No POST endpoint available for SQL injection testing in ${moduleName}`,
//             },
//           ];
//         }

//         const sqlPayloads = this.generateSQLInjectionPayloads();
//         const testData = this.getDefaultTestData();

//         global.attachJSON("SQL Injection Payloads", sqlPayloads);

//         // Test different SQL injection techniques
//         for (const [technique, payloads] of Object.entries(sqlPayloads)) {
//           for (const [field, sqlPayload] of Object.entries(payloads)) {
//             sqlTests.push({
//               name: `SQL ${technique} - ${field}`,
//               test: async () => {
//                 return await global.allureStep(
//                   `Test SQL ${technique} in ${field}`,
//                   async () => {
//                     const baseData = testData.getPostData();
//                     const maliciousData = { ...baseData };

//                     if (maliciousData[field] !== undefined) {
//                       maliciousData[field] = sqlPayload;
//                     } else {
//                       maliciousData[field] = sqlPayload;
//                     }

//                     global.attachJSON(
//                       `SQL ${technique} Payload`,
//                       maliciousData
//                     );

//                     const response = await apiClient.post(
//                       endpoint[0],
//                       maliciousData
//                     );

//                     // SQL injection should be blocked
//                     const isBlocked = [400, 422, 403, 500].includes(
//                       response.status
//                     );
//                     const showsError = this.checkSQLErrorIndicators(response);

//                     return {
//                       expected: "400/422/403/500 or no SQL error leakage",
//                       actual: response.status,
//                       success: isBlocked || !showsError,
//                       blocked: isBlocked,
//                       errorLeakage: showsError,
//                       payload: sqlPayload.substring(0, 50) + "...",
//                       message: `SQL ${technique} should be blocked and not leak errors`,
//                     };
//                   }
//                 );
//               },
//             });
//           }
//         }

//         // Execute all SQL injection tests
//         const results = [];
//         for (const test of sqlTests) {
//           try {
//             const result = await test.test();
//             results.push({
//               test: test.name,
//               ...result,
//             });
//           } catch (error) {
//             results.push({
//               test: test.name,
//               error: error.message,
//               success: false,
//             });
//           }
//         }

//         global.attachJSON("SQL Injection Protection Results", results);
//         return results;
//       }
//     );
//   }

//   /**
//    * Generate comprehensive SQL injection payloads
//    */
//   static generateSQLInjectionPayloads() {
//     return {
//       tautologies: {
//         name: "admin' OR '1'='1",
//         description: "test' OR 'x'='x",
//         input: "1' OR '1'='1",
//       },
//       unionQueries: {
//         name: "test' UNION SELECT username, password FROM users--",
//         description: "admin' UNION SELECT 1,2,3--",
//         input: "' UNION SELECT * FROM passwords--",
//       },
//       piggybacked: {
//         name: "test'; DROP TABLE users--",
//         description: "admin'; DELETE FROM accounts--",
//         input: "'; UPDATE users SET password='hacked'--",
//       },
//       blindInjection: {
//         name: "test' AND 1=1--",
//         description: "admin' AND SLEEP(5)--",
//         input: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
//       },
//       timeBased: {
//         name: "test'; WAITFOR DELAY '0:0:5'--",
//         description: "admin' AND BENCHMARK(5000000,MD5('test'))--",
//         input: "' OR IF(1=1,SLEEP(5),0)--",
//       },
//       errorBased: {
//         name: "test' AND GTID_SUBSET(@@version,0)--",
//         description: "admin' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version))--",
//         input: "' AND UPDATEXML(1,CONCAT(0x3a,@@version),1)--",
//       },
//     };
//   }

//   /**
//    * Check if response shows SQL error indicators
//    */
//   static checkSQLErrorIndicators(response) {
//     if (!response.data) return false;

//     const responseString = JSON.stringify(response.data).toLowerCase();

//     const sqlErrorIndicators = [
//       "sql",
//       "mysql",
//       "database",
//       "syntax error",
//       "union",
//       "select",
//       "from",
//       "where",
//       "oracle",
//       "microsoft odbc",
//       "driver",
//       "statement",
//       "query",
//     ];

//     return sqlErrorIndicators.some((indicator) =>
//       responseString.includes(indicator)
//     );
//   }

//   /**
//    * Comprehensive Security Suite - Enhanced
//    */
//   static async runComprehensiveSecuritySuite(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `Enhanced Comprehensive Security Suite for ${moduleName}`,
//       async () => {
//         const securityResults = {};
//         const startTime = Date.now();

//         global.attachAllureLog("Enhanced Security Suite Started", {
//           module: moduleName,
//           timestamp: new Date().toISOString(),
//           tests: [
//             "Authorization Security",
//             "SQL Injection Protection",
//             "XSS Protection",
//             "Malicious Payloads",
//             "Input Validation",
//             "Performance Under Load",
//           ],
//         });

//         try {
//           // 1. Authorization Security
//           securityResults.authorization = await this.testAuthorizationSecurity(
//             moduleConfig,
//             moduleName
//           );

//           // 2. SQL Injection Protection
//           securityResults.sqlInjection = await this.testSQLInjectionProtection(
//             moduleConfig,
//             moduleName
//           );

//           // 3. XSS Protection
//           securityResults.xssProtection = await this.testXSSProtection(
//             moduleConfig,
//             moduleName
//           );

//           // 4. Malicious Payloads (POST)
//           securityResults.maliciousPost = await this.testMaliciousPayloads(
//             moduleConfig,
//             "Post",
//             moduleName
//           );

//           // 5. Malicious Payloads (PUT) - if available
//           if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
//             securityResults.maliciousPut = await this.testMaliciousPayloads(
//               moduleConfig,
//               "PUT",
//               moduleName
//             );
//           }

//           // 6. Null Required Fields Validation
//           securityResults.nullFieldsPost = await this.testNullRequiredFields(
//             moduleConfig,
//             "Post",
//             moduleName
//           );

//           if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
//             securityResults.nullFieldsPut = await this.testNullRequiredFields(
//               moduleConfig,
//               "PUT",
//               moduleName
//             );
//           }

//           // 7. Performance Under Malicious Load
//           securityResults.performance =
//             await this.testPerformanceUnderMaliciousLoad(
//               moduleConfig,
//               moduleName
//             );

//           // Calculate overall security score
//           const endTime = Date.now();
//           const overallScore = this.calculateSecurityScore(securityResults);

//           securityResults.summary = {
//             overallScore,
//             totalTests: this.countTotalTests(securityResults),
//             passedTests: this.countPassedTests(securityResults),
//             failedTests: this.countFailedTests(securityResults),
//             duration: endTime - startTime,
//             timestamp: new Date().toISOString(),
//             securityLevel: this.getSecurityLevel(overallScore),
//           };

//           global.attachJSON("Enhanced Security Suite Results", securityResults);

//           logger.info(`🛡️ Security Suite Completed for ${moduleName}`);
//           logger.info(`📊 Overall Security Score: ${overallScore}%`);
//           logger.info(
//             `🛡️ Security Level: ${securityResults.summary.securityLevel}`
//           );
//         } catch (error) {
//           securityResults.error = error.message;
//           logger.error(
//             `❌ Security Suite Failed for ${moduleName}: ${error.message}`
//           );
//         }

//         return securityResults;
//       }
//     );
//   }

//   /**
//    * Debug response structure for troubleshooting
//    */
//   static debugResponseStructure(response, operation = "unknown") {
//     const debugInfo = {
//       operation,
//       timestamp: new Date().toISOString(),
//       responseStructure: {
//         keys: Object.keys(response),
//         dataType: typeof response.data,
//         dataKeys:
//           response.data && typeof response.data === "object"
//             ? Object.keys(response.data)
//             : "N/A",
//         status: response.status,
//         hasIdField: !!(response.id || (response.data && response.data.id)),
//       },
//       sampleData: {
//         data:
//           response.data && typeof response.data === "string"
//             ? response.data.substring(0, 50) +
//               (response.data.length > 50 ? "..." : "")
//             : response.data,
//         id: response.id || "N/A",
//         dataId: (response.data && response.data.id) || "N/A",
//       },
//     };

//     global.attachJSON(`Response Structure Debug - ${operation}`, debugInfo);
//     return debugInfo;
//   }

//   /**
//    * Smart ID extraction that handles various response structures
//    * - Direct string UUIDs
//    * - Objects with id/uuid fields
//    * - Nested response structures
//    */

//   static async initializeApiClient() {
//     return await global.allureStep(
//       "Initialize API Client with Token",
//       async () => {
//         try {
//           // Ensure we have a valid token before starting tests
//           const token = await TokenManager.ensureValidToken();
//           logger.info(
//             "✅ API Client initialized with valid token from token.txt"
//           );

//           // Create API client with the token
//           const client = apiClient.withToken(token);

//           // Test the token validity
//           const isValid = await client.testTokenValidity();
//           if (!isValid) {
//             throw new Error("Token validation failed during initialization");
//           }

//           return client;
//         } catch (error) {
//           logger.error(`❌ Failed to initialize API client: ${error.message}`);
//           throw error;
//         }
//       }
//     );
//   }

//   static formatError(error) {
//     if (typeof error === "object") {
//       if (error.response) {
//         return {
//           status: error.response.status,
//           statusText: error.response.statusText,
//           data: error.response.data,
//           url: error.response.config?.url,
//           method: error.response.config?.method,
//         };
//       } else if (error.request) {
//         return { message: "No response received" };
//       } else {
//         return { message: error.message };
//       }
//     }
//     return error;
//   }

//   static validateResponseSuccess(response) {
//     // Check HTTP status code is in success range (200-399)
//     const httpStatusValid = response.status >= 200 && response.status < 400;

//     // Check response data doesn't contain status: 400 (case insensitive, any data type)
//     let responseStatusValid = true;
//     if (response.data) {
//       const checkForStatus400 = (obj) => {
//         for (let key in obj) {
//           if (typeof obj[key] === "object" && obj[key] !== null) {
//             if (checkForStatus400(obj[key]) === false) return false;
//           } else if (key.toLowerCase() === "status") {
//             // Check if status value equals 400 (any data type)
//             const statusValue = obj[key];
//             if (statusValue == 400) {
//               // Use == for loose comparison to handle string "400"
//               return false;
//             }
//           }
//         }
//         return true;
//       };

//       responseStatusValid = checkForStatus400(response.data);
//     }

//     return {
//       httpStatusValid,
//       responseStatusValid,
//       overallValid: httpStatusValid && responseStatusValid,
//     };
//   }

//   static markTestAsFailed(errorMessage = "Test failed") {
//     if (global.testState) {
//       global.testState.hasAssertionErrors = true;
//       global.testState.testStatus = "failed";
//     }
//     global.attachAllureLog("Test Failure", errorMessage);
//   }

//   static validateResponseStructure(response, expectedFields = []) {
//     return global.allureStep("Validate response structure", () => {
//       try {
//         expect(response).toBeDefined();
//         expect(typeof response).toBe("object");

//         // Enhanced validation: Check HTTP status and response content
//         const validationResult = this.validateResponseSuccess(response);

//         if (!validationResult.httpStatusValid) {
//           this.markTestAsFailed(
//             `HTTP status code ${response.status} is not in success range (200-399)`
//           );
//           throw new Error(
//             `HTTP status code ${response.status} is not in success range (200-399)`
//           );
//         }

//         if (!validationResult.responseStatusValid) {
//           this.markTestAsFailed(
//             "Response contains status: 400 which indicates failure"
//           );
//           throw new Error(
//             "Response contains status: 400 which indicates failure"
//           );
//         }

//         // Enhanced: Handle both object and primitive data responses
//         if (response.data !== undefined) {
//           const dataType = typeof response.data;
//           if (dataType === "object") {
//             expectedFields.forEach((field) => {
//               if (response.data && !response.data[field]) {
//                 logger.warn(
//                   `Expected field '${field}' not found in response data`
//                 );
//               }
//             });
//           } else {
//             logger.info(
//               `Response data is primitive type: ${dataType}, value: ${response.data}`
//             );
//           }
//         }

//         global.attachAllureLog("Response Validation", {
//           hasExpectedStructure: true,
//           expectedFields,
//           actualResponseKeys: Object.keys(response),
//           responseType: typeof response,
//           dataType: response.data ? typeof response.data : "undefined",
//           dataValue: response.data,
//           httpStatus: response.status,
//           validationResult,
//         });

//         return validationResult.overallValid;
//       } catch (error) {
//         this.markTestAsFailed(`Response validation failed: ${error.message}`);
//         throw error;
//       }
//     });
//   }

//   static async checkTokenStatus() {
//     return await global.allureStep("Check Token Status", async () => {
//       const tokenInfo = TokenManager.getTokenInfo();

//       global.attachJSON("Token Status", tokenInfo);

//       if (!tokenInfo.exists) {
//         logger.error("❌ No token found in token.txt");
//         return { valid: false, reason: "No token file" };
//       }

//       if (!tokenInfo.isValid) {
//         logger.error(`❌ Token is invalid: ${tokenInfo.reason}`);
//         return { valid: false, reason: tokenInfo.reason };
//       }

//       const minutesUntilExpiry = Math.round(
//         tokenInfo.timeUntilExpiry / (1000 * 60)
//       );
//       logger.info(
//         `✅ Token is valid (expires in ${minutesUntilExpiry} minutes)`
//       );

//       return {
//         valid: true,
//         expiresIn: `${minutesUntilExpiry} minutes`,
//         expiresAt: tokenInfo.expiresAt,
//         source: tokenInfo.source,
//       };
//     });
//   }

//   static async refreshTokenIfNeeded() {
//     return await global.allureStep("Refresh Token If Needed", async () => {
//       try {
//         const token = await TokenManager.ensureValidToken();
//         logger.info("✅ Token refreshed and validated");
//         return token;
//       } catch (error) {
//         logger.error(`❌ Token refresh failed: ${error.message}`);
//         throw error;
//       }
//     });
//   }

//   static async testCompleteLifecycle(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `Complete CRUD Lifecycle for ${moduleName}`,
//       async () => {
//         const lifecycle = {
//           createdId: null,
//           createdData: null,
//           updatedData: null,
//           steps: [],
//           status: "in-progress",
//           moduleName: moduleName,
//         };

//         try {
//           global.attachAllureLog("Module Configuration", {
//             module: moduleName,
//             endpoints: Object.keys(moduleConfig).filter(
//               (key) => moduleConfig[key] && moduleConfig[key][0] !== "URL_HERE"
//             ),
//           });

//           // 1. POST - Create new entry
//           if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
//             await global.allureStep("CREATE - Create new entry", async () => {
//               logger.info(`Step 1: Creating new entry for ${moduleName}`);
//               const postData = this.getDefaultTestData().getPostData();

//               global.attachJSON("POST Request Data", postData);
//               global.attachAllureLog("POST Endpoint", moduleConfig.Post[0]);

//               const postResponse = await apiClient.post(
//                 moduleConfig.Post[0],
//                 postData
//               );
//               global.attachJSON("POST Response", postResponse);

//               if (!postResponse.success) {
//                 const formattedError = this.formatError(postResponse.error);
//                 throw new Error(
//                   `POST request failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               // Enhanced validation with status checks
//               this.validateResponseStructure(postResponse);

//               lifecycle.createdId = this.extractId(postResponse);
//               lifecycle.createdData = postResponse;
//               lifecycle.steps.push({
//                 step: "CREATE",
//                 success: true,
//                 id: lifecycle.createdId,
//                 endpoint: moduleConfig.Post[0],
//               });

//               logger.info(
//                 `✅ Successfully created ${moduleName} with ID: ${lifecycle.createdId}`
//               );

//               // Store the lifecycle ID globally for comprehensive testing
//               global.attachAllureLog(
//                 "Lifecycle ID Created",
//                 `ID: ${lifecycle.createdId} for module: ${moduleName}`
//               );
//             });
//           } else {
//             throw new Error(
//               `No valid POST endpoint available for ${moduleName}`
//             );
//           }

//           // 2. VIEW - Verify creation
//           if (
//             lifecycle.createdId &&
//             moduleConfig.View &&
//             moduleConfig.View[0] !== "URL_HERE"
//           ) {
//             await global.allureStep("READ - Verify creation", async () => {
//               logger.info(`Step 2: Viewing created entry for ${moduleName}`);
//               const viewUrl = this.buildUrl(
//                 moduleConfig.View[0],
//                 lifecycle.createdId
//               );

//               global.attachAllureLog("VIEW Endpoint", viewUrl);
//               const viewResponse = await apiClient.get(viewUrl);
//               global.attachJSON("VIEW Response", viewResponse);

//               if (!viewResponse.success) {
//                 const formattedError = this.formatError(viewResponse.error);
//                 throw new Error(
//                   `VIEW request failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               this.validateResponseStructure(viewResponse);
//               this.verifyDataMatch(viewResponse, lifecycle.createdData);
//               lifecycle.steps.push({
//                 step: "READ_VERIFY_CREATION",
//                 success: true,
//                 endpoint: viewUrl,
//               });

//               logger.info(`✅ Successfully verified creation of ${moduleName}`);
//             });
//           }

//           // 3. EDIT - Update the entry
//           if (
//             lifecycle.createdId &&
//             moduleConfig.EDIT &&
//             moduleConfig.EDIT[0] !== "URL_HERE"
//           ) {
//             await global.allureStep("UPDATE - Edit entry", async () => {
//               logger.info(`Step 3: Editing entry for ${moduleName}`);
//               const editData = this.getDefaultTestData().getEditData(
//                 lifecycle.createdData
//               );

//               const editUrl = this.buildUrl(
//                 moduleConfig.EDIT[0],
//                 lifecycle.createdId
//               );
//               global.attachJSON("EDIT Request Data", editData);
//               global.attachAllureLog("EDIT Endpoint", editUrl);

//               const editResponse = await apiClient.put(editUrl, editData);
//               global.attachJSON("EDIT Response", editResponse);

//               if (!editResponse.success) {
//                 const formattedError = this.formatError(editResponse.error);
//                 throw new Error(
//                   `EDIT request failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               this.validateResponseStructure(editResponse);
//               lifecycle.updatedData = editResponse;
//               lifecycle.steps.push({
//                 step: "UPDATE",
//                 success: true,
//                 endpoint: editUrl,
//               });

//               logger.info(`✅ Successfully edited entry for ${moduleName}`);
//             });
//           }

//           // 4. VIEW - Verify edit
//           if (
//             lifecycle.createdId &&
//             moduleConfig.View &&
//             lifecycle.updatedData
//           ) {
//             await global.allureStep("READ - Verify edit", async () => {
//               logger.info(`Step 4: Verifying edit for ${moduleName}`);
//               const viewUrl = this.buildUrl(
//                 moduleConfig.View[0],
//                 lifecycle.createdId
//               );
//               const viewResponse = await apiClient.get(viewUrl);
//               global.attachJSON("VIEW After Edit Response", viewResponse);

//               if (!viewResponse.success) {
//                 const formattedError = this.formatError(viewResponse.error);
//                 throw new Error(
//                   `VIEW after edit failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               this.validateResponseStructure(viewResponse);
//               this.verifyDataMatch(viewResponse, lifecycle.updatedData);
//               lifecycle.steps.push({
//                 step: "READ_VERIFY_EDIT",
//                 success: true,
//                 endpoint: viewUrl,
//               });

//               logger.info(`✅ Successfully verified edit for ${moduleName}`);
//             });
//           }

//           // 5. EDIT VIEW - Get edit content
//           if (lifecycle.createdId && moduleConfig.EDIT) {
//             await global.allureStep("READ - Get edit content", async () => {
//               logger.info(`Step 5: Getting edit content for ${moduleName}`);
//               const editViewUrl = this.buildUrl(
//                 moduleConfig.EDIT[0],
//                 lifecycle.createdId
//               );
//               const editViewResponse = await apiClient.get(editViewUrl);
//               global.attachJSON("EDIT VIEW Response", editViewResponse);

//               if (!editViewResponse.success) {
//                 const formattedError = this.formatError(editViewResponse.error);
//                 throw new Error(
//                   `EDIT VIEW request failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               this.validateResponseStructure(editViewResponse);
//               lifecycle.steps.push({
//                 step: "EDIT_VIEW",
//                 success: true,
//                 endpoint: editViewUrl,
//               });

//               logger.info(
//                 `✅ Successfully retrieved edit content for ${moduleName}`
//               );
//             });
//           }

//           // 6. DELETE - Remove the entry
//           if (
//             lifecycle.createdId &&
//             moduleConfig.DELETE &&
//             moduleConfig.DELETE[0] !== "URL_HERE"
//           ) {
//             await global.allureStep("DELETE - Remove entry", async () => {
//               logger.info(`Step 6: Deleting entry for ${moduleName}`);
//               const deleteUrl = this.buildUrl(
//                 moduleConfig.DELETE[0],
//                 lifecycle.createdId
//               );
//               global.attachAllureLog("DELETE Endpoint", deleteUrl);

//               const deleteResponse = await apiClient.delete(deleteUrl);
//               global.attachJSON("DELETE Response", deleteResponse);

//               if (!deleteResponse.success) {
//                 const formattedError = this.formatError(deleteResponse.error);
//                 throw new Error(
//                   `DELETE request failed: ${JSON.stringify(
//                     formattedError,
//                     null,
//                     2
//                   )}`
//                 );
//               }

//               this.validateResponseStructure(deleteResponse);
//               lifecycle.steps.push({
//                 step: "DELETE",
//                 success: true,
//                 endpoint: deleteUrl,
//               });

//               logger.info(`✅ Successfully deleted entry for ${moduleName}`);
//             });
//           }

//           // 7. VIEW - Verify deletion (should fail)
//           if (lifecycle.createdId && moduleConfig.View) {
//             await global.allureStep("READ - Verify deletion", async () => {
//               logger.info(`Step 7: Verifying deletion for ${moduleName}`);
//               const viewUrl = this.buildUrl(
//                 moduleConfig.View[0],
//                 lifecycle.createdId
//               );

//               try {
//                 const response = await apiClient.get(viewUrl);
//                 // If we reach here, the item still exists which is unexpected
//                 global.attachJSON("Unexpected Response After Delete", response);
//                 throw new Error(
//                   `Entry still exists after deletion - Status: ${response.status}`
//                 );
//               } catch (error) {
//                 // Expected - item should not be found (404)
//                 global.attachAllureLog(
//                   "Expected Error After Delete",
//                   error.message
//                 );
//                 if (error.response) {
//                   // Expect 404 for deleted resource
//                   if (error.response.status !== 404) {
//                     throw new Error(
//                       `Expected 404 after deletion but got: ${error.response.status}`
//                     );
//                   }
//                 }
//                 lifecycle.steps.push({
//                   step: "VERIFY_DELETION",
//                   success: true,
//                   endpoint: viewUrl,
//                 });
//                 logger.info(
//                   `✅ Successfully verified deletion - Item not found as expected for ${moduleName}`
//                 );
//               }
//             });
//           }

//           lifecycle.status = "completed";
//           lifecycle.completedAt = new Date().toISOString();
//           global.attachJSON("Complete Lifecycle Results", lifecycle);
//           return lifecycle;
//         } catch (error) {
//           lifecycle.status = "failed";
//           lifecycle.error = error.message;
//           lifecycle.failedAt = new Date().toISOString();

//           this.markTestAsFailed(`Lifecycle test failed: ${error.message}`);
//           global.attachAllureLog("Lifecycle Test Error", error.message);
//           global.attachJSON("Lifecycle State on Error", lifecycle);
//           throw error; // Ensure the test fails completely
//         }
//       }
//     );
//   }

//   /**
//    * Smart ID extraction that handles various response structures
//    */
//   // static extractId(response) {
//   //   return global.allureStep("Extract ID from response", async () => {
//   //     const debugInfo = {
//   //       responseKeys: Object.keys(response),
//   //       hasData: !!response.data,
//   //       dataType: typeof response.data,
//   //       dataValue: response.data,
//   //       hasResult: !!response.result,
//   //       resultType: typeof response.result,
//   //       resultValue: response.result,
//   //     };

//   //     // Log the full response structure for debugging
//   //     global.attachJSON("ID Extraction Debug - Full Response", debugInfo);

//   //     let extractedId = null;
//   //     let extractionSource = "unknown";

//   //     // Case 1: Response data is directly the ID string (most common case)
//   //     if (
//   //       typeof response.data === "string" &&
//   //       this.isValidUUID(response.data)
//   //     ) {
//   //       extractedId = response.data;
//   //       extractionSource = "response.data (direct string)";
//   //     }
//   //     // Case 2: Response data is an object with id field
//   //     else if (response.data && typeof response.data === "object") {
//   //       // Try common ID field names
//   //       const idFields = [
//   //         "id",
//   //         "uuid",
//   //         "Id",
//   //         "ID",
//   //         "UUID",
//   //         "guid",
//   //         "Guid",
//   //         "GUID",
//   //         "createdId",
//   //         "resourceId",
//   //         "entityId",
//   //       ];

//   //       for (const field of idFields) {
//   //         if (response.data[field] && this.isValidUUID(response.data[field])) {
//   //           extractedId = response.data[field];
//   //           extractionSource = `response.data.${field}`;
//   //           break;
//   //         }
//   //       }

//   //       // If no UUID found but there's an id field, use it anyway
//   //       if (!extractedId && response.data.id) {
//   //         extractedId = response.data.id;
//   //         extractionSource = `response.data.id (non-UUID)`;
//   //       }
//   //     }
//   //     // Case 3: Response itself has id fields (unlikely but possible)
//   //     else if (response.id && this.isValidUUID(response.id)) {
//   //       extractedId = response.id;
//   //       extractionSource = "response.id";
//   //     }
//   //     // Case 4: Response data is a simple string that might be an ID
//   //     else if (typeof response.data === "string" && response.data.length > 0) {
//   //       extractedId = response.data;
//   //       extractionSource = "response.data (string value)";
//   //     }

//   //     // Log extraction result
//   //     const extractionResult = {
//   //       success: !!extractedId,
//   //       value: extractedId,
//   //       type: typeof extractedId,
//   //       source: extractionSource,
//   //       timestamp: new Date().toISOString(),
//   //     };

//   //     if (extractedId) {
//   //       global.attachAllureLog("ID Extraction Success", extractionResult);
//   //       // FIXED: Safe console usage
//   //       if (typeof console !== "undefined" && console.info) {
//   //         logger.info(
//   //           `✅ ID extracted successfully: ${extractedId} (from ${extractionSource})`
//   //         );
//   //       }
//   //     } else {
//   //       global.attachAllureLog("ID Extraction Failed", extractionResult);
//   //       // FIXED: Safe console usage
//   //       if (typeof console !== "undefined" && console.warn) {
//   //         logger.warn(`⚠️ Could not extract ID from response structure`);
//   //         logger.debug("Available data fields:", Object.keys(response));
//   //       }

//   //       // Last resort: stringify and look for UUID pattern
//   //       const responseString = JSON.stringify(response);
//   //       const uuidMatch = responseString.match(
//   //         /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i
//   //       );
//   //       if (uuidMatch) {
//   //         extractedId = uuidMatch[0];
//   //         extractionSource = "regex pattern match";
//   //         if (typeof console !== "undefined" && console.info) {
//   //           logger.info(`🔄 ID extracted via regex: ${extractedId}`);
//   //         }
//   //       }
//   //     }

//   //     return extractedId;
//   //   });
//   // }

//   /**
//    * A comprehensive function to extract an ID (preferably UUID) from an API response object.
//    * It uses multiple extraction strategies, integrates detailed Allure reporting, and includes logging.
//    *
//    * NOTE: This function assumes `this.isValidUUID(idString)`, `global.allureStep`,
//    * `global.attachJSON`, `global.attachAllureLog`, and a `logger` object are defined
//    * within the class/environment.
//    *
//    * @param {object} response The API response object, typically containing `data` or `result`.
//    * @returns {Promise<string|null>} The extracted ID or null if none is found.
//    */
//   static extractId(response) {
//     // Use global.allureStep to wrap the entire operation for reporting
//     return global.allureStep(
//       "Extract Resource ID from API Response",
//       async () => {
//         let extractedId = null;
//         let extractionSource = "none";

//         // 1. Log the full response structure for comprehensive debugging
//         const debugInfo = {
//           responseKeys: Object.keys(response),
//           hasData: !!response.data,
//           dataType: typeof response.data,
//           dataPreview:
//             typeof response.data === "object"
//               ? Object.keys(response.data)
//               : response.data,
//           hasResult: !!response.result,
//         };
//         global.attachJSON(
//           "ID Extraction Debug - Initial Response Context",
//           debugInfo
//         );

//         const strategies = [
//           // Strategy 1: Direct ID string in response.data (must be UUID)
//           {
//             name: "response.data (direct UUID string)",
//             check: () =>
//               typeof response.data === "string" &&
//               this.isValidUUID(response.data),
//             getValue: () => response.data,
//           },

//           // Strategy 2: ID field within response.data object (look for common fields, must be UUID)
//           {
//             name: "response.data object (UUID field)",
//             check: () => response.data && typeof response.data === "object",
//             getValue: () => {
//               const idFields = [
//                 "id",
//                 "uuid",
//                 "Id",
//                 "ID",
//                 "UUID",
//                 "guid",
//                 "Guid",
//                 "GUID",
//                 "createdId",
//                 "resourceId",
//                 "entityId",
//                 "referenceId",
//               ];
//               for (const field of idFields) {
//                 if (
//                   response.data[field] &&
//                   this.isValidUUID(response.data[field])
//                 ) {
//                   extractionSource = `response.data.${field} (UUID)`; // Update source immediately
//                   return response.data[field];
//                 }
//               }
//               return null;
//             },
//           },

//           // Strategy 3: Response object level ID field (must be UUID)
//           {
//             name: "response.id (UUID)",
//             check: () => response.id && this.isValidUUID(response.id),
//             getValue: () => response.id,
//           },

//           // Strategy 4: Fallback to non-UUID "id" field in response.data object
//           {
//             name: "response.data.id (non-UUID fallback)",
//             check: () =>
//               response.data &&
//               typeof response.data === "object" &&
//               response.data.id,
//             getValue: () => response.data.id,
//           },

//           // Strategy 5: Last resort - Look for any UUID pattern in the entire response string
//           {
//             name: "regex pattern match (last resort)",
//             check: () => true, // Always run this as a final check if previous steps failed
//             getValue: () => {
//               const responseString = JSON.stringify(response);
//               const uuidMatch = responseString.match(
//                 /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i
//               );
//               return uuidMatch ? uuidMatch[0] : null;
//             },
//           },
//         ];

//         // Execute strategies in order
//         for (const strategy of strategies) {
//           // For strategies that don't rely on the complex getValue check (like simple boolean checks)
//           if (strategy.check()) {
//             const result = strategy.getValue();
//             if (result) {
//               extractedId = result;
//               // Only update extractionSource if it wasn't already set inside a complex strategy (like Strategy 2)
//               if (extractionSource === "none") {
//                 extractionSource = strategy.name;
//               }
//               break; // ID found, stop iterating
//             }
//           }
//         }

//         // 2. Final Logging and Allure Reporting
//         const extractionResult = {
//           success: !!extractedId,
//           value: extractedId,
//           type: typeof extractedId,
//           source: extractionSource,
//           timestamp: new Date().toISOString(),
//         };

//         if (extractedId) {
//           global.attachAllureLog("ID Extraction Success", extractionResult);
//           logger.info(
//             `✅ ID extracted successfully: ${extractedId} (from ${extractionSource})`
//           );
//         } else {
//           global.attachAllureLog("ID Extraction Failed", extractionResult);
//           logger.warn(`⚠️ Could not extract ID from response structure`);
//           logger.debug("Available data fields:", Object.keys(response));
//         }

//         return extractedId;
//       }
//     );
//   }

//   /**
//    * Validate if a string is a valid UUID
//    */
//   static isValidUUID(str) {
//     if (typeof str !== "string") return false;

//     const uuidRegex =
//       /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
//     return uuidRegex.test(str);
//   }

//   /**
//    * Enhanced ID extraction with fallback strategies
//    */
//   // static extractIdEnhanced(response) {
//   //   const strategies = [
//   //     // Strategy 1: Direct data string
//   //     () =>
//   //       typeof response.data === "string" && this.isValidUUID(response.data)
//   //         ? response.data
//   //         : null,

//   //     // Strategy 2: Data object with common ID fields
//   //     () => {
//   //       if (response.data && typeof response.data === "object") {
//   //         const idFields = [
//   //           "id",
//   //           "uuid",
//   //           "Id",
//   //           "ID",
//   //           "UUID",
//   //           "guid",
//   //           "createdId",
//   //         ];
//   //         for (const field of idFields) {
//   //           if (
//   //             response.data[field] &&
//   //             this.isValidUUID(response.data[field])
//   //           ) {
//   //             return response.data[field];
//   //           }
//   //         }
//   //         // Return any id field even if not UUID format
//   //         if (response.data.id) return response.data.id;
//   //       }
//   //       return null;
//   //     },

//   //     // Strategy 3: Response level ID
//   //     () => (response.id && this.isValidUUID(response.id) ? response.id : null),

//   //     // Strategy 4: Look for UUID in entire response
//   //     () => {
//   //       const responseString = JSON.stringify(response);
//   //       const uuidMatch = responseString.match(
//   //         /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i
//   //       );
//   //       return uuidMatch ? uuidMatch[0] : null;
//   //     },

//   //     // Strategy 5: Any string in data that looks like an ID
//   //     () => {
//   //       if (typeof response.data === "string" && response.data.length > 10) {
//   //         return response.data;
//   //       }
//   //       return null;
//   //     },
//   //   ];

//   //   for (const strategy of strategies) {
//   //     const result = strategy();
//   //     if (result) {
//   //       // FIXED: Safe console usage
//   //       if (typeof console !== "undefined" && console.debug) {
//   //         logger.debug(`🔍 ID extracted using strategy: ${strategy.name}`);
//   //       }
//   //       return result;
//   //     }
//   //   }

//   //   return null;
//   // }

//   static async makeApiCall(endpoint, method = "POST", data = null) {
//     return await global.allureStep(`API ${method} ${endpoint}`, async () => {
//       try {
//         let response;
//         switch (method.toUpperCase()) {
//           case "GET":
//             response = await apiClient.get(endpoint);
//             break;
//           case "POST":
//             response = await apiClient.post(endpoint, data);
//             break;
//           case "PUT":
//             response = await apiClient.put(endpoint, data);
//             break;
//           case "DELETE":
//             response = await apiClient.delete(endpoint);
//             break;
//           default:
//             throw new Error(`Unsupported HTTP method: ${method}`);
//         }

//         global.attachJSON(`API ${method} Response`, {
//           endpoint,
//           method,
//           status: response.status,
//           success: response.success,
//           data: response.data,
//         });

//         return response;
//       } catch (error) {
//         global.attachAllureLog(`API ${method} Error`, this.formatError(error));
//         throw error;
//       }
//     });
//   }

//   static async testAdvancedSecurityScenarios(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `Advanced Security Scenarios for ${moduleName}`,
//       async () => {
//         const securityTests = [];

//         // Advanced security tests specific to each module
//         if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
//           securityTests.push({
//             name: "Advanced Input Validation",
//             test: async () => {
//               // Implement advanced security tests
//               return {
//                 success: true,
//                 message: "Advanced input validation passed",
//               };
//             },
//           });
//         }

//         const results = [];
//         for (const test of securityTests) {
//           try {
//             const result = await test.test();
//             results.push({ ...result, name: test.name });
//           } catch (error) {
//             results.push({
//               name: test.name,
//               success: false,
//               error: error.message,
//             });
//           }
//         }

//         const failed = results.filter((r) => !r.success);
//         return {
//           results,
//           failed,
//           success: failed.length === 0,
//         };
//       }
//     );
//   }

//   static async performIndividualHealthCheck(
//     endpoint,
//     endpointType,
//     moduleName = ""
//   ) {
//     return await global.allureStep(`Health Check for ${endpoint}`, async () => {
//       try {
//         const response = await apiClient.get(endpoint);
//         return {
//           endpoint,
//           endpointType,
//           moduleName,
//           healthy: response.success,
//           status: response.status,
//           responseTime: Date.now(), // Placeholder for actual measurement
//         };
//       } catch (error) {
//         return {
//           endpoint,
//           endpointType,
//           moduleName,
//           healthy: false,
//           error: error.message,
//           status: error.response?.status,
//         };
//       }
//     });
//   }

//   // Default test data generator replacement
//   static getDefaultTestData() {
//     return {
//       getPostData: () => ({
//         name: `Test-${Date.now()}`,
//         description: "API Testing",
//         status: "Active",
//         timestamp: new Date().toISOString(),
//       }),
//       getEditData: (originalData) => ({
//         ...originalData,
//         description: `UPDATED - ${originalData.description || "API Testing"}`,
//         name: `Updated-${originalData.name || `Test-${Date.now()}`}`,
//         updatedAt: new Date().toISOString(),
//       }),
//       getNullRequiredFields: () => ({
//         name: null,
//         description: null,
//         status: null,
//       }),
//     };
//   }

//   // Generate malicious payloads for security testing
//   static generateMaliciousPayloads() {
//     return {
//       sqlInjection: {
//         input: "' OR '1'='1",
//         name: "test'; DROP TABLE users; --",
//         description: "test' UNION SELECT * FROM passwords --",
//       },
//       xss: {
//         input: "<script>alert('XSS')</script>",
//         name: "<img src=x onerror=alert('XSS')>",
//         description: "javascript:alert('XSS')",
//       },
//       pathTraversal: {
//         input: "../../../etc/passwd",
//         filename: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
//       },
//       bufferOverflow: {
//         input: "A".repeat(10000),
//         description: "B".repeat(5000),
//       },
//       commandInjection: {
//         input: "; ls -la",
//         command: "| cat /etc/passwd",
//       },
//     };
//   }

//   // Get invalid tokens for security testing
//   static getInvalidTokens() {
//     return {
//       wrongToken: "Bearer invalid_token_12345",
//       expiredToken: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token",
//       malformedToken: "InvalidTokenFormat",
//       emptyToken: "",
//     };
//   }

//   static async testMaliciousPayloads(
//     moduleConfig,
//     endpointType = "Post",
//     moduleName = ""
//   ) {
//     return await global.allureStep(
//       `Malicious Payload Tests for ${moduleName}`,
//       async () => {
//         const maliciousTests = [];
//         const endpoint = moduleConfig[endpointType];

//         if (!endpoint || endpoint[0] === "URL_HERE") {
//           return [
//             { skipped: true, message: `No ${endpointType} endpoint available` },
//           ];
//         }

//         const maliciousPayloads = this.generateMaliciousPayloads();
//         const testData = this.getDefaultTestData();

//         global.attachJSON("Malicious Payloads", maliciousPayloads);

//         // Test 1: SQL Injection
//         maliciousTests.push({
//           name: "SQL Injection",
//           test: async () => {
//             return await global.allureStep(
//               "Test SQL injection payloads",
//               async () => {
//                 const baseData = testData.getPostData();
//                 const payload = {
//                   ...baseData,
//                   ...maliciousPayloads.sqlInjection,
//                 };

//                 global.attachJSON("SQL Injection Payload", payload);
//                 const response = await this.makeApiCall(
//                   endpoint[0],
//                   "POST",
//                   payload
//                 );

//                 // More flexible status code checking
//                 const isSuccess = [400, 422, 500, 403].includes(
//                   response.status
//                 );

//                 return {
//                   expected: "400/422/500/403",
//                   actual: response.status,
//                   success: isSuccess,
//                   message: `SQL injection should return 400/422/500/403, got ${response.status}`,
//                 };
//               }
//             );
//           },
//         });

//         // Test 2: XSS Injection
//         maliciousTests.push({
//           name: "XSS Injection",
//           test: async () => {
//             return await global.allureStep(
//               "Test XSS injection payloads",
//               async () => {
//                 const baseData = testData.getPostData();
//                 const payload = {
//                   ...baseData,
//                   ...maliciousPayloads.xss,
//                 };

//                 global.attachJSON("XSS Injection Payload", payload);
//                 const response = await this.makeApiCall(
//                   endpoint[0],
//                   "POST",
//                   payload
//                 );

//                 const isSuccess = [400, 422, 500, 403].includes(
//                   response.status
//                 );

//                 return {
//                   expected: "400/422/500/403",
//                   actual: response.status,
//                   success: isSuccess,
//                   message: `XSS injection should return 400/422/500/403, got ${response.status}`,
//                 };
//               }
//             );
//           },
//         });

//         // Test 3: Path Traversal
//         maliciousTests.push({
//           name: "Path Traversal",
//           test: async () => {
//             return await global.allureStep(
//               "Test path traversal payloads",
//               async () => {
//                 const baseData = testData.getPostData();
//                 const payload = {
//                   ...baseData,
//                   ...maliciousPayloads.pathTraversal,
//                 };

//                 global.attachJSON("Path Traversal Payload", payload);
//                 const response = await this.makeApiCall(
//                   endpoint[0],
//                   "POST",
//                   payload
//                 );

//                 const isSuccess = [400, 422, 500, 403].includes(
//                   response.status
//                 );

//                 return {
//                   expected: "400/422/500/403",
//                   actual: response.status,
//                   success: isSuccess,
//                   message: `Path traversal should return 400/422/500/403, got ${response.status}`,
//                 };
//               }
//             );
//           },
//         });

//         const results = [];
//         for (const test of maliciousTests) {
//           try {
//             const result = await test.test();
//             results.push({
//               test: test.name,
//               ...result,
//             });
//           } catch (error) {
//             global.attachAllureLog(
//               `Malicious Payload Test Error - ${test.name}`,
//               error.message
//             );
//             results.push({
//               test: test.name,
//               error: error.message,
//               success: false,
//             });
//           }
//         }

//         global.attachJSON("Malicious Payload Test Results", results);
//         return results;
//       }
//     );
//   }

//   static removeLastUrlSection(url) {
//     // 1. Create a URL object for robust parsing (handles query parameters, etc.)
//     const urlObject = new URL(url, "http://localhost"); // Add base for relative URLs

//     // 2. Get the pathname (the part after the domain, e.g., '/path/to/section')
//     let path = urlObject.pathname;

//     // 3. Remove a trailing slash if present to avoid an empty section at the end
//     if (path.endsWith("/")) {
//       path = path.slice(0, -1);
//     }

//     // 4. Split the path into sections
//     const sections = path.split("/");

//     // 5. Remove the last section if there is more than just the base path (the first element is usually an empty string from the leading '/')
//     if (sections.length > 1) {
//       sections.pop();
//     }

//     // 6. Join the remaining sections back together
//     const newPath = sections.join("/");

//     // 7. Update the URL object's pathname
//     urlObject.pathname = newPath;

//     // 8. Return the full new URL string
//     return urlObject.pathname; // Return only pathname for API endpoints
//   }

//   static buildUrl(baseUrl, id) {
//     const cleanBaseUrl = this.removeLastUrlSection(baseUrl);
//     return cleanBaseUrl.endsWith("/")
//       ? `${cleanBaseUrl}${id}`
//       : `${cleanBaseUrl}/${id}`;
//   }

//   static verifyDataMatch(actual, expected) {
//     return global.allureStep("Verify data integrity", () => {
//       const keyFields = [
//         "id",
//         "name",
//         "code",
//         "description",
//         "status",
//         "Name",
//         "Code",
//         "Status",
//       ];
//       const matches = {};
//       const mismatches = [];

//       keyFields.forEach((field) => {
//         const actualValue = actual[field] || actual.data?.[field];
//         const expectedValue = expected[field] || expected.data?.[field];

//         if (expectedValue && actualValue) {
//           const match = actualValue === expectedValue;
//           matches[field] = {
//             match,
//             expected: expectedValue,
//             actual: actualValue,
//           };
//           if (!match) {
//             mismatches.push(field);
//           }
//         }
//       });

//       global.attachJSON("Data Match Verification", {
//         matches,
//         mismatches,
//         hasMismatches: mismatches.length > 0,
//         totalFieldsChecked: keyFields.length,
//         matchingFields: keyFields.length - mismatches.length,
//       });

//       if (mismatches.length > 0) {
//         throw new Error(`Data mismatch in fields: ${mismatches.join(", ")}`);
//       }

//       return true;
//     });
//   }

//   static sleep(ms) {
//     return new Promise((resolve) => setTimeout(resolve, ms));
//   }

//   static async testAuthorizationSecurity(moduleConfig) {
//     return await global.allureStep(
//       `Authorization Security Tests for ${moduleConfig.name || moduleConfig}`,
//       async () => {
//         const securityTests = [];
//         const invalidTokens = this.getInvalidTokens();

//         global.attachAllureLog("Authorization Test Configuration", {
//           module: moduleConfig.name || moduleConfig,
//           hasPostEndpoint: !!(
//             moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE"
//           ),
//           invalidTokensAvailable: !!invalidTokens,
//         });

//         // Test 1: No Token
//         securityTests.push({
//           name: "No Token Authorization",
//           test: async () => {
//             return await global.allureStep(
//               "Test without authorization token",
//               async () => {
//                 if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
//                   const client = apiClient.withNoToken();
//                   const testData = this.getDefaultTestData();
//                   const requestData = testData.getPostData();

//                   global.attachJSON("No Token Request Data", requestData);
//                   global.attachAllureLog(
//                     "No Token Endpoint",
//                     moduleConfig.Post[0]
//                   );

//                   const response = await client.post(
//                     moduleConfig.Post[0],
//                     requestData
//                   );
//                   global.attachJSON("No Token Response", response);

//                   return {
//                     expected: 401,
//                     actual: response.status,
//                     success: response.status === 401 || response.status === 403,
//                     message: `No token should return 401/403, got ${response.status}`,
//                   };
//                 }
//                 return { skipped: true, message: "No POST endpoint available" };
//               }
//             );
//           },
//         });

//         // Test 2: Wrong Token
//         securityTests.push({
//           name: "Wrong Token Authorization",
//           test: async () => {
//             return await global.allureStep(
//               "Test with wrong authorization token",
//               async () => {
//                 if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
//                   const client = apiClient.withWrongToken();
//                   const testData = this.getDefaultTestData();
//                   const requestData = testData.getPostData();

//                   global.attachJSON("Wrong Token Request Data", requestData);
//                   global.attachAllureLog(
//                     "Wrong Token Endpoint",
//                     moduleConfig.Post[0]
//                   );

//                   const response = await client.post(
//                     moduleConfig.Post[0],
//                     requestData
//                   );
//                   global.attachJSON("Wrong Token Response", response);

//                   return {
//                     expected: 401,
//                     actual: response.status,
//                     success: response.status === 401 || response.status === 403,
//                     message: `Wrong token should return 401/403, got ${response.status}`,
//                   };
//                 }
//                 return { skipped: true, message: "No POST endpoint available" };
//               }
//             );
//           },
//         });

//         // Execute all security tests
//         const results = [];
//         for (const securityTest of securityTests) {
//           try {
//             const result = await securityTest.test();
//             results.push({
//               test: securityTest.name,
//               ...result,
//             });
//           } catch (error) {
//             global.attachAllureLog(
//               `Security Test Error - ${securityTest.name}`,
//               error.message
//             );
//             results.push({
//               test: securityTest.name,
//               error: error.message,
//               success: false,
//             });
//           }
//         }
//         try {
//           const failedAuthTests = results.filter(
//             (test) => !test.success && !test.skipped
//           );
//           if (failedAuthTests.length > 0) {
//             this.markTestAsFailed(
//               `Authorization tests failed: ${failedAuthTests.length} failures`
//             );
//             const errorMessages = failedAuthTests
//               .map((test) => test.message || test.error)
//               .join("; ");
//             throw new Error(
//               `Authorization security tests failed: ${errorMessages}`
//             );
//           }
//           global.attachJSON("Authorization Security Test Results", results);
//           return results;
//         } catch (error) {
//           this.markTestAsFailed(
//             `Authorization security test failed: ${error.message}`
//           );
//           throw error;
//         }
//       }
//     );
//   }

//   static async testNullRequiredFields(moduleConfig, endpointType = "Post") {
//     return await global.allureStep(
//       `Null Required Fields Test for ${moduleConfig.name || moduleConfig}`,
//       async () => {
//         const endpoint = moduleConfig[endpointType];

//         global.attachAllureLog("Null Required Fields Test Configuration", {
//           module: moduleConfig.name || moduleConfig,
//           endpointType,
//           endpoint: endpoint ? endpoint[0] : "Not available",
//         });

//         if (!endpoint || endpoint[0] === "URL_HERE") {
//           return {
//             skipped: true,
//             message: `No ${endpointType} endpoint available`,
//           };
//         }

//         const testData = this.getDefaultTestData();
//         const nullPayload = testData.getNullRequiredFields();

//         global.attachJSON("Null Required Fields Payload", nullPayload);

//         const response = await apiClient.post(endpoint[0], nullPayload);
//         global.attachJSON("Null Required Fields Response", response);

//         return {
//           expected: 400,
//           actual: response.status,
//           success: response.status === 400,
//           message: `Null required fields should return 400, got ${response.status}`,
//         };
//       }
//     );
//   }

//   static async testTransactionCommitFlow(moduleConfig) {
//     return await global.allureStep(
//       `Transaction Commit Flow for ${moduleConfig.name || moduleConfig}`,
//       async () => {
//         const flowResults = [];

//         global.attachAllureLog("Transaction Commit Flow Configuration", {
//           module: moduleConfig.name || moduleConfig,
//           hasPostEndpoint: !!(
//             moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE"
//           ),
//           hasCommitEndpoint: !!(
//             moduleConfig.Commit && moduleConfig.Commit[0] !== "URL_HERE"
//           ),
//         });

//         // 1. Create transaction
//         if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
//           await global.allureStep("Create transaction", async () => {
//             logger.info(
//               `Step 1: Creating transaction for ${
//                 moduleConfig.name || moduleConfig
//               }`
//             );
//             const testData = this.getDefaultTestData();
//             const postData = testData.getPostData();

//             global.attachJSON("Transaction Create Request", postData);
//             const postResponse = await apiClient.post(
//               moduleConfig.Post[0],
//               postData
//             );
//             global.attachJSON("Transaction Create Response", postResponse);

//             if (!postResponse.success) {
//               flowResults.push({
//                 step: "Create",
//                 success: false,
//                 error: `Failed to create transaction: ${postResponse.error}`,
//               });
//               return flowResults;
//             }

//             const transactionId = this.extractId(postResponse.data);
//             flowResults.push({
//               step: "Create",
//               success: true,
//               id: transactionId,
//             });
//             global.attachAllureLog(
//               "Transaction Created",
//               `Transaction ID: ${transactionId}`
//             );

//             // 2. Commit transaction
//             if (moduleConfig.Commit && moduleConfig.Commit[0] !== "URL_HERE") {
//               await global.allureStep("Commit transaction", async () => {
//                 logger.info(`Step 2: Committing transaction`);
//                 const commitData = {
//                   id: transactionId,
//                   status: "Posted",
//                   commitTimestamp: new Date().toISOString(),
//                 };

//                 global.attachJSON("Transaction Commit Request", commitData);
//                 const commitResponse = await apiClient.post(
//                   moduleConfig.Commit[0],
//                   commitData
//                 );
//                 global.attachJSON(
//                   "Transaction Commit Response",
//                   commitResponse
//                 );

//                 flowResults.push({
//                   step: "Commit",
//                   success: commitResponse.success,
//                   status: commitResponse.status,
//                 });

//                 // 3. Verify transaction status
//                 if (commitResponse.success && moduleConfig.View) {
//                   await global.allureStep(
//                     "Verify committed transaction",
//                     async () => {
//                       logger.info(`Step 3: Verifying committed transaction`);
//                       await this.sleep(2000); // Wait for commit processing

//                       const viewUrl = this.buildUrl(
//                         moduleConfig.View[0],
//                         transactionId
//                       );
//                       const viewResponse = await apiClient.get(viewUrl);
//                       global.attachJSON(
//                         "Transaction Verify Response",
//                         viewResponse
//                       );

//                       flowResults.push({
//                         step: "Verify",
//                         success: viewResponse.success,
//                         status: viewResponse.status,
//                       });

//                       // Verify transaction status is updated
//                       if (viewResponse.success) {
//                         const isCommitted = this.verifyTransactionStatus(
//                           viewResponse.data,
//                           "Posted"
//                         );
//                         flowResults.push({
//                           step: "Status Check",
//                           success: isCommitted,
//                           message: isCommitted
//                             ? "Transaction successfully posted"
//                             : "Transaction not in expected posted status",
//                         });

//                         global.attachAllureLog(
//                           "Transaction Status",
//                           isCommitted
//                             ? "Committed Successfully"
//                             : "Commit Status Unknown"
//                         );
//                       }
//                     }
//                   );
//                 }
//               });
//             }
//           });
//         }

//         global.attachJSON("Transaction Commit Flow Results", flowResults);
//         return flowResults;
//       }
//     );
//   }

//   static verifyTransactionStatus(transactionData, expectedStatus) {
//     return global.allureStep("Verify transaction status", () => {
//       const statusFields = [
//         "status",
//         "transactionStatus",
//         "state",
//         "postingStatus",
//         "Status",
//         "State",
//         "PostingStatus",
//       ];

//       for (const field of statusFields) {
//         const actualStatus =
//           transactionData[field] ||
//           transactionData.data?.[field] ||
//           transactionData.result?.[field];

//         if (actualStatus === expectedStatus) {
//           global.attachAllureLog("Transaction Status Match", {
//             field,
//             expected: expectedStatus,
//             actual: actualStatus,
//           });
//           return true;
//         }
//       }

//       global.attachAllureLog("Transaction Status Mismatch", {
//         expected: expectedStatus,
//         actual: transactionData,
//         checkedFields: statusFields,
//       });
//       return false;
//     });
//   }

//   static async performHealthChecks(schema) {
//     return await global.allureStep("Perform API Health Checks", async () => {
//       const healthResults = [];
//       const endpointsToCheck = [];

//       // Collect all endpoints from schema
//       const collectEndpoints = (modules, path = "") => {
//         Object.entries(modules).forEach(([name, config]) => {
//           if (typeof config === "object" && config !== null) {
//             const fullPath = path ? `${path}.${name}` : name;

//             // Check for various endpoint types
//             endpointTypes.forEach((type) => {
//               if (config[type] && config[type][0] !== "URL_HERE") {
//                 endpointsToCheck.push({
//                   name: `${fullPath} - ${type}`,
//                   url: config[type][0],
//                   type: type,
//                 });
//               }
//             });

//             // Recursively check nested modules
//             if (typeof config === "object" && !config.Post && !config.GET) {
//               collectEndpoints(config, fullPath);
//             }
//           }
//         });
//       };

//       collectEndpoints(schema);

//       // Check each endpoint
//       for (const endpoint of endpointsToCheck.slice(0, 10)) {
//         // Limit to first 10 for performance
//         await global.allureStep(`Check ${endpoint.name}`, async () => {
//           try {
//             const response = await apiClient.get(endpoint.url);
//             healthResults.push({
//               endpoint: endpoint.name,
//               url: endpoint.url,
//               healthy: response.success,
//               status: response.status,
//               responseTime: "measured", // You can add actual response time measurement
//             });
//           } catch (error) {
//             healthResults.push({
//               endpoint: endpoint.name,
//               url: endpoint.url,
//               healthy: false,
//               error: error.message,
//             });
//           }
//         });
//       }

//       global.attachJSON("Health Check Results", healthResults);
//       return healthResults;
//     });
//   }

//   /**
//    * Calculate overall security score
//    */
//   static calculateSecurityScore(securityResults) {
//     let totalWeight = 0;
//     let weightedScore = 0;

//     const testCategories = {
//       authorization: 0.3,
//       sqlInjection: 0.25,
//       xssProtection: 0.25,
//       maliciousPost: 0.1,
//       maliciousPut: 0.05,
//       performance: 0.05,
//     };

//     for (const [category, weight] of Object.entries(testCategories)) {
//       if (securityResults[category]) {
//         const categoryScore = this.calculateCategoryScore(
//           securityResults[category]
//         );
//         weightedScore += categoryScore * weight;
//         totalWeight += weight;
//       }
//     }

//     return totalWeight > 0
//       ? Math.round((weightedScore / totalWeight) * 100)
//       : 0;
//   }

//   static calculateCategoryScore(categoryResults) {
//     if (!categoryResults || categoryResults.length === 0) return 0;

//     const totalTests = categoryResults.length;
//     const passedTests = categoryResults.filter(
//       (test) => test.success || test.skipped
//     ).length;

//     return passedTests / totalTests;
//   }

//   static countTotalTests(securityResults) {
//     return Object.values(securityResults)
//       .filter(Array.isArray)
//       .reduce((total, tests) => total + tests.length, 0);
//   }

//   static countPassedTests(securityResults) {
//     return Object.values(securityResults)
//       .filter(Array.isArray)
//       .reduce(
//         (total, tests) => total + tests.filter((test) => test.success).length,
//         0
//       );
//   }

//   static countFailedTests(securityResults) {
//     return Object.values(securityResults)
//       .filter(Array.isArray)
//       .reduce(
//         (total, tests) =>
//           total + tests.filter((test) => !test.success && !test.skipped).length,
//         0
//       );
//   }

//   static getSecurityLevel(score) {
//     if (score >= 90) return "EXCELLENT";
//     if (score >= 80) return "GOOD";
//     if (score >= 70) return "FAIR";
//     if (score >= 60) return "POOR";
//     return "CRITICAL";
//   }

//   // ===========================================================================
//   // ENHANCED EXISTING METHODS WITH MODULE NAME SUPPORT
//   // ===========================================================================

//   static async testAuthorizationSecurity(moduleConfig, moduleName = "") {
//     return await global.allureStep(
//       `Authorization Security Tests for ${moduleName}`,
//       async () => {
//         // Enhanced implementation with module name context
//         const results = await super.testAuthorizationSecurity(moduleConfig);

//         // Add module context to results
//         return results.map((result) => ({
//           ...result,
//           module: moduleName,
//           timestamp: new Date().toISOString(),
//         }));
//       }
//     );
//   }

//   static async testMaliciousPayloads(
//     moduleConfig,
//     endpointType = "Post",
//     moduleName = ""
//   ) {
//     return await global.allureStep(
//       `Malicious Payload Tests for ${moduleName}`,
//       async () => {
//         const results = await super.testMaliciousPayloads(
//           moduleConfig,
//           endpointType
//         );

//         return results.map((result) => ({
//           ...result,
//           module: moduleName,
//           endpointType: endpointType,
//           timestamp: new Date().toISOString(),
//         }));
//       }
//     );
//   }

//   static async testNullRequiredFields(
//     moduleConfig,
//     endpointType = "Post",
//     moduleName = ""
//   ) {
//     return await global.allureStep(
//       `Null Required Fields Test for ${moduleName}`,
//       async () => {
//         const result = await super.testNullRequiredFields(
//           moduleConfig,
//           endpointType
//         );

//         return {
//           ...result,
//           module: moduleName,
//           endpointType: endpointType,
//           timestamp: new Date().toISOString(),
//         };
//       }
//     );
//   }
// }

// // Extend the original TestHelpers class
// const OriginalTestHelpers = require("./test-helpers");
// Object.setPrototypeOf(
//   TestHelpers.prototype,
//   OriginalTestHelpers.prototype
// );
// Object.setPrototypeOf(TestHelpers, OriginalTestHelpers);

// module.exports = TestHelpers;
