// utils/test-helpers.js
const apiClient = require("./api-client");
const logger = require("./logger");
const TokenManager = require("./token-manager");
const {
  endpointTypes,
  TEST_TAGS,
  HTTP_STATUS_CODES,
} = require("../Constants/Constants");

class TestHelpers {
  /**
   * 🎯 ENHANCED ID EXTRACTION WITH COMPREHENSIVE VALIDATION
   * Extracts resource IDs from API responses with multiple fallback strategies
   */
  static extractId(response) {
    const startTime = Date.now();
    logger.debug("🆔 Starting ID extraction from response");

    let extractedId = null;
    let extractionSource = "none";
    let extractionStrategy = "unknown";

    // Debug response structure
    const debugInfo = {
      responseKeys: Object.keys(response),
      hasData: !!response.data,
      dataType: typeof response.data,
      dataPreview:
        typeof response.data === "object" && response.data !== null
          ? Object.keys(response.data)
          : response.data,
      hasResult: !!response.result,
      status: response.status,
    };

    logger.debug("🔍 ID Extraction Debug - Response Context:", debugInfo);

    // Comprehensive extraction strategies with priority
    const strategies = [
      // Strategy 1: Direct UUID string in response.data
      {
        name: "direct_uuid_string",
        priority: 1,
        check: () =>
          typeof response.data === "string" && this.isValidUUID(response.data),
        extract: () => {
          extractionSource = "response.data";
          extractionStrategy = "direct_uuid_string";
          return response.data;
        },
      },

      // Strategy 2: ID fields within response.data object
      {
        name: "data_object_id_fields",
        priority: 2,
        check: () =>
          response.data &&
          typeof response.data === "object" &&
          response.data !== null,
        extract: () => {
          const idFields = [
            "id",
            "uuid",
            "Id",
            "ID",
            "UUID",
            "guid",
            "Guid",
            "GUID",
            "createdId",
            "resourceId",
            "entityId",
            "referenceId",
            "documentId",
            "recordId",
            "itemId",
            "objectId",
          ];

          for (const field of idFields) {
            if (response.data[field] && this.isValidId(response.data[field])) {
              extractionSource = `response.data.${field}`;
              extractionStrategy = "data_object_id_fields";
              return response.data[field];
            }
          }
          return null;
        },
      },

      // Strategy 3: Response-level ID fields
      {
        name: "response_level_id",
        priority: 3,
        check: () => response.id && this.isValidId(response.id),
        extract: () => {
          extractionSource = "response.id";
          extractionStrategy = "response_level_id";
          return response.id;
        },
      },

      // Strategy 4: Nested result/response objects
      {
        name: "nested_result_objects",
        priority: 4,
        check: () =>
          response.data &&
          typeof response.data === "object" &&
          (response.data.result ||
            response.data.response ||
            response.data.data),
        extract: () => {
          const nestedPaths = [
            "data.result.id",
            "data.response.id",
            "data.data.id",
            "result.id",
            "response.id",
          ];

          for (const path of nestedPaths) {
            const value = this.getNestedValue(response, path);
            if (value && this.isValidId(value)) {
              extractionSource = path;
              extractionStrategy = "nested_result_objects";
              return value;
            }
          }
          return null;
        },
      },

      // Strategy 5: Location header extraction
      {
        name: "location_header",
        priority: 5,
        check: () => response.headers && response.headers.location,
        extract: () => {
          const location = response.headers.location;
          // Extract ID from URL path
          const idMatch = location.match(/\/([^\/]+)$/);
          if (idMatch && this.isValidId(idMatch[1])) {
            extractionSource = "headers.location";
            extractionStrategy = "location_header";
            return idMatch[1];
          }
          return null;
        },
      },

      // Strategy 6: Regex pattern matching in entire response
      {
        name: "regex_pattern_match",
        priority: 6,
        check: () => true, // Always attempt as last resort
        extract: () => {
          const responseString = JSON.stringify(response);
          // UUID pattern matching
          const uuidRegex =
            /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi;
          const uuidMatches = responseString.match(uuidRegex);

          if (uuidMatches && uuidMatches.length > 0) {
            // Return the first valid UUID
            for (const match of uuidMatches) {
              if (this.isValidUUID(match)) {
                extractionSource = "regex_pattern_match";
                extractionStrategy = "uuid_regex";
                return match;
              }
            }
          }

          // Numeric ID pattern matching
          const numericIdRegex = /"id":\s*(\d+)/gi;
          const numericMatches = responseString.match(numericIdRegex);
          if (numericMatches && numericMatches.length > 0) {
            const numericId = numericMatches[0].match(/\d+/)[0];
            if (this.isValidId(numericId)) {
              extractionSource = "regex_pattern_match";
              extractionStrategy = "numeric_id_regex";
              return numericId;
            }
          }

          return null;
        },
      },
    ];

    // Execute strategies in priority order
    const sortedStrategies = strategies.sort((a, b) => a.priority - b.priority);

    for (const strategy of sortedStrategies) {
      if (strategy.check()) {
        try {
          const result = strategy.extract();
          if (result) {
            extractedId = result;
            extractionStrategy = strategy.name;
            break;
          }
        } catch (error) {
          logger.debug(`Strategy ${strategy.name} failed: ${error.message}`);
          continue;
        }
      }
    }

    const extractionTime = Date.now() - startTime;

    if (extractedId) {
      logger.info(
        `✅ ID extracted: ${extractedId} (source: ${extractionSource}, strategy: ${extractionStrategy}, time: ${extractionTime}ms)`
      );
    } else {
      logger.error(
        `❌ CRITICAL: No valid ID extracted from response. Strategies attempted: ${strategies
          .map((s) => s.name)
          .join(", ")}`
      );
      logger.debug(
        "Full response for debugging:",
        JSON.stringify(response, null, 2)
      );
    }

    return extractedId;
  }

  /**
   * 🎯 COMPREHENSIVE ID VALIDATION
   */
  static isValidId(id) {
    if (!id) return false;

    const idStr = String(id).trim();

    // Basic validation
    if (idStr.length === 0) return false;
    if (idStr === "null" || idStr === "undefined") return false;
    if (idStr === "0" || idStr === "0") return false;
    if (idStr === "00000000-0000-0000-0000-000000000000") return false;

    // UUID validation
    if (this.isValidUUID(idStr)) return true;

    // Numeric ID validation
    if (!isNaN(idStr) && idStr > 0) return true;

    // String ID validation (minimum length, not just whitespace)
    if (idStr.length >= 1 && idStr.trim().length > 0) return true;

    return false;
  }

  /**
   * 🎯 STRICT UUID VALIDATION
   */
  static isValidUUID(str) {
    if (typeof str !== "string") return false;
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
  }

  /**
   * 🎯 ENHANCED RESPONSE STRUCTURE DEBUGGING
   */
  static debugResponseStructure(response, operation) {
    logger.debug(`🔍 ${operation} Response Structure Analysis:`);
    logger.debug(`   Status: ${response.status}`);
    logger.debug(`   Headers: ${JSON.stringify(response.headers)}`);
    logger.debug(`   Data Type: ${typeof response.data}`);
    logger.debug(
      `   Data Keys: ${response.data ? Object.keys(response.data) : "NO DATA"}`
    );

    if (response.data) {
      const dataSample = JSON.stringify(response.data);
      logger.debug(
        `   Data Sample: ${dataSample.substring(0, 200)}${
          dataSample.length > 200 ? "..." : ""
        }`
      );
    }

    // Check for common success indicators
    const successIndicators = {
      hasId: response.data && (response.data.id || response.data.uuid),
      hasSuccessField: response.data && response.data.success !== undefined,
      hasStatusField: response.data && response.data.status !== undefined,
      hasMessage: response.data && response.data.message,
    };

    logger.debug(`   Success Indicators:`, successIndicators);
  }

  /**
   * 🎯 GET NESTED OBJECT VALUE
   */
  static getNestedValue(obj, path) {
    return path
      .split(".")
      .reduce(
        (current, key) =>
          current && current[key] !== undefined ? current[key] : undefined,
        obj
      );
  }

  // ===========================================================================
  // 🛡️ SECURITY TESTING IMPLEMENTATIONS
  // ===========================================================================

  /**
   * 🎯 COMPREHENSIVE AUTHORIZATION SECURITY TESTING
   */
  static async testAuthorizationSecurity(moduleConfig, moduleName = "") {
    const securityTests = [];
    const results = [];

    logger.info(`🛡️ Starting authorization security tests for: ${moduleName}`);

    // Test 1: No Token Authorization
    securityTests.push({
      name: "No Token Authorization",
      test: async () => {
        logger.debug(`   Testing: No Token for ${moduleName}`);

        if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
          const client = apiClient.withNoToken();
          const testData = this.getDefaultTestData().getPostData();

          try {
            const response = await client.post(moduleConfig.Post[0], testData);

            return {
              expected: [401, 403],
              actual: response.status,
              success: response.status === 401 || response.status === 403,
              message: `No token should return 401/403, got ${response.status}`,
            };
          } catch (error) {
            const status = error.response?.status;
            return {
              expected: [401, 403],
              actual: status || "Network Error",
              success: status === 401 || status === 403,
              message: `No token request handled appropriately`,
            };
          }
        }
        return { skipped: true, message: "No POST endpoint available" };
      },
    });

    // Test 2: Wrong Token Authorization
    securityTests.push({
      name: "Wrong Token Authorization",
      test: async () => {
        logger.debug(`   Testing: Wrong Token for ${moduleName}`);

        if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
          const client = apiClient.withWrongToken();
          const testData = this.getDefaultTestData().getPostData();

          try {
            const response = await client.post(moduleConfig.Post[0], testData);

            return {
              expected: [401, 403],
              actual: response.status,
              success: response.status === 401 || response.status === 403,
              message: `Wrong token should return 401/403, got ${response.status}`,
            };
          } catch (error) {
            const status = error.response?.status;
            return {
              expected: [401, 403],
              actual: status || "Network Error",
              success: status === 401 || status === 403,
              message: `Wrong token request handled appropriately`,
            };
          }
        }
        return { skipped: true, message: "No POST endpoint available" };
      },
    });

    // Test 3: Expired Token Authorization
    securityTests.push({
      name: "Expired Token Authorization",
      test: async () => {
        logger.debug(`   Testing: Expired Token for ${moduleName}`);

        if (moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE") {
          const client = apiClient.withExpiredToken();
          const testData = this.getDefaultTestData().getPostData();

          try {
            const response = await client.post(moduleConfig.Post[0], testData);

            return {
              expected: [401, 403],
              actual: response.status,
              success: response.status === 401 || response.status === 403,
              message: `Expired token should return 401/403, got ${response.status}`,
            };
          } catch (error) {
            const status = error.response?.status;
            return {
              expected: [401, 403],
              actual: status || "Network Error",
              success: status === 401 || status === 403,
              message: `Expired token request handled appropriately`,
            };
          }
        }
        return { skipped: true, message: "No POST endpoint available" };
      },
    });

    // Execute all security tests
    for (const securityTest of securityTests) {
      try {
        const result = await securityTest.test();
        results.push({
          test: securityTest.name,
          ...result,
          module: moduleName,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        logger.error(
          `❌ Security test ${securityTest.name} failed: ${error.message}`
        );
        results.push({
          test: securityTest.name,
          error: error.message,
          success: false,
          module: moduleName,
        });
      }
    }

    // Analyze results
    const failedAuthTests = results.filter(
      (test) => !test.success && !test.skipped
    );
    if (failedAuthTests.length > 0) {
      const errorMessages = failedAuthTests
        .map((test) => test.message || test.error)
        .join("; ");
      throw new Error(`Authorization security tests failed: ${errorMessages}`);
    }

    logger.info(`✅ Authorization security tests completed for ${moduleName}`);
    return results;
  }

  /**
   * 🎯 SQL INJECTION PROTECTION TESTING
   */
  static async testSQLInjectionProtection(moduleConfig, moduleName = "") {
    const results = [];
    const endpoint = moduleConfig.Post;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          skipped: true,
          message: `No POST endpoint available for SQL injection testing in ${moduleName}`,
        },
      ];
    }

    logger.info(
      `💉 Starting SQL injection protection tests for: ${moduleName}`
    );

    const sqlPayloads = this.generateSQLInjectionPayloads();
    const testData = this.getDefaultTestData();

    for (const [technique, payloads] of Object.entries(sqlPayloads)) {
      for (const [field, sqlPayload] of Object.entries(payloads)) {
        try {
          logger.debug(`   Testing SQL ${technique} in ${field}`);

          const baseData = testData.getPostData();
          const maliciousData = { ...baseData };

          if (maliciousData[field] !== undefined) {
            maliciousData[field] = sqlPayload;
          } else {
            maliciousData[field] = sqlPayload;
          }

          const response = await apiClient.post(endpoint[0], maliciousData);

          const isBlocked = [400, 422, 403, 500].includes(response.status);
          const showsError = this.checkSQLErrorIndicators(response);

          results.push({
            test: `SQL ${technique} - ${field}`,
            expected: "400/422/403/500 or no SQL error leakage",
            actual: response.status,
            success: isBlocked || !showsError,
            blocked: isBlocked,
            errorLeakage: showsError,
            payload: sqlPayload.substring(0, 50) + "...",
            message: `SQL ${technique} should be blocked and not leak errors`,
            module: moduleName,
          });
        } catch (error) {
          const status = error.response?.status;
          const isBlocked = [400, 422, 403, 500].includes(status);

          results.push({
            test: `SQL ${technique} - ${field}`,
            expected: "400/422/403/500 or no SQL error leakage",
            actual: status || "Error",
            success: isBlocked,
            blocked: isBlocked,
            errorLeakage: false,
            payload: sqlPayload.substring(0, 50) + "...",
            message: `SQL ${technique} handled with error`,
            module: moduleName,
          });
        }
      }
    }

    logger.info(
      `✅ SQL injection protection tests completed for ${moduleName}`
    );
    return results;
  }

  /**
   * 🎯 XSS PROTECTION TESTING
   */
  static async testXSSProtection(moduleConfig, moduleName = "") {
    const results = [];
    const endpoint = moduleConfig.Post;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          skipped: true,
          message: `No POST endpoint available for XSS testing in ${moduleName}`,
        },
      ];
    }

    logger.info(`🕷️ Starting XSS protection tests for: ${moduleName}`);

    const xssPayloads = this.generateXSSPayloads();
    const testData = this.getDefaultTestData();

    for (const [vectorType, payloads] of Object.entries(xssPayloads)) {
      for (const [field, xssPayload] of Object.entries(payloads)) {
        try {
          logger.debug(`   Testing XSS ${vectorType} in ${field}`);

          const baseData = testData.getPostData();
          const maliciousData = { ...baseData };

          if (maliciousData[field] !== undefined) {
            maliciousData[field] = xssPayload;
          } else {
            maliciousData[field] = xssPayload;
          }

          const response = await apiClient.post(endpoint[0], maliciousData);

          const isBlocked = [400, 422, 403, 500].includes(response.status);
          const isSanitized = this.checkXSSSanitization(response, xssPayload);

          results.push({
            test: `XSS ${vectorType} - ${field}`,
            expected: "400/422/403 or sanitized content",
            actual: response.status,
            success: isBlocked || isSanitized,
            blocked: isBlocked,
            sanitized: isSanitized,
            payload: xssPayload.substring(0, 50) + "...",
            message: `XSS ${vectorType} should be blocked or sanitized`,
            module: moduleName,
          });
        } catch (error) {
          const status = error.response?.status;
          const isBlocked = [400, 422, 403, 500].includes(status);

          results.push({
            test: `XSS ${vectorType} - ${field}`,
            expected: "400/422/403 or sanitized content",
            actual: status || "Error",
            success: isBlocked,
            blocked: isBlocked,
            sanitized: false,
            payload: xssPayload.substring(0, 50) + "...",
            message: `XSS ${vectorType} handled with error`,
            module: moduleName,
          });
        }
      }
    }

    logger.info(`✅ XSS protection tests completed for ${moduleName}`);
    return results;
  }

  /**
   * 🎯 MALICIOUS PAYLOAD TESTING
   */
  static async testMaliciousPayloads(
    moduleConfig,
    endpointType = "Post",
    moduleName = ""
  ) {
    const results = [];
    const endpoint = moduleConfig[endpointType];

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return [
        {
          skipped: true,
          message: `No ${endpointType} endpoint available for malicious payload testing`,
        },
      ];
    }

    logger.info(`🦠 Starting malicious payload tests for: ${moduleName}`);

    const maliciousPayloads = this.generateMaliciousPayloads();
    const testData = this.getDefaultTestData();

    // SQL Injection Test
    try {
      logger.debug(`   Testing SQL Injection`);
      const sqlData = {
        ...testData.getPostData(),
        ...maliciousPayloads.sqlInjection,
      };
      const sqlResponse = await apiClient.post(endpoint[0], sqlData);

      const sqlSuccess = [400, 422, 500, 403].includes(sqlResponse.status);
      results.push({
        test: "SQL Injection",
        expected: "400/422/500/403",
        actual: sqlResponse.status,
        success: sqlSuccess,
        message: `SQL injection should return 400/422/500/403, got ${sqlResponse.status}`,
        module: moduleName,
        endpointType: endpointType,
      });
    } catch (error) {
      const status = error.response?.status;
      const sqlSuccess = [400, 422, 500, 403].includes(status);
      results.push({
        test: "SQL Injection",
        expected: "400/422/500/403",
        actual: status || "Error",
        success: sqlSuccess,
        message: `SQL injection handled with error`,
        module: moduleName,
        endpointType: endpointType,
      });
    }

    // XSS Injection Test
    try {
      logger.debug(`   Testing XSS Injection`);
      const xssData = { ...testData.getPostData(), ...maliciousPayloads.xss };
      const xssResponse = await apiClient.post(endpoint[0], xssData);

      const xssSuccess = [400, 422, 500, 403].includes(xssResponse.status);
      results.push({
        test: "XSS Injection",
        expected: "400/422/500/403",
        actual: xssResponse.status,
        success: xssSuccess,
        message: `XSS injection should return 400/422/500/403, got ${xssResponse.status}`,
        module: moduleName,
        endpointType: endpointType,
      });
    } catch (error) {
      const status = error.response?.status;
      const xssSuccess = [400, 422, 500, 403].includes(status);
      results.push({
        test: "XSS Injection",
        expected: "400/422/500/403",
        actual: status || "Error",
        success: xssSuccess,
        message: `XSS injection handled with error`,
        module: moduleName,
        endpointType: endpointType,
      });
    }

    logger.info(`✅ Malicious payload tests completed for ${moduleName}`);
    return results;
  }

  /**
   * 🎯 NULL REQUIRED FIELDS VALIDATION
   */
  static async testNullRequiredFields(
    moduleConfig,
    endpointType = "Post",
    moduleName = ""
  ) {
    const endpoint = moduleConfig[endpointType];

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return {
        skipped: true,
        message: `No ${endpointType} endpoint available for null fields testing`,
      };
    }

    logger.info(`📝 Testing null required fields for: ${moduleName}`);

    const testData = this.getDefaultTestData();
    const nullPayload = testData.getNullRequiredFields();

    try {
      const response = await apiClient.post(endpoint[0], nullPayload);

      return {
        expected: 400,
        actual: response.status,
        success: response.status === 400,
        message: `Null required fields should return 400, got ${response.status}`,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const status = error.response?.status;
      return {
        expected: 400,
        actual: status || "Error",
        success: status === 400,
        message: `Null required fields handled with error`,
        module: moduleName,
        endpointType: endpointType,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // ===========================================================================
  // ⚡ PERFORMANCE TESTING
  // ===========================================================================

  /**
   * 🎯 PERFORMANCE UNDER MALICIOUS LOAD TESTING
   */
  static async testPerformanceUnderMaliciousLoad(
    moduleConfig,
    moduleName = ""
  ) {
    const endpoint = moduleConfig.Post;

    if (!endpoint || endpoint[0] === "URL_HERE") {
      return {
        success: false,
        skipped: true,
        message: `No POST endpoint available for performance testing in ${moduleName}`,
      };
    }

    logger.info(
      `⚡ Starting performance under malicious load for: ${moduleName}`
    );

    const performanceMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      totalResponseTime: 0,
      responseTimes: [],
      errorRate: 0,
      throughput: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
    };

    const testData = this.getDefaultTestData();
    const concurrentRequests = 10;
    const requestsPerUser = 5;
    const maliciousPayloads = this.generatePerformanceTestPayloads();

    const startTime = Date.now();
    const promises = [];

    // Generate concurrent requests
    for (let i = 0; i < concurrentRequests; i++) {
      for (let j = 0; j < requestsPerUser; j++) {
        const payloadType =
          Object.keys(maliciousPayloads)[
            j % Object.keys(maliciousPayloads).length
          ];
        const payload = {
          ...testData.getPostData(),
          ...maliciousPayloads[payloadType],
          requestId: `user${i}_req${j}`,
          timestamp: new Date().toISOString(),
        };
        promises.push(this.makeTimedApiCall(endpoint[0], "POST", payload));
      }
    }

    const results = await Promise.allSettled(promises);
    const endTime = Date.now();
    const totalDuration = endTime - startTime;

    // Process results
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

    // Calculate metrics
    performanceMetrics.errorRate =
      (performanceMetrics.failedRequests / performanceMetrics.totalRequests) *
      100;
    performanceMetrics.throughput = (
      performanceMetrics.totalRequests /
      (totalDuration / 1000)
    ).toFixed(2);
    performanceMetrics.averageResponseTime =
      performanceMetrics.responseTimes.length > 0
        ? performanceMetrics.totalResponseTime /
          performanceMetrics.responseTimes.length
        : 0;
    performanceMetrics.p95ResponseTime = this.calculatePercentile(
      performanceMetrics.responseTimes,
      95
    );
    performanceMetrics.p99ResponseTime = this.calculatePercentile(
      performanceMetrics.responseTimes,
      99
    );

    const meetsPerformanceStandards =
      performanceMetrics.averageResponseTime < 2000 &&
      performanceMetrics.errorRate < 5 &&
      performanceMetrics.p95ResponseTime < 3000;

    const performanceResult = {
      success: meetsPerformanceStandards,
      metrics: performanceMetrics,
      thresholds: {
        maxAverageResponseTime: 2000,
        maxErrorRate: 5,
        maxP95ResponseTime: 3000,
      },
      meetsStandards: meetsPerformanceStandards,
      duration: totalDuration,
      timestamp: new Date().toISOString(),
      module: moduleName,
    };

    if (!meetsPerformanceStandards) {
      logger.warn(`⚠️ Performance below standards for ${moduleName}`);
    } else {
      logger.info(`✅ Performance meets standards for ${moduleName}`);
    }

    return performanceResult;
  }

  // ===========================================================================
  // 🎯 SECURITY VALIDATION HELPERS
  // ===========================================================================

  static checkXSSSanitization(response, originalPayload) {
    if (!response.data) return false;
    const responseString = JSON.stringify(response.data).toLowerCase();
    const payloadLower = originalPayload.toLowerCase();

    const dangerousPatterns = [
      "script",
      "javascript:",
      "onerror=",
      "onload=",
      "onmouseover=",
      "expression(",
      "eval(",
      "alert(",
      "document.cookie",
    ];

    const containsPayload = responseString.includes(
      payloadLower.replace(/<script>|javascript:|on\w+=/gi, "")
    );
    const hasDangerousContent = dangerousPatterns.some((pattern) =>
      responseString.includes(pattern)
    );

    return containsPayload && !hasDangerousContent;
  }

  static checkSQLErrorIndicators(response) {
    if (!response.data) return false;
    const responseString = JSON.stringify(response.data).toLowerCase();
    const sqlErrorIndicators = [
      "sql",
      "mysql",
      "database",
      "syntax error",
      "union",
      "select",
      "from",
      "where",
      "oracle",
      "microsoft",
      "odbc",
      "driver",
    ];
    return sqlErrorIndicators.some((indicator) =>
      responseString.includes(indicator)
    );
  }

  // ===========================================================================
  // 🛠️ UTILITY METHODS
  // ===========================================================================

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
   * Sleep utility for delays
   */
  static sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Calculate percentile from array of numbers
   */
  static calculatePercentile(numbers, percentile) {
    if (!numbers || numbers.length === 0) return 0;
    const sorted = [...numbers].sort((a, b) => a - b);
    const index = (percentile / 100) * (sorted.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    if (lower === upper) return sorted[lower];
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
  }

  /**
   * Make timed API call for performance testing
   */
  static async makeTimedApiCall(endpoint, method, data) {
    const startTime = Date.now();
    try {
      const response = await apiClient.post(endpoint, data);
      const responseTime = Date.now() - startTime;
      return {
        success: response.status >= 200 && response.status < 300,
        status: response.status,
        responseTime,
        data: response.data,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        success: false,
        error: error.message,
        responseTime,
        status: error.response?.status,
      };
    }
  }

  // ===========================================================================
  // 📦 PAYLOAD GENERATORS
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
        description:
          "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
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
                  object: Object.fromEntries(
                    new Array(20)
                      .fill(0)
                      .map((_, i) => [`key${i}`, `value${i}`])
                  ),
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
  // 📊 TEST DATA GENERATORS
  // ===========================================================================

  static getDefaultTestData() {
    return {
      getPostData: () => ({
        name: `Test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        description: "API Testing - Auto-generated test data",
        status: "Active",
        code: `TEST-${Date.now()}`,
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
        code: null,
      }),
    };
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
  // 🎯 COMPREHENSIVE TEST SUITES
  // ===========================================================================

  /**
   * 🎯 RUN COMPREHENSIVE SECURITY SUITE
   */
  static async runComprehensiveSecuritySuite(moduleConfig, moduleName = "") {
    const securityResults = {};
    const startTime = Date.now();

    logger.info(`🛡️ Starting comprehensive security suite for: ${moduleName}`);

    try {
      // Run all security tests
      securityResults.authorization = await this.testAuthorizationSecurity(
        moduleConfig,
        moduleName
      );
      securityResults.sqlInjection = await this.testSQLInjectionProtection(
        moduleConfig,
        moduleName
      );
      securityResults.xssProtection = await this.testXSSProtection(
        moduleConfig,
        moduleName
      );
      securityResults.maliciousPost = await this.testMaliciousPayloads(
        moduleConfig,
        "Post",
        moduleName
      );

      if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
        securityResults.maliciousPut = await this.testMaliciousPayloads(
          moduleConfig,
          "PUT",
          moduleName
        );
      }

      securityResults.nullFieldsPost = await this.testNullRequiredFields(
        moduleConfig,
        "Post",
        moduleName
      );

      if (moduleConfig.PUT && moduleConfig.PUT[0] !== "URL_HERE") {
        securityResults.nullFieldsPut = await this.testNullRequiredFields(
          moduleConfig,
          "PUT",
          moduleName
        );
      }

      securityResults.performance =
        await this.testPerformanceUnderMaliciousLoad(moduleConfig, moduleName);

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
        module: moduleName,
      };

      logger.info(`🛡️ Security Suite Completed for ${moduleName}`);
      logger.info(`📊 Overall Security Score: ${overallScore}%`);
      logger.info(
        `🛡️ Security Level: ${securityResults.summary.securityLevel}`
      );
    } catch (error) {
      securityResults.error = error.message;
      logger.error(
        `❌ Security Suite Failed for ${moduleName}: ${error.message}`
      );
    }

    return securityResults;
  }

  // ===========================================================================
  // 📈 SCORING & ANALYTICS
  // ===========================================================================

  static calculateSecurityScore(securityResults) {
    let totalWeight = 0;
    let weightedScore = 0;

    const testCategories = {
      authorization: 0.3,
      sqlInjection: 0.25,
      xssProtection: 0.25,
      maliciousPost: 0.1,
      maliciousPut: 0.05,
      performance: 0.05,
    };

    for (const [category, weight] of Object.entries(testCategories)) {
      if (securityResults[category]) {
        const categoryScore = this.calculateCategoryScore(
          securityResults[category]
        );
        weightedScore += categoryScore * weight;
        totalWeight += weight;
      }
    }

    return totalWeight > 0
      ? Math.round((weightedScore / totalWeight) * 100)
      : 0;
  }

  static calculateCategoryScore(categoryResults) {
    if (!categoryResults || categoryResults.length === 0) return 0;
    const totalTests = categoryResults.length;
    const passedTests = categoryResults.filter(
      (test) => test.success || test.skipped
    ).length;
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
      .reduce(
        (total, tests) => total + tests.filter((test) => test.success).length,
        0
      );
  }

  static countFailedTests(securityResults) {
    return Object.values(securityResults)
      .filter(Array.isArray)
      .reduce(
        (total, tests) =>
          total + tests.filter((test) => !test.success && !test.skipped).length,
        0
      );
  }

  static getSecurityLevel(score) {
    if (score >= 90) return "EXCELLENT";
    if (score >= 80) return "GOOD";
    if (score >= 70) return "FAIR";
    if (score >= 60) return "POOR";
    return "CRITICAL";
  }

  // ===========================================================================
  // 🔧 URL MANIPULATION
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
    return cleanBaseUrl.endsWith("/")
      ? `${cleanBaseUrl}${id}`
      : `${cleanBaseUrl}/${id}`;
  }

  // ===========================================================================
  // ✅ RESPONSE VALIDATION
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
    try {
      if (!response) {
        throw new Error("Response is undefined or null");
      }

      if (typeof response !== "object") {
        throw new Error(`Response is not an object, got: ${typeof response}`);
      }

      const validationResult = this.validateResponseSuccess(response);

      if (!validationResult.httpStatusValid) {
        throw new Error(
          `HTTP status code ${response.status} is not in success range (200-399)`
        );
      }

      if (!validationResult.responseStatusValid) {
        throw new Error(
          "Response contains status: 400 which indicates failure"
        );
      }

      // Handle both object and primitive data responses
      if (response.data !== undefined) {
        const dataType = typeof response.data;
        if (dataType === "object") {
          expectedFields.forEach((field) => {
            if (response.data && !response.data[field]) {
              logger.warn(
                `Expected field '${field}' not found in response data`
              );
            }
          });
        } else {
          logger.info(
            `Response data is primitive type: ${dataType}, value: ${response.data}`
          );
        }
      }

      return validationResult.overallValid;
    } catch (error) {
      logger.error(`Response validation failed: ${error.message}`);
      throw error;
    }
  }
}

module.exports = TestHelpers;
