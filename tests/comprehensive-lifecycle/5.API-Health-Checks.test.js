// tests/comprehensive-lifecycle/5.API-Health-Checks.test.js
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const Constants = require("../../Constants");
const fs = require("fs");
const path = require("path");

const { TEST_CONFIG, HTTP_STATUS_CODES, FILE_PATHS } = Constants;

/**
 * API ENDPOINT HEALTH CHECKS
 *
 * Professional health monitoring for all backend API endpoints
 * Purpose: Verify connectivity, response times, and basic functionality
 *
 * @version 3.0.0
 * @author Mohamed Said Ibrahim
 */

describe("API Endpoint Health Checks", () => {
  let allEndpoints = [];
  let healthCheckResults = [];
  let testSummary = {
    totalEndpoints: 0,
    testedEndpoints: 0,
    healthyEndpoints: 0,
    unhealthyEndpoints: 0,
    skippedEndpoints: 0,
    averageResponseTime: 0,
    startTime: null,
    endTime: null,
  };

  // Enhanced URL validation
  const isValidUrl = (string) => {
    if (!string || typeof string !== "string") return false;
    if (string === "URL_HERE" || string.trim() === "") return false;
    if (string.includes("<createdId>")) return false; // Skip endpoints requiring dynamic IDs

    try {
      const url = new URL(string);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) {
      return false;
    }
  };

  // Map operation to HTTP method
  const getHttpMethod = (operation) => {
    const methodMap = {
      Post: "POST",
      PUT: "PUT",
      DELETE: "DELETE",
      View: "GET",
      GET: "GET",
      EDIT: "PUT",
      LookUP: "GET",
      Commit: "POST",
    };
    return methodMap[operation] || "GET";
  };

  // PROFESSIONAL SCHEMA PROCESSING - Fixed traversal logic
  const extractEndpointsFromSchema = (schema) => {
    const endpoints = [];
    let endpointCount = 0;

    logger.info("🔄 Starting schema traversal...");

    const traverse = (obj, path = []) => {
      if (!obj || typeof obj !== "object") return;

      // Check if current object has HTTP operations
      const httpOperations = [
        "Post",
        "PUT",
        "DELETE",
        "View",
        "GET",
        "EDIT",
        "LookUP",
        "Commit",
      ];
      const hasOperations = httpOperations.some((op) => obj[op]);

      if (hasOperations) {
        // Process each HTTP operation in this module
        httpOperations.forEach((operation) => {
          if (
            obj[operation] &&
            Array.isArray(obj[operation]) &&
            obj[operation][0]
          ) {
            const endpointUrl = obj[operation][0];

            if (isValidUrl(endpointUrl)) {
              const modulePath = path.join(".") || "Root";
              endpointCount++;

              endpoints.push({
                url: endpointUrl,
                method: getHttpMethod(operation),
                operation: operation,
                module: modulePath,
                fullPath: `${modulePath}.${operation}`,
                payload: obj[operation][1] || null,
                requiresAuth: true,
                testId: `endpoint-${endpointCount}`,
              });

              logger.debug(`📍 Found endpoint: ${operation} - ${endpointUrl}`);
            }
          }
        });
      }

      // Recursively traverse all properties
      Object.keys(obj).forEach((key) => {
        const value = obj[key];
        if (value && typeof value === "object" && !Array.isArray(value)) {
          traverse(value, [...path, key]);
        }
      });
    };

    traverse(schema);
    logger.info(
      `✅ Schema traversal complete. Found ${endpoints.length} valid endpoints`
    );
    return endpoints;
  };

  // Load schema from file
  const loadSchema = () => {
    try {
      const schemaPath = path.resolve(
        process.cwd(),
        "test-data/Input/JL-Backend-Api-Schema.json"
      );

      if (!fs.existsSync(schemaPath)) {
        throw new Error(`Schema file not found at: ${schemaPath}`);
      }

      logger.info(`📁 Loading schema from: ${schemaPath}`);
      const schemaData = fs.readFileSync(schemaPath, "utf8");
      const schema = JSON.parse(schemaData);

      logger.info("✅ Schema loaded successfully");
      return schema;
    } catch (error) {
      logger.error(`❌ Failed to load schema: ${error.message}`);
      throw error;
    }
  };

  // Enhanced health check for a single endpoint
  const testEndpointHealth = async (endpoint) => {
    const startTime = Date.now();
    let responseTime = 0;
    let status = "unknown";
    let statusCode = 0;
    let error = null;
    let responseData = null;

    try {
      let response;

      // Choose appropriate HTTP method and handle payload
      switch (endpoint.method) {
        case "POST":
          // For POST requests, use a minimal payload or the configured one
          const payload = endpoint.payload || {
            test: true,
            timestamp: new Date().toISOString(),
          };
          response = await apiClient.post(endpoint.url, payload);
          break;

        case "PUT":
          // For PUT requests, use minimal update data
          const updatePayload = endpoint.payload || {
            id: "test-id",
            description: "Health check test",
            timestamp: new Date().toISOString(),
          };
          response = await apiClient.put(endpoint.url, updatePayload);
          break;

        case "DELETE":
          // For DELETE, append /test to avoid deleting real data
          const safeDeleteUrl =
            endpoint.url + (endpoint.url.endsWith("/") ? "test" : "/test");
          response = await apiClient.delete(safeDeleteUrl);
          break;

        default:
          // GET requests
          response = await apiClient.get(endpoint.url);
      }

      responseTime = Date.now() - startTime;
      statusCode = response.status;
      responseData = response.data;

      // Enhanced status classification
      if (response.status >= 200 && response.status < 300) {
        status = "healthy";
      } else if (response.status === 401 || response.status === 403) {
        status = "auth_required"; // Endpoint exists but needs authentication
      } else if (response.status === 404) {
        status = "not_found";
      } else if (response.status === 405) {
        status = "method_not_allowed";
      } else if (response.status >= 400 && response.status < 500) {
        status = "client_error";
      } else if (response.status >= 500) {
        status = "server_error";
      } else {
        status = "unknown_status";
      }
    } catch (err) {
      responseTime = Date.now() - startTime;
      error = err.message;
      responseData = err.response?.data;

      // Enhanced error classification
      if (err.response) {
        statusCode = err.response.status;
        if (err.response.status === 401 || err.response.status === 403) {
          status = "auth_required";
        } else if (err.response.status === 404) {
          status = "not_found";
        } else if (err.response.status === 405) {
          status = "method_not_allowed";
        } else if (err.response.status === 400) {
          status = "bad_request"; // Often means endpoint exists but validation failed
        } else {
          status = "http_error";
        }
      } else if (err.code === "ECONNREFUSED") {
        status = "connection_refused";
      } else if (err.code === "ETIMEDOUT") {
        status = "timeout";
      } else if (err.code === "ENOTFOUND") {
        status = "dns_error";
      } else {
        status = "network_error";
      }
    }

    const result = {
      ...endpoint,
      responseTime,
      status,
      statusCode,
      error,
      responseData: responseData
        ? JSON.stringify(responseData).substring(0, 200) + "..."
        : null,
      timestamp: new Date().toISOString(),
    };

    // Log result for monitoring
    const statusIcon =
      status === "healthy" ? "✅" : status === "auth_required" ? "🔐" : "❌";

    logger.info(
      `${statusIcon} ${endpoint.method} ${endpoint.url} - ${status} (${responseTime}ms)`
    );

    return result;
  };

  // Batch processing with progress tracking
  const processEndpointsBatch = async (endpoints, batchSize = 3) => {
    const results = [];
    const totalBatches = Math.ceil(endpoints.length / batchSize);

    logger.info(
      `🔄 Processing ${endpoints.length} endpoints in batches of ${batchSize}`
    );

    for (let batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
      const startIndex = batchIndex * batchSize;
      const endIndex = Math.min(startIndex + batchSize, endpoints.length);
      const batch = endpoints.slice(startIndex, endIndex);

      logger.info(
        `📦 Processing batch ${batchIndex + 1}/${totalBatches} (${
          batch.length
        } endpoints)`
      );

      const batchPromises = batch.map((endpoint, index) => {
        const endpointNumber = startIndex + index + 1;
        logger.debug(
          `   ${endpointNumber}/${endpoints.length}: ${endpoint.method} ${endpoint.url}`
        );
        return testEndpointHealth(endpoint);
      });

      const batchResults = await Promise.allSettled(batchPromises);

      // Process batch results
      batchResults.forEach((result, index) => {
        if (result.status === "fulfilled") {
          results.push(result.value);
        } else {
          const failedEndpoint = batch[index];
          logger.error(
            `   ❌ Failed to test ${failedEndpoint.url}: ${result.reason.message}`
          );

          results.push({
            ...failedEndpoint,
            responseTime: 0,
            status: "test_error",
            statusCode: 0,
            error: result.reason.message,
            timestamp: new Date().toISOString(),
          });
        }
      });

      // Progress update
      const completed = results.length;
      const progress = Math.round((completed / endpoints.length) * 100);
      logger.info(
        `   📊 Progress: ${completed}/${endpoints.length} (${progress}%)`
      );

      // Rate limiting - wait between batches
      if (batchIndex < totalBatches - 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    return results;
  };

  // Suite setup - runs before all tests
  beforeAll(async () => {
    testSummary.startTime = new Date().toISOString();
    logger.info("🚀 Starting Comprehensive API Endpoint Health Checks");
    logger.info("=".repeat(60));

    try {
      // Load and process schema
      const schema = loadSchema();
      allEndpoints = extractEndpointsFromSchema(schema);
      testSummary.totalEndpoints = allEndpoints.length;

      if (allEndpoints.length === 0) {
        logger.warn(
          "⚠️ No endpoints found in schema. Checking schema structure..."
        );

        // Debug: Log schema structure to understand the issue
        logger.debug(
          "Schema structure sample:",
          JSON.stringify(schema, null, 2).substring(0, 500)
        );
        return;
      }

      logger.info(`🎯 Found ${allEndpoints.length} endpoints to test`);

      // Log endpoint categories for overview
      const categories = {};
      allEndpoints.forEach((ep) => {
        const category = ep.module.split(".")[0] || "Other";
        categories[category] = (categories[category] || 0) + 1;
      });

      logger.info("📋 Endpoint Categories:");
      Object.entries(categories).forEach(([category, count]) => {
        logger.info(`   - ${category}: ${count} endpoints`);
      });

      // Process all endpoints
      healthCheckResults = await processEndpointsBatch(allEndpoints);
      testSummary.testedEndpoints = healthCheckResults.length;

      // Calculate comprehensive statistics
      const healthyResults = healthCheckResults.filter((r) =>
        ["healthy", "auth_required", "bad_request"].includes(r.status)
      );

      testSummary.healthyEndpoints = healthyResults.length;
      testSummary.unhealthyEndpoints =
        healthCheckResults.length - healthyResults.length;

      // Calculate average response time from successful requests
      const successfulRequests = healthCheckResults.filter(
        (r) =>
          r.responseTime > 0 &&
          !["connection_refused", "timeout", "dns_error"].includes(r.status)
      );

      if (successfulRequests.length > 0) {
        const totalResponseTime = successfulRequests.reduce(
          (sum, r) => sum + r.responseTime,
          0
        );
        testSummary.averageResponseTime = Math.round(
          totalResponseTime / successfulRequests.length
        );
      }

      logger.info("✅ Health check processing completed");
    } catch (error) {
      logger.error(`💥 Critical error in health check setup: ${error.message}`);
      throw error;
    }
  });

  // Suite teardown - runs after all tests
  afterAll(() => {
    testSummary.endTime = new Date().toISOString();

    // Generate comprehensive health report
    logger.info("📈 HEALTH CHECK EXECUTION SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`   Total Endpoints: ${testSummary.totalEndpoints}`);
    logger.info(`   Tested Endpoints: ${testSummary.testedEndpoints}`);
    logger.info(`   ✅ Healthy: ${testSummary.healthyEndpoints}`);
    logger.info(`   ❌ Unhealthy: ${testSummary.unhealthyEndpoints}`);
    logger.info(
      `   📊 Success Rate: ${
        testSummary.totalEndpoints > 0
          ? Math.round(
              (testSummary.healthyEndpoints / testSummary.totalEndpoints) * 100
            )
          : 0
      }%`
    );
    logger.info(
      `   ⏱️ Average Response Time: ${testSummary.averageResponseTime}ms`
    );
    logger.info("=".repeat(50));

    // Detailed status breakdown
    const statusBreakdown = healthCheckResults.reduce((acc, result) => {
      acc[result.status] = (acc[result.status] || 0) + 1;
      return acc;
    }, {});

    logger.info("📋 Detailed Status Breakdown:");
    Object.entries(statusBreakdown)
      .sort(([, a], [, b]) => b - a)
      .forEach(([status, count]) => {
        const percentage = Math.round(
          (count / healthCheckResults.length) * 100
        );
        const icon =
          status === "healthy"
            ? "✅"
            : status === "auth_required"
            ? "🔐"
            : status === "bad_request"
            ? "⚠️"
            : "❌";
        logger.info(`   ${icon} ${status}: ${count} (${percentage}%)`);
      });

    // Top 5 slowest endpoints
    const slowEndpoints = healthCheckResults
      .filter((r) => r.responseTime > 0)
      .sort((a, b) => b.responseTime - a.responseTime)
      .slice(0, 5);

    if (slowEndpoints.length > 0) {
      logger.info("🐌 Top 5 Slowest Endpoints:");
      slowEndpoints.forEach((ep, index) => {
        logger.info(
          `   ${index + 1}. ${ep.responseTime}ms - ${ep.method} ${ep.url}`
        );
      });
    }

    logger.info(`🏁 Health checks completed at ${testSummary.endTime}`);
  });

  // =========================================================================
  // TEST CASES
  // =========================================================================

  test("Should discover and test all endpoints from schema", () => {
    logger.info(`🔍 Schema Analysis:`);
    logger.info(`   - Endpoints discovered: ${allEndpoints.length}`);
    logger.info(`   - Endpoints tested: ${healthCheckResults.length}`);

    // Critical: We must find endpoints in the schema
    expect(allEndpoints.length).toBeGreaterThan(0);

    if (allEndpoints.length === 0) {
      logger.error("❌ CRITICAL: No endpoints found in schema. Check:");
      logger.error("   1. Schema file exists and is valid JSON");
      logger.error(
        "   2. Schema has the expected structure with HTTP operations"
      );
      logger.error("   3. Endpoints have valid URLs (not 'URL_HERE')");
      return;
    }

    // We should test all discovered endpoints
    expect(healthCheckResults.length).toBe(allEndpoints.length);

    logger.info(`✅ Endpoint discovery and testing validated`);
  });

  test("Should have healthy endpoints with reasonable response times", () => {
    const healthyEndpoints = healthCheckResults.filter((r) =>
      ["healthy", "auth_required", "bad_request"].includes(r.status)
    );

    const trulyHealthy = healthCheckResults.filter(
      (r) => r.status === "healthy"
    );

    logger.info(`📊 Health Analysis:`);
    logger.info(`   - Total endpoints: ${healthCheckResults.length}`);
    logger.info(`   - Healthy/Accessible: ${healthyEndpoints.length}`);
    logger.info(`   - Truly healthy (2xx): ${trulyHealthy.length}`);

    // At least some endpoints should be accessible
    expect(healthyEndpoints.length).toBeGreaterThan(0);

    if (healthyEndpoints.length === 0) {
      logger.warn("⚠️ No healthy endpoints found. Possible issues:");
      logger.warn("   - Network connectivity problems");
      logger.warn("   - API server is down");
      logger.warn("   - Authentication tokens expired");
      logger.warn("   - Endpoint URLs are incorrect");

      // Log first few errors for debugging
      const errors = healthCheckResults.slice(0, 3);
      errors.forEach((result) => {
        logger.warn(
          `   - ${result.url}: ${result.status} (${
            result.error || "No details"
          })`
        );
      });
    }

    // Check response times for healthy endpoints
    const reasonableResponseTimes = healthyEndpoints.filter(
      (r) => r.responseTime < 10000 // 10 seconds max
    );

    expect(reasonableResponseTimes.length).toBeGreaterThan(0);

    if (reasonableResponseTimes.length < healthyEndpoints.length) {
      logger.warn(
        `⚠️ ${
          healthyEndpoints.length - reasonableResponseTimes.length
        } endpoints have slow response times`
      );
    }

    logger.info(`✅ Health status validated`);
  });

  test("Should generate comprehensive health check summary", () => {
    // Validate summary data structure and integrity
    expect(testSummary.totalEndpoints).toBe(allEndpoints.length);
    expect(testSummary.testedEndpoints).toBe(healthCheckResults.length);
    expect(testSummary.healthyEndpoints).toBeLessThanOrEqual(
      testSummary.testedEndpoints
    );
    expect(testSummary.unhealthyEndpoints).toBeLessThanOrEqual(
      testSummary.testedEndpoints
    );
    expect(testSummary.averageResponseTime).toBeGreaterThanOrEqual(0);

    // All endpoints should have results
    expect(healthCheckResults).toHaveLength(allEndpoints.length);

    // Results should have required properties
    healthCheckResults.forEach((result) => {
      expect(result).toHaveProperty("url");
      expect(result).toHaveProperty("status");
      expect(result).toHaveProperty("responseTime");
      expect(result).toHaveProperty("timestamp");
    });

    logger.info("✅ Health check summary validated successfully");
  });

  test("Should validate endpoint configurations", () => {
    const invalidEndpoints = allEndpoints.filter((ep) => !isValidUrl(ep.url));

    if (invalidEndpoints.length > 0) {
      logger.warn(
        `⚠️ Found ${invalidEndpoints.length} endpoints with invalid URLs:`
      );
      invalidEndpoints.slice(0, 5).forEach((ep) => {
        logger.warn(`   - ${ep.url} (${ep.module})`);
      });
    }

    expect(invalidEndpoints.length).toBe(0);

    // Validate HTTP methods are correctly mapped
    const validMethods = ["GET", "POST", "PUT", "DELETE"];
    const invalidMethods = allEndpoints.filter(
      (ep) => !validMethods.includes(ep.method)
    );

    expect(invalidMethods.length).toBe(0);

    logger.info("✅ Endpoint configuration validation passed");
  });
});
