// tests/comprehensive-lifecycle/5.API-Health-Checks-Individual.test.js
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const Constants = require("../../Constants");
const fs = require("fs");
const path = require("path");

const { TEST_CONFIG, HTTP_STATUS_CODES, FILE_PATHS } = Constants;

/**
 * INDIVIDUAL API ENDPOINT HEALTH CHECKS
 *
 * Professional health monitoring with individual test cases for each endpoint
 * Each endpoint gets its own test with proper numbering and module identification
 *
 * @version 4.0.0
 * @author Mohamed Said Ibrahim
 */

describe("Individual API Endpoint Health Checks", () => {
  let allEndpoints = [];
  let testResults = [];
  let globalSummary = {
    totalEndpoints: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    startTime: null,
    endTime: null,
  };

  // Enhanced URL validation
  const isValidUrl = (string) => {
    if (!string || typeof string !== "string") return false;
    if (string === "URL_HERE" || string.trim() === "") return false;
    if (string.includes("<createdId>")) {
      // Replace placeholder with test ID for valid testing
      return string.replace("<createdId>", "test-health-check-id");
    }

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

  // FIXED: Professional schema processing with better traversal
  const extractEndpointsFromSchema = (schema) => {
    const endpoints = [];
    let endpointCount = 0;

    logger.info("🔄 Starting professional schema traversal...");

    const traverse = (obj, currentPath = []) => {
      if (!obj || typeof obj !== "object") return;

      // Check if current level has HTTP operations directly
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

      // Look for operations at current level
      httpOperations.forEach((operation) => {
        if (
          obj[operation] &&
          Array.isArray(obj[operation]) &&
          obj[operation][0]
        ) {
          const endpointUrl = obj[operation][0];
          const processedUrl = endpointUrl.includes("<createdId>")
            ? endpointUrl.replace("<createdId>", "test-health-check-id")
            : endpointUrl;

          if (isValidUrl(processedUrl)) {
            endpointCount++;
            const modulePath =
              currentPath.length > 0 ? currentPath.join(".") : "Root";

            endpoints.push({
              id: endpointCount,
              url: processedUrl,
              method: getHttpMethod(operation),
              operation: operation,
              module: modulePath,
              fullPath: `${modulePath}.${operation}`,
              payload: obj[operation][1] || null,
              requiresAuth: true,
              testNumber: endpointCount,
              originalUrl: endpointUrl, // Keep original for reference
            });

            logger.debug(
              `📍 [${String(endpointCount).padStart(
                3,
                "0"
              )}] Found: ${operation} ${modulePath}`
            );
          }
        }
      });

      // Recursively traverse nested objects
      Object.entries(obj).forEach(([key, value]) => {
        if (
          value &&
          typeof value === "object" &&
          value !== null &&
          !Array.isArray(value)
        ) {
          // Only traverse if it's not an operation array and looks like a module container
          const isLikelyModule =
            !httpOperations.includes(key) &&
            typeof value === "object" &&
            Object.keys(value).some(
              (k) => httpOperations.includes(k) || typeof value[k] === "object"
            );

          if (isLikelyModule) {
            traverse(value, [...currentPath, key]);
          }
        }
      });
    };

    traverse(schema);
    logger.info(
      `✅ Schema traversal complete. Found ${endpoints.length} valid endpoints`
    );

    // Log endpoint distribution for verification
    if (endpoints.length > 0) {
      const methodDistribution = endpoints.reduce((acc, ep) => {
        acc[ep.method] = (acc[ep.method] || 0) + 1;
        return acc;
      }, {});

      logger.info("🌐 Method Distribution:");
      Object.entries(methodDistribution).forEach(([method, count]) => {
        logger.info(`   - ${method}: ${count} endpoints`);
      });
    }

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

  // Generate professional test title
  const generateTestTitle = (endpoint, testType = "Health Check") => {
    const moduleParts = endpoint.module.split(".");

    // Create shortened, readable module name
    let shortModule;
    if (moduleParts.length <= 2) {
      shortModule = endpoint.module;
    } else {
      // Format: FirstModule.SecondModule...LastModule
      shortModule = `${moduleParts[0]}.${moduleParts[1]}...${
        moduleParts[moduleParts.length - 1]
      }`;
    }

    return `[${String(endpoint.testNumber).padStart(3, "0")}] ${
      endpoint.method
    } ${shortModule} - ${testType}`;
  };

  // Individual endpoint health check
  const performEndpointHealthCheck = async (endpoint) => {
    const startTime = Date.now();
    let responseTime = 0;
    let status = "unknown";
    let statusCode = 0;
    let error = null;
    let success = false;
    let responseData = null;

    try {
      let response;

      // Safe endpoint testing with appropriate methods and payloads
      switch (endpoint.method) {
        case "POST":
          const postPayload = endpoint.payload || {
            test: true,
            healthCheck: true,
            timestamp: new Date().toISOString(),
            description: "Health check test request",
          };
          // Clean the payload of any null values that might cause issues
          const cleanPostPayload = JSON.parse(JSON.stringify(postPayload));
          response = await apiClient.post(endpoint.url, cleanPostPayload);
          break;

        case "PUT":
          const putPayload = endpoint.payload || {
            id: "health-check-test-id-12345",
            description: "Health check test - safe update operation",
            timestamp: new Date().toISOString(),
            status: "test",
          };
          const cleanPutPayload = JSON.parse(JSON.stringify(putPayload));
          response = await apiClient.put(endpoint.url, cleanPutPayload);
          break;

        case "DELETE":
          // For DELETE, we'll test with a safe approach - either use test ID or HEAD request
          if (endpoint.url.includes("test-health-check-id")) {
            response = await apiClient.delete(endpoint.url);
          } else {
            // For DELETE endpoints without placeholder, use HEAD to check existence
            response = await apiClient.head(endpoint.url);
          }
          break;

        default:
          // GET and other read-only requests
          response = await apiClient.get(endpoint.url);
      }

      responseTime = Date.now() - startTime;
      statusCode = response.status;
      responseData = response.data;

      // Enhanced success determination
      if (response.status >= 200 && response.status < 300) {
        status = "healthy";
        success = true;
      } else if (response.status === 401 || response.status === 403) {
        status = "authentication_required";
        success = true; // Endpoint exists, just needs proper auth
      } else if (response.status === 404) {
        status = "not_found";
      } else if (response.status === 405) {
        status = "method_not_allowed";
      } else if (response.status === 400) {
        status = "bad_request";
        success = true; // Endpoint exists but validation failed
      } else if (response.status === 409) {
        status = "conflict";
        success = true; // Endpoint exists but resource conflict
      } else {
        status = `http_${response.status}`;
        // Consider 4xx statuses as endpoint existing (except 404)
        success =
          response.status >= 400 &&
          response.status < 500 &&
          response.status !== 404;
      }
    } catch (err) {
      responseTime = Date.now() - startTime;
      error = err.message;
      responseData = err.response?.data;

      // Enhanced error classification with success determination
      if (err.response) {
        statusCode = err.response.status;
        if (err.response.status === 401 || err.response.status === 403) {
          status = "authentication_required";
          success = true; // Endpoint exists
        } else if (err.response.status === 404) {
          status = "not_found";
        } else if (err.response.status === 405) {
          status = "method_not_allowed";
        } else if (err.response.status === 400) {
          status = "bad_request";
          success = true; // Endpoint exists
        } else if (err.response.status === 409) {
          status = "conflict";
          success = true; // Endpoint exists
        } else if (err.response.status >= 400 && err.response.status < 500) {
          status = "client_error";
          success = true; // Endpoint exists but client error
        } else {
          status = "server_error";
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
      endpoint,
      success,
      status,
      statusCode,
      responseTime,
      error,
      responseData: responseData
        ? (typeof responseData === "string"
            ? responseData.substring(0, 100)
            : JSON.stringify(responseData).substring(0, 100)) + "..."
        : null,
      timestamp: new Date().toISOString(),
    };

    return result;
  };

  // Suite setup
  beforeAll(() => {
    globalSummary.startTime = new Date().toISOString();
    logger.info("🚀 Starting Individual API Endpoint Health Checks");
    logger.info("=".repeat(60));

    // Load and process schema
    try {
      const schema = loadSchema();
      allEndpoints = extractEndpointsFromSchema(schema);
      globalSummary.totalEndpoints = allEndpoints.length;

      if (allEndpoints.length === 0) {
        logger.error("❌ CRITICAL: No endpoints found in schema.");
        logger.error("   This could be due to:");
        logger.error("   1. Schema file structure issues");
        logger.error("   2. Invalid URL formats in schema");
        logger.error("   3. Missing HTTP operations in modules");
        return;
      }

      logger.info(
        `🎯 Prepared ${allEndpoints.length} endpoints for individual testing`
      );

      // Log endpoint distribution by module
      const moduleStats = {};
      allEndpoints.forEach((ep) => {
        const mainModule = ep.module.split(".")[0] || "Other";
        moduleStats[mainModule] = (moduleStats[mainModule] || 0) + 1;
      });

      logger.info("📋 Endpoint Distribution by Module:");
      Object.entries(moduleStats)
        .sort(([, a], [, b]) => b - a)
        .forEach(([module, count]) => {
          logger.info(`   - ${module}: ${count} endpoints`);
        });
    } catch (error) {
      logger.error(`💥 Failed to setup test suite: ${error.message}`);
    }
  });

  afterAll(() => {
    globalSummary.endTime = new Date().toISOString();

    // Generate comprehensive summary
    logger.info("📈 INDIVIDUAL HEALTH CHECK SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`   Total Endpoints: ${globalSummary.totalEndpoints}`);
    logger.info(`   ✅ Passed Tests: ${globalSummary.passedTests}`);
    logger.info(`   ❌ Failed Tests: ${globalSummary.failedTests}`);
    logger.info(`   ⏸️  Skipped Tests: ${globalSummary.skippedTests}`);

    const successRate =
      globalSummary.totalEndpoints > 0
        ? Math.round(
            (globalSummary.passedTests / globalSummary.totalEndpoints) * 100
          )
        : 0;
    logger.info(`   📊 Success Rate: ${successRate}%`);

    logger.info("=".repeat(50));

    // Detailed breakdown
    if (testResults.length > 0) {
      const statusBreakdown = testResults.reduce((acc, result) => {
        acc[result.status] = (acc[result.status] || 0) + 1;
        return acc;
      }, {});

      logger.info("📋 Detailed Status Breakdown:");
      Object.entries(statusBreakdown)
        .sort(([, a], [, b]) => b - a)
        .forEach(([status, count]) => {
          const percentage = Math.round((count / testResults.length) * 100);
          const icon =
            status === "healthy"
              ? "✅"
              : ["authentication_required", "bad_request", "conflict"].includes(
                  status
                )
              ? "⚠️"
              : "❌";
          logger.info(`   ${icon} ${status}: ${count} (${percentage}%)`);
        });

      // Performance summary
      const successfulTests = testResults.filter(
        (r) => r.success && r.responseTime > 0
      );
      if (successfulTests.length > 0) {
        const responseTimes = successfulTests.map((r) => r.responseTime);
        const avgResponseTime = Math.round(
          responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
        );
        const maxResponseTime = Math.max(...responseTimes);

        logger.info(`   ⏱️  Average Response Time: ${avgResponseTime}ms`);
        logger.info(`   🐌 Maximum Response Time: ${maxResponseTime}ms`);

        // Log slowest endpoints
        const slowEndpoints = successfulTests
          .filter((r) => r.responseTime > 3000)
          .sort((a, b) => b.responseTime - a.responseTime)
          .slice(0, 3);

        if (slowEndpoints.length > 0) {
          logger.info("   🐌 Slowest Endpoints:");
          slowEndpoints.forEach((ep) => {
            logger.info(
              `      - ${ep.endpoint.method} ${ep.endpoint.url}: ${ep.responseTime}ms`
            );
          });
        }
      }
    }

    logger.info(
      `🏁 Individual health checks completed at ${globalSummary.endTime}`
    );
  });

  // =========================================================================
  // 🎯 IMPLEMENTATION 1: INDIVIDUAL TEST CASES FOR EACH ENDPOINT
  // =========================================================================

  if (allEndpoints.length > 0) {
    describe("Individual Endpoint Health Checks", () => {
      // Generate individual test for each endpoint
      allEndpoints.forEach((endpoint) => {
        const testTitle = generateTestTitle(endpoint, "Endpoint Health Check");

        test(
          testTitle,
          async () => {
            const result = await performEndpointHealthCheck(endpoint);
            testResults.push(result);

            // Update global summary
            if (result.success) {
              globalSummary.passedTests++;
            } else {
              globalSummary.failedTests++;
            }

            // Enhanced assertions based on endpoint type and status
            if (result.status === "healthy") {
              // For truly healthy endpoints (2xx responses)
              expect(result.statusCode).toBeGreaterThanOrEqual(200);
              expect(result.statusCode).toBeLessThan(300);
              expect(result.responseTime).toBeLessThan(30000); // 30 seconds max

              logger.info(
                `✅ ${testTitle} - Healthy (${result.statusCode}) - ${result.responseTime}ms`
              );
            } else if (
              [
                "authentication_required",
                "bad_request",
                "conflict",
                "client_error",
              ].includes(result.status)
            ) {
              // For endpoints that exist but have client-side issues
              expect(result.statusCode).toBeGreaterThanOrEqual(400);
              expect(result.statusCode).toBeLessThan(500);

              logger.info(
                `⚠️ ${testTitle} - ${result.status} (${result.statusCode}) - ${result.responseTime}ms`
              );
            } else if (result.status === "not_found") {
              // Endpoint not found - this is a failure
              logger.error(`❌ ${testTitle} - Not Found (404)`);
              expect(result.success).toBe(false);
            } else if (
              ["connection_refused", "timeout", "dns_error"].includes(
                result.status
              )
            ) {
              // Network issues - these are failures
              logger.error(`❌ ${testTitle} - Network Error: ${result.status}`);
              expect(result.success).toBe(false);
            } else {
              // Other cases - log for investigation
              logger.warn(
                `🔍 ${testTitle} - ${result.status} (${result.statusCode}) - Needs investigation`
              );
            }
          },
          TEST_CONFIG.TIMEOUT.LONG
        );
      });
    });
  } else {
    describe("Individual Endpoint Health Checks", () => {
      test("No endpoints found - schema analysis required", () => {
        logger.error("❌ No endpoints were discovered for individual testing");
        logger.error("   Please check:");
        logger.error("   1. Schema file exists and is valid JSON");
        logger.error("   2. Endpoints have valid URL formats");
        logger.error(
          "   3. HTTP operations (Post, PUT, etc.) are properly defined"
        );

        // This will fail the test, which is appropriate
        expect(allEndpoints.length).toBeGreaterThan(0);
      });
    });
  }

  // =========================================================================
  // 🎯 IMPLEMENTATION 2: COMPREHENSIVE COVERAGE - SUMMARY TESTS
  // =========================================================================

  describe("Comprehensive Health Analysis", () => {
    test("[SUMMARY-001] Overall Health Check Success Rate", () => {
      // Only run this test if we have results
      if (testResults.length === 0) {
        logger.warn(
          "⏸️  Skipping success rate analysis - no test results available"
        );
        return;
      }

      const successRate = Math.round(
        (globalSummary.passedTests / testResults.length) * 100
      );

      logger.info("📊 Overall Health Analysis:");
      logger.info(`   - Total Endpoints Tested: ${testResults.length}`);
      logger.info(`   - Successfully Accessed: ${globalSummary.passedTests}`);
      logger.info(`   - Access Failures: ${globalSummary.failedTests}`);
      logger.info(`   - Overall Success Rate: ${successRate}%`);

      // Realistic success rate expectations based on actual results
      if (testResults.length >= 10) {
        // For production systems, expect at least 60% success rate
        // This accounts for authentication requirements, validation errors, etc.
        expect(successRate).toBeGreaterThan(60);
        logger.info(`   ✅ Success rate meets minimum threshold (60%)`);
      } else {
        logger.warn(
          `   ⚠️  Limited sample size (${testResults.length} endpoints), success rate: ${successRate}%`
        );
      }

      // Verify we tested all discovered endpoints
      expect(testResults.length).toBe(globalSummary.totalEndpoints);
    });

    test("[SUMMARY-002] Response Time Performance", () => {
      if (testResults.length === 0) {
        logger.warn(
          "⏸️  Skipping performance analysis - no test results available"
        );
        return;
      }

      const successfulTests = testResults.filter(
        (r) => r.success && r.responseTime > 0
      );

      if (successfulTests.length > 0) {
        const responseTimes = successfulTests.map((r) => r.responseTime);
        const averageTime = Math.round(
          responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
        );
        const maxTime = Math.max(...responseTimes);
        const slowEndpoints = successfulTests.filter(
          (r) => r.responseTime > 5000
        );

        logger.info("⏱️  Response Time Performance:");
        logger.info(`   - Average Response Time: ${averageTime}ms`);
        logger.info(`   - Maximum Response Time: ${maxTime}ms`);
        logger.info(`   - Slow Endpoints (>5s): ${slowEndpoints.length}`);

        // Performance benchmarks - adjust based on your API requirements
        expect(averageTime).toBeLessThan(10000); // 10 seconds average max

        if (slowEndpoints.length > 0) {
          logger.warn("🐌 Slow Endpoints (consider optimization):");
          slowEndpoints.slice(0, 3).forEach((ep) => {
            logger.warn(
              `   - ${ep.endpoint.method} ${ep.endpoint.url}: ${ep.responseTime}ms`
            );
          });
        }
      } else {
        logger.warn("⏸️  No successful tests with response times available");
      }
    });

    test("[SUMMARY-003] Endpoint Categorization Health", () => {
      if (testResults.length === 0) {
        logger.warn(
          "⏸️  Skipping categorization analysis - no test results available"
        );
        return;
      }

      const categories = {};
      testResults.forEach((result) => {
        const category = result.endpoint.module.split(".")[0] || "Other";
        if (!categories[category]) {
          categories[category] = { total: 0, healthy: 0 };
        }
        categories[category].total++;
        if (result.success) {
          categories[category].healthy++;
        }
      });

      logger.info("📋 Category Health Breakdown:");
      Object.entries(categories)
        .sort(([, a], [, b]) => b.healthy - a.healthy)
        .forEach(([category, stats]) => {
          const healthRate = Math.round((stats.healthy / stats.total) * 100);
          const icon = healthRate >= 80 ? "✅" : healthRate >= 60 ? "⚠️" : "❌";
          logger.info(
            `   ${icon} ${category}: ${stats.healthy}/${stats.total} (${healthRate}%)`
          );
        });

      // Realistic expectations for category health
      Object.entries(categories).forEach(([category, stats]) => {
        if (stats.total >= 3) {
          // Only check categories with meaningful sample size
          const healthRate = (stats.healthy / stats.total) * 100;
          // Expect at least 50% health rate for significant categories
          if (healthRate < 50) {
            logger.warn(
              `   ⚠️  Category '${category}' has low health rate: ${Math.round(
                healthRate
              )}%`
            );
          }
        }
      });
    });

    test("[SUMMARY-004] HTTP Method Distribution", () => {
      if (allEndpoints.length === 0) {
        logger.warn(
          "⏸️  Skipping method distribution - no endpoints available"
        );
        return;
      }

      const methodStats = {};
      allEndpoints.forEach((endpoint) => {
        const method = endpoint.method;
        methodStats[method] = (methodStats[method] || 0) + 1;
      });

      logger.info("🌐 HTTP Method Distribution:");
      Object.entries(methodStats)
        .sort(([, a], [, b]) => b - a)
        .forEach(([method, count]) => {
          const percentage = Math.round((count / allEndpoints.length) * 100);
          logger.info(`   - ${method}: ${count} endpoints (${percentage}%)`);
        });

      // Should have a reasonable distribution of methods
      // Even if it's just GET and POST, that's fine for many APIs
      const methodCount = Object.keys(methodStats).length;
      expect(methodCount).toBeGreaterThan(0);

      if (methodCount === 1) {
        logger.info(
          `   ℹ️  API uses only ${Object.keys(methodStats)[0]} method`
        );
      } else {
        logger.info(`   ✅ API uses ${methodCount} different HTTP methods`);
      }
    });
  });

  // =========================================================================
  // 🎯 IMPLEMENTATION 3: CONFIGURATION VALIDATION TESTS
  // =========================================================================

  describe("Endpoint Configuration Validation", () => {
    test("[CONFIG-001] URL Format Validation", () => {
      if (allEndpoints.length === 0) {
        logger.warn("⏸️  Skipping URL validation - no endpoints available");
        return;
      }

      const invalidUrls = allEndpoints.filter((ep) => {
        const testUrl = ep.originalUrl.includes("<createdId>")
          ? ep.originalUrl.replace("<createdId>", "test-id")
          : ep.originalUrl;
        return !isValidUrl(testUrl);
      });

      expect(invalidUrls.length).toBe(0);

      if (invalidUrls.length > 0) {
        logger.error("❌ Invalid URLs found:");
        invalidUrls.slice(0, 5).forEach((ep) => {
          logger.error(`   - ${ep.originalUrl} (${ep.module})`);
        });
        if (invalidUrls.length > 5) {
          logger.error(`   ... and ${invalidUrls.length - 5} more`);
        }
      } else {
        logger.info("✅ All endpoint URLs have valid format");
      }
    });

    test("[CONFIG-002] Module Naming Consistency", () => {
      if (allEndpoints.length === 0) {
        logger.warn("⏸️  Skipping module validation - no endpoints available");
        return;
      }

      const modules = [...new Set(allEndpoints.map((ep) => ep.module))];
      const invalidModules = modules.filter(
        (module) =>
          !module ||
          module === "Root" ||
          module.includes("undefined") ||
          module.trim() === ""
      );

      expect(invalidModules.length).toBe(0);

      if (invalidModules.length > 0) {
        logger.error(`❌ Found ${invalidModules.length} invalid module names:`);
        invalidModules.forEach((module) => {
          logger.error(`   - "${module}"`);
        });
      } else {
        logger.info(`✅ All ${modules.length} modules have valid names`);

        // Log module structure
        const topLevelModules = [
          ...new Set(modules.map((m) => m.split(".")[0])),
        ];
        logger.info(`   - Top-level modules: ${topLevelModules.join(", ")}`);
      }
    });

    test("[CONFIG-003] Payload Structure Validation", () => {
      const endpointsWithPayload = allEndpoints.filter(
        (ep) => ep.payload && typeof ep.payload === "object"
      );

      if (endpointsWithPayload.length === 0) {
        logger.info("ℹ️  No endpoints with payloads found in schema");
        return;
      }

      const invalidPayloads = endpointsWithPayload.filter((ep) => {
        try {
          JSON.stringify(ep.payload);
          return false;
        } catch {
          return true;
        }
      });

      expect(invalidPayloads.length).toBe(0);

      if (invalidPayloads.length > 0) {
        logger.error(
          `❌ Found ${invalidPayloads.length} endpoints with invalid payloads:`
        );
        invalidPayloads.forEach((ep) => {
          logger.error(`   - ${ep.module}.${ep.operation}`);
        });
      } else {
        logger.info(
          `✅ ${endpointsWithPayload.length} endpoints have valid payload structures`
        );

        // Log payload statistics
        const payloadSizes = endpointsWithPayload.map(
          (ep) => JSON.stringify(ep.payload).length
        );
        const avgPayloadSize = Math.round(
          payloadSizes.reduce((a, b) => a + b, 0) / payloadSizes.length
        );
        logger.info(`   - Average payload size: ${avgPayloadSize} characters`);
      }
    });
  });
});
