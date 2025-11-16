// tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js
const {
  testPerformanceUnderMaliciousLoad,
} = require("../../utils/performance-helpers");
const logger = require("../../utils/logger");
const { TEST_TAGS, FILE_PATHS, HTTP_STATUS_CODES } = require("../../Constants");
const { loadSchema, isValidUrl } = require("../../utils/helper");

/**
 * PERFORMANCE UNDER MALICIOUS LOAD TESTING SUITE
 *
 * Purpose: Test system performance and resilience under malicious load conditions
 * Coverage: Concurrent requests, error handling, response times, throughput
 * Scope: Automatically tests all modules with POST endpoints under stress conditions
 *
 * @version 2.0.3
 * @author Mohamed Said Ibrahim
 */

// Load the schema once at the top level
let API_MODULE_SCHEMA = {};
try {
  API_MODULE_SCHEMA = loadSchema();
} catch (error) {
  logger.error(
    `FATAL: Failed to load API schema for performance tests: ${error.message}`
  );
}

describe("Performance Under Malicious Load", () => {
  const allTestResults = [];
  let performanceTestSummary = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    modulesTested: 0,
    startTime: null,
    endTime: null,
  };

  beforeAll(() => {
    performanceTestSummary.startTime = new Date().toISOString();
    logger.info("⚡ Starting Performance Under Malicious Load Testing");
    logger.info("=".repeat(60));
  });

  afterAll(() => {
    performanceTestSummary.endTime = new Date().toISOString();

    // Helper to calculate the average of a specific metric across all results
    const calculateAverageMetric = (results, metric) => {
      const validResults = results.filter(
        (r) =>
          r.performanceMetrics &&
          r.performanceMetrics[metric] !== undefined &&
          r.status !== "skipped"
      );
      if (validResults.length === 0) return 0;
      return (
        validResults.reduce((sum, r) => sum + r.performanceMetrics[metric], 0) /
        validResults.length
      );
    };

    const summary = {
      execution: {
        ...performanceTestSummary,
        duration: performanceTestSummary.endTime
          ? new Date(performanceTestSummary.endTime) -
            new Date(performanceTestSummary.startTime)
          : 0,
      },
      modules: {
        total: performanceTestSummary.modulesTested,
        tested: allTestResults.filter((r) => r.status !== "skipped").length,
        passed: allTestResults.filter((r) => r.status === "passed").length,
        failed: allTestResults.filter((r) => r.status === "failed").length,
        skipped: allTestResults.filter((r) => r.status === "skipped").length,
      },
      performance: {
        avgRT: calculateAverageMetric(allTestResults, "averageResponseTime"),
        avgSuccessRate: calculateAverageMetric(allTestResults, "successRate"),
        avgThroughput: calculateAverageMetric(allTestResults, "throughput"),
      },
    };

    logger.info("📊 PERFORMANCE TEST EXECUTION SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`  Total Modules Configured: ${summary.modules.total}`);
    logger.info(`  Tested Endpoints: ${summary.modules.tested}`);
    logger.info(`  ✅ Passed Tests: ${performanceTestSummary.passedTests}`);
    logger.info(`  ❌ Failed Tests: ${performanceTestSummary.failedTests}`);
    logger.info(`  ⏸️  Skipped Tests: ${performanceTestSummary.skippedTests}`);
    logger.info(`  ⏱️  Total Duration: ${summary.execution.duration}ms`);
    logger.info(
      `  📈 Avg Throughput: ${summary.performance.avgThroughput.toFixed(
        2
      )} req/sec`
    );
    logger.info(
      `  ⏱️ Avg Response Time: ${summary.performance.avgRT.toFixed(2)}ms`
    );
    logger.info("=".repeat(50));

    logger.info(
      `🏁 Completed performance tests for ${performanceTestSummary.modulesTested} modules`
    );
  });

  /**
   * ENHANCED PERFORMANCE TESTING FUNCTION
   */
  const runPerformanceTestsOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const fullModuleName = parentPath
        ? `${parentPath}.${moduleName}`
        : moduleName;

      // Check for nested configuration objects (recursion)
      const hasNestedModules = Object.values(moduleConfig).some(
        (val) => typeof val === "object" && val !== null && !Array.isArray(val)
      );

      const endpointArray = moduleConfig.Post || [];
      const hasPostEndpoint =
        endpointArray.length > 0 && isValidUrl(endpointArray[0]);

      if (hasPostEndpoint) {
        performanceTestSummary.modulesTested++;

        describe(`Performance Testing: ${fullModuleName}`, () => {
          let moduleStartTime;
          let performanceResults = {}; // Reset results for each module suite
          let testContext = {};
          let moduleTestCount = 0;

          beforeAll(() => {
            moduleStartTime = Date.now();
            logger.info(`⚡ Starting performance tests for: ${fullModuleName}`);
          });

          afterAll(() => {
            const moduleDuration = Date.now() - moduleStartTime;
            logger.info(
              `✅ Completed performance tests for ${fullModuleName} in ${moduleDuration}ms`
            );
          });

          beforeEach(() => {
            testContext = {
              module: fullModuleName,
              startTime: new Date().toISOString(),
              endpoint: moduleConfig.Post[0],
            };
          });

          afterEach(() => {
            const testState = expect.getState();
            const testName = testState.currentTestName || "Unknown Test";

            // Exclude the setup validation test
            if (testName.includes("[TC-0]")) return;

            moduleTestCount++;
            performanceTestSummary.totalTests++;

            let testStatus = "passed";

            // 🎯 FIX 1: Safely handle potentially undefined testFailureExceptions array
            if ((testState.testFailureExceptions || []).length > 0) {
              testStatus = "failed";
              performanceTestSummary.failedTests++;
            } else if (performanceResults.skipped) {
              testStatus = "skipped";
              performanceTestSummary.skippedTests++;
            } else {
              performanceTestSummary.passedTests++;
            }

            const testResult = {
              module: fullModuleName,
              testName: testName,
              status: testStatus,
              // Use defensive chaining here in case metrics is undefined
              performanceMetrics: performanceResults.metrics || {},
              timestamp: new Date().toISOString(),
              context: testContext,
              testCount: moduleTestCount,
            };

            allTestResults.push(testResult);

            if (testStatus === "passed") {
              logger.debug(
                `✅ ${fullModuleName} - ${testName} completed successfully`
              );
            } else if (testStatus === "skipped") {
              logger.debug(`⏸️  ${fullModuleName} - ${testName} skipped`);
            } else {
              logger.error(`❌ ${fullModuleName} - ${testName} failed`);
            }
          });

          // =========================================================================
          // 🎯 PERFORMANCE TEST CASES - Enhanced with realistic expectations
          // =========================================================================

          test("🎯 [TC-1] Performance Under Malicious Load", async () => {
            testContext.testType = "malicious_load_performance";

            logger.info(
              `⚡ Testing performance under malicious load for ${fullModuleName}...`
            );

            // EXECUTE LOAD TEST
            const results = await testPerformanceUnderMaliciousLoad(
              moduleConfig,
              fullModuleName
            );
            performanceResults = results; // Store results for afterEach analysis

            if (results.skipped) {
              logger.warn(
                `⏸️ Test skipped for ${fullModuleName}: ${results.details}`
              );
              expect(true).toBe(true);
              return;
            }

            // Defensively check for metrics before declaring the variable
            const metrics = results.metrics;
            if (!metrics) {
              logger.error(
                `❌ TC-1 failed to generate metrics for ${fullModuleName}. Check test helper.`
              );
              expect(metrics).toBeDefined(); // Fail the test explicitly
              return;
            }

            // Enhanced performance validation with realistic expectations
            const realisticThresholds = {
              maxAverageResponseTime: 5000,
              maxErrorRate: 70,
              maxP95ResponseTime: 10000,
              minSuccessfulRequests: 1,
            };

            const successRate =
              metrics.totalRequests > 0
                ? (metrics.successfulRequests / metrics.totalRequests) * 100
                : 0;
            const errorRate =
              metrics.totalRequests > 0
                ? (metrics.failedRequests / metrics.totalRequests) * 100
                : 0;

            const meetsRealisticStandards =
              metrics.successfulRequests >=
                realisticThresholds.minSuccessfulRequests &&
              metrics.averageResponseTime <
                realisticThresholds.maxAverageResponseTime &&
              errorRate < realisticThresholds.maxErrorRate &&
              metrics.p95ResponseTime < realisticThresholds.maxP95ResponseTime;

            // Log detailed performance metrics
            logger.info(`📊 Performance Metrics for ${fullModuleName}:`);
            logger.info(`  Total Requests: ${metrics.totalRequests}`);
            logger.info(
              `  ✅ Successful Requests: ${metrics.successfulRequests}`
            );
            logger.info(`  📈 Success Rate: ${successRate.toFixed(2)}%`);
            logger.info(
              `  ⏱️  Average Response Time: ${metrics.averageResponseTime.toFixed(
                2
              )}ms`
            );
            logger.info(`  📉 Error Rate: ${errorRate.toFixed(2)}%`);
            logger.info(
              `  🚀 Throughput: ${metrics.throughput.toFixed(2)} req/sec`
            );
            logger.info(
              `  🎯 P95 Response Time: ${metrics.p95ResponseTime.toFixed(2)}ms`
            );

            // Assertions
            expect(metrics.totalRequests).toBeGreaterThan(0);
            expect(metrics.averageResponseTime).toBeLessThan(
              realisticThresholds.maxAverageResponseTime
            );
            expect(errorRate).toBeLessThan(realisticThresholds.maxErrorRate);
            expect(metrics.p95ResponseTime).toBeLessThan(
              realisticThresholds.maxP95ResponseTime
            );

            if (meetsRealisticStandards) {
              logger.info(
                `✅ Performance under malicious load validated for ${fullModuleName}`
              );
            } else {
              logger.warn(
                `⚠️  Performance degradation detected for ${fullModuleName}. Check metrics.`
              );
            }
          }, 90000);

          test("🎯 [TC-2] Error Handling Stability Under Load", async () => {
            testContext.testType = "error_handling_analysis";

            // This test analyzes the results from TC-1
            // 🎯 FIX 2: Safely check for skipped/missing metrics before accessing properties
            if (performanceResults.skipped || !performanceResults.metrics) {
              logger.warn(
                `⏸️ Error analysis skipped for ${fullModuleName}. Load test was skipped or failed setup.`
              );
              expect(true).toBe(true);
              return;
            }

            const metrics = performanceResults.metrics;

            logger.info(
              `🔧 Analyzing error handling stability for ${fullModuleName} under load...`
            );

            // This line (318) is now safe due to the check above
            const errorRate =
              metrics.totalRequests > 0
                ? (metrics.failedRequests / metrics.totalRequests) * 100
                : 0;

            // Stability is assumed if we maintain minimal throughput (system didn't crash).
            const isStable = metrics.throughput > 0.1;

            if (isStable) {
              logger.info(
                `✅ System showed stability under load. High error rate is expected for malicious inputs.`
              );
            } else {
              logger.error(
                `❌ System instability detected for ${fullModuleName}. Error Rate: ${errorRate.toFixed(
                  2
                )}%, Throughput: ${metrics.throughput.toFixed(2)} req/sec.`
              );
            }

            // Assert stability
            expect(metrics.throughput).toBeGreaterThan(0.1);
          }, 30000);
        });
      }

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && hasNestedModules) {
        runPerformanceTestsOnAllModules(moduleConfig, fullModuleName);
      }
    });
  };

  // --- Primary Test Execution Flow ---

  // 1. ADD MANDATORY SYNCHRONOUS TEST FOR JEST VALIDATION (TC-0)
  test("📋 [TC-0] Test Setup Validation", () => {
    // Check 1: Existence and type (must be an object, not null, not an array)
    const schemaIsObject =
      typeof API_MODULE_SCHEMA === "object" &&
      API_MODULE_SCHEMA !== null &&
      !Array.isArray(API_MODULE_SCHEMA);

    // Check 2: Verify it's not an empty object (must contain modules)
    const schemaIsPopulated = Object.keys(API_MODULE_SCHEMA).length > 0;

    const schemaExists = schemaIsObject && schemaIsPopulated;

    expect(schemaExists).toBe(true);

    if (!schemaExists) {
      logger.error(
        "FATAL: Configuration schema (API_MODULE_SCHEMA) is not loaded, is null/array, or is an empty object."
      );
    }
    logger.info("✅ Test setup validated.");
  });

  // 2. Run performance tests on all modules (dynamic suite generation)
  runPerformanceTestsOnAllModules(API_MODULE_SCHEMA);
});
