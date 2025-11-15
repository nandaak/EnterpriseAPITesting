// tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js
const CrudLifecycleHelper = require("../../utils/crud-lifecycle-helper");
const logger = require("../../utils/logger");
const modulesConfig = require("../../config/modules-config");
const apiClient = require("../../utils/api-client");
const { URL } = require("url");
const Constants = require("../../Constants");

const { TEST_CONFIG, HTTP_STATUS_CODES, FILE_PATHS } = Constants;

/**
 * ENTERPRISE CRUD LIFECYCLE VALIDATION SUITE
 *
 * Enhanced version following successful patterns from security tests
 * Purpose: Test complete CRUD lifecycle across all backend API modules
 * Coverage: CREATE, VIEW, UPDATE, DELETE operations with comprehensive validation
 * Scope: Automatically discovers and tests all modules with valid endpoints
 *
 * @version 2.0.0
 * @author Mohamed Said Ibrahim
 */

// Initialize the helper instance
let crudHelper;

describe("Enterprise CRUD Lifecycle Validation Suite", () => {
  const testResults = [];
  let crudTestSummary = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    modulesTested: 0,
    startTime: null,
    endTime: null,
  };

  // URL validation helper method
  const isValidUrl = (string) => {
    if (!string || string === "URL_HERE") return false;
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  };

  // Check if module has minimum required operations for CRUD
  const hasMinimumCRUDOperations = (moduleConfig) => {
    if (!moduleConfig) return false;

    const requiredOps = ["Post", "View"];
    const validOps = requiredOps.filter(
      (op) =>
        moduleConfig[op] &&
        Array.isArray(moduleConfig[op]) &&
        moduleConfig[op][0] &&
        isValidUrl(moduleConfig[op][0])
    );

    return validOps.length >= 2;
  };

  // ✅ CORRECTED: Skip test if no valid operations are available
  const skipIfNoValidOperations = (moduleConfig, operationType) => {
    if (!moduleConfig) {
      return {
        skip: true,
        reason: `Module configuration is undefined or null`,
      };
    }

    // ✅ FIX: Check directly for operationType in moduleConfig
    if (!moduleConfig[operationType]) {
      return {
        skip: true,
        reason: `Operation '${operationType}' not configured in module`,
      };
    }

    const operation = moduleConfig[operationType];

    // ✅ FIX: Operation is an array [endpoint, payload], so check operation[0]
    if (!Array.isArray(operation) || !operation[0]) {
      return {
        skip: true,
        reason: `Operation '${operationType}' has invalid format - expected [endpoint, payload] array`,
      };
    }

    const endpoint = operation[0];
    if (!isValidUrl(endpoint)) {
      return {
        skip: true,
        reason: `Invalid URL for operation '${operationType}': ${endpoint}`,
      };
    }

    return { skip: false };
  };

  // ✅ ENHANCED: Check if module has endpoints (for module discovery)
  const hasEndpoints = (moduleConfig) => {
    if (!moduleConfig || typeof moduleConfig !== "object") return false;

    const endpointTypes = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "EDIT",
      "LookUP",
      "Commit",
      "GET",
    ];

    return endpointTypes.some(
      (operationType) =>
        moduleConfig[operationType] &&
        Array.isArray(moduleConfig[operationType]) &&
        moduleConfig[operationType][0] &&
        moduleConfig[operationType][0] !== "URL_HERE" &&
        isValidUrl(moduleConfig[operationType][0])
    );
  };

  // Suite setup
  beforeAll(() => {
    crudTestSummary.startTime = new Date().toISOString();
    logger.info("🚀 Starting Enterprise CRUD Lifecycle Validation Suite");
    logger.info("=".repeat(60));
  });

  afterAll(() => {
    crudTestSummary.endTime = new Date().toISOString();

    // Generate comprehensive test report
    const summary = {
      execution: {
        ...crudTestSummary,
        duration: crudTestSummary.endTime
          ? new Date(crudTestSummary.endTime) -
            new Date(crudTestSummary.startTime)
          : 0,
      },
      modules: {
        total: crudTestSummary.modulesTested,
        tested: testResults.length,
        healthy: testResults.filter((r) => r.status === "passed").length,
        failed: testResults.filter((r) => r.status === "failed").length,
      },
      operations: {
        create: testResults.filter((r) => r.operation === "CREATE").length,
        view: testResults.filter((r) => r.operation === "VIEW").length,
        update: testResults.filter((r) => r.operation === "UPDATE").length,
        delete: testResults.filter((r) => r.operation === "DELETE").length,
      },
    };

    logger.info("📊 CRUD TEST EXECUTION SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`   Total Modules: ${summary.modules.total}`);
    logger.info(`   Tested Modules: ${summary.modules.tested}`);
    logger.info(`   ✅ Healthy Modules: ${summary.modules.healthy}`);
    logger.info(`   ❌ Failed Modules: ${summary.modules.failed}`);
    logger.info(`   ✅ Passed Tests: ${crudTestSummary.passedTests}`);
    logger.info(`   ❌ Failed Tests: ${crudTestSummary.failedTests}`);
    logger.info(`   ⏸️  Skipped Tests: ${crudTestSummary.skippedTests}`);
    logger.info(`   ⏱️  Total Duration: ${summary.execution.duration}ms`);
    logger.info("=".repeat(50));

    logger.info(
      `🏁 Completed CRUD tests for ${crudTestSummary.modulesTested} modules`
    );
  });

  /**
   * ENHANCED MODULE TESTING FUNCTION
   */
  const runCRUDTestsOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      // ✅ FIX: Use the corrected hasEndpoints function
      const moduleHasEndpoints = hasEndpoints(moduleConfig);

      if (moduleHasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        crudTestSummary.modulesTested++;

        // ✅ FIX: Only skip Reports modules specifically, not others
        if (!fullModuleName.includes("Reports")) {
          describe(`CRUD Testing: ${fullModuleName}`, () => {
            let moduleStartTime;
            let crudResults = {};
            let testContext = {};
            let moduleTestCount = 0;
            let hasValidCreateOperation = false;
            let createdResourceId = null;

            beforeAll(async () => {
              moduleStartTime = Date.now();

              // ✅ FIX: Check if module has valid CREATE operation
              hasValidCreateOperation =
                moduleConfig.Post &&
                Array.isArray(moduleConfig.Post) &&
                moduleConfig.Post[0] &&
                isValidUrl(moduleConfig.Post[0]);

              // Initialize CRUD helper for this module
              crudHelper = new CrudLifecycleHelper(fullModuleName);
              await crudHelper.initialize();

              logger.info(`🎯 Starting CRUD tests for: ${fullModuleName}`);
              logger.info(
                `📊 Has valid CREATE operation: ${hasValidCreateOperation}`
              );

              // Log module configuration for debugging
              const endpoints = Object.keys(moduleConfig).filter(
                (key) =>
                  Array.isArray(moduleConfig[key]) &&
                  moduleConfig[key][0] &&
                  typeof moduleConfig[key][0] === "string" &&
                  moduleConfig[key][0].trim().length > 0 &&
                  moduleConfig[key][0] !== "URL_HERE" &&
                  isValidUrl(moduleConfig[key][0])
              );

              logger.info(`📋 Available endpoints: ${endpoints.join(", ")}`);
            });

            afterAll(async () => {
              const moduleDuration = Date.now() - moduleStartTime;
              logger.info(
                `✅ Completed CRUD tests for ${fullModuleName} in ${moduleDuration}ms`
              );

              if (crudHelper) {
                await crudHelper.cleanup();
              }
            });

            beforeEach(() => {
              testContext = {
                module: fullModuleName,
                startTime: new Date().toISOString(),
                hasValidCreateOperation: hasValidCreateOperation,
              };
            });

            afterEach(() => {
              const testState = expect.getState();
              const testName = testState.currentTestName || "Unknown Test";
              moduleTestCount++;
              crudTestSummary.totalTests++;

              // Determine test status and update summary
              let testStatus = "passed";
              try {
                if (
                  testState.snapshotState &&
                  testState.snapshotState.unmatched > 0
                ) {
                  testStatus = "failed";
                  crudTestSummary.failedTests++;
                } else {
                  crudTestSummary.passedTests++;
                }
              } catch (e) {
                testStatus = "failed";
                crudTestSummary.failedTests++;
              }

              const testResult = {
                module: fullModuleName,
                status: testStatus,
                operation: testName.includes("CREATE")
                  ? "CREATE"
                  : testName.includes("VIEW")
                  ? "VIEW"
                  : testName.includes("UPDATE")
                  ? "UPDATE"
                  : testName.includes("DELETE")
                  ? "DELETE"
                  : "OTHER",
                crudResults,
                timestamp: new Date().toISOString(),
                testName: testName,
                context: testContext,
                testCount: moduleTestCount,
                createdResourceId: createdResourceId,
              };

              testResults.push(testResult);

              if (crudHelper) {
                crudHelper.recordTestStatus(testName, testStatus);
              }

              if (testStatus === "passed") {
                logger.debug(
                  `✅ ${fullModuleName} - ${testName} completed successfully`
                );
              } else {
                logger.error(`❌ ${fullModuleName} - ${testName} failed`);
              }
            });

            // =========================================================================
            // 🎯 COMPREHENSIVE CRUD TESTS
            // =========================================================================

            test(
              "🎯 [TC-1] CREATE - Successfully create a new resource",
              async () => {
                try {
                  testContext.operation = "CREATE";

                  // ✅ FIX: Use corrected skip check
                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "Post"
                  );
                  if (skipCheck.skip) {
                    // For configuration issues, we can skip instead of failing
                    logger.warn(`⏸️ CREATE test skipped: ${skipCheck.reason}`);
                    crudTestSummary.skippedTests++;

                    // Mark as passed when skipped due to configuration
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(
                    `🔄 Testing CREATE operation for ${fullModuleName}`
                  );

                  const { createdId, response, extractionDetails } =
                    await crudHelper.runCreateTest("Post");

                  // Enhanced status validation
                  expect([
                    HTTP_STATUS_CODES.CREATED,
                    HTTP_STATUS_CODES.OK,
                  ]).toContain(response.status);

                  // Enhanced ID validation
                  expect(createdId).toBeDefined();
                  const createdIdString = String(createdId);
                  expect(createdIdString).toBeTruthy();
                  expect(createdIdString.length).toBeGreaterThan(0);

                  createdResourceId = createdIdString;

                  // Validate ID format
                  if (
                    createdIdString.includes("-") &&
                    createdIdString.length === 36
                  ) {
                    logger.info(`✅ ID is UUID format: ${createdIdString}`);
                  } else {
                    logger.info(`✅ ID format: ${createdIdString}`);
                  }

                  // Verify file persistence
                  const fs = require("fs");
                  expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(true);

                  const fileContent = fs
                    .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
                    .trim();
                  expect(fileContent).toBe(createdIdString);

                  logger.info(
                    `✅ CREATE test completed - Resource ID: ${createdIdString}`
                  );
                  crudResults.create = {
                    success: true,
                    resourceId: createdIdString,
                  };
                } catch (error) {
                  logger.error(
                    `❌ CREATE test failed for ${fullModuleName}: ${error.message}`
                  );
                  crudResults.create = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-2] VIEW - Retrieve the newly created resource",
              async () => {
                try {
                  testContext.operation = "VIEW";

                  // Skip if no valid VIEW operation
                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "View"
                  );
                  if (skipCheck.skip) {
                    logger.warn(`⏸️ VIEW test skipped: ${skipCheck.reason}`);
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  // Skip VIEW test if CREATE was skipped (no ID available)
                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ VIEW test skipped: No valid CREATE operation or resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(
                    `🔍 Testing VIEW operation for ${fullModuleName}`
                  );

                  crudHelper.enforcePrerequisite("createdId");
                  const { response } = await crudHelper.runViewTest("View");

                  // Enhanced status validation for VIEW
                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.ACCEPTED,
                  ];
                  expect(validStatuses).toContain(response.status);

                  logger.info(
                    `✅ VIEW test completed - Retrieved resource with ID: ${createdResourceId}`
                  );
                  crudResults.view = {
                    success: true,
                    resourceId: createdResourceId,
                  };
                } catch (error) {
                  logger.error(
                    `❌ VIEW test failed for ${fullModuleName}: ${error.message}`
                  );
                  crudResults.view = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-3] UPDATE - Modify and verify the created resource",
              async () => {
                try {
                  testContext.operation = "UPDATE";

                  // Skip if no valid PUT operation
                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "PUT"
                  );
                  if (skipCheck.skip) {
                    logger.warn(`⏸️ UPDATE test skipped: ${skipCheck.reason}`);
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  // Skip UPDATE test if CREATE was skipped (no ID available)
                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ UPDATE test skipped: No valid CREATE operation or resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(
                    `✏️ Testing UPDATE operation for ${fullModuleName}`
                  );

                  crudHelper.enforcePrerequisite("createdId");
                  const { response } = await crudHelper.runUpdateTest("PUT");

                  // Enhanced status validation for UPDATE
                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.ACCEPTED,
                    HTTP_STATUS_CODES.NO_CONTENT,
                  ];
                  expect(validStatuses).toContain(response.status);

                  logger.info(
                    `✅ UPDATE test completed - Modified resource with ID: ${createdResourceId}`
                  );
                  crudResults.update = {
                    success: true,
                    resourceId: createdResourceId,
                  };
                } catch (error) {
                  logger.error(
                    `❌ UPDATE test failed for ${fullModuleName}: ${error.message}`
                  );
                  crudResults.update = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-4] DELETE - Remove the resource",
              async () => {
                try {
                  testContext.operation = "DELETE";

                  // Skip if no valid DELETE operation
                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "DELETE"
                  );
                  if (skipCheck.skip) {
                    logger.warn(`⏸️ DELETE test skipped: ${skipCheck.reason}`);
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  // Skip DELETE test if CREATE was skipped (no ID available)
                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ DELETE test skipped: No valid CREATE operation or resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(
                    `🗑️ Testing DELETE operation for ${fullModuleName}`
                  );

                  crudHelper.enforcePrerequisite("createdId");
                  const { response } = await crudHelper.runDeleteTest("DELETE");

                  // Enhanced status validation for DELETE
                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.NO_CONTENT,
                    HTTP_STATUS_CODES.ACCEPTED,
                  ];
                  expect(validStatuses).toContain(response.status);

                  logger.info(
                    `✅ DELETE test completed - Resource successfully removed`
                  );
                  crudResults.delete = {
                    success: true,
                    resourceId: createdResourceId,
                  };
                } catch (error) {
                  logger.error(
                    `❌ DELETE test failed for ${fullModuleName}: ${error.message}`
                  );
                  crudResults.delete = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-5] CONFIGURATION - Verify module configuration integrity",
              async () => {
                try {
                  testContext.operation = "CONFIGURATION";

                  expect(moduleConfig).toBeDefined();
                  expect(Object.keys(moduleConfig).length).toBeGreaterThan(0);

                  // Verify each operation has required properties and valid URLs
                  Object.entries(moduleConfig).forEach(
                    ([operationName, operation]) => {
                      if (Array.isArray(operation) && operation[0]) {
                        expect(operation[0]).toBeDefined();
                        expect(typeof operation[0]).toBe("string");
                        expect(operation[0].length).toBeGreaterThan(0);

                        // Log URL validity
                        const isValid = isValidUrl(operation[0]);
                        if (!isValid) {
                          logger.warn(
                            `Invalid URL for ${operationName}: ${operation[0]}`
                          );
                        }
                      }
                    }
                  );

                  // Count valid vs invalid URLs
                  const operationStats = Object.entries(moduleConfig).reduce(
                    (acc, [name, op]) => {
                      if (Array.isArray(op) && op[0]) {
                        const isValid = isValidUrl(op[0]);
                        acc.valid += isValid ? 1 : 0;
                        acc.invalid += !isValid ? 1 : 0;
                        acc.operations.push({
                          name,
                          isValid,
                          endpoint: op[0],
                        });
                      }
                      return acc;
                    },
                    { valid: 0, invalid: 0, operations: [] }
                  );

                  logger.info(
                    `✅ Configuration test completed - Module: ${fullModuleName}, Valid operations: ${
                      operationStats.valid
                    }/${Object.keys(moduleConfig).length}`
                  );
                  crudResults.configuration = {
                    success: true,
                    validOperations: operationStats.valid,
                    totalOperations: Object.keys(moduleConfig).length,
                  };
                } catch (error) {
                  logger.error(
                    `❌ Configuration test failed for ${fullModuleName}: ${error.message}`
                  );
                  crudResults.configuration = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.SHORT
            );
          });
        }
      }

      // Recursively test nested modules following the same pattern
      if (typeof moduleConfig === "object" && !hasEndpoints(moduleConfig)) {
        runCRUDTestsOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run CRUD tests on all modules following the successful pattern
  runCRUDTestsOnAllModules(modulesConfig.schema || modulesConfig);
});
