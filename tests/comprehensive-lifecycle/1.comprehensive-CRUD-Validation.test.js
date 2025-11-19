// tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js - COMPLETE CRUD LIFECYCLE
const CrudLifecycleHelper = require("../../utils/crud-lifecycle-helper");
const logger = require("../../utils/logger");
const modulesConfig = require("../../config/modules-config");
const apiClient = require("../../utils/api-client");
const { URL } = require("url");
const Constants = require("../../Constants");

const { TEST_CONFIG, HTTP_STATUS_CODES, FILE_PATHS } = Constants;

/**
 * ENTERPRISE COMPLETE CRUD LIFECYCLE VALIDATION SUITE
 *
 * Complete CRUD Lifecycle: Create >> View >> Edit >> View >> Delete >> View [Negative Test]
 * Professional validation with comprehensive state tracking
 * Isolated modules with no global dependencies
 *
 * @version 4.0.0 - Complete CRUD Lifecycle
 * @author Mohamed Said Ibrahim
 */

// Module-level tracking
const moduleResults = new Map();

describe("Enterprise Complete CRUD Lifecycle Validation Suite", () => {
  const testResults = [];
  let crudTestSummary = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    modulesTested: 0,
    modulesPassed: 0,
    modulesFailed: 0,
    startTime: null,
    endTime: null,
  };

  // Helper methods (keep existing implementations)
  const isValidUrl = (string) => {
    if (!string || string === "URL_HERE") return false;
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  };

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

  const skipIfNoValidOperations = (moduleConfig, operationType) => {
    if (!moduleConfig) {
      return {
        skip: true,
        reason: `Module configuration is undefined or null`,
      };
    }
    if (!moduleConfig[operationType]) {
      return {
        skip: true,
        reason: `Operation '${operationType}' not configured in module`,
      };
    }
    const operation = moduleConfig[operationType];
    if (!Array.isArray(operation) || !operation[0]) {
      return {
        skip: true,
        reason: `Operation '${operationType}' has invalid format`,
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
    logger.info("🚀 ENTERPRISE COMPLETE CRUD LIFECYCLE VALIDATION SUITE");
    logger.info("=".repeat(70));
    logger.info(
      "🎯 COMPLETE LIFECYCLE: Create → View → Edit → View → Delete → Negative View"
    );
    logger.info("=".repeat(70));
  });

  afterAll(() => {
    crudTestSummary.endTime = new Date().toISOString();
    const duration = crudTestSummary.endTime
      ? new Date(crudTestSummary.endTime) - new Date(crudTestSummary.startTime)
      : 0;

    logger.info("📊 COMPLETE CRUD LIFECYCLE EXECUTION SUMMARY");
    logger.info("=".repeat(60));
    logger.info(`   Total Modules: ${crudTestSummary.modulesTested}`);
    logger.info(`   ✅ Healthy Modules: ${crudTestSummary.modulesPassed}`);
    logger.info(`   ❌ Failed Modules: ${crudTestSummary.modulesFailed}`);
    logger.info(`   ✅ Passed Tests: ${crudTestSummary.passedTests}`);
    logger.info(`   ❌ Failed Tests: ${crudTestSummary.failedTests}`);
    logger.info(`   ⏸️  Skipped Tests: ${crudTestSummary.skippedTests}`);
    logger.info(`   ⏱️  Total Duration: ${duration}ms`);
    logger.info(
      `   📈 Success Rate: ${(
        (crudTestSummary.modulesPassed / crudTestSummary.modulesTested) *
        100
      ).toFixed(1)}%`
    );
    logger.info("=".repeat(60));

    // Detailed module status
    logger.info("🔍 MODULE LIFECYCLE STATUS:");
    moduleResults.forEach((result, moduleName) => {
      const status = result.overallSuccess ? "✅ COMPLETE" : "❌ FAILED";
      const lifecycle = result.completedLifecycle
        ? "FULL LIFECYCLE"
        : "PARTIAL";
      logger.info(`   ${status} - ${moduleName} [${lifecycle}]`);
    });

    logger.info(
      `🏁 Completed complete CRUD lifecycle for ${crudTestSummary.modulesTested} modules`
    );
  });

  /**
   * COMPLETE CRUD LIFECYCLE TESTING FUNCTION
   */
  const runCompleteCRUDLifecycleOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const moduleHasEndpoints = hasEndpoints(moduleConfig);

      if (moduleHasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        crudTestSummary.modulesTested++;

        if (!fullModuleName.includes("Reports")) {
          describe(`COMPLETE CRUD LIFECYCLE: ${fullModuleName}`, () => {
            let moduleStartTime;
            let lifecycleResults = {};
            let testContext = {};
            let moduleTestCount = 0;
            let hasValidCreateOperation = false;
            let createdResourceId = null;
            let crudHelper;
            let moduleOverallSuccess = true;
            let completedLifecycle = false;

            beforeAll(async () => {
              moduleStartTime = Date.now();

              // Initialize CRUD helper for this module
              crudHelper = new CrudLifecycleHelper(fullModuleName);

              try {
                await crudHelper.initialize();
                hasValidCreateOperation =
                  moduleConfig.Post &&
                  Array.isArray(moduleConfig.Post) &&
                  moduleConfig.Post[0] &&
                  isValidUrl(moduleConfig.Post[0]);

                logger.info(
                  `🎯 STARTING COMPLETE CRUD LIFECYCLE FOR: ${fullModuleName}`
                );
                logger.info(
                  `📊 Has valid CREATE operation: ${hasValidCreateOperation}`
                );

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
              } catch (error) {
                logger.error(
                  `❌ ${fullModuleName} - CRUD helper initialization failed: ${error.message}`
                );
                moduleOverallSuccess = false;
              }
            });

            afterAll(async () => {
              const moduleDuration = Date.now() - moduleStartTime;

              const moduleResult = {
                module: fullModuleName,
                overallSuccess: moduleOverallSuccess,
                completedLifecycle: completedLifecycle,
                duration: moduleDuration,
                testCount: moduleTestCount,
                createdResourceId: createdResourceId,
                timestamp: new Date().toISOString(),
              };

              moduleResults.set(fullModuleName, moduleResult);

              if (moduleOverallSuccess && completedLifecycle) {
                crudTestSummary.modulesPassed++;
                logger.info(
                  `✅ ${fullModuleName} - COMPLETE LIFECYCLE SUCCESS in ${moduleDuration}ms`
                );
              } else {
                crudTestSummary.modulesFailed++;
                logger.error(
                  `❌ ${fullModuleName} - LIFECYCLE FAILED in ${moduleDuration}ms`
                );
              }

              if (crudHelper) {
                await crudHelper.cleanup();
              }
            });

            beforeEach(() => {
              testContext = {
                module: fullModuleName,
                startTime: new Date().toISOString(),
                hasValidCreateOperation: hasValidCreateOperation,
                lifecyclePhase: "UNKNOWN",
              };
            });

            afterEach(() => {
              const testState = expect.getState();
              const testName = testState.currentTestName || "Unknown Test";
              moduleTestCount++;
              crudTestSummary.totalTests++;

              let testStatus = "passed";
              try {
                if (
                  testState.snapshotState &&
                  testState.snapshotState.unmatched > 0
                ) {
                  testStatus = "failed";
                  crudTestSummary.failedTests++;
                  moduleOverallSuccess = false;
                } else {
                  crudTestSummary.passedTests++;
                }
              } catch (e) {
                testStatus = "failed";
                crudTestSummary.failedTests++;
                moduleOverallSuccess = false;
              }

              const testResult = {
                module: fullModuleName,
                status: testStatus,
                operation: testName,
                lifecycleResults,
                timestamp: new Date().toISOString(),
                testName: testName,
                context: testContext,
                testCount: moduleTestCount,
                createdResourceId: createdResourceId,
                completedLifecycle: completedLifecycle,
              };

              testResults.push(testResult);

              if (crudHelper) {
                crudHelper.recordTestStatus(testName, testStatus);
              }

              if (testStatus === "passed") {
                logger.debug(`✅ ${fullModuleName} - ${testName} completed`);
              } else {
                logger.error(`❌ ${fullModuleName} - ${testName} failed`);
              }
            });

            // =========================================================================
            // 🎯 COMPLETE CRUD LIFECYCLE - 6 PHASES
            // =========================================================================

            test(
              "🎯 [PHASE 1/6] CREATE - Successfully create a new resource",
              async () => {
                try {
                  testContext.lifecyclePhase = "CREATE";
                  testContext.operation = "CREATE";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - CREATE skipped: Module initialization failed`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "Post"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - CREATE skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(`🔄 ${fullModuleName} - PHASE 1: CREATE`);

                  const { createdId, response, originalData } =
                    await crudHelper.runCreateTest("Post");

                  expect([
                    HTTP_STATUS_CODES.CREATED,
                    HTTP_STATUS_CODES.OK,
                  ]).toContain(response.status);
                  expect(createdId).toBeDefined();

                  const createdIdString = String(createdId);
                  expect(createdIdString).toBeTruthy();
                  expect(createdIdString.length).toBeGreaterThan(0);

                  createdResourceId = createdIdString;

                  // Verify file persistence
                  const fs = require("fs");
                  expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(true);
                  const fileContent = fs
                    .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
                    .trim();
                  expect(fileContent).toBe(createdIdString);

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 1 COMPLETE: Resource created - ID: ${createdIdString}`
                  );
                  lifecycleResults.create = {
                    success: true,
                    resourceId: createdIdString,
                    originalData: originalData,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 1 FAILED: ${error.message}`
                  );
                  lifecycleResults.create = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [PHASE 2/6] VIEW - Retrieve and verify the newly created resource",
              async () => {
                try {
                  testContext.lifecyclePhase = "VIEW_INITIAL";
                  testContext.operation = "VIEW";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - INITIAL VIEW skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "View"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - INITIAL VIEW skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - INITIAL VIEW skipped: No resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(`🔍 ${fullModuleName} - PHASE 2: INITIAL VIEW`);

                  const { response, resourceData } =
                    await crudHelper.runInitialViewTest("View");

                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.ACCEPTED,
                  ];
                  expect(validStatuses).toContain(response.status);
                  expect(resourceData).toBeDefined();

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 2 COMPLETE: Resource verified - ID: ${createdResourceId}`
                  );
                  lifecycleResults.viewInitial = {
                    success: true,
                    resourceId: createdResourceId,
                    resourceData: resourceData,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 2 FAILED: ${error.message}`
                  );
                  lifecycleResults.viewInitial = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [PHASE 3/6] UPDATE - Modify and update the created resource",
              async () => {
                try {
                  testContext.lifecyclePhase = "UPDATE";
                  testContext.operation = "UPDATE";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - UPDATE skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "PUT"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - UPDATE skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - UPDATE skipped: No resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(`✏️ ${fullModuleName} - PHASE 3: UPDATE`);

                  const { response, updatedData } =
                    await crudHelper.runUpdateTest("PUT");

                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.ACCEPTED,
                    HTTP_STATUS_CODES.NO_CONTENT,
                  ];
                  expect(validStatuses).toContain(response.status);

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 3 COMPLETE: Resource updated - ID: ${createdResourceId}`
                  );
                  lifecycleResults.update = {
                    success: true,
                    resourceId: createdResourceId,
                    updatedData: updatedData,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 3 FAILED: ${error.message}`
                  );
                  lifecycleResults.update = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [PHASE 4/6] VIEW - Verify the updates were applied successfully",
              async () => {
                try {
                  testContext.lifecyclePhase = "VIEW_POST_UPDATE";
                  testContext.operation = "VIEW_POST_UPDATE";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - POST-UPDATE VIEW skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "View"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - POST-UPDATE VIEW skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - POST-UPDATE VIEW skipped: No resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(
                    `🔍 ${fullModuleName} - PHASE 4: POST-UPDATE VIEW`
                  );

                  const { response, currentData, changesVerified } =
                    await crudHelper.runPostUpdateViewTest("View");

                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.ACCEPTED,
                  ];
                  expect(validStatuses).toContain(response.status);
                  expect(currentData).toBeDefined();

                  if (changesVerified) {
                    logger.info(
                      `📈 Changes verified: ${changesVerified.changeCount} modifications detected`
                    );
                  }

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 4 COMPLETE: Updates verified - ID: ${createdResourceId}`
                  );
                  lifecycleResults.viewPostUpdate = {
                    success: true,
                    resourceId: createdResourceId,
                    currentData: currentData,
                    changesVerified: changesVerified,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 4 FAILED: ${error.message}`
                  );
                  lifecycleResults.viewPostUpdate = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [PHASE 5/6] DELETE - Remove the resource from the system",
              async () => {
                try {
                  testContext.lifecyclePhase = "DELETE";
                  testContext.operation = "DELETE";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - DELETE skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "DELETE"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - DELETE skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - DELETE skipped: No resource ID`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(`🗑️ ${fullModuleName} - PHASE 5: DELETE`);

                  const { response, deletionVerified } =
                    await crudHelper.runDeleteTest("DELETE");

                  const validStatuses = [
                    HTTP_STATUS_CODES.OK,
                    HTTP_STATUS_CODES.NO_CONTENT,
                    HTTP_STATUS_CODES.ACCEPTED,
                  ];
                  expect(validStatuses).toContain(response.status);
                  expect(deletionVerified).toBe(true);

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 5 COMPLETE: Resource deleted - ID: ${createdResourceId}`
                  );
                  lifecycleResults.delete = {
                    success: true,
                    resourceId: createdResourceId,
                    deletionVerified: deletionVerified,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 5 FAILED: ${error.message}`
                  );
                  lifecycleResults.delete = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [PHASE 6/6] NEGATIVE VIEW - Verify resource no longer exists (404 Test)",
              async () => {
                try {
                  testContext.lifecyclePhase = "NEGATIVE_VIEW";
                  testContext.operation = "NEGATIVE_VIEW";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - NEGATIVE VIEW skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "View"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - NEGATIVE VIEW skipped: ${skipCheck.reason}`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  logger.info(`🚫 ${fullModuleName} - PHASE 6: NEGATIVE VIEW`);

                  const negativeResult = await crudHelper.runNegativeViewTest(
                    "View"
                  );

                  expect(negativeResult.success).toBe(true);
                  expect(negativeResult.expectedError).toBe(true);
                  expect([404, 410]).toContain(negativeResult.status);

                  logger.info(
                    `✅ ${fullModuleName} - PHASE 6 COMPLETE: Resource properly deleted (${negativeResult.status} received)`
                  );
                  lifecycleResults.negativeView = {
                    success: true,
                    expectedError: true,
                    status: negativeResult.status,
                    message: negativeResult.message,
                  };

                  // Mark lifecycle as completed successfully
                  completedLifecycle = true;
                  logger.info(
                    `🏁 ${fullModuleName} - COMPLETE CRUD LIFECYCLE FINISHED SUCCESSFULLY`
                  );
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - PHASE 6 FAILED: ${error.message}`
                  );
                  lifecycleResults.negativeView = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [VALIDATION] CONFIGURATION - Verify module configuration integrity",
              async () => {
                try {
                  testContext.lifecyclePhase = "CONFIGURATION";
                  testContext.operation = "CONFIGURATION";

                  if (!moduleOverallSuccess) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - CONFIGURATION skipped: Module failure`
                    );
                    crudTestSummary.skippedTests++;
                    expect(true).toBe(true);
                    return;
                  }

                  expect(moduleConfig).toBeDefined();
                  expect(Object.keys(moduleConfig).length).toBeGreaterThan(0);

                  const operationStats = Object.entries(moduleConfig).reduce(
                    (acc, [name, op]) => {
                      if (Array.isArray(op) && op[0]) {
                        const isValid = isValidUrl(op[0]);
                        acc.valid += isValid ? 1 : 0;
                        acc.invalid += !isValid ? 1 : 0;
                        acc.operations.push({ name, isValid, endpoint: op[0] });
                      }
                      return acc;
                    },
                    { valid: 0, invalid: 0, operations: [] }
                  );

                  logger.info(
                    `✅ ${fullModuleName} - Configuration validated: ${
                      operationStats.valid
                    }/${Object.keys(moduleConfig).length} valid operations`
                  );
                  lifecycleResults.configuration = {
                    success: true,
                    validOperations: operationStats.valid,
                    totalOperations: Object.keys(moduleConfig).length,
                  };
                } catch (error) {
                  logger.error(
                    `❌ ${fullModuleName} - Configuration validation failed: ${error.message}`
                  );
                  lifecycleResults.configuration = {
                    success: false,
                    error: error.message,
                  };
                  moduleOverallSuccess = false;
                  throw error;
                }
              },
              TEST_CONFIG.TIMEOUT.SHORT
            );
          });
        }
      }

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && !hasEndpoints(moduleConfig)) {
        runCompleteCRUDLifecycleOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run complete CRUD lifecycle on all modules
  runCompleteCRUDLifecycleOnAllModules(modulesConfig.schema || modulesConfig);
});
