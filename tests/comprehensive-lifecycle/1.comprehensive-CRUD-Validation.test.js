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
 * ID MANAGEMENT SYSTEM:
 * - createdId.txt (root): Current active ID used for UPDATE/DELETE/VIEW operations
 * - tests/createdId.json: Legacy single-module ID storage (backward compatibility)
 * - tests/createdIds.json: NEW - Centralized registry for ALL module IDs (no overwriting)
 *
 * The centralized registry maintains complete history of all created IDs across
 * all tested modules, enabling comprehensive tracking and audit trails.
 *
 * @version 5.0.0 - Enhanced with Centralized ID Registry
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
    // Check for null, undefined, empty string, or placeholder
    if (!string || string === "URL_HERE" || string.trim() === "") return false;
    
    // Ensure it's a string
    if (typeof string !== 'string') return false;
    
    // Accept relative URLs that start with /
    if (string.startsWith('/')) {
      return true;
    }
    
    // Try to parse as absolute URL
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  };

  const hasMinimumCRUDOperations = (moduleConfig) => {
    if (!moduleConfig) return false;
    const requiredOps = ["CREATE", "View"];
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
    
    // Check for empty string explicitly
    if (endpoint === '' || (typeof endpoint === 'string' && endpoint.trim() === '')) {
      return {
        skip: true,
        reason: `Empty URL for operation '${operationType}'`,
      };
    }
    
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
      "CREATE",
      "EDIT",
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

    // Display centralized registry statistics
    try {
      const registryStats = CrudLifecycleHelper.getRegistryStats();
      logger.info("=".repeat(60));
      logger.info("📋 CENTRALIZED ID REGISTRY STATISTICS:");
      logger.info(`   Total Modules Tracked: ${registryStats.totalModules}`);
      logger.info(`   Total IDs Created: ${registryStats.totalIds}`);
      logger.info(`   Registry Location: tests/createdIds.json`);
    } catch (error) {
      logger.warn(`Could not retrieve registry statistics: ${error.message}`);
    }

    logger.info(
      `🏁 Completed complete CRUD lifecycle for ${crudTestSummary.modulesTested} modules`
    );
  });

  /**
   * COMPLETE CRUD LIFECYCLE TESTING FUNCTION
   */
  const runCompleteCRUDLifecycleOnAllModules = (modules, parentPath = "") => {
    logger.debug(`Processing level: "${parentPath || 'ROOT'}" with ${Object.keys(modules).length} entries`);
    
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) {
        logger.debug(`  Skipping ${moduleName}: not an object`);
        return;
      }

      const moduleHasEndpoints = hasEndpoints(moduleConfig);
      logger.debug(`  Checking ${moduleName}: hasEndpoints=${moduleHasEndpoints}`);

      if (moduleHasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        crudTestSummary.modulesTested++;
        
        logger.info(`Found module with endpoints: ${fullModuleName}`);

        if (!fullModuleName.includes("Reports")) {
          logger.info(`Creating test suite for: ${fullModuleName}`);
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
                  moduleConfig.CREATE &&
                  Array.isArray(moduleConfig.CREATE) &&
                  moduleConfig.CREATE[0] &&
                  isValidUrl(moduleConfig.CREATE[0]);

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
                wasSkipped: false, // Track if test was skipped
              };
            });

            afterEach(() => {
              const testState = expect.getState();
              const testName = testState.currentTestName || "Unknown Test";
              moduleTestCount++;
              crudTestSummary.totalTests++;

              let testStatus = "passed";
              
              // Check if test was marked as skipped
              if (testContext.wasSkipped) {
                testStatus = "skipped";
                // Don't increment passedTests or failedTests for skipped tests
              } else {
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
              } else if (testStatus === "skipped") {
                logger.debug(`⏸️ ${fullModuleName} - ${testName} skipped`);
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
                    testContext.wasSkipped = true;
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "CREATE"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - CREATE skipped: ${skipCheck.reason}`
                    );
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    hasValidCreateOperation = false;
                    return;
                  }

                  logger.info(`🔄 ${fullModuleName} - PHASE 1: CREATE`);

                  const { createdId, response, originalData } =
                    await crudHelper.runCreateTest("CREATE");

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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - INITIAL VIEW skipped: No resource ID (CREATE was skipped or failed)`
                    );
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  const skipCheck = skipIfNoValidOperations(
                    moduleConfig,
                    "EDIT"
                  );
                  if (skipCheck.skip) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - UPDATE skipped: ${skipCheck.reason}`
                    );
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - UPDATE skipped: No resource ID (CREATE was skipped or failed)`
                    );
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  logger.info(`✏️ ${fullModuleName} - PHASE 3: UPDATE`);

                  const { response, updatedData } =
                    await crudHelper.runUpdateTest("EDIT");

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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - POST-UPDATE VIEW skipped: No resource ID (CREATE was skipped or failed)`
                    );
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - DELETE skipped: No resource ID (CREATE was skipped or failed)`
                    );
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
                    return;
                  }

                  if (!hasValidCreateOperation || !createdResourceId) {
                    logger.warn(
                      `⏸️ ${fullModuleName} - NEGATIVE VIEW skipped: No resource ID (CREATE was skipped or failed)`
                    );
                    crudTestSummary.skippedTests++;
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
                    testContext.wasSkipped = true;
                    crudTestSummary.skippedTests++;
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
        const newPath = parentPath ? `${parentPath}.${moduleName}` : moduleName;
        logger.debug(`  Recursing into ${moduleName} (path: ${newPath})`);
        runCompleteCRUDLifecycleOnAllModules(moduleConfig, newPath);
      }
    });
  };

  // Debug: Log what we're working with
  const schemaToUse = modulesConfig.schema || modulesConfig;
  logger.info(`About to process schema with ${Object.keys(schemaToUse).length} top-level keys`);
  logger.info(`Top-level keys: ${Object.keys(schemaToUse).join(', ')}`);
  
  // Check first module structure
  const firstKey = Object.keys(schemaToUse)[0];
  if (firstKey) {
    const firstModule = schemaToUse[firstKey];
    logger.info(`First key "${firstKey}" type: ${typeof firstModule}`);
    logger.info(`First key has endpoints: ${hasEndpoints(firstModule)}`);
    if (typeof firstModule === 'object') {
      logger.info(`First key sub-keys: ${Object.keys(firstModule).slice(0, 5).join(', ')}`);
    }
  }
  
  // Run complete CRUD lifecycle on all modules
  // This MUST be called synchronously during test discovery
  runCompleteCRUDLifecycleOnAllModules(schemaToUse);
  
  logger.info(`After processing: ${crudTestSummary.modulesTested} modules tested`);
  
  // Dummy test to ensure Jest doesn't complain if no modules found
  if (crudTestSummary.modulesTested === 0) {
    test("No testable modules found", () => {
      logger.warn("No testable modules were found in the schema");
      expect(modulesConfig).toBeDefined();
    });
  }
});
