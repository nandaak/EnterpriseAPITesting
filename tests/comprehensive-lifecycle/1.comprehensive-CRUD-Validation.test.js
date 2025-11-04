// tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js - Enhanced for Multi-Module Schema
const CrudLifecycleHelper = require("../../utils/crud-lifecycle-helper");
const logger = require("../../utils/logger");
const Constants = require("../../Constants");
const modulesConfig = require("../../config/modules-config");
const { URL } = require("url");

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
    if (!moduleConfig?.operations) return false;

    const requiredOps = ["Post", "View"]; // At minimum need CREATE and VIEW
    const validOps = requiredOps.filter(
      (op) =>
        moduleConfig.operations[op] &&
        isValidUrl(moduleConfig.operations[op].endpoint)
    );

    return validOps.length >= 2; // Need at least CREATE and one other operation
  };

  // Skip test if no valid operations are available
  const skipIfNoValidOperations = (moduleConfig, operationType) => {
    if (!moduleConfig?.operations?.[operationType]) {
      return {
        skip: true,
        reason: `Operation '${operationType}' not configured`,
      };
    }

    const operation = moduleConfig.operations[operationType];
    if (!isValidUrl(operation.endpoint)) {
      return {
        skip: true,
        reason: `Invalid URL for operation '${operationType}': ${operation.endpoint}`,
      };
    }

    return { skip: false };
  };

  // Allure suite setup
  beforeAll(() => {
    crudTestSummary.startTime = new Date().toISOString();

    if (global.allure) {
      global.allure.epic("Enterprise API Testing");
      global.allure.feature("CRUD Lifecycle Operations");
      global.allure.story("Multi-Module CRUD Operations");
      global.allure.addLabel("suite", "comprehensive-crud");
      global.allure.addLabel("framework", "Jest");
      global.allure.addLabel("language", "JavaScript");
      global.allure.addLabel("testType", "functional");
      global.allure.addLabel("priority", "high");
    }

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

    global.attachJSON("CRUD Test Execution Summary", summary);
    global.attachAllureLog("Detailed CRUD Results", testResults);

    logger.info(
      `🏁 Completed CRUD tests for ${crudTestSummary.modulesTested} modules`
    );
  });

  /**
   * ENHANCED MODULE TESTING FUNCTION
   * Following the successful pattern from security tests
   */
  const runCRUDTestsOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const hasEndpoints =
        moduleConfig.Post ||
        moduleConfig.PUT ||
        moduleConfig.DELETE ||
        moduleConfig.View ||
        moduleConfig.EDIT ||
        moduleConfig.LookUP ||
        moduleConfig.Commit ||
        moduleConfig.GET;

      if (hasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        crudTestSummary.modulesTested++;
        if (!fullModuleName.includes("Reports"))
          describe(`CRUD Testing: ${fullModuleName}`, () => {
            let moduleStartTime;
            let crudResults = {};
            let testContext = {};
            let moduleTestCount = 0;
            let hasValidCreateOperation = false;
            let createdResourceId = null;

            beforeAll(async () => {
              moduleStartTime = Date.now();

              if (global.allure) {
                global.allure.story(fullModuleName);
                global.allure.addLabel("module", fullModuleName);
              }

              // Initialize CRUD helper for this module
              crudHelper = new CrudLifecycleHelper(fullModuleName);
              await crudHelper.initialize();

              // Determine if module has valid CREATE operation
              hasValidCreateOperation =
                moduleConfig.Post && isValidUrl(moduleConfig.Post.endpoint);

              logger.info(`🎯 Starting CRUD tests for: ${fullModuleName}`);
              logger.info(
                `📊 Has valid CREATE operation: ${hasValidCreateOperation}`
              );

              // Log module configuration details
              global.attachJSON(`Module Configuration - ${fullModuleName}`, {
                selectedModule: fullModuleName,
                hasValidCreateOperation: hasValidCreateOperation,
                operations: moduleConfig ? Object.keys(moduleConfig) : [],
                operationDetails: moduleConfig
                  ? Object.entries(moduleConfig).reduce((acc, [key, op]) => {
                      if (Array.isArray(op) && op[0]) {
                        acc[key] = {
                          endpoint: op[0],
                          isValid: isValidUrl(op[0]),
                        };
                      }
                      return acc;
                    }, {})
                  : {},
              });
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

              global.attachAllureLog(
                `CRUD Test Result - ${fullModuleName}`,
                testResult
              );

              if (testStatus === "passed") {
                logger.debug(
                  `✅ ${fullModuleName} - ${testName} completed successfully`
                );
              } else {
                logger.error(`❌ ${fullModuleName} - ${testName} failed`);
              }
            });

            // =========================================================================
            // 🎯 COMPREHENSIVE CRUD TESTS - Enhanced for Multi-Module Schema
            // =========================================================================

            test(
              "🎯 [TC-1] CREATE - Successfully create a new resource",
              async () => {
                if (global.allure) {
                  global.allure.severity("critical");
                  global.allure.description(
                    "Test the creation of a new resource through POST operation"
                  );
                  global.allure.addLabel("operation", "CREATE");
                  global.allure.addLabel("module", fullModuleName);
                }

                await global.allureStep(
                  `CREATE Operation for ${fullModuleName}`,
                  async () => {
                    try {
                      testContext.operation = "CREATE";

                      // Skip if no valid POST operation
                      const skipCheck = skipIfNoValidOperations(
                        moduleConfig,
                        "Post"
                      );
                      if (skipCheck.skip) {
                        logger.warn(
                          `⏸️ CREATE test skipped: ${skipCheck.reason}`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("CREATE Test Skipped", {
                          reason: skipCheck.reason,
                          module: fullModuleName,
                          operationEndpoint:
                            moduleConfig?.Post?.[0] || "Not configured",
                          recommendation:
                            "Update schema with valid endpoint URL",
                        });

                        // Mark test as passed when skipped due to configuration
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

                      // Attach validation details to Allure
                      global.attachJSON("CREATE Validation Details", {
                        status: response.status,
                        createdId: createdIdString,
                        extractionMethod:
                          extractionDetails?.operation || "unknown",
                        idLength: createdIdString.length,
                        isUUID:
                          createdIdString.includes("-") &&
                          createdIdString.length === 36,
                        module: fullModuleName,
                      });

                      // Validate ID format
                      if (
                        createdIdString.includes("-") &&
                        createdIdString.length === 36
                      ) {
                        logger.info(`✅ ID is UUID format: ${createdIdString}`);
                        global.allure.addLabel("idFormat", "UUID");
                      } else {
                        logger.info(`✅ ID format: ${createdIdString}`);
                        global.allure.addLabel("idFormat", "Custom");
                      }

                      // Verify file persistence
                      const fs = require("fs");
                      expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(
                        true
                      );

                      const fileContent = fs
                        .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
                        .trim();
                      expect(fileContent).toBe(createdIdString);

                      global.attachAllureLog("File Persistence Verified", {
                        txtFile: FILE_PATHS.CREATED_ID_TXT,
                        jsonFile: FILE_PATHS.CREATED_ID_FILE,
                        contentMatches: fileContent === createdIdString,
                        module: fullModuleName,
                      });

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
                  }
                );
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-2] VIEW - Retrieve the newly created resource",
              async () => {
                if (global.allure) {
                  global.allure.severity("high");
                  global.allure.description(
                    "Test retrieval of the created resource through VIEW operation"
                  );
                  global.allure.addLabel("operation", "VIEW");
                  global.allure.addLabel("module", fullModuleName);
                }

                await global.allureStep(
                  `VIEW Operation for ${fullModuleName}`,
                  async () => {
                    try {
                      testContext.operation = "VIEW";

                      // Skip if no valid VIEW operation
                      const skipCheck = skipIfNoValidOperations(
                        moduleConfig,
                        "View"
                      );
                      if (skipCheck.skip) {
                        logger.warn(
                          `⏸️ VIEW test skipped: ${skipCheck.reason}`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("VIEW Test Skipped", {
                          reason: skipCheck.reason,
                          module: fullModuleName,
                          operationEndpoint:
                            moduleConfig?.View?.[0] || "Not configured",
                        });

                        expect(true).toBe(true);
                        return;
                      }

                      // Skip VIEW test if CREATE was skipped (no ID available)
                      if (!hasValidCreateOperation || !createdResourceId) {
                        logger.warn(
                          `⏸️ VIEW test skipped: No valid CREATE operation or resource ID`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("VIEW Test Skipped", {
                          reason:
                            "CREATE operation was not executed or no resource ID available",
                          module: fullModuleName,
                          dependency:
                            "CREATE test must run first to generate resource ID",
                          hasValidCreateOperation: hasValidCreateOperation,
                          createdResourceId: createdResourceId,
                        });

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

                      global.attachJSON("VIEW Operation Results", {
                        status: response.status,
                        resourceId: createdResourceId,
                        validation: "SUCCESS",
                        module: fullModuleName,
                      });

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
                  }
                );
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-3] UPDATE - Modify and verify the created resource",
              async () => {
                if (global.allure) {
                  global.allure.severity("high");
                  global.allure.description(
                    "Test modification of the created resource through UPDATE operation"
                  );
                  global.allure.addLabel("operation", "UPDATE");
                  global.allure.addLabel("module", fullModuleName);
                }

                await global.allureStep(
                  `UPDATE Operation for ${fullModuleName}`,
                  async () => {
                    try {
                      testContext.operation = "UPDATE";

                      // Skip if no valid PUT operation
                      const skipCheck = skipIfNoValidOperations(
                        moduleConfig,
                        "PUT"
                      );
                      if (skipCheck.skip) {
                        logger.warn(
                          `⏸️ UPDATE test skipped: ${skipCheck.reason}`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("UPDATE Test Skipped", {
                          reason: skipCheck.reason,
                          module: fullModuleName,
                          operationEndpoint:
                            moduleConfig?.PUT?.[0] || "Not configured",
                        });

                        expect(true).toBe(true);
                        return;
                      }

                      // Skip UPDATE test if CREATE was skipped (no ID available)
                      if (!hasValidCreateOperation || !createdResourceId) {
                        logger.warn(
                          `⏸️ UPDATE test skipped: No valid CREATE operation or resource ID`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("UPDATE Test Skipped", {
                          reason:
                            "CREATE operation was not executed or no resource ID available",
                          module: fullModuleName,
                          dependency:
                            "CREATE test must run first to generate resource ID",
                        });

                        expect(true).toBe(true);
                        return;
                      }

                      logger.info(
                        `✏️ Testing UPDATE operation for ${fullModuleName}`
                      );

                      crudHelper.enforcePrerequisite("createdId");
                      const { response } = await crudHelper.runUpdateTest(
                        "PUT"
                      );

                      // Enhanced status validation for UPDATE
                      const validStatuses = [
                        HTTP_STATUS_CODES.OK,
                        HTTP_STATUS_CODES.ACCEPTED,
                        HTTP_STATUS_CODES.NO_CONTENT,
                      ];
                      expect(validStatuses).toContain(response.status);

                      global.attachJSON("UPDATE Operation Results", {
                        status: response.status,
                        resourceId: createdResourceId,
                        expectedStatuses: validStatuses,
                        validation: "SUCCESS",
                        module: fullModuleName,
                      });

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
                  }
                );
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-4] DELETE - Remove the resource",
              async () => {
                if (global.allure) {
                  global.allure.severity("critical");
                  global.allure.description(
                    "Test deletion of the resource through DELETE operation"
                  );
                  global.allure.addLabel("operation", "DELETE");
                  global.allure.addLabel("module", fullModuleName);
                }

                await global.allureStep(
                  `DELETE Operation for ${fullModuleName}`,
                  async () => {
                    try {
                      testContext.operation = "DELETE";

                      // Skip if no valid DELETE operation
                      const skipCheck = skipIfNoValidOperations(
                        moduleConfig,
                        "DELETE"
                      );
                      if (skipCheck.skip) {
                        logger.warn(
                          `⏸️ DELETE test skipped: ${skipCheck.reason}`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("DELETE Test Skipped", {
                          reason: skipCheck.reason,
                          module: fullModuleName,
                          operationEndpoint:
                            moduleConfig?.DELETE?.[0] || "Not configured",
                        });

                        expect(true).toBe(true);
                        return;
                      }

                      // Skip DELETE test if CREATE was skipped (no ID available)
                      if (!hasValidCreateOperation || !createdResourceId) {
                        logger.warn(
                          `⏸️ DELETE test skipped: No valid CREATE operation or resource ID`
                        );
                        crudTestSummary.skippedTests++;

                        global.attachJSON("DELETE Test Skipped", {
                          reason:
                            "CREATE operation was not executed or no resource ID available",
                          module: fullModuleName,
                          dependency:
                            "CREATE test must run first to generate resource ID",
                        });

                        expect(true).toBe(true);
                        return;
                      }

                      logger.info(
                        `🗑️ Testing DELETE operation for ${fullModuleName}`
                      );

                      crudHelper.enforcePrerequisite("createdId");
                      const { response } = await crudHelper.runDeleteTest(
                        "DELETE"
                      );

                      // Enhanced status validation for DELETE
                      const validStatuses = [
                        HTTP_STATUS_CODES.OK,
                        HTTP_STATUS_CODES.NO_CONTENT,
                        HTTP_STATUS_CODES.ACCEPTED,
                      ];
                      expect(validStatuses).toContain(response.status);

                      global.attachJSON("DELETE Operation Results", {
                        status: response.status,
                        expectedStatuses: validStatuses,
                        validation: "SUCCESS",
                        module: fullModuleName,
                      });

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
                  }
                );
              },
              TEST_CONFIG.TIMEOUT.MEDIUM
            );

            test(
              "🎯 [TC-5] CONFIGURATION - Verify module configuration integrity",
              async () => {
                if (global.allure) {
                  global.allure.severity("normal");
                  global.allure.description(
                    "Verify that module configuration is properly loaded and valid"
                  );
                  global.allure.addLabel("operation", "CONFIGURATION");
                  global.allure.addLabel("module", fullModuleName);
                }

                await global.allureStep(
                  `Configuration Validation for ${fullModuleName}`,
                  async () => {
                    try {
                      testContext.operation = "CONFIGURATION";

                      expect(moduleConfig).toBeDefined();
                      expect(Object.keys(moduleConfig).length).toBeGreaterThan(
                        0
                      );

                      // Verify each operation has required properties and valid URLs
                      Object.entries(moduleConfig).forEach(
                        ([operationName, operation]) => {
                          if (Array.isArray(operation) && operation[0]) {
                            expect(operation[0]).toBeDefined();
                            expect(typeof operation[0]).toBe("string");
                            expect(operation[0].length).toBeGreaterThan(0);

                            // Log URL validity
                            const isValid = isValidUrl(operation[0]);
                            global.attachAllureLog(
                              `Operation ${operationName} Validation`,
                              {
                                endpoint: operation[0],
                                isValidUrl: isValid,
                                operationType: operationName,
                              }
                            );
                          }
                        }
                      );

                      // Count valid vs invalid URLs
                      const operationStats = Object.entries(
                        moduleConfig
                      ).reduce(
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

                      global.attachJSON("Module Configuration Validation", {
                        module: fullModuleName,
                        operationCount: Object.keys(moduleConfig).length,
                        validOperations: operationStats.valid,
                        invalidOperations: operationStats.invalid,
                        operations: operationStats.operations,
                        validation:
                          operationStats.valid > 0
                            ? "PARTIAL_SUCCESS"
                            : "FAILED",
                        hasValidCreateOperation: hasValidCreateOperation,
                        note:
                          operationStats.invalid > 0
                            ? "Some operations have invalid URLs (URL_HERE)"
                            : "All operations have valid URLs",
                      });

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
                  }
                );
              },
              TEST_CONFIG.TIMEOUT.SHORT
            );
          });
      }

      // Recursively test nested modules following the same pattern
      if (typeof moduleConfig === "object" && !hasEndpoints) {
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
