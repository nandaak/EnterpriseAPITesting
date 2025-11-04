const TestHelpers = require("../../utils/test-helpers");
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const {
  schema,
  TEST_TAGS,
  HTTP_STATUS_CODES,
} = require("../../Constants/Constants");

/**
 * ADVANCED SECURITY TESTING SUITE
 *
 * Enhanced version with real security tests targeting actual vulnerabilities
 * Purpose: Test sophisticated security scenarios beyond basic validation
 * Coverage: Business logic flaws, privilege escalation, mass assignment, IDOR, etc.
 * Scope: Comprehensive security testing across all ERP modules
 *
 * @version 2.0.0
 * @author Mohamed Said Ibrahim
 */

describe("Advanced Security Testing", () => {
  const testResults = [];
  let securityTestSummary = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    modulesTested: 0,
    vulnerabilitiesFound: 0,
    startTime: null,
    endTime: null,
  };

  beforeAll(() => {
    securityTestSummary.startTime = new Date().toISOString();

    if (global.allure) {
      global.allure.epic("Security Testing");
      global.allure.feature("Advanced Security Scenarios");
      global.allure.addLabel("framework", "Jest");
      global.allure.addLabel("language", "JavaScript");
      global.allure.addLabel("testType", "security");
      global.allure.addLabel("priority", "critical");
    }

    logger.info("🔒 Starting Advanced Security Testing");
    logger.info("=".repeat(60));
  });

  afterAll(() => {
    securityTestSummary.endTime = new Date().toISOString();

    // Generate comprehensive security test report
    const summary = {
      execution: {
        ...securityTestSummary,
        duration: securityTestSummary.endTime
          ? new Date(securityTestSummary.endTime) -
            new Date(securityTestSummary.startTime)
          : 0,
      },
      modules: {
        total: securityTestSummary.modulesTested,
        tested: testResults.length,
        passed: testResults.filter((r) => r.status === "passed").length,
        failed: testResults.filter((r) => r.status === "failed").length,
        vulnerabilities: securityTestSummary.vulnerabilitiesFound,
      },
      security: {
        businessLogic: testResults.filter(
          (r) => r.securityResults?.businessLogic
        ).length,
        privilegeEscalation: testResults.filter(
          (r) => r.securityResults?.privilegeEscalation
        ).length,
        massAssignment: testResults.filter(
          (r) => r.securityResults?.massAssignment
        ).length,
        idor: testResults.filter((r) => r.securityResults?.idor).length,
        raceConditions: testResults.filter(
          (r) => r.securityResults?.raceConditions
        ).length,
      },
    };

    logger.info("📊 ADVANCED SECURITY TEST SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`   Total Modules: ${summary.modules.total}`);
    logger.info(`   Tested Modules: ${summary.modules.tested}`);
    logger.info(`   ✅ Passed Tests: ${securityTestSummary.passedTests}`);
    logger.info(`   ❌ Failed Tests: ${securityTestSummary.failedTests}`);
    logger.info(
      `   ⚠️  Vulnerabilities Found: ${securityTestSummary.vulnerabilitiesFound}`
    );
    logger.info(`   ⏱️  Total Duration: ${summary.execution.duration}ms`);
    logger.info("=".repeat(50));

    global.attachJSON("Advanced Security Test Execution Summary", summary);
    global.attachAllureLog("Detailed Security Results", testResults);

    logger.info(
      `🏁 Completed advanced security tests for ${securityTestSummary.modulesTested} modules`
    );
  });

  /**
   * ENHANCED ADVANCED SECURITY TESTING FUNCTION
   * Implements real security tests targeting actual vulnerabilities
   */
  const runAdvancedSecurityOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const hasEndpoints =
        moduleConfig.Post ||
        moduleConfig.PUT ||
        moduleConfig.DELETE ||
        moduleConfig.View ||
        moduleConfig.EDIT ||
        moduleConfig.LookUP ||
        moduleConfig.Commit;

      if (hasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        securityTestSummary.modulesTested++;

        describe(`Advanced Security Testing: ${fullModuleName}`, () => {
          let moduleStartTime;
          let securityResults = {};
          let testContext = {};
          let moduleTestCount = 0;
          let createdResourceIds = {};

          beforeAll(async () => {
            moduleStartTime = Date.now();

            if (global.allure) {
              global.allure.story(fullModuleName);
              global.allure.addLabel("module", fullModuleName);
            }

            logger.info(
              `🛡️ Starting advanced security tests for: ${fullModuleName}`
            );

            // Log module configuration for security testing
            global.attachJSON(
              `Advanced Security Configuration - ${fullModuleName}`,
              {
                module: fullModuleName,
                availableEndpoints: Object.keys(moduleConfig).filter(
                  (key) =>
                    Array.isArray(moduleConfig[key]) &&
                    moduleConfig[key][0] &&
                    moduleConfig[key][0] !== "URL_HERE"
                ),
                endpoints: Object.entries(moduleConfig).reduce(
                  (acc, [key, value]) => {
                    if (
                      Array.isArray(value) &&
                      value[0] &&
                      value[0] !== "URL_HERE"
                    ) {
                      acc[key] = value[0];
                    }
                    return acc;
                  },
                  {}
                ),
              }
            );
          });

          afterAll(() => {
            const moduleDuration = Date.now() - moduleStartTime;
            logger.info(
              `✅ Completed advanced security tests for ${fullModuleName} in ${moduleDuration}ms`
            );
          });

          beforeEach(() => {
            testContext = {
              module: fullModuleName,
              startTime: new Date().toISOString(),
              endpoints: Object.keys(moduleConfig).filter(
                (key) =>
                  Array.isArray(moduleConfig[key]) &&
                  moduleConfig[key][0] !== "URL_HERE"
              ),
            };
          });

          afterEach(() => {
            const testState = expect.getState();
            const testName = testState.currentTestName || "Unknown Test";
            moduleTestCount++;
            securityTestSummary.totalTests++;

            // Determine test status and update summary
            let testStatus = "passed";
            try {
              if (
                testState.snapshotState &&
                testState.snapshotState.unmatched > 0
              ) {
                testStatus = "failed";
                securityTestSummary.failedTests++;
              } else {
                securityTestSummary.passedTests++;
              }
            } catch (e) {
              testStatus = "failed";
              securityTestSummary.failedTests++;
            }

            const testResult = {
              module: fullModuleName,
              status: testStatus,
              securityResults,
              timestamp: new Date().toISOString(),
              testName: testName,
              context: testContext,
              testCount: moduleTestCount,
              vulnerabilities: securityTestSummary.vulnerabilitiesFound,
            };

            testResults.push(testResult);

            global.attachAllureLog(
              `Advanced Security Test Result - ${fullModuleName}`,
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
          // 🎯 REAL ADVANCED SECURITY TESTS - No Simulations
          // =========================================================================

          test("🎯 [TC-1] Business Logic Flaws - Price Manipulation", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Business Logic Security");
              global.allure.description(
                `Test for business logic vulnerabilities like price manipulation in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "business-logic");
            }

            await global.allureStep(
              `Business Logic Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "business_logic_flaws";
                  testContext.operation = "price_manipulation";

                  logger.info(
                    `💰 Testing business logic flaws for ${fullModuleName}`
                  );

                  const businessLogicResults =
                    await TestHelpers.testBusinessLogicFlaws(
                      moduleConfig,
                      fullModuleName
                    );

                  securityResults.businessLogic = businessLogicResults;

                  global.attachJSON(
                    `Business Logic Test Results - ${fullModuleName}`,
                    businessLogicResults
                  );

                  // Check for vulnerabilities
                  if (
                    businessLogicResults.vulnerabilities &&
                    businessLogicResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      businessLogicResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  Business logic vulnerabilities found in ${fullModuleName}: ${businessLogicResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !businessLogicResults.success &&
                    businessLogicResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `Business logic vulnerabilities detected: ${businessLogicResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ Business logic testing completed for ${fullModuleName}`
                  );
                  return businessLogicResults;
                } catch (error) {
                  logger.error(
                    `❌ Business logic testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.businessLogic = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 30000);

          test("🎯 [TC-2] Privilege Escalation - Horizontal & Vertical", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Privilege Escalation");
              global.allure.description(
                `Test for privilege escalation vulnerabilities in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "privilege-escalation");
            }

            await global.allureStep(
              `Privilege Escalation Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "privilege_escalation";
                  testContext.operation = "access_control";

                  logger.info(
                    `🔄 Testing privilege escalation for ${fullModuleName}`
                  );

                  const privilegeResults =
                    await TestHelpers.testPrivilegeEscalation(
                      moduleConfig,
                      fullModuleName
                    );

                  securityResults.privilegeEscalation = privilegeResults;

                  global.attachJSON(
                    `Privilege Escalation Results - ${fullModuleName}`,
                    privilegeResults
                  );

                  // Check for vulnerabilities
                  if (
                    privilegeResults.vulnerabilities &&
                    privilegeResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      privilegeResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  Privilege escalation vulnerabilities found in ${fullModuleName}: ${privilegeResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !privilegeResults.success &&
                    privilegeResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `Privilege escalation vulnerabilities detected: ${privilegeResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ Privilege escalation testing completed for ${fullModuleName}`
                  );
                  return privilegeResults;
                } catch (error) {
                  logger.error(
                    `❌ Privilege escalation testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.privilegeEscalation = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 30000);

          test("🎯 [TC-3] Mass Assignment Vulnerabilities", async () => {
            if (global.allure) {
              global.allure.severity("high");
              global.allure.story("Mass Assignment");
              global.allure.description(
                `Test for mass assignment vulnerabilities in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "mass-assignment");
            }

            await global.allureStep(
              `Mass Assignment Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "mass_assignment";
                  testContext.operation = "parameter_pollution";

                  logger.info(
                    `📦 Testing mass assignment for ${fullModuleName}`
                  );

                  const massAssignmentResults =
                    await TestHelpers.testMassAssignment(
                      moduleConfig,
                      fullModuleName
                    );

                  securityResults.massAssignment = massAssignmentResults;

                  global.attachJSON(
                    `Mass Assignment Results - ${fullModuleName}`,
                    massAssignmentResults
                  );

                  // Check for vulnerabilities
                  if (
                    massAssignmentResults.vulnerabilities &&
                    massAssignmentResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      massAssignmentResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  Mass assignment vulnerabilities found in ${fullModuleName}: ${massAssignmentResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !massAssignmentResults.success &&
                    massAssignmentResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `Mass assignment vulnerabilities detected: ${massAssignmentResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ Mass assignment testing completed for ${fullModuleName}`
                  );
                  return massAssignmentResults;
                } catch (error) {
                  logger.error(
                    `❌ Mass assignment testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.massAssignment = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 30000);

          test("🎯 [TC-4] Insecure Direct Object References (IDOR)", async () => {
            if (global.allure) {
              global.allure.severity("high");
              global.allure.story("IDOR Vulnerabilities");
              global.allure.description(
                `Test for Insecure Direct Object References in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "idor");
            }

            await global.allureStep(
              `IDOR Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "idor";
                  testContext.operation = "object_reference";

                  logger.info(
                    `🔗 Testing IDOR vulnerabilities for ${fullModuleName}`
                  );

                  const idorResults = await TestHelpers.testIDORVulnerabilities(
                    moduleConfig,
                    fullModuleName
                  );

                  securityResults.idor = idorResults;

                  global.attachJSON(
                    `IDOR Test Results - ${fullModuleName}`,
                    idorResults
                  );

                  // Check for vulnerabilities
                  if (
                    idorResults.vulnerabilities &&
                    idorResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      idorResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  IDOR vulnerabilities found in ${fullModuleName}: ${idorResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !idorResults.success &&
                    idorResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `IDOR vulnerabilities detected: ${idorResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ IDOR testing completed for ${fullModuleName}`
                  );
                  return idorResults;
                } catch (error) {
                  logger.error(
                    `❌ IDOR testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.idor = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 30000);

          test("🎯 [TC-5] Race Conditions & Concurrency", async () => {
            if (global.allure) {
              global.allure.severity("medium");
              global.allure.story("Race Conditions");
              global.allure.description(
                `Test for race condition vulnerabilities in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "race-conditions");
            }

            await global.allureStep(
              `Race Condition Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "race_conditions";
                  testContext.operation = "concurrency";

                  logger.info(
                    `🏁 Testing race conditions for ${fullModuleName}`
                  );

                  const raceConditionResults =
                    await TestHelpers.testRaceConditions(
                      moduleConfig,
                      fullModuleName
                    );

                  securityResults.raceConditions = raceConditionResults;

                  global.attachJSON(
                    `Race Condition Results - ${fullModuleName}`,
                    raceConditionResults
                  );

                  // Check for vulnerabilities
                  if (
                    raceConditionResults.vulnerabilities &&
                    raceConditionResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      raceConditionResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  Race condition vulnerabilities found in ${fullModuleName}: ${raceConditionResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !raceConditionResults.success &&
                    raceConditionResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `Race condition vulnerabilities detected: ${raceConditionResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ Race condition testing completed for ${fullModuleName}`
                  );
                  return raceConditionResults;
                } catch (error) {
                  logger.error(
                    `❌ Race condition testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.raceConditions = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 45000);

          test("🎯 [TC-6] Advanced Input Validation Bypass", async () => {
            if (global.allure) {
              global.allure.severity("high");
              global.allure.story("Input Validation Bypass");
              global.allure.description(
                `Test for advanced input validation bypass techniques in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("test-type", "input-validation");
            }

            await global.allureStep(
              `Advanced Input Validation Testing for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "input_validation_bypass";
                  testContext.operation = "validation_bypass";

                  logger.info(
                    `🎯 Testing advanced input validation bypass for ${fullModuleName}`
                  );

                  const inputValidationResults =
                    await TestHelpers.testAdvancedInputValidation(
                      moduleConfig,
                      fullModuleName
                    );

                  securityResults.inputValidation = inputValidationResults;

                  global.attachJSON(
                    `Advanced Input Validation Results - ${fullModuleName}`,
                    inputValidationResults
                  );

                  // Check for vulnerabilities
                  if (
                    inputValidationResults.vulnerabilities &&
                    inputValidationResults.vulnerabilities.length > 0
                  ) {
                    securityTestSummary.vulnerabilitiesFound +=
                      inputValidationResults.vulnerabilities.length;
                    logger.warn(
                      `⚠️  Input validation bypass vulnerabilities found in ${fullModuleName}: ${inputValidationResults.vulnerabilities.length}`
                    );
                  }

                  if (
                    !inputValidationResults.success &&
                    inputValidationResults.vulnerabilities.length > 0
                  ) {
                    throw new Error(
                      `Input validation bypass vulnerabilities detected: ${inputValidationResults.vulnerabilities.join(
                        ", "
                      )}`
                    );
                  }

                  logger.info(
                    `✅ Advanced input validation testing completed for ${fullModuleName}`
                  );
                  return inputValidationResults;
                } catch (error) {
                  logger.error(
                    `❌ Advanced input validation testing failed for ${fullModuleName}: ${error.message}`
                  );
                  securityResults.inputValidation = {
                    success: false,
                    error: error.message,
                  };
                  throw error;
                }
              }
            );
          }, 30000);
        });
      }

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && !hasEndpoints) {
        runAdvancedSecurityOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run advanced security tests on all modules
  runAdvancedSecurityOnAllModules(schema);
});
