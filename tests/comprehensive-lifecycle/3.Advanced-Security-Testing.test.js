// tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js
const {
  testBusinessLogicFlaws,
  testPrivilegeEscalation,
  testMassAssignment,
  testIDORVulnerabilities,
  testRaceConditions,
} = require("../../utils/advanced-security-helpers");
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const { TEST_TAGS, FILE_PATHS, HTTP_STATUS_CODES } = require("../../Constants");

/**
 *
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

    logger.info(
      `🏁 Completed advanced security tests for ${securityTestSummary.modulesTested} modules`
    );
  });

  /**
   * ENHANCED ADVANCED SECURITY TESTING FUNCTION
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
            logger.info(
              `🛡️ Starting advanced security tests for: ${fullModuleName}`
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
            try {
              testContext.testType = "business_logic_flaws";
              testContext.operation = "price_manipulation";

              logger.info(
                `💰 Testing business logic flaws for ${fullModuleName}`
              );

              const businessLogicResults = await testBusinessLogicFlaws(
                moduleConfig,
                fullModuleName
              );

              securityResults.businessLogic = businessLogicResults;

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
          }, 30000);

          test("🎯 [TC-2] Privilege Escalation - Horizontal & Vertical", async () => {
            try {
              testContext.testType = "privilege_escalation";
              testContext.operation = "access_control";

              logger.info(
                `🔄 Testing privilege escalation for ${fullModuleName}`
              );

              const privilegeResults = await testPrivilegeEscalation(
                moduleConfig,
                fullModuleName
              );

              securityResults.privilegeEscalation = privilegeResults;

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
          }, 30000);

          test("🎯 [TC-3] Mass Assignment Vulnerabilities", async () => {
            try {
              testContext.testType = "mass_assignment";
              testContext.operation = "parameter_pollution";

              logger.info(`📦 Testing mass assignment for ${fullModuleName}`);

              const massAssignmentResults = await testMassAssignment(
                moduleConfig,
                fullModuleName
              );

              securityResults.massAssignment = massAssignmentResults;

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
          }, 30000);

          test("🎯 [TC-4] Insecure Direct Object References (IDOR)", async () => {
            try {
              testContext.testType = "idor";
              testContext.operation = "object_reference";

              logger.info(
                `🔗 Testing IDOR vulnerabilities for ${fullModuleName}`
              );

              const idorResults = await testIDORVulnerabilities(
                moduleConfig,
                fullModuleName
              );

              securityResults.idor = idorResults;

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

              logger.info(`✅ IDOR testing completed for ${fullModuleName}`);
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
          }, 30000);

          test("🎯 [TC-5] Race Conditions & Concurrency", async () => {
            try {
              testContext.testType = "race_conditions";
              testContext.operation = "concurrency";

              logger.info(`🏁 Testing race conditions for ${fullModuleName}`);

              const raceConditionResults = await testRaceConditions(
                moduleConfig,
                fullModuleName
              );

              securityResults.raceConditions = raceConditionResults;

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
          }, 45000);
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
  runAdvancedSecurityOnAllModules(FILE_PATHS.SCHEMA_PATH);
});
