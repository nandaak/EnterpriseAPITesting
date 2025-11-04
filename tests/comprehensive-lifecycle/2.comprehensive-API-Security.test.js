const fs = require("fs");
const path = require("path");
const TestHelpers = require("../../utils/test-helpers");
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const {
  TEST_TAGS,
  FILE_PATHS,
  HTTP_STATUS_CODES,
} = require("../../Constants/Constants");

/**
 * COMPREHENSIVE API SECURITY TESTING SUITE
 * 
 * Enhanced version following the successful pattern from 3.Advanced-Security-Testing.test.js
 * Purpose: Test security across all backend API modules in the ERP system
 * Coverage: Authorization, Input Validation, SQL Injection, XSS, Data Validation
 * Scope: Automatically discovers and tests all modules with endpoints from schema
 *
 * @version 2.0.0
 * @author Mohamed Said Ibrahim
 */

// Load the generated schema with enhanced error handling
let schema = {};
try {
  if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
    const schemaContent = fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8");
    schema = JSON.parse(schemaContent);
    logger.info(`✅ Schema loaded successfully from: ${FILE_PATHS.SCHEMA_PATH}`);
    logger.debug(`📁 Schema structure: ${Object.keys(schema).join(", ")}`);
  } else {
    throw new Error(`Schema file not found at: ${FILE_PATHS.SCHEMA_PATH}`);
  }
} catch (error) {
  logger.error(`❌ Failed to load schema: ${error.message}`);
  throw error;
}

describe("Comprehensive API Security Testing", () => {
  const testResults = [];
  let securityTestSummary = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    modulesTested: 0,
    startTime: null,
    endTime: null,
  };

  beforeAll(() => {
    securityTestSummary.startTime = new Date().toISOString();

    // Set epic and feature for all tests in this suite
    if (global.allure) {
      global.allure.epic("Enterprise API Testing");
      global.allure.feature("Comprehensive Security Testing");
      global.allure.addLabel("framework", "Jest");
      global.allure.addLabel("language", "JavaScript");
      global.allure.addLabel("testType", "security");
      global.allure.addLabel("priority", "high");
    }

    logger.info("🔒 Starting Comprehensive API Security Testing");
    logger.info("=".repeat(60));
  });

  afterAll(() => {
    securityTestSummary.endTime = new Date().toISOString();

    // Generate comprehensive test report
    const summary = {
      execution: {
        ...securityTestSummary,
        duration: securityTestSummary.endTime 
          ? new Date(securityTestSummary.endTime) - new Date(securityTestSummary.startTime)
          : 0
      },
      modules: {
        total: securityTestSummary.modulesTested,
        tested: testResults.length,
        healthy: testResults.filter(r => r.status === "passed").length,
        failed: testResults.filter(r => r.status === "failed").length,
      },
      security: {
        authorization: testResults.filter(r => r.securityResults?.authorization).length,
        maliciousPayloads: testResults.filter(r => r.securityResults?.maliciousPayloads).length,
        sqlInjection: testResults.filter(r => r.securityResults?.sqlInjection).length,
        xssProtection: testResults.filter(r => r.securityResults?.xssProtection).length,
      },
    };

    logger.info("📊 SECURITY TEST EXECUTION SUMMARY");
    logger.info("=".repeat(50));
    logger.info(`   Total Modules: ${summary.modules.total}`);
    logger.info(`   Tested Modules: ${summary.modules.tested}`);
    logger.info(`   ✅ Healthy Modules: ${summary.modules.healthy}`);
    logger.info(`   ❌ Failed Modules: ${summary.modules.failed}`);
    logger.info(`   ✅ Passed Tests: ${securityTestSummary.passedTests}`);
    logger.info(`   ❌ Failed Tests: ${securityTestSummary.failedTests}`);
    logger.info(`   ⏸️  Skipped Tests: ${securityTestSummary.skippedTests}`);
    logger.info(`   ⏱️  Total Duration: ${summary.execution.duration}ms`);
    logger.info("=".repeat(50));

    global.attachJSON("Security Test Execution Summary", summary);
    global.attachAllureLog("Detailed Security Results", testResults);

    logger.info(`🏁 Completed security tests for ${securityTestSummary.modulesTested} modules`);
  });

  /**
   * ENHANCED MODULE DISCOVERY FUNCTION
   * Following the pattern from 3.Advanced-Security-Testing.test.js
   */
  const runComprehensiveSecurityOnAllModules = (modules, parentPath = "") => {
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

        securityTestSummary.modulesTested++;

        describe(`Security Testing: ${fullModuleName}`, () => {
          let moduleStartTime;
          let securityResults = {};
          let testContext = {};
          let moduleTestCount = 0;

          beforeAll(() => {
            moduleStartTime = Date.now();

            if (global.allure) {
              global.allure.story(fullModuleName);
              global.allure.addLabel("module", fullModuleName);
            }

            logger.info(`🛡️ Starting security tests for: ${fullModuleName}`);

            // Log module configuration for debugging
            const endpoints = Object.keys(moduleConfig).filter(key => 
              Array.isArray(moduleConfig[key]) && 
              moduleConfig[key][0] && 
              typeof moduleConfig[key][0] === 'string' &&
              moduleConfig[key][0].trim().length > 0 &&
              moduleConfig[key][0] !== "URL_HERE"
            );

            global.attachJSON(`Module Configuration - ${fullModuleName}`, {
              name: fullModuleName,
              path: parentPath,
              endpoints: endpoints,
              configKeys: Object.keys(moduleConfig),
            });
          });

          afterAll(() => {
            const moduleDuration = Date.now() - moduleStartTime;
            logger.info(`✅ Completed security tests for ${fullModuleName} in ${moduleDuration}ms`);
          });

          beforeEach(() => {
            testContext = {
              module: fullModuleName,
              startTime: new Date().toISOString(),
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
              if (testState.snapshotState && testState.snapshotState.unmatched > 0) {
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
            };

            testResults.push(testResult);

            global.attachAllureLog(
              `Security Test Result - ${fullModuleName}`,
              testResult
            );

            if (testStatus === "passed") {
              logger.debug(`✅ ${fullModuleName} - ${testName} completed successfully`);
            } else {
              logger.error(`❌ ${fullModuleName} - ${testName} failed`);
            }
          });

          // =========================================================================
          // SECURITY TEST CASE 1: AUTHORIZATION SECURITY
          // =========================================================================
          test("[TC-1] Authorization Security - Reject Unauthorized Access", async () => {
            if (global.allure) {
              global.allure.severity("blocker");
              global.allure.story("Authorization Security");
              global.allure.description(
                `Validates that endpoints properly reject unauthorized access attempts for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "authorization");
              global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `Authorization Security Tests for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "authorization";
                  testContext.operation = "security_validation";

                  logger.info(`🔐 Testing authorization security for ${fullModuleName}`);

                  const authResults = await TestHelpers.testAuthorizationSecurity(
                    moduleConfig
                  );
                  securityResults.authorization = authResults;

                  global.attachJSON("Authorization Test Results", authResults);

                  // Check if any authorization test failed
                  const failedAuthTests = authResults.filter(
                    (test) => !test.success && !test.skipped
                  );

                  if (failedAuthTests.length > 0) {
                    global.attachAllureLog(
                      "Authorization Test Failures",
                      failedAuthTests
                    );
                    const errorMessages = failedAuthTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(
                      `Authorization security tests failed: ${errorMessages}`
                    );
                  }

                  logger.info(`✅ Authorization security tests passed for ${fullModuleName}`);
                  return authResults;
                } catch (error) {
                  logger.error(`❌ Authorization security tests failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 30000);

          // =========================================================================
          // SECURITY TEST CASE 2: MALICIOUS PAYLOAD PROTECTION
          // =========================================================================
          test("[TC-2] Input Validation - Reject Malicious Payloads", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Input Validation Security");
              global.allure.description(
                `Tests protection against various malicious payload types for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "input-validation");
              global.allure.addLabel("tag", TEST_TAGS.Malicious);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `Malicious Payload Tests for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "malicious_payloads";
                  testContext.operation = "security_validation";

                  logger.info(`🦠 Testing malicious payload protection for ${fullModuleName}`);

                  const maliciousResults = await TestHelpers.testMaliciousPayloads(
                    moduleConfig,
                    "Post",
                    fullModuleName
                  );
                  securityResults.maliciousPayloads = maliciousResults;

                  global.attachJSON("Malicious Payload Test Results", maliciousResults);

                  // If any malicious test fails, the whole test fails
                  const failedMaliciousTests = maliciousResults.filter(
                    (test) => !test.success && !test.skipped
                  );

                  if (failedMaliciousTests.length > 0) {
                    const errorMessages = failedMaliciousTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(`Malicious payload tests failed: ${errorMessages}`);
                  }

                  logger.info(`✅ Malicious payload protection tests passed for ${fullModuleName}`);
                  return maliciousResults;
                } catch (error) {
                  logger.error(`❌ Malicious payload tests failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 30000);

          // =========================================================================
          // SECURITY TEST CASE 3: NULL REQUIRED FIELDS VALIDATION
          // =========================================================================
          test("[TC-3] Data Validation - Reject Null Required Fields", async () => {
            if (global.allure) {
              global.allure.severity("normal");
              global.allure.story("Data Validation");
              global.allure.description(
                `Validates that required fields properly reject null values for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "validation");
              global.allure.addLabel("tag", TEST_TAGS.Mandatory);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `Null Required Fields Test for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "null_validation";
                  testContext.operation = "data_validation";

                  logger.info(`📝 Testing null required fields validation for ${fullModuleName}`);

                  const nullFieldsResult = await TestHelpers.testNullRequiredFields(
                    moduleConfig,
                    "Post",
                    fullModuleName
                  );
                  securityResults.nullFields = nullFieldsResult;

                  global.attachJSON("Null Fields Test Result", nullFieldsResult);

                  if (!nullFieldsResult.skipped && !nullFieldsResult.success) {
                    throw new Error(`Null required fields test failed: ${nullFieldsResult.message}`);
                  }

                  if (nullFieldsResult.skipped) {
                    logger.info(`⏸️ Null required fields test skipped for ${fullModuleName}: ${nullFieldsResult.message}`);
                    securityTestSummary.skippedTests++;
                  } else {
                    logger.info(`✅ Null required fields validation passed for ${fullModuleName}`);
                  }

                  return nullFieldsResult;
                } catch (error) {
                  logger.error(`❌ Null required fields test failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 30000);

          // =========================================================================
          // SECURITY TEST CASE 4: EDIT WITH NULL REQUIRED FIELDS (Conditional)
          // =========================================================================
          if (moduleConfig.PUT) {
            test("[TC-4] Edit Validation - Reject Null Required Fields in Updates", async () => {
              if (global.allure) {
                global.allure.severity("normal");
                global.allure.story("Edit Validation");
                global.allure.description(
                  `Validates that edit operations properly reject null required fields for ${fullModuleName}`
                );
                global.allure.addLabel("test-type", "validation");
                global.allure.addLabel("tag", TEST_TAGS.Mandatory);
                global.allure.addLabel("module", fullModuleName);
              }

              await global.allureStep(
                `Edit with Null Required Fields for ${fullModuleName}`,
                async () => {
                  try {
                    testContext.testType = "edit_null_validation";
                    testContext.operation = "data_validation";

                    logger.info(`✏️ Testing edit with null required fields for ${fullModuleName}`);

                    const nullEditResult = await TestHelpers.testNullRequiredFields(
                      moduleConfig,
                      "PUT",
                      fullModuleName
                    );
                    securityResults.nullFieldsEdit = nullEditResult;

                    global.attachJSON("Null Edit Fields Test Result", nullEditResult);

                    if (!nullEditResult.skipped && !nullEditResult.success) {
                      throw new Error(`Edit with null required fields test failed: ${nullEditResult.message}`);
                    }

                    if (nullEditResult.skipped) {
                      logger.info(`⏸️ Edit null fields test skipped for ${fullModuleName}: ${nullEditResult.message}`);
                      securityTestSummary.skippedTests++;
                    } else {
                      logger.info(`✅ Edit with null required fields validation passed for ${fullModuleName}`);
                    }

                    return nullEditResult;
                  } catch (error) {
                    logger.error(`❌ Edit with null required fields test failed for ${fullModuleName}: ${error.message}`);
                    throw error;
                  }
                }
              );
            }, 30000);
          }

          // =========================================================================
          // SECURITY TEST CASE 5: SQL INJECTION PROTECTION
          // =========================================================================
          test("[TC-5] SQL Injection Protection", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("SQL Injection Protection");
              global.allure.description(
                `Tests protection against SQL injection attacks for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "sql-injection");
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `SQL Injection Tests for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "sql_injection";
                  testContext.operation = "security_validation";

                  logger.info(`💉 Testing SQL injection protection for ${fullModuleName}`);

                  const sqlInjectionResults = await TestHelpers.testSQLInjectionProtection(
                    moduleConfig,
                    fullModuleName
                  );
                  securityResults.sqlInjection = sqlInjectionResults;

                  global.attachJSON("SQL Injection Test Results", sqlInjectionResults);

                  const failedTests = sqlInjectionResults.filter(
                    (test) => !test.success && !test.skipped
                  );

                  if (failedTests.length > 0) {
                    const errorMessages = failedTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(`SQL injection tests failed: ${errorMessages}`);
                  }

                  logger.info(`✅ SQL injection protection tests passed for ${fullModuleName}`);
                  return sqlInjectionResults;
                } catch (error) {
                  logger.error(`❌ SQL injection tests failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 30000);

          // =========================================================================
          // SECURITY TEST CASE 6: XSS PROTECTION
          // =========================================================================
          test("[TC-6] XSS Protection", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("XSS Protection");
              global.allure.description(
                `Tests protection against Cross-Site Scripting attacks for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "xss");
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `XSS Protection Tests for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "xss_protection";
                  testContext.operation = "security_validation";

                  logger.info(`🕷️ Testing XSS protection for ${fullModuleName}`);

                  const xssResults = await TestHelpers.testXSSProtection(
                    moduleConfig,
                    fullModuleName
                  );
                  securityResults.xssProtection = xssResults;

                  global.attachJSON("XSS Protection Test Results", xssResults);

                  const failedTests = xssResults.filter(
                    (test) => !test.success && !test.skipped
                  );

                  if (failedTests.length > 0) {
                    const errorMessages = failedTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(`XSS protection tests failed: ${errorMessages}`);
                  }

                  logger.info(`✅ XSS protection tests passed for ${fullModuleName}`);
                  return xssResults;
                } catch (error) {
                  logger.error(`❌ XSS protection tests failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 30000);

          // =========================================================================
          // SECURITY TEST CASE 7: COMPREHENSIVE SECURITY SUITE
          // =========================================================================
          test("[TC-7] Comprehensive Security Suite", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Comprehensive Security Suite");
              global.allure.description(
                `Runs comprehensive security validation suite for ${fullModuleName}`
              );
              global.allure.addLabel("test-type", "security-suite");
              global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
              global.allure.addLabel("module", fullModuleName);
            }

            await global.allureStep(
              `Comprehensive Security Suite for ${fullModuleName}`,
              async () => {
                try {
                  testContext.testType = "comprehensive_security";
                  testContext.operation = "security_suite";

                  logger.info(`🛡️ Running comprehensive security suite for ${fullModuleName}`);

                  const comprehensiveResults = await TestHelpers.runComprehensiveSecuritySuite(
                    moduleConfig,
                    fullModuleName
                  );
                  securityResults = { ...securityResults, ...comprehensiveResults };

                  global.attachJSON("Comprehensive Security Results", comprehensiveResults);

                  // Check overall security test results
                  let allSecurityTestsPassed = true;
                  const securityFailures = [];

                  Object.entries(comprehensiveResults).forEach(([category, results]) => {
                    if (Array.isArray(results)) {
                      const failed = results.filter(r => !r.success && !r.skipped);
                      if (failed.length > 0) {
                        allSecurityTestsPassed = false;
                        securityFailures.push(`${category}: ${failed.length} failures`);
                      }
                    } else if (results && !results.success && !results.skipped) {
                      allSecurityTestsPassed = false;
                      securityFailures.push(`${category}: ${results.message}`);
                    }
                  });

                  if (!allSecurityTestsPassed) {
                    global.attachAllureLog("Security Suite Failures", securityFailures);
                    throw new Error(`Security suite failed: ${securityFailures.join("; ")}`);
                  }

                  logger.info(`✅ Comprehensive security suite passed for ${fullModuleName}`);
                  return comprehensiveResults;
                } catch (error) {
                  logger.error(`❌ Comprehensive security suite failed for ${fullModuleName}: ${error.message}`);
                  throw error;
                }
              }
            );
          }, 60000);
        });
      }

      // Recursively test nested modules following the same pattern
      if (typeof moduleConfig === "object" && !hasEndpoints) {
        runComprehensiveSecurityOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run comprehensive security on all modules following the successful pattern
  runComprehensiveSecurityOnAllModules(schema);
});