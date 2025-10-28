const fs = require("fs");
const path = require("path");
const TestHelpers = require("../../utils/test-helpers");
const TestDataGenerator = require("../../test-data/test-data-generator");
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const {
  TEST_TAGS,
  FILE_PATHS,
  HTTP_STATUS_CODES,
} = require("../../Constants/Constants");

// Load the generated schema
let schema = {};
try {
  if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
    schema = JSON.parse(fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8"));
    logger.info(
      `✅ Schema loaded successfully from: ${FILE_PATHS.SCHEMA_PATH}`
    );
  } else {
    throw new Error(`Schema file not found at: ${FILE_PATHS.SCHEMA_PATH}`);
  }
} catch (error) {
  logger.error(`❌ Failed to load schema: ${error.message}`);
  throw error;
}

describe("Comprehensive API Security Testing", () => {
  const testResults = [];

  // Define the module under test - you can use either short name or full path
  const moduleName = "Discount_Policy"; // Short name
  // const moduleName = "General_Settings.Master_Data.Discount_Policy"; // Full path

  // Import module configuration (endpoints)
  const moduleConfigs = require("../../config/modules-config");

  // Find module configuration - try different naming patterns
  let moduleConfig = moduleConfigs[moduleName];

  // If not found with exact name, try to find by leaf name
  if (!moduleConfig) {
    const leafName = moduleName.split(".").pop();
    moduleConfig = moduleConfigs[leafName];

    if (moduleConfig) {
      logger.info(
        `🔍 Found module by leaf name: ${leafName} -> ${moduleConfig.fullPath}`
      );
    }
  }

  // Validate module configuration exists
  if (!moduleConfig) {
    const availableModules = Object.keys(moduleConfigs).filter(
      (key) =>
        ![
          "extractModuleConfigs",
          "moduleConfigs",
          "schema",
          "schemaPath",
          "createAliases",
          "aliases",
        ].includes(key)
    );

    // Show suggestions for similar module names
    const suggestions = availableModules.filter(
      (availableModule) =>
        availableModule.toLowerCase().includes(moduleName.toLowerCase()) ||
        moduleName.toLowerCase().includes(availableModule.toLowerCase())
    );

    let errorMessage = `Module configuration not found for: "${moduleName}".\n`;
    errorMessage += `Available modules: ${availableModules.length} total\n`;

    if (suggestions.length > 0) {
      errorMessage += `Did you mean one of these?\n${suggestions
        .map((s) => `  - ${s}`)
        .join("\n")}`;
    } else {
      errorMessage += `Top 10 available modules:\n${availableModules
        .slice(0, 10)
        .map((m) => `  - ${m}`)
        .join("\n")}`;
    }

    throw new Error(errorMessage);
  }

  // Use the full path for display purposes
  const actualModulePath = moduleConfig.fullPath || moduleName;
  const fullModuleName = `${actualModulePath} Module`;
  logger.info(`🎯 Testing module: ${actualModulePath}`);

  beforeAll(() => {
    // Set epic and feature for all tests in this suite
    if (global.allure) {
      global.allure.epic("Enterprise API Testing");
      global.allure.feature("Comprehensive Security Testing");
      global.allure.addLabel("framework", "Jest");
      global.allure.addLabel("language", "JavaScript");
      global.allure.addLabel("target-module", actualModulePath);
    }
    logger.info("🔒 Starting Comprehensive API Security Testing");

    // Log module configuration for debugging
    logger.info(`🔧 Module configuration loaded for: ${actualModulePath}`);
    const availableEndpoints = Object.keys(moduleConfig).filter(
      (key) =>
        Array.isArray(moduleConfig[key]) && moduleConfig[key][0] !== "URL_HERE"
    );
    logger.info(
      `📋 Available endpoints: ${availableEndpoints.join(", ") || "None"}`
    );
  });

  afterAll(() => {
    // Generate comprehensive test report
    const summary = {
      totalModules: testResults.length,
      passed: testResults.filter((r) => r.status === "passed").length,
      failed: testResults.filter((r) => r.status === "failed").length,
      totalDuration: testResults.reduce((sum, r) => sum + r.duration, 0),
      modules: testResults.map((r) => ({
        module: r.module,
        status: r.status,
        duration: r.duration,
      })),
    };

    logger.info(`📊 Security Test Execution Summary:`);
    logger.info(`   Total Modules: ${summary.totalModules}`);
    logger.info(`   ✅ Passed: ${summary.passed}`);
    logger.info(`   ❌ Failed: ${summary.failed}`);
    logger.info(`   ⏱️ Total Duration: ${summary.totalDuration}ms`);

    global.attachJSON("Security Test Execution Summary", summary);
    global.attachAllureLog("Detailed Security Results", testResults);

    logger.info(`🏁 Completed security tests for ${fullModuleName}`);
  });

  const testSecurityAcrossModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([currentModuleName, moduleData]) => {
      if (typeof moduleData !== "object" || moduleData === null) {
        return;
      }

      // Check if this module has endpoints
      const hasEndpoints =
        (moduleData.Post &&
          Array.isArray(moduleData.Post) &&
          moduleData.Post[0] !== "URL_HERE") ||
        (moduleData.PUT &&
          Array.isArray(moduleData.PUT) &&
          moduleData.PUT[0] !== "URL_HERE") ||
        (moduleData.DELETE &&
          Array.isArray(moduleData.DELETE) &&
          moduleData.DELETE[0] !== "URL_HERE") ||
        (moduleData.View &&
          Array.isArray(moduleData.View) &&
          moduleData.View[0] !== "URL_HERE") ||
        (moduleData.EDIT &&
          Array.isArray(moduleData.EDIT) &&
          moduleData.EDIT[0] !== "URL_HERE") ||
        (moduleData.LookUP &&
          Array.isArray(moduleData.LookUP) &&
          moduleData.LookUP[0] !== "URL_HERE") ||
        (moduleData.Commit &&
          Array.isArray(moduleData.Commit) &&
          moduleData.Commit[0] !== "URL_HERE");

      if (hasEndpoints) {
        const fullModulePath = parentPath
          ? `${parentPath}.${currentModuleName}`
          : currentModuleName;

        describe(`Comprehensive Security Testing: ${fullModulePath}`, () => {
          let startTime;
          let securityResults = {};
          let testContext = {};

          beforeAll(() => {
            if (global.allure) {
              global.allure.story(fullModulePath);
              global.allure.addLabel("module", fullModulePath);
            }

            logger.info(`🛡️ Starting security tests for ${fullModulePath}`);

            // Log available endpoints for this module
            const availableEndpoints = Object.keys(moduleData).filter(
              (key) =>
                moduleData[key] &&
                Array.isArray(moduleData[key]) &&
                moduleData[key][0] !== "URL_HERE"
            );
            logger.info(
              `🔧 Available endpoints: ${availableEndpoints.join(", ")}`
            );
          });

          beforeEach(() => {
            startTime = Date.now();
            testContext = {
              module: fullModulePath,
              startTime: new Date().toISOString(),
            };
          });

          afterEach(() => {
            const duration = Date.now() - startTime;
            const testState = expect.getState();
            const testName = testState.currentTestName || "Unknown Test";

            // Determine test status
            let testStatus = "passed";
            try {
              if (
                testState.snapshotState &&
                testState.snapshotState.unmatched > 0
              ) {
                testStatus = "failed";
              }
            } catch (e) {
              testStatus = "failed";
            }

            const testResult = {
              module: fullModulePath,
              duration,
              status: testStatus,
              securityResults,
              timestamp: new Date().toISOString(),
              testName: testName,
              context: testContext,
            };
            testResults.push(testResult);

            global.attachAllureLog(
              `Security Test Result - ${fullModulePath}`,
              testResult
            );

            if (testStatus === "passed") {
              logger.info(
                `✅ ${fullModulePath} - ${testName} completed in ${duration}ms`
              );
            } else {
              logger.error(
                `❌ ${fullModulePath} - ${testName} failed in ${duration}ms`
              );
            }
          });

          // ==========================================================
          // [TC-1] Authorization Security Testing
          // ==========================================================
          test("[TC-1] Authorization Security - Reject Unauthorized Access", async () => {
            if (global.allure) {
              global.allure.severity("blocker");
              global.allure.story("Authorization Security");
              global.allure.description(
                `Authorization security testing for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "authorization");
              global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `Authorization Security Tests for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "authorization";
                  testContext.operation = "security_validation";

                  const authResults =
                    await TestHelpers.testAuthorizationSecurity(moduleData);
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

                  logger.info(
                    `✅ Authorization security tests passed for ${fullModulePath}`
                  );
                  return authResults;
                } catch (error) {
                  logger.error(
                    `❌ Authorization security tests failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 30000);

          // ==========================================================
          // [TC-2] Malicious Payload Protection
          // ==========================================================
          test("[TC-2] Input Validation - Reject Malicious Payloads", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Input Validation Security");
              global.allure.description(
                `Malicious payload protection testing for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "input-validation");
              global.allure.addLabel("tag", TEST_TAGS.Malicious);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `Malicious Payload Tests for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "malicious_payloads";
                  testContext.operation = "security_validation";

                  const maliciousResults =
                    await TestHelpers.testMaliciousPayloads(
                      moduleData,
                      "Post",
                      fullModulePath
                    );
                  securityResults.maliciousPayloads = maliciousResults;

                  global.attachJSON(
                    "Malicious Payload Test Results",
                    maliciousResults
                  );

                  // If any malicious test fails, the whole test fails
                  const failedMaliciousTests = maliciousResults.filter(
                    (test) => !test.success && !test.skipped
                  );
                  if (failedMaliciousTests.length > 0) {
                    const errorMessages = failedMaliciousTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(
                      `Malicious payload tests failed: ${errorMessages}`
                    );
                  }

                  logger.info(
                    `✅ Malicious payload protection tests passed for ${fullModulePath}`
                  );
                  return maliciousResults;
                } catch (error) {
                  logger.error(
                    `❌ Malicious payload tests failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 30000);

          // ==========================================================
          // [TC-3] Null Required Fields Validation
          // ==========================================================
          test("[TC-3] Data Validation - Reject Null Required Fields", async () => {
            if (global.allure) {
              global.allure.severity("normal");
              global.allure.story("Data Validation");
              global.allure.description(
                `Null required fields validation for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "validation");
              global.allure.addLabel("tag", TEST_TAGS.Mandatory);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `Null Required Fields Test for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "null_validation";
                  testContext.operation = "data_validation";

                  const nullFieldsResult =
                    await TestHelpers.testNullRequiredFields(
                      moduleData,
                      "Post",
                      fullModulePath
                    );
                  securityResults.nullFields = nullFieldsResult;

                  global.attachJSON(
                    "Null Fields Test Result",
                    nullFieldsResult
                  );

                  if (!nullFieldsResult.skipped && !nullFieldsResult.success) {
                    throw new Error(
                      `Null required fields test failed: ${nullFieldsResult.message}`
                    );
                  }

                  logger.info(
                    `✅ Null required fields validation passed for ${fullModulePath}`
                  );
                  return nullFieldsResult;
                } catch (error) {
                  logger.error(
                    `❌ Null required fields test failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 30000);

          // ==========================================================
          // [TC-4] Edit with Null Required Fields (if PUT endpoint exists)
          // ==========================================================
          if (moduleData.PUT && moduleData.PUT[0] !== "URL_HERE") {
            test("[TC-4] Edit Validation - Reject Null Required Fields in Updates", async () => {
              if (global.allure) {
                global.allure.severity("normal");
                global.allure.story("Edit Validation");
                global.allure.description(
                  `Edit with null required fields validation for ${fullModulePath}`
                );
                global.allure.addLabel("test-type", "validation");
                global.allure.addLabel("tag", TEST_TAGS.Mandatory);
                global.allure.addLabel("module", fullModulePath);
              }

              await global.allureStep(
                `Edit with Null Required Fields for ${fullModulePath}`,
                async () => {
                  try {
                    testContext.testType = "edit_null_validation";
                    testContext.operation = "data_validation";

                    const nullEditResult =
                      await TestHelpers.testNullRequiredFields(
                        moduleData,
                        "PUT",
                        fullModulePath
                      );
                    securityResults.nullFieldsEdit = nullEditResult;

                    global.attachJSON(
                      "Null Edit Fields Test Result",
                      nullEditResult
                    );

                    if (!nullEditResult.skipped && !nullEditResult.success) {
                      throw new Error(
                        `Edit with null required fields test failed: ${nullEditResult.message}`
                      );
                    }

                    logger.info(
                      `✅ Edit with null required fields validation passed for ${fullModulePath}`
                    );
                    return nullEditResult;
                  } catch (error) {
                    logger.error(
                      `❌ Edit with null required fields test failed for ${fullModulePath}: ${error.message}`
                    );
                    throw error;
                  }
                }
              );
            }, 30000);
          }

          // ==========================================================
          // [TC-5] SQL Injection Protection
          // ==========================================================
          test("[TC-5] SQL Injection Protection", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("SQL Injection Protection");
              global.allure.description(
                `SQL injection protection testing for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "sql-injection");
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `SQL Injection Tests for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "sql_injection";
                  testContext.operation = "security_validation";

                  const sqlInjectionResults =
                    await TestHelpers.testSQLInjectionProtection(
                      moduleData,
                      fullModulePath
                    );
                  securityResults.sqlInjection = sqlInjectionResults;

                  global.attachJSON(
                    "SQL Injection Test Results",
                    sqlInjectionResults
                  );

                  const failedTests = sqlInjectionResults.filter(
                    (test) => !test.success && !test.skipped
                  );
                  if (failedTests.length > 0) {
                    const errorMessages = failedTests
                      .map((test) => test.message || test.error)
                      .join("; ");
                    throw new Error(
                      `SQL injection tests failed: ${errorMessages}`
                    );
                  }

                  logger.info(
                    `✅ SQL injection protection tests passed for ${fullModulePath}`
                  );
                  return sqlInjectionResults;
                } catch (error) {
                  logger.error(
                    `❌ SQL injection tests failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 30000);

          // ==========================================================
          // [TC-6] XSS Protection
          // ==========================================================
          test("[TC-6] XSS Protection", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("XSS Protection");
              global.allure.description(
                `XSS protection testing for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "security");
              global.allure.addLabel("category", "xss");
              global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `XSS Protection Tests for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "xss_protection";
                  testContext.operation = "security_validation";

                  const xssResults = await TestHelpers.testXSSProtection(
                    moduleData,
                    fullModulePath
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
                    throw new Error(
                      `XSS protection tests failed: ${errorMessages}`
                    );
                  }

                  logger.info(
                    `✅ XSS protection tests passed for ${fullModulePath}`
                  );
                  return xssResults;
                } catch (error) {
                  logger.error(
                    `❌ XSS protection tests failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 30000);

          // ==========================================================
          // [TC-7] Comprehensive Security Suite
          // ==========================================================
          test("[TC-7] Comprehensive Security Suite", async () => {
            if (global.allure) {
              global.allure.severity("critical");
              global.allure.story("Comprehensive Security Suite");
              global.allure.description(
                `Comprehensive security suite testing for ${fullModulePath}`
              );
              global.allure.addLabel("test-type", "security-suite");
              global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
              global.allure.addLabel("module", fullModulePath);
            }

            await global.allureStep(
              `Comprehensive Security Suite for ${fullModulePath}`,
              async () => {
                try {
                  testContext.testType = "comprehensive_security";
                  testContext.operation = "security_suite";

                  const comprehensiveResults =
                    await TestHelpers.runComprehensiveSecuritySuite(
                      moduleData,
                      fullModulePath
                    );
                  securityResults = {
                    ...securityResults,
                    ...comprehensiveResults,
                  };

                  global.attachJSON(
                    "Comprehensive Security Results",
                    comprehensiveResults
                  );

                  // Check overall security test results
                  let allSecurityTestsPassed = true;
                  const securityFailures = [];

                  Object.entries(comprehensiveResults).forEach(
                    ([category, results]) => {
                      if (Array.isArray(results)) {
                        const failed = results.filter(
                          (r) => !r.success && !r.skipped
                        );
                        if (failed.length > 0) {
                          allSecurityTestsPassed = false;
                          securityFailures.push(
                            `${category}: ${failed.length} failures`
                          );
                        }
                      } else if (
                        results &&
                        !results.success &&
                        !results.skipped
                      ) {
                        allSecurityTestsPassed = false;
                        securityFailures.push(
                          `${category}: ${results.message}`
                        );
                      }
                    }
                  );

                  if (!allSecurityTestsPassed) {
                    global.attachAllureLog(
                      "Security Suite Failures",
                      securityFailures
                    );
                    throw new Error(
                      `Security suite failed: ${securityFailures.join("; ")}`
                    );
                  }

                  logger.info(
                    `✅ Comprehensive security suite passed for ${fullModulePath}`
                  );
                  return comprehensiveResults;
                } catch (error) {
                  logger.error(
                    `❌ Comprehensive security suite failed for ${fullModulePath}: ${error.message}`
                  );
                  throw error;
                }
              }
            );
          }, 60000);
        });
      }

      // Recursively test nested modules
      if (typeof moduleData === "object" && !Array.isArray(moduleData)) {
        const hasNestedEndpoints = Object.keys(moduleData).some(
          (key) =>
            typeof moduleData[key] === "object" &&
            !Array.isArray(moduleData[key]) &&
            moduleData[key] !== null
        );

        if (hasNestedEndpoints) {
          testSecurityAcrossModules(
            moduleData,
            parentPath
              ? `${parentPath}.${currentModuleName}`
              : currentModuleName
          );
        }
      }
    });
  };

  // Start comprehensive security testing
  testSecurityAcrossModules(schema);
});
