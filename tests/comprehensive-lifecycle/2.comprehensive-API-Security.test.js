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
 * Purpose: Test security across all backend API modules in the ERP system
 * Coverage: Authorization, Input Validation, SQL Injection, XSS, Data Validation
 * Scope: Automatically discovers and tests all modules with endpoints from schema
 *
 * @version 1.0.0
 * @author Enterprise Testing Team
 */

// Load the generated schema with enhanced error handling
let schema = {};
try {
  if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
    const schemaContent = fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8");
    schema = JSON.parse(schemaContent);
    logger.info(
      `✅ Schema loaded successfully from: ${FILE_PATHS.SCHEMA_PATH}`
    );
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
  let availableModules = [];
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

    // Discover all modules with endpoints from schema
    availableModules = discoverModulesWithEndpoints(schema);
    securityTestSummary.modulesTested = availableModules.length;

    logger.info(
      `📋 Found ${availableModules.length} modules for security testing`
    );

    if (availableModules.length === 0) {
      logger.warn(
        "⚠️ No modules with endpoints found in schema - please verify schema structure"
      );
      // Perform schema analysis for debugging
      analyzeSchemaForDebugging(schema);
    } else {
      // Log discovered modules for transparency
      logger.info("📋 Discovered Modules:");
      availableModules.forEach((module, index) => {
        logger.info(
          `   ${index + 1}. ${module.name} (${
            module.endpoints.length
          } endpoints: ${module.endpoints.join(", ")})`
        );
      });
    }

    logger.info("=".repeat(60));
  });

  afterAll(() => {
    securityTestSummary.endTime = new Date().toISOString();

    // Generate comprehensive test report
    const healthyModules = testResults.filter(
      (r) => r.status === "passed"
    ).length;
    const failedModules = testResults.filter(
      (r) => r.status === "failed"
    ).length;

    const summary = {
      execution: {
        ...securityTestSummary,
        healthyModules,
        failedModules,
      },
      modules: {
        total: availableModules.length,
        tested: testResults.length,
        healthy: healthyModules,
        failed: failedModules,
      },
      security: {
        authorization: testResults.filter(
          (r) => r.securityResults?.authorization
        ).length,
        maliciousPayloads: testResults.filter(
          (r) => r.securityResults?.maliciousPayloads
        ).length,
        sqlInjection: testResults.filter((r) => r.securityResults?.sqlInjection)
          .length,
        xssProtection: testResults.filter(
          (r) => r.securityResults?.xssProtection
        ).length,
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
    logger.info(
      `   ⏱️  Total Duration: ${
        securityTestSummary.endTime
          ? new Date(securityTestSummary.endTime) -
            new Date(securityTestSummary.startTime)
          : 0
      }ms`
    );
    logger.info("=".repeat(50));

    global.attachJSON("Security Test Execution Summary", summary);
    global.attachAllureLog("Detailed Security Results", testResults);

    logger.info(
      `🏁 Completed security tests for ${availableModules.length} modules`
    );
  });

  /**
   * ENHANCED MODULE DISCOVERY ALGORITHM
   * Recursively discovers all modules with valid endpoints in the schema
   */
  function discoverModulesWithEndpoints(modules, parentPath = "") {
    const modulesWithEndpoints = [];
    const processedPaths = new Set();

    const traverseModules = (currentModules, currentPath = "") => {
      if (!currentModules || typeof currentModules !== "object") {
        return;
      }

      Object.entries(currentModules).forEach(([moduleName, moduleData]) => {
        if (typeof moduleData !== "object" || moduleData === null) {
          return;
        }

        const fullPath = currentPath
          ? `${currentPath}.${moduleName}`
          : moduleName;

        // Avoid processing the same path multiple times
        if (processedPaths.has(fullPath)) {
          return;
        }
        processedPaths.add(fullPath);

        // Enhanced endpoint detection with comprehensive validation
        const validEndpoints = [];
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

        endpointTypes.forEach((endpointType) => {
          if (
            moduleData[endpointType] &&
            Array.isArray(moduleData[endpointType]) &&
            moduleData[endpointType].length > 0
          ) {
            const endpoint = moduleData[endpointType][0];
            // Validate endpoint is a non-empty string and not a placeholder
            if (
              typeof endpoint === "string" &&
              endpoint.trim().length > 0 &&
              endpoint !== "URL_HERE" &&
              !endpoint.includes("placeholder") &&
              !endpoint.includes("example.com")
            ) {
              validEndpoints.push(endpointType);
            }
          }
        });

        // If we found valid endpoints, this is a testable module
        if (validEndpoints.length > 0) {
          modulesWithEndpoints.push({
            name: fullPath,
            config: moduleData,
            path: fullPath,
            endpoints: validEndpoints,
            endpointCount: validEndpoints.length,
          });

          logger.debug(
            `🔍 Found module: ${fullPath} with endpoints: ${validEndpoints.join(
              ", "
            )}`
          );
        }

        // Recursively check nested modules with depth control
        if (typeof moduleData === "object" && !Array.isArray(moduleData)) {
          // Avoid infinite recursion by checking if we're going too deep
          const pathDepth = fullPath.split(".").length;
          if (pathDepth < 10) {
            // Reasonable depth limit
            traverseModules(moduleData, fullPath);
          }
        }
      });
    };

    traverseModules(modules, parentPath);
    return modulesWithEndpoints;
  }

  /**
   * Schema analysis for debugging when no modules are found
   */
  function analyzeSchemaForDebugging(schemaObj) {
    logger.info("🔍 Analyzing schema structure for debugging...");

    const analysis = {
      topLevelKeys: Object.keys(schemaObj),
      totalKeys: countKeys(schemaObj),
      maxDepth: getMaxDepth(schemaObj),
      potentialModules: findPotentialModules(schemaObj),
    };

    logger.debug(`Schema Analysis: ${JSON.stringify(analysis, null, 2)}`);
    global.attachJSON("Schema Structure Analysis", analysis);
  }

  function countKeys(obj, count = 0) {
    if (typeof obj !== "object" || obj === null) return count;

    Object.keys(obj).forEach((key) => {
      count++;
      if (typeof obj[key] === "object" && obj[key] !== null) {
        count = countKeys(obj[key], count);
      }
    });

    return count;
  }

  function getMaxDepth(obj, depth = 1) {
    if (typeof obj !== "object" || obj === null) return depth;

    let maxDepth = depth;
    Object.keys(obj).forEach((key) => {
      if (typeof obj[key] === "object" && obj[key] !== null) {
        const currentDepth = getMaxDepth(obj[key], depth + 1);
        maxDepth = Math.max(maxDepth, currentDepth);
      }
    });

    return maxDepth;
  }

  function findPotentialModules(obj, path = "") {
    const potentials = [];
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

    if (typeof obj === "object" && obj !== null) {
      Object.keys(obj).forEach((key) => {
        const currentPath = path ? `${path}.${key}` : key;

        // Check if this object has any endpoint-like structures
        const hasEndpointLikeStructures = endpointTypes.some(
          (type) => obj[type] !== undefined
        );

        if (hasEndpointLikeStructures) {
          potentials.push({
            path: currentPath,
            endpoints: endpointTypes.filter((type) => obj[type] !== undefined),
          });
        }

        // Recursively check children
        if (typeof obj[key] === "object" && obj[key] !== null) {
          potentials.push(...findPotentialModules(obj[key], currentPath));
        }
      });
    }

    return potentials;
  }

  // =============================================================================
  // MAIN TEST EXECUTION: Only run if modules are actually found
  // =============================================================================
  if (availableModules.length > 0) {
    // TEST EXECUTION: Run security tests for each discovered module
    availableModules.forEach((moduleInfo) => {
      const {
        name: moduleName,
        config: moduleConfig,
        path: modulePath,
        endpoints,
      } = moduleInfo;

      describe(`Security Testing: ${moduleName}`, () => {
        let moduleStartTime;
        let securityResults = {};
        let testContext = {};
        let moduleTestCount = 0;

        beforeAll(() => {
          moduleStartTime = Date.now();

          if (global.allure) {
            global.allure.story(moduleName);
            global.allure.addLabel("module", moduleName);
            global.allure.addLabel("endpoints", endpoints.join(","));
          }

          logger.info(`🛡️ Starting security tests for: ${moduleName}`);
          logger.info(`🔧 Available endpoints: ${endpoints.join(", ")}`);

          // Log module configuration for debugging
          global.attachJSON(`Module Configuration - ${moduleName}`, {
            name: moduleName,
            path: modulePath,
            endpoints: endpoints,
            configKeys: Object.keys(moduleConfig).filter(
              (key) =>
                Array.isArray(moduleConfig[key]) &&
                moduleConfig[key][0] !== "URL_HERE"
            ),
          });
        });

        afterAll(() => {
          const moduleDuration = Date.now() - moduleStartTime;
          logger.info(
            `✅ Completed security tests for ${moduleName} in ${moduleDuration}ms`
          );

          // Update security test summary
          securityTestSummary.totalTests += moduleTestCount;
        });

        beforeEach(() => {
          testContext = {
            module: moduleName,
            startTime: new Date().toISOString(),
            endpoints: endpoints,
          };
        });

        afterEach(() => {
          const testState = expect.getState();
          const testName = testState.currentTestName || "Unknown Test";
          moduleTestCount++;

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
            module: moduleName,
            status: testStatus,
            securityResults,
            timestamp: new Date().toISOString(),
            testName: testName,
            context: testContext,
            testCount: moduleTestCount,
          };

          testResults.push(testResult);

          global.attachAllureLog(
            `Security Test Result - ${moduleName}`,
            testResult
          );

          if (testStatus === "passed") {
            logger.debug(
              `✅ ${moduleName} - ${testName} completed successfully`
            );
          } else {
            logger.error(`❌ ${moduleName} - ${testName} failed`);
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
              `Validates that endpoints properly reject unauthorized access attempts for ${moduleName}`
            );
            global.allure.addLabel("test-type", "security");
            global.allure.addLabel("category", "authorization");
            global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `Authorization Security Tests for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "authorization";
                testContext.operation = "security_validation";

                logger.info(
                  `🔐 Testing authorization security for ${moduleName}`
                );

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

                logger.info(
                  `✅ Authorization security tests passed for ${moduleName}`
                );
                return authResults;
              } catch (error) {
                logger.error(
                  `❌ Authorization security tests failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
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
              `Tests protection against various malicious payload types for ${moduleName}`
            );
            global.allure.addLabel("test-type", "security");
            global.allure.addLabel("category", "input-validation");
            global.allure.addLabel("tag", TEST_TAGS.Malicious);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `Malicious Payload Tests for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "malicious_payloads";
                testContext.operation = "security_validation";

                logger.info(
                  `🦠 Testing malicious payload protection for ${moduleName}`
                );

                const maliciousResults =
                  await TestHelpers.testMaliciousPayloads(
                    moduleConfig,
                    "Post",
                    moduleName
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
                  `✅ Malicious payload protection tests passed for ${moduleName}`
                );
                return maliciousResults;
              } catch (error) {
                logger.error(
                  `❌ Malicious payload tests failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
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
              `Validates that required fields properly reject null values for ${moduleName}`
            );
            global.allure.addLabel("test-type", "validation");
            global.allure.addLabel("tag", TEST_TAGS.Mandatory);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `Null Required Fields Test for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "null_validation";
                testContext.operation = "data_validation";

                logger.info(
                  `📝 Testing null required fields validation for ${moduleName}`
                );

                const nullFieldsResult =
                  await TestHelpers.testNullRequiredFields(
                    moduleConfig,
                    "Post",
                    moduleName
                  );
                securityResults.nullFields = nullFieldsResult;

                global.attachJSON("Null Fields Test Result", nullFieldsResult);

                if (!nullFieldsResult.skipped && !nullFieldsResult.success) {
                  throw new Error(
                    `Null required fields test failed: ${nullFieldsResult.message}`
                  );
                }

                if (nullFieldsResult.skipped) {
                  logger.info(
                    `⏸️ Null required fields test skipped for ${moduleName}: ${nullFieldsResult.message}`
                  );
                  securityTestSummary.skippedTests++;
                } else {
                  logger.info(
                    `✅ Null required fields validation passed for ${moduleName}`
                  );
                }

                return nullFieldsResult;
              } catch (error) {
                logger.error(
                  `❌ Null required fields test failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
                throw error;
              }
            }
          );
        }, 30000);

        // =========================================================================
        // SECURITY TEST CASE 4: EDIT WITH NULL REQUIRED FIELDS (Conditional)
        // =========================================================================
        if (endpoints.includes("PUT")) {
          test("[TC-4] Edit Validation - Reject Null Required Fields in Updates", async () => {
            if (global.allure) {
              global.allure.severity("normal");
              global.allure.story("Edit Validation");
              global.allure.description(
                `Validates that edit operations properly reject null required fields for ${moduleName}`
              );
              global.allure.addLabel("test-type", "validation");
              global.allure.addLabel("tag", TEST_TAGS.Mandatory);
              global.allure.addLabel("module", moduleName);
            }

            await global.allureStep(
              `Edit with Null Required Fields for ${moduleName}`,
              async () => {
                try {
                  testContext.testType = "edit_null_validation";
                  testContext.operation = "data_validation";

                  logger.info(
                    `✏️ Testing edit with null required fields for ${moduleName}`
                  );

                  const nullEditResult =
                    await TestHelpers.testNullRequiredFields(
                      moduleConfig,
                      "PUT",
                      moduleName
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

                  if (nullEditResult.skipped) {
                    logger.info(
                      `⏸️ Edit null fields test skipped for ${moduleName}: ${nullEditResult.message}`
                    );
                    securityTestSummary.skippedTests++;
                  } else {
                    logger.info(
                      `✅ Edit with null required fields validation passed for ${moduleName}`
                    );
                  }

                  return nullEditResult;
                } catch (error) {
                  logger.error(
                    `❌ Edit with null required fields test failed for ${moduleName}: ${error.message}`
                  );
                  securityTestSummary.failedTests++;
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
              `Tests protection against SQL injection attacks for ${moduleName}`
            );
            global.allure.addLabel("test-type", "security");
            global.allure.addLabel("category", "sql-injection");
            global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `SQL Injection Tests for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "sql_injection";
                testContext.operation = "security_validation";

                logger.info(
                  `💉 Testing SQL injection protection for ${moduleName}`
                );

                const sqlInjectionResults =
                  await TestHelpers.testSQLInjectionProtection(
                    moduleConfig,
                    moduleName
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
                  `✅ SQL injection protection tests passed for ${moduleName}`
                );
                return sqlInjectionResults;
              } catch (error) {
                logger.error(
                  `❌ SQL injection tests failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
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
              `Tests protection against Cross-Site Scripting attacks for ${moduleName}`
            );
            global.allure.addLabel("test-type", "security");
            global.allure.addLabel("category", "xss");
            global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `XSS Protection Tests for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "xss_protection";
                testContext.operation = "security_validation";

                logger.info(`🕷️ Testing XSS protection for ${moduleName}`);

                const xssResults = await TestHelpers.testXSSProtection(
                  moduleConfig,
                  moduleName
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

                logger.info(`✅ XSS protection tests passed for ${moduleName}`);
                return xssResults;
              } catch (error) {
                logger.error(
                  `❌ XSS protection tests failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
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
              `Runs comprehensive security validation suite for ${moduleName}`
            );
            global.allure.addLabel("test-type", "security-suite");
            global.allure.addLabel("tag", TEST_TAGS.ComprehensiveSecurity);
            global.allure.addLabel("module", moduleName);
          }

          await global.allureStep(
            `Comprehensive Security Suite for ${moduleName}`,
            async () => {
              try {
                testContext.testType = "comprehensive_security";
                testContext.operation = "security_suite";

                logger.info(
                  `🛡️ Running comprehensive security suite for ${moduleName}`
                );

                const comprehensiveResults =
                  await TestHelpers.runComprehensiveSecuritySuite(
                    moduleConfig,
                    moduleName
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
                      securityFailures.push(`${category}: ${results.message}`);
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
                  `✅ Comprehensive security suite passed for ${moduleName}`
                );
                return comprehensiveResults;
              } catch (error) {
                logger.error(
                  `❌ Comprehensive security suite failed for ${moduleName}: ${error.message}`
                );
                securityTestSummary.failedTests++;
                throw error;
              }
            }
          );
        }, 60000);
      });
    });
  } else {
    // =============================================================================
    // FALLBACK TEST: Only run when NO modules are discovered
    // =============================================================================
    describe("Security Testing - Schema Analysis", () => {
      test("Schema Analysis and Module Discovery Diagnostic", () => {
        logger.warn(
          "🔍 No modules with endpoints found in schema. Running diagnostic..."
        );

        // Perform comprehensive schema analysis
        const diagnostic = performSchemaDiagnostic(schema);
        global.attachJSON("Schema Diagnostic Report", diagnostic);

        logger.info(`📊 Schema Diagnostic Results:`);
        logger.info(
          `   - Top-level keys: ${diagnostic.topLevelKeys.join(", ")}`
        );
        logger.info(`   - Total objects: ${diagnostic.totalObjects}`);
        logger.info(`   - Max depth: ${diagnostic.maxDepth}`);
        logger.info(
          `   - Potential modules found: ${diagnostic.potentialModules.length}`
        );

        if (diagnostic.potentialModules.length > 0) {
          logger.info("   - Potential module paths:");
          diagnostic.potentialModules.forEach((module) => {
            logger.info(
              `        ${module.path} (${module.endpoints.join(", ")})`
            );
          });
        }

        // This test should fail to alert about the schema issue
        expect(availableModules.length).toBeGreaterThan(0);
      });

      function performSchemaDiagnostic(schemaObj) {
        const diagnostic = {
          topLevelKeys: Object.keys(schemaObj),
          totalObjects: countObjects(schemaObj),
          maxDepth: getMaxDepth(schemaObj),
          potentialModules: findPotentialModules(schemaObj),
          schemaSample:
            JSON.stringify(schemaObj, null, 2).substring(0, 1000) + "...",
        };

        return diagnostic;
      }

      function countObjects(obj, count = 0) {
        if (typeof obj !== "object" || obj === null) return count;

        if (Array.isArray(obj)) {
          return count + 1;
        }

        count++;
        Object.keys(obj).forEach((key) => {
          if (typeof obj[key] === "object" && obj[key] !== null) {
            count = countObjects(obj[key], count);
          }
        });

        return count;
      }
    });
  }
});
