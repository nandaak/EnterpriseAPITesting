// utils/test-orchestrator.js - Enhanced test orchestration
const logger = require("./logger");
const TestHelpers = require("./test-helpers");

class TestOrchestrator {
  static async executeSecurityTestsForModule(moduleConfig, moduleName) {
    const testResults = {
      module: moduleName,
      startTime: new Date().toISOString(),
      tests: {},
      summary: {},
    };

    try {
      logger.info(`🛡️ Starting security tests for: ${moduleName}`);

      // Execute all security tests
      testResults.tests.authorization =
        await TestHelpers.testAuthorizationSecurity(
          moduleConfig,
          moduleName
        );

      testResults.tests.sqlInjection =
        await TestHelpers.testSQLInjectionProtection(
          moduleConfig,
          moduleName
        );

      testResults.tests.xssProtection =
        await TestHelpers.testXSSProtection(moduleConfig, moduleName);

      testResults.tests.maliciousPayloads =
        await TestHelpers.testMaliciousPayloads(
          moduleConfig,
          "Post",
          moduleName
        );

      testResults.tests.performance =
        await TestHelpers.testPerformanceUnderMaliciousLoad(
          moduleConfig,
          moduleName
        );

      // Calculate summary
      testResults.summary = this.calculateTestSummary(testResults.tests);
      testResults.endTime = new Date().toISOString();
      testResults.success = testResults.summary.failedTests === 0;

      logger.info(`✅ Completed security tests for: ${moduleName}`);
    } catch (error) {
      testResults.error = error.message;
      testResults.success = false;
      testResults.endTime = new Date().toISOString();
      logger.error(
        `❌ Security tests failed for ${moduleName}: ${error.message}`
      );
    }

    return testResults;
  }

  static calculateTestSummary(testResults) {
    const allTests = Object.values(testResults).flat();

    return {
      totalTests: allTests.length,
      passedTests: allTests.filter((test) => test.success).length,
      failedTests: allTests.filter((test) => !test.success && !test.skipped)
        .length,
      skippedTests: allTests.filter((test) => test.skipped).length,
      successRate:
        allTests.length > 0
          ? (
              (allTests.filter((test) => test.success).length /
                allTests.length) *
              100
            ).toFixed(2) + "%"
          : "0%",
    };
  }

  static async executeTestsForAllModules(modules, testType = "security") {
    const results = [];

    for (const moduleInfo of modules) {
      const result = await this.executeSecurityTestsForModule(
        moduleInfo.config,
        moduleInfo.name
      );
      results.push(result);

      // Add delay between modules to avoid overwhelming the API
      await TestHelpers.sleep(1000);
    }

    return this.generateComprehensiveReport(results, testType);
  }

  static generateComprehensiveReport(results, testType) {
    const report = {
      testType,
      generatedAt: new Date().toISOString(),
      modulesTested: results.length,
      modulesPassed: results.filter((r) => r.success).length,
      modulesFailed: results.filter((r) => !r.success).length,
      detailedResults: results,
      overallSummary: this.calculateOverallSummary(results),
    };

    global.attachJSON(`Comprehensive ${testType} Test Report`, report);
    return report;
  }

  static calculateOverallSummary(results) {
    const allTests = results.flatMap((r) =>
      Object.values(r.tests || {}).flat()
    );

    return {
      totalModules: results.length,
      totalTests: allTests.length,
      passedTests: allTests.filter((test) => test.success).length,
      failedTests: allTests.filter((test) => !test.success && !test.skipped)
        .length,
      skippedTests: allTests.filter((test) => test.skipped).length,
      overallSuccessRate:
        allTests.length > 0
          ? (
              (allTests.filter((test) => test.success).length /
                allTests.length) *
              100
            ).toFixed(2) + "%"
          : "0%",
    };
  }
}

module.exports = TestOrchestrator;
