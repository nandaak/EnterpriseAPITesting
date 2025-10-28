// utils/custom-allure-reporter.js - Custom Jest reporter for Allure
const allureReporter = require("./allure-reporter");

class CustomAllureReporter {
  constructor(globalConfig, options) {
    this._globalConfig = globalConfig;
    this._options = options;
  }

  onRunStart(results, options) {
    console.log("🚀 Starting test run with Custom Allure Reporter");
  }

  onTestStart(test) {
    const testName = test.path.replace(/^.*[\\/]/, "").replace(".test.js", "");
    allureReporter.startTest(testName);
  }

  onTestResult(test, testResult, aggregatedResult) {
    const status = testResult.status === "passed" ? "passed" : "failed";
    allureReporter.endTest(status);

    // Add attachments for test result
    if (testResult.failureMessage) {
      allureReporter.addAttachment(
        "Test Failure",
        testResult.failureMessage,
        "text/plain"
      );
    }
  }

  onRunComplete(contexts, results) {
    console.log("✅ Test run completed");
    console.log(`📊 Allure results saved to: ${process.cwd()}/allure-results`);
  }
}

module.exports = CustomAllureReporter;
