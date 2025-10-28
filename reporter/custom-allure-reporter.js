// reporter/custom-allure-reporter.js - Custom Jest reporter for Allure
const fs = require("fs");
const path = require("path");

class CustomAllureReporter {
  constructor(globalConfig, options) {
    this._globalConfig = globalConfig;
    this._options = options;
    this.resultsDir = path.join(process.cwd(), "allure-results");
    this.ensureResultsDir();
  }

  ensureResultsDir() {
    if (!fs.existsSync(this.resultsDir)) {
      fs.mkdirSync(this.resultsDir, { recursive: true });
    }
  }

  generateUUID() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c == "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }
    );
  }

  onRunStart(results, options) {
    console.log("🚀 Starting test run with Custom Allure Reporter");
    console.log(`📊 Results will be saved to: ${this.resultsDir}`);
  }

  onTestStart(test) {
    const testName = this.getTestName(test);
    const testResult = {
      uuid: this.generateUUID(),
      name: testName,
      historyId: this.generateHistoryId(testName),
      fullName: testName,
      labels: [
        { name: "framework", value: "Jest" },
        { name: "language", value: "JavaScript" },
        { name: "package", value: "api-testing-project" },
      ],
      start: Date.now(),
      steps: [],
      attachments: [],
      status: "passed",
      stage: "running",
    };

    // Store test result in global context for jest.setup.js to access
    global.currentAllureTest = testResult;
  }

  onTestResult(test, testResult, aggregatedResult) {
    if (!global.currentAllureTest) return;

    const testStatus =
      testResult.status === "passed"
        ? "passed"
        : testResult.status === "failed"
        ? "failed"
        : "broken";

    global.currentAllureTest.status = testStatus;
    global.currentAllureTest.stop = Date.now();
    global.currentAllureTest.stage = "finished";
    global.currentAllureTest.duration =
      global.currentAllureTest.stop - global.currentAllureTest.start;

    // Add failure details if test failed
    if (testStatus === "failed" && testResult.failureMessage) {
      global.currentAllureTest.statusDetails = {
        message: testResult.failureMessage,
        trace: testResult.failureMessage,
      };
    }

    this.saveTestResult(global.currentAllureTest);
    global.currentAllureTest = null;
  }

  onRunComplete(contexts, results) {
    console.log("✅ Test run completed");
    console.log(`📊 Allure results saved to: ${this.resultsDir}`);
    console.log(
      `📈 Summary: ${results.numPassedTests} passed, ${results.numFailedTests} failed, ${results.numPendingTests} skipped`
    );
  }

  getTestName(test) {
    return test.path
      .replace(/^.*[\\/]/, "")
      .replace(".test.js", "")
      .replace(".test.test.js", "");
  }

  generateHistoryId(testName) {
    return Buffer.from(testName).toString("base64");
  }

  saveTestResult(testResult) {
    const resultFile = path.join(
      this.resultsDir,
      `${testResult.uuid}-result.json`
    );

    // Format according to Allure specification
    const allureResult = {
      uuid: testResult.uuid,
      historyId: testResult.historyId,
      fullName: testResult.fullName,
      labels: testResult.labels,
      name: testResult.name,
      status: testResult.status,
      statusDetails: testResult.statusDetails || {},
      stage: testResult.stage,
      steps: testResult.steps,
      attachments: testResult.attachments,
      start: testResult.start,
      stop: testResult.stop,
    };

    fs.writeFileSync(resultFile, JSON.stringify(allureResult, null, 2));
    console.log(
      `💾 Saved Allure result: ${testResult.name} - ${testResult.status}`
    );
  }
}

module.exports = CustomAllureReporter;
