const fs = require("fs");
const path = require("path");
const { AllureRuntime, AllureTest, Status } = require("allure-js-commons");

class AllureReporter {
  constructor(globalConfig, options) {
    this.resultsDir = options?.resultsDir || "allure-results";
    if (!fs.existsSync(this.resultsDir)) fs.mkdirSync(this.resultsDir, { recursive: true });
    this.runtime = new AllureRuntime({ resultsDir: this.resultsDir });
  }

  onTestResult(test, testResult) {
    for (const result of testResult.testResults) {
      const allureTest = new AllureTest(this.runtime, Date.now().toString());
      allureTest.name = result.fullName;
      allureTest.fullName = result.fullName;
      allureTest.stage = "finished";

      switch (result.status) {
        case "passed":
          allureTest.status = Status.PASSED;
          break;
        case "failed":
          allureTest.status = Status.FAILED;
          break;
        default:
          allureTest.status = Status.SKIPPED;
      }

      allureTest.addLabel("framework", "Jest");
      allureTest.addLabel("suite", path.basename(test.path));
      allureTest.addLabel("language", "JavaScript");

      if (result.failureMessages?.length) {
        allureTest.addAttachment(
          "Failure details",
          "text/plain",
          result.failureMessages.join("\n")
        );
      }

      allureTest.endTest();
    }
  }
}

module.exports = AllureReporter;
