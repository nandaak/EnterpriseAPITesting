// utils/allure-reporter.js - Lightweight Allure reporter for Jest
const fs = require("fs");
const path = require("path");
const { AllureRuntime, InMemoryAllureWriter } = require("allure-js-commons");
const { v4: uuidv4 } = require("uuid");

class AllureReporter {
  constructor() {
    this.allure = new AllureRuntime({
      resultsDir: path.join(process.cwd(), "allure-results"),
      writer: new InMemoryAllureWriter(),
    });

    this.currentTest = null;
    this.currentStep = null;

    this.resultsDir = path.join(process.cwd(), "allure-results");
    this.ensureResultsDir();
  }

  ensureResultsDir() {
    if (!fs.existsSync(this.resultsDir)) {
      fs.mkdirSync(this.resultsDir, { recursive: true });
    }
  }

  startSuite(suiteName) {
    this.currentSuite = this.allure.startGroup(suiteName);
  }

  endSuite() {
    if (this.currentSuite) {
      this.currentSuite.endGroup();
      this.currentSuite = null;
    }
  }

  startTest(testName) {
    const testResult = {
      uuid: uuidv4(),
      name: testName,
      start: Date.now(),
      stage: "running",
      steps: [],
      labels: [
        { name: "framework", value: "Jest" },
        { name: "language", value: "JavaScript" },
        { name: "package", value: "api-testing-project" },
      ],
    };

    global.currentAllureTest = testResult;
    return testResult;
  }

  endTest(status = "passed") {
    if (!global.currentAllureTest) return;

    const testResult = global.currentAllureTest;
    testResult.stop = Date.now();
    testResult.status = status;
    testResult.stage = "finished";

    this.saveTestResult(testResult);
    global.currentAllureTest = null;
  }

  startStep(stepName) {
    this.currentStep = this.allure.startStep(stepName);
  }

  endStep() {
    if (this.currentStep) {
      this.currentStep.endStep();
      this.currentStep = null;
    }
  }

  saveTestResult(testResult) {
    const filePath = path.join(
      this.resultsDir,
      `${testResult.uuid}-result.json`
    );
    fs.writeFileSync(filePath, JSON.stringify(testResult, null, 2));
    console.log(
      `💾 Saved Allure result: ${testResult.name} - ${testResult.status}`
    );
  }

  addLabel(name, value) {
    if (!global.currentAllureTest) return;

    global.currentAllureTest.labels.push({ name, value });
  }

  addStep(stepName, status = "passed", duration = 0) {
    if (!global.currentAllureTest) return;

    global.currentAllureTest.steps.push({
      name: stepName,
      status: status,
      start: Date.now() - duration,
      stop: Date.now(),
    });
  }

  addAttachment(name, content, type = "text/plain") {
    if (this.currentTest) {
      if (typeof content === "object") {
        content = JSON.stringify(content, null, 2);
      }
      this.currentTest.addAttachment(name, type, content);
    }
  }

  setSeverity(severity) {
    if (this.currentTest) {
      this.currentTest.severity = severity;
    }
  }

  setDescription(description) {
    if (this.currentTest) {
      this.currentTest.description = description;
    }
  }
}

// Create singleton instance
const allureReporter = new AllureReporter();

module.exports = allureReporter;
