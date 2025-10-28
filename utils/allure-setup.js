// utils/allure-setup.js - Professional Allure integration
const fs = require("fs");
const path = require("path");

class AllureReporter {
  constructor() {
    this.resultsDir = path.join(process.cwd(), "allure-results");
    this.ensureResultsDir();
    this.currentTest = null;
    this.testSuite = "Enterprise API Testing Suite";
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

  startTest(testName) {
    this.currentTest = {
      uuid: this.generateUUID(),
      name: testName,
      historyId: this.generateHistoryId(testName),
      fullName: `${this.testSuite} - ${testName}`,
      labels: [
        { name: "framework", value: "Jest" },
        { name: "language", value: "JavaScript" },
        { name: "package", value: "api-testing-project" },
        { name: "suite", value: this.testSuite },
        { name: "testType", value: this.determineTestType(testName) },
        { name: "epic", value: "Enterprise API Testing" },
      ],
      links: [],
      start: Date.now(),
      steps: [],
      attachments: [],
      parameters: [],
      status: "passed",
      statusDetails: {},
      stage: "running",
    };

    console.log(`🔧 Starting Allure test: ${testName}`);
    return this.currentTest;
  }

  generateHistoryId(testName) {
    // Create consistent history ID for trend analysis
    return Buffer.from(testName).toString("base64");
  }

  determineTestType(testName) {
    const name = testName.toLowerCase();
    if (
      name.includes("crud") ||
      name.includes("create") ||
      name.includes("update") ||
      name.includes("delete")
    ) {
      return "CRUD";
    } else if (name.includes("security") || name.includes("malicious")) {
      return "Security";
    } else if (name.includes("token") || name.includes("auth")) {
      return "Authentication";
    } else if (name.includes("validation") || name.includes("schema")) {
      return "Validation";
    } else if (name.includes("resilience") || name.includes("persistence")) {
      return "Resilience";
    } else {
      return "Functional";
    }
  }

  endTest(status = "passed", error = null) {
    if (this.currentTest) {
      const validStatus = ["passed", "failed", "broken", "skipped"].includes(
        status
      )
        ? status
        : "failed";

      this.currentTest.status = validStatus;
      this.currentTest.stop = Date.now();
      this.currentTest.duration =
        this.currentTest.stop - this.currentTest.start;
      this.currentTest.stage = "finished";

      // Enhanced status details
      if (validStatus === "failed" || validStatus === "broken") {
        this.currentTest.statusDetails = {
          message: error?.message || "Test execution failed",
          trace:
            error?.stack || `Test failed after ${this.currentTest.duration}ms`,
          flaky: false,
        };
      }

      // Add severity based on test type
      this.addSeverityLabel();

      this.saveToAllureFormat();
      console.log(
        `📊 Allure test ended: ${this.currentTest.name} - Status: ${validStatus}, Duration: ${this.currentTest.duration}ms`
      );
      this.currentTest = null;
    }
  }

  addSeverityLabel() {
    const testName = this.currentTest.name.toLowerCase();
    let severity = "normal";

    if (testName.includes("critical") || testName.includes("security")) {
      severity = "critical";
    } else if (testName.includes("important") || testName.includes("crud")) {
      severity = "high";
    } else if (testName.includes("minor") || testName.includes("optional")) {
      severity = "low";
    }

    this.addLabel("severity", severity);
  }

  startStep(stepName, parameters = {}) {
    if (this.currentTest) {
      const step = {
        name: stepName,
        start: Date.now(),
        status: "passed",
        stage: "running",
        steps: [],
        attachments: [],
        parameters: Object.entries(parameters).map(([name, value]) => ({
          name,
          value: String(value),
          excluded: false,
          mode: "hidden",
        })),
      };
      this.currentTest.steps.push(step);
      console.log(`  ↳ Starting step: ${stepName}`);
      return step;
    }
    return null;
  }

  endStep(step, status = "passed", error = null) {
    if (step) {
      step.status = status;
      step.stop = Date.now();
      step.duration = step.stop - step.start;
      step.stage = "finished";

      if (status === "failed" && error) {
        step.statusDetails = {
          message: error.message,
          trace: error.stack,
        };
      }

      // If step fails, mark the test as failed
      if (status === "failed" && this.currentTest.status === "passed") {
        this.currentTest.status = "failed";
        this.currentTest.statusDetails = step.statusDetails;
      }

      console.log(
        `  ↳ Step completed: ${step.name} - ${status} (${step.duration}ms)`
      );
    }
  }

  addAttachment(name, content, type = "text/plain") {
    if (this.currentTest) {
      const attachmentId = this.generateUUID();
      const attachmentContent =
        typeof content === "object"
          ? JSON.stringify(content, null, 2)
          : content.toString();

      const attachmentFile = path.join(
        this.resultsDir,
        `${attachmentId}-attachment.txt`
      );
      fs.writeFileSync(attachmentFile, attachmentContent);

      this.currentTest.attachments.push({
        name,
        source: `${attachmentId}-attachment.txt`,
        type,
      });

      console.log(`  📎 Attachment added: ${name}`);
    }
  }

  // Enhanced Allure API methods
  epic(value) {
    this.addLabel("epic", value);
  }

  feature(value) {
    this.addLabel("feature", value);
  }

  story(value) {
    this.addLabel("story", value);
  }

  severity(value) {
    this.addLabel("severity", value);
  }

  addLabel(name, value) {
    if (this.currentTest) {
      // Remove existing label if it exists
      this.currentTest.labels = this.currentTest.labels.filter(
        (label) => label.name !== name
      );
      this.currentTest.labels.push({ name, value });
    }
  }

  description(value) {
    if (this.currentTest) {
      this.currentTest.description = value;
    }
  }

  addParameter(name, value, mode = "hidden") {
    if (this.currentTest) {
      this.currentTest.parameters.push({
        name,
        value: String(value),
        excluded: false,
        mode,
      });
    }
  }

  addLink(name, url, type = "custom") {
    if (this.currentTest) {
      this.currentTest.links.push({
        name,
        url,
        type,
      });
    }
  }

  setDescription(value) {
    this.description(value);
  }

  setSeverity(value) {
    this.severity(value);
  }

  saveToAllureFormat() {
    if (this.currentTest) {
      const resultFile = path.join(
        this.resultsDir,
        `${this.currentTest.uuid}-result.json`
      );

      const allureResult = {
        uuid: this.currentTest.uuid,
        historyId: this.currentTest.historyId,
        fullName: this.currentTest.fullName,
        labels: this.currentTest.labels,
        links: this.currentTest.links,
        name: this.currentTest.name,
        status: this.currentTest.status,
        statusDetails: this.currentTest.statusDetails,
        stage: this.currentTest.stage,
        description: this.currentTest.description,
        steps: this.currentTest.steps.map((step) => this.formatStep(step)),
        attachments: this.currentTest.attachments,
        parameters: this.currentTest.parameters,
        start: this.currentTest.start,
        stop: this.currentTest.stop,
      };

      fs.writeFileSync(resultFile, JSON.stringify(allureResult, null, 2));
    }
  }

  formatStep(step) {
    return {
      name: step.name,
      status: step.status,
      stage: step.stage,
      statusDetails: step.statusDetails || {},
      steps: step.steps.map((subStep) => this.formatStep(subStep)),
      attachments: step.attachments,
      parameters: step.parameters,
      start: step.start,
      stop: step.stop,
    };
  }
}

// Create global instance
const allureReporter = new AllureReporter();

module.exports = allureReporter;
