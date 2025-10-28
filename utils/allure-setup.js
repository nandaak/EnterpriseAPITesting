// utils/allure-setup.js - Enhanced with proper status handling
const fs = require("fs");
const path = require("path");

class AllureReporter {
  constructor() {
    this.resultsDir = path.join(process.cwd(), "allure-results");
    this.ensureResultsDir();
    this.currentTest = null;
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
      historyId: testName,
      fullName: testName,
      labels: [
        { name: "framework", value: "Jest" },
        { name: "language", value: "JavaScript" },
        { name: "epic", value: "API Testing" },
        { name: "feature", value: "Comprehensive API Security and Validation" },
      ],
      links: [],
      start: Date.now(),
      steps: [],
      attachments: [],
      parameters: [],
      status: "passed", // Default status
      statusDetails: {},
      stage: "finished",
    };

    console.log(`🔧 Starting Allure test: ${testName}`);
    return this.currentTest;
  }

  endTest(status = "passed") {
    if (this.currentTest) {
      // Ensure status is valid for Allure
      const validStatus = ["passed", "failed", "broken", "skipped"].includes(
        status
      )
        ? status
        : "failed";

      this.currentTest.status = validStatus;
      this.currentTest.stop = Date.now();
      this.currentTest.duration =
        this.currentTest.stop - this.currentTest.start;

      // Add status details for failed tests
      if (validStatus === "failed") {
        this.currentTest.statusDetails = {
          message: "Test failed due to assertion errors or exceptions",
          trace: `Test duration: ${this.currentTest.duration}ms`,
        };
      }

      this.saveToAllureFormat();
      console.log(
        `📊 Allure test ended: ${this.currentTest.name} - Status: ${validStatus}`
      );
      this.currentTest = null;
    }
  }

  addStep(stepName) {
    if (this.currentTest) {
      const step = {
        name: stepName,
        start: Date.now(),
        status: "passed",
        stage: "finished",
        steps: [],
        attachments: [],
      };
      this.currentTest.steps.push(step);
      return step;
    }
    return null;
  }

  endStep(step, status = "passed") {
    if (step) {
      step.status = status;
      step.stop = Date.now();
      step.duration = step.stop - step.start;

      // If step fails, mark the test as failed
      if (status === "failed" && this.currentTest.status === "passed") {
        this.currentTest.status = "failed";
      }
    }
  }

  addAttachment(name, content, type = "text/plain") {
    if (this.currentTest) {
      const attachmentId = this.generateUUID();
      const attachmentContent =
        typeof content === "object"
          ? JSON.stringify(content, null, 2)
          : content.toString();

      // Save attachment file
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
    }
  }

  // Allure API methods
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

      // Format according to Allure specification
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
      console.log(
        `💾 Saved Allure result: ${this.currentTest.name} - ${this.currentTest.status}`
      );
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
      start: step.start,
      stop: step.stop,
    };
  }
}

// Create global instance
const allureReporter = new AllureReporter();

module.exports = allureReporter;
