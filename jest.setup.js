// jest.setup.js - Enhanced with missing methods
const fs = require("fs");
const path = require("path");

class AllureSetup {
  constructor() {
    this.resultsDir = path.join(process.cwd(), "allure-results");
    this.ensureResultsDir();
    this._isInitialized = false;
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

  // SAFE: Direct console.log without using logger
  safeLog(message) {
    console.log(`[ALLURE] ${message}`);
  }

  attachAllureLog(name, content) {
    // Prevent recursion - don't process if this is a logger message
    if (
      typeof content === "string" &&
      (content.includes("[INFO]") ||
        content.includes("[DEBUG]") ||
        content.includes("[WARN]") ||
        content.includes("[ERROR]") ||
        content.includes("[ALLURE]"))
    ) {
      return; // Skip logger messages to prevent recursion
    }

    if (!global.currentAllureTest) return;

    const attachmentId = this.generateUUID();
    const attachmentContent =
      typeof content === "object"
        ? JSON.stringify(content, null, 2)
        : String(content);

    const attachmentFile = path.join(
      this.resultsDir,
      `${attachmentId}-attachment.txt`
    );
    fs.writeFileSync(attachmentFile, attachmentContent);

    if (!global.currentAllureTest.attachments) {
      global.currentAllureTest.attachments = [];
    }

    global.currentAllureTest.attachments.push({
      name: name,
      source: `${attachmentId}-attachment.txt`,
      type: "text/plain",
    });

    this.safeLog(`ATTACHMENT: ${name}`);
  }

  attachJSON(name, jsonData) {
    if (!global.currentAllureTest) return;

    const attachmentId = this.generateUUID();
    const jsonContent =
      typeof jsonData === "object"
        ? JSON.stringify(jsonData, null, 2)
        : jsonData;

    const attachmentFile = path.join(
      this.resultsDir,
      `${attachmentId}-attachment.json`
    );
    fs.writeFileSync(attachmentFile, jsonContent);

    if (!global.currentAllureTest.attachments) {
      global.currentAllureTest.attachments = [];
    }

    global.currentAllureTest.attachments.push({
      name: name,
      source: `${attachmentId}-attachment.json`,
      type: "application/json",
    });

    this.safeLog(`ATTACHMENT: ${name} (JSON)`);
  }

  addLabel(name, value) {
    if (!global.currentAllureTest) return;

    if (!global.currentAllureTest.labels) {
      global.currentAllureTest.labels = [];
    }

    // Remove existing label if it exists
    global.currentAllureTest.labels = global.currentAllureTest.labels.filter(
      (label) => label.name !== name
    );

    global.currentAllureTest.labels.push({ name, value });
  }

  // ADD MISSING METHOD: addParameter
  addParameter(name, value, mode = "hidden") {
    if (!global.currentAllureTest) return;

    if (!global.currentAllureTest.parameters) {
      global.currentAllureTest.parameters = [];
    }

    global.currentAllureTest.parameters.push({
      name,
      value: String(value),
      excluded: false,
      mode,
    });
  }

  // ADD MISSING METHOD: description
  description(value) {
    if (global.currentAllureTest) {
      global.currentAllureTest.description = value;
    }
  }

  // ADD MISSING METHOD: addLink
  addLink(name, url, type = "custom") {
    if (!global.currentAllureTest) return;

    if (!global.currentAllureTest.links) {
      global.currentAllureTest.links = [];
    }

    global.currentAllureTest.links.push({
      name,
      url,
      type,
    });
  }

  addStep(stepName) {
    if (!global.currentAllureTest) return null;

    if (!global.currentAllureTest.steps) {
      global.currentAllureTest.steps = [];
    }

    const step = {
      name: stepName,
      start: Date.now(),
      status: "passed",
      stage: "running",
    };

    global.currentAllureTest.steps.push(step);
    return step;
  }

  endStep(step, status = "passed") {
    if (step) {
      step.status = status;
      step.stop = Date.now();
      step.stage = "finished";
      step.duration = step.stop - step.start;
    }
  }

  initialize() {
    if (this._isInitialized) return;

    // Global allure methods - SAFE: No logger dependencies
    global.attachAllureLog = this.attachAllureLog.bind(this);
    global.attachJSON = this.attachJSON.bind(this);

    global.allureStep = async function (stepName, stepFunction) {
      const step = allureSetup.addStep(stepName);
      try {
        const result = await stepFunction();
        allureSetup.endStep(step, "passed");
        return result;
      } catch (error) {
        allureSetup.endStep(step, "failed");
        throw error;
      }
    };

    // Enhanced global allure object with ALL required methods
    global.allure = {
      // Labels and metadata
      addLabel: this.addLabel.bind(this),
      addParameter: this.addParameter.bind(this),
      description: this.description.bind(this),
      addLink: this.addLink.bind(this),

      // Test categorization
      epic: (value) => this.addLabel("epic", value),
      feature: (value) => this.addLabel("feature", value),
      story: (value) => this.addLabel("story", value),
      severity: (value) => this.addLabel("severity", value),

      // Suite organization
      suite: (value) => this.addLabel("suite", value),
      parentSuite: (value) => this.addLabel("parentSuite", value),
      subSuite: (value) => this.addLabel("subSuite", value),

      // Test management
      owner: (value) => this.addLabel("owner", value),
      lead: (value) => this.addLabel("lead", value),

      // Issue tracking
      issue: (value) =>
        this.addLink(value, `https://example.com/issue/${value}`, "issue"),
      tms: (value) =>
        this.addLink(value, `https://example.com/tms/${value}`, "tms"),
      testId: (value) => this.addLabel("testId", value),

      // Convenience methods
      setDescription: this.description.bind(this),
      setSeverity: (value) => this.addLabel("severity", value),
    };

    this._isInitialized = true;
    this.safeLog("Enhanced Allure Setup initialized - COMPLETE METHODS");
    this.safeLog(
      "Available methods: addLabel, addParameter, description, epic, feature, story, severity, suite, etc."
    );
  }
}

// Initialize safely
const allureSetup = new AllureSetup();
allureSetup.initialize();

module.exports = allureSetup;
