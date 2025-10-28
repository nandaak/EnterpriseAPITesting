// jest.setup.js - Complete CommonJS version with all required Allure methods
const logger = require("./utils/logger");

// Enhanced global allure object with all required methods
global.allure = {
  // Test lifecycle methods
  startTest: (testName) => {
    console.log(`🔧 Starting Allure test: ${testName}`);
    // Initialize test state for this test
    global.currentTest = {
      name: testName,
      startTime: new Date(),
      status: "passed",
      steps: [],
    };
  },

  endTest: (status = "passed") => {
    const testName = global.currentTest?.name || "Unknown Test";
    const duration = global.currentTest
      ? new Date() - global.currentTest.startTime
      : 0;

    console.log(
      `📊 Allure test ended: ${testName} - Status: ${status}, Duration: ${duration}ms`
    );

    // Reset current test
    global.currentTest = null;
  },

  // Test metadata methods
  epic: (name) => {
    console.log(`📖 EPIC: ${name}`);
    global.allure.addLabel("epic", name);
  },

  feature: (name) => {
    console.log(`🎯 FEATURE: ${name}`);
    global.allure.addLabel("feature", name);
  },

  story: (name) => {
    console.log(`📚 STORY: ${name}`);
    global.allure.addLabel("story", name);
  },

  severity: (level) => {
    console.log(`🚨 SEVERITY: ${level}`);
    global.allure.addLabel("severity", level);
  },

  description: (text) => {
    console.log(`📝 DESCRIPTION: ${text}`);
  },

  addLabel: (name, value) => {
    console.log(`🏷️ LABEL: ${name}=${value}`);
  },

  // Step methods
  step: (name, stepFn) => {
    console.log(`🔹 ALLURE STEP: ${name}`);
    const startTime = new Date();
    try {
      const result = stepFn();
      const duration = new Date() - startTime;
      console.log(`✅ ALLURE STEP COMPLETED: ${name} (${duration}ms)`);
      return result;
    } catch (error) {
      const duration = new Date() - startTime;
      console.log(
        `❌ ALLURE STEP FAILED: ${name} - ${error.message} (${duration}ms)`
      );
      throw error;
    }
  },

  // Attachment methods
  attachment: (name, content, type = "text/plain") => {
    console.log(`📎 ATTACHMENT: ${name} (${type})`);
    if (typeof content === "object") {
      content = JSON.stringify(content, null, 2);
    }
    console.log(`   Content: ${content.substring(0, 100)}...`);
  },

  // Parameter methods
  parameter: (name, value) => {
    console.log(`🔧 PARAMETER: ${name}=${value}`);
  },

  // Link methods
  link: (url, name, type) => {
    console.log(`🔗 LINK: ${name} - ${url} (${type})`);
  },

  // Suite methods
  parentSuite: (name) => {
    console.log(`🏠 PARENT SUITE: ${name}`);
  },

  suite: (name) => {
    console.log(`📁 SUITE: ${name}`);
  },

  subSuite: (name) => {
    console.log(`📂 SUB SUITE: ${name}`);
  },

  // Owner methods
  owner: (name) => {
    console.log(`👤 OWNER: ${name}`);
  },

  // Lead methods
  lead: (name) => {
    console.log(`👑 LEAD: ${name}`);
  },

  // Issue and TMS links
  issue: (name, url) => {
    console.log(`🐛 ISSUE: ${name} - ${url}`);
  },

  tms: (name, url) => {
    console.log(`✅ TMS: ${name} - ${url}`);
  },

  // Test ID
  testId: (id) => {
    console.log(`🆔 TEST ID: ${id}`);
  },

  // History ID
  historyId: (id) => {
    console.log(`🕰️ HISTORY ID: ${id}`);
  },
};

// Global allureStep function (enhanced version)
global.allureStep = async (name, stepFunction) => {
  console.log(`🔹 STEP: ${name}`);
  const startTime = new Date();

  try {
    const result = await stepFunction();
    const duration = new Date() - startTime;
    console.log(`✅ STEP COMPLETED: ${name} (${duration}ms)`);

    // Add step to current test if it exists
    if (global.currentTest) {
      global.currentTest.steps.push({
        name,
        status: "passed",
        duration,
      });
    }

    return result;
  } catch (error) {
    const duration = new Date() - startTime;
    console.log(`❌ STEP FAILED: ${name} - ${error.message} (${duration}ms)`);

    // Mark step as failed
    if (global.currentTest) {
      global.currentTest.steps.push({
        name,
        status: "failed",
        duration,
        error: error.message,
      });
      global.currentTest.status = "failed";
    }

    throw error;
  }
};

// Global attach functions
global.attachJSON = (name, data) => {
  const content =
    typeof data === "string" ? data : JSON.stringify(data, null, 2);
  console.log(
    `📊 ${name}:`,
    content.substring(0, 200) + (content.length > 200 ? "..." : "")
  );

  // Also add as allure attachment
  if (global.allure.attachment) {
    global.allure.attachment(name, content, "application/json");
  }
};

global.attachAllureLog = (name, message) => {
  const content =
    typeof message === "string" ? message : JSON.stringify(message);
  console.log(`📋 ${name}:`, content);

  // Also add as allure attachment
  if (global.allure.attachment) {
    global.allure.attachment(name, content, "text/plain");
  }
};

// Enhanced test state tracking
global.testState = {
  hasAssertionErrors: false,
  testStatus: "passed",
  currentTest: null,
  startTime: null,
};

// Enhanced test lifecycle hooks with proper status detection
beforeEach(() => {
  const testState = expect.getState();
  const testName = testState.currentTestName;

  if (testName) {
    // Start allure test
    global.allure.startTest(testName);

    // Reset test state
    global.testState.hasAssertionErrors = false;
    global.testState.testStatus = "passed";
    global.testState.currentTest = testName;
    global.testState.startTime = new Date();

    // Set default labels
    global.allure.addLabel("framework", "Jest");
    global.allure.addLabel("language", "JavaScript");
    global.allure.addLabel("test-type", "api-testing");

    console.log(`🚀 Test starting: ${testName}`);
  }
});

afterEach(() => {
  const testState = expect.getState();
  const testName = testState.currentTestName || global.testState.currentTest;

  if (!testName) return;

  // Determine test status based on multiple factors
  let finalStatus = "passed";

  // Check if we have assertion errors
  if (global.testState.hasAssertionErrors) {
    finalStatus = "failed";
  }

  // Check Jest's internal state
  if (testState.snapshotState && testState.snapshotState.unmatched > 0) {
    finalStatus = "failed";
  }

  // Check if any test results indicate failure
  if (
    testState.currentTestResults &&
    testState.currentTestResults.some((r) => r.status === "failed")
  ) {
    finalStatus = "failed";
  }

  // Check our internal test state
  if (global.testState.testStatus === "failed") {
    finalStatus = "failed";
  }

  // Check if current test was marked as failed
  if (global.currentTest && global.currentTest.status === "failed") {
    finalStatus = "failed";
  }

  // Calculate duration
  const duration = global.testState.startTime
    ? new Date() - global.testState.startTime
    : 0;

  // End the test with proper status
  global.allure.endTest(finalStatus);

  // Log test completion
  if (finalStatus === "passed") {
    console.log(`✅ ${testName} - PASSED (${duration}ms)`);
  } else {
    console.log(`❌ ${testName} - FAILED (${duration}ms)`);

    // Log any step failures
    if (global.currentTest && global.currentTest.steps) {
      const failedSteps = global.currentTest.steps.filter(
        (step) => step.status === "failed"
      );
      if (failedSteps.length > 0) {
        console.log(
          `   Failed steps: ${failedSteps.map((step) => step.name).join(", ")}`
        );
      }
    }
  }

  // Clean up
  global.testState.currentTest = null;
  global.testState.startTime = null;
});

// Enhanced error handling
process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
  global.testState.hasAssertionErrors = true;
  global.testState.testStatus = "failed";

  // Mark current test as failed if there is one
  if (global.currentTest) {
    global.currentTest.status = "failed";
  }
});

process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
  global.testState.hasAssertionErrors = true;
  global.testState.testStatus = "failed";

  // Mark current test as failed if there is one
  if (global.currentTest) {
    global.currentTest.status = "failed";
  }
});

// Test environment verification
console.log(
  "✅ Enhanced Allure Reporter initialized with proper test status detection"
);
console.log(
  "✅ Global allure methods available:",
  Object.keys(global.allure).join(", ")
);
