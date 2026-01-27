// jest.config.js - Configuration with Jest-HTML-Reporters
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,

  // Global setup - runs ONCE before all tests (token validation)
  globalSetup: "./jest.globalSetup.js",

  // Enable the setup file
  setupFilesAfterEnv: ["./jest.setup.js"],

  testMatch: [
    "**/tests/**/*.test.js",
    "**/tests/**/*.spec.js",
    "**/*.test.js",
    "**/*.spec.js",
  ],

  moduleFileExtensions: ["js", "json"],

  // Essential flags
  forceExit: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Disable coverage for now
  collectCoverage: false,

  // Simple ignore patterns
  testPathIgnorePatterns: ["/node_modules/", "/coverage/"],

  // Jest HTML Reporters configuration
  reporters: [
    "default",
    [
      "jest-html-reporters",
      {
        pageTitle: "API Testing Report",
        publicPath: "./html-report",
        filename: "test-report.html",
        expand: true,
        hideIcon: true,
        includeFailureMsg: true, // ✅ Show failure messages
        includeSuiteFailure: true, // ✅ Show suite failures
        includeConsoleLog: true, // ✅ Include console logs for failures
        includeStackTrace: true, // ✅ Show stack traces for failures
        customInfos: [
          { title: "Project", value: "ERP API Testing" },
          { title: "Test Type", value: "Comprehensive" },
          { title: "Framework", value: "Jest" },
        ],
        // Filter to show only failed tests in report
        failureMessageOnly: false, // Set to true for only failure messages
      },
    ],
  ],

  // Test failure options
  bail: false, // Continue running all tests even if some fail
  verbose: true, // Show detailed failure info
};
