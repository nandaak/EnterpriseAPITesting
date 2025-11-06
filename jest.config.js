// jest.config.js - Configuration with Jest-HTML-Reporters
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,
  
  // Enable the setup file
  setupFilesAfterEnv: ["./jest.setup.js"],
  
  testMatch: [
    "**/tests/**/*.test.js",
    "**/tests/**/*.spec.js", 
    "**/*.test.js",
    "**/*.spec.js"
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
  testPathIgnorePatterns: [
    "/node_modules/",
    "/coverage/"
  ],

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
        includeFailureMsg: true,
        includeSuiteFailure: true,
        logoImgPath: undefined,
        customInfos: [
          { title: "Project", value: "ERP API Testing" },
          { title: "Test Type", value: "Comprehensive" },
          { title: "Framework", value: "Jest" }
        ]
      }
    ]
  ]
};