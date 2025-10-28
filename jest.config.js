// jest.config.js - Fixed configuration without external reporters
module.exports = {
  testEnvironment: "node",
  setupFilesAfterEnv: ["./jest.setup.js"],
  testTimeout: 30000,
  reporters: [
    "default",
  ],
  collectCoverage: true,
  coverageDirectory: "coverage",
  coverageReporters: ["text", "lcov", "html"],
  testMatch: [
    "**/tests/**/*.test.js",
    "**/tests/**/*.spec.js",
    "**/tests/**/*.test.test.js", // Add this pattern for your specific file
  ],
  moduleFileExtensions: ["js", "json"],
  verbose: true,
  forceExit: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
  testPathIgnorePatterns: [
    "/node_modules/",
    "/coverage/",
    "/allure-results/",
    "/allure-report/",
  ],
};
