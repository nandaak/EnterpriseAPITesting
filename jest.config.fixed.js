// jest.config.fixed.js - Clean fixed configuration
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,

  // Remove setupFilesAfterEnv completely for now
  // setupFilesAfterEnv: ["./jest.setup.js"],

  testMatch: [
    "**/tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js",
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
  testPathIgnorePatterns: ["/node_modules/"],
  forceExit: true,
};
