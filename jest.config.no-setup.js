// jest.config.no-setup.js - Configuration without setup file
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,
  forceExit: true,
  clearMocks: true,
  testMatch: [
    "**/tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js",
  ],
  moduleFileExtensions: ["js", "json"],
  testPathIgnorePatterns: ["/node_modules/"],
  collectCoverage: false,
};
