// jest.config.js
// =============================================================
// ✅ Jest configuration with Allure integration
// =============================================================
module.exports = {
  testEnvironment: "<rootDir>/custom-allure-environment.js",
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],

  testMatch: [
    "**/tests/**/*.test.js",
    "**/tests/**/*.spec.js"
  ],

  verbose: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  testPathIgnorePatterns: ["/node_modules/", "/coverage/"],
  testTimeout: 60000,
  forceExit: true,

  testEnvironmentOptions: {
    resultsDir: "allure-results"
  }
};
