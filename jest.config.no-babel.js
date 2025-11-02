// jest.config.no-babel.js - No Babel configuration
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,
  forceExit: true,
  clearMocks: true,
  
  // Disable transformation
  transform: {},
  
  testMatch: [
    "**/tests/**/*.test.js",
    "**/tests/**/*.spec.js"
  ],
  
  moduleFileExtensions: ["js", "json"],
  
  collectCoverage: false,
  testPathIgnorePatterns: ["/node_modules/"]
};