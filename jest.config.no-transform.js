// jest.config.no-transform.js
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,
  forceExit: true,
  clearMocks: true,
  
  // Completely disable transformation
  transform: {},
  
  testMatch: [
    "**/tests/**/*.test.js"
  ],
  
  moduleFileExtensions: ["js", "json"],
  
  // Tell Jest to use Node.js native modules
  moduleNameMapping: {},
  
  collectCoverage: false,
  testPathIgnorePatterns: ["/node_modules/"]
};