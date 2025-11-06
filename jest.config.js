// jest.config.js - Fixed configuration with proper setup
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
  ]
};