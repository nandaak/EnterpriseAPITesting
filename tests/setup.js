const apiClient = require("../utils/api-client");
const logger = require("../utils/logger");

// Global test setup
beforeAll(() => {
  logger.info("Starting API Test Suite");
});

afterAll(() => {
  logger.info("API Test Suite completed");
});

// Global test timeout
jest.setTimeout(30000);

// Global error handling
process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
});
