// Constants/FileConstants.js
const path = require("path");

const FILE_PATHS = {
  CREATED_ID_FILE: path.join(__dirname, "..", "tests", "createdId.json"),
  CREATED_ID_TXT: path.join(__dirname, "..", "createdId.txt"), // NEW: Simple text file

  SCHEMA_PATH: path.join(
    __dirname,
    "..",
    "test-data",
    "Input",
    "Main-Standarized-Backend-Api-Schema.json"
  ),
  TEST_RESULTS: path.join(__dirname, "..", "test-results"),
};

const TEST_CONFIG = {
  TIMEOUT: {
    SHORT: 10000,
    MEDIUM: 30000,
    LONG: 60000,
  },
  RETRY_ATTEMPTS: 3,
  SLOW_TEST_THRESHOLD: 5000,
};

module.exports = {
  FILE_PATHS,
  TEST_CONFIG,
};
