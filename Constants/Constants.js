// Constants/Constants.js - Fixed CommonJS version
const fs = require("fs");
const path = require("path");

// File paths and constants
const FILE_PATHS = {
  SCHEMA_PATH: require("./../test-data/Input/Main-Backend-Api-Schema.json"), // Make sure this path is correct
  TOKEN_PATH: "./token.txt",
  // Path to your API's input JSON files
  INPUT_DATA_ROOT: path.join(__dirname, "test-data", "Input"),
  // Path to store generated IDs for CRUD lifecycle
  ID_STORAGE_ROOT: path.join(__dirname, "test-data", "Runtime"),
  CREATED_ID_FILE: path.join(__dirname, "..", "tests", "createdId.json"),
  SCHEMA_PATH: path.join(
    __dirname,
    "..",
    "test-data",
    "Input",
    "Main-Standarized-Backend-Api-Schema.json"
  ),
  TEST_RESULTS: path.join(__dirname, "..", "test-results"),
};

const endpointTypes = [
  "Post",
  "PUT",
  "DELETE",
  "View",
  "EDIT",
  "LookUP",
  "Commit",
  "GET",
];

const TEST_TAGS = {
  HEALTH: "health",
  REGRESSION: "regression",
  CRITICAL: "critical",
  CRUD: "CRUD_Lifecycle",
  SECURITY: "API_Security",
  PERFORMANCE: "Performance",
};

const HTTP_STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401, // Crucial for security test TC-1
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  UNPROCESSABLE_ENTITY: 422,
  INTERNAL_SERVER_ERROR: 500,
};

const SECURITY_PAYLOADS = {
  sqlInjection: [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM passwords --",
  ],
  xss: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
  ],
  pathTraversal: [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
  ],
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

// File paths and other constants
const createdIdFile = "./createdId.json";

// Load the generated schema
const SCHEMA_PATH =
  "./test-data/Input/Main-Standarized-Backend-Api-Schema.json";
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

// Export as CommonJS module
module.exports = {
  FILE_PATHS,
  endpointTypes,
  HTTP_STATUS_CODES,
  SECURITY_PAYLOADS,
  TEST_CONFIG,
  createdIdFile,
  SCHEMA_PATH,
  schema,
  TEST_TAGS,
};
