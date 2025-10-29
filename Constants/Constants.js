// Constants/Constants.js - Fixed CommonJS version
const fs = require("fs");
const path = require("path");

// File paths and constants
const FILE_PATHS = {
  CREATED_ID_FILE: path.join(__dirname, "..", "tests", "createdId.json"),
  SCHEMA_PATH: path.join(
    __dirname,
    "..",
    "test-data",
    "Input",
    "Main-Backend-Api-Schema.json"
  ),
  TEST_RESULTS: path.join(__dirname, "..", "test-results"),
  ALLURE_RESULTS: path.join(__dirname, "..", "allure-results"),
};

// Test tags for Allure filtering
const TEST_TAGS = {
  CRUD: "CRUD",
  POSTTransaction: "POSTTransaction",
  Malicious: "Malicious",
  Mandatory: "Mandatory",
  ComprehensiveSecurity: "ComprehensiveSecurity",
  AdvancedSecurity: "AdvancedSecurity",
  Performance: "Performance",
  HealthChecks: "HealthChecks",
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

const HTTP_STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
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
const SCHEMA_PATH = "./test-data/Input/Main-Backend-Api-Schema.json";
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

// Export as CommonJS module
module.exports = {
  FILE_PATHS,
  TEST_TAGS,
  endpointTypes,
  HTTP_STATUS_CODES,
  SECURITY_PAYLOADS,
  TEST_CONFIG,
  createdIdFile,
  SCHEMA_PATH,
  schema,
};
