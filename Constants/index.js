// Constants/index.js - Main constants entry point
const {
  endpointTypes,
  TEST_TAGS,
  HTTP_STATUS_CODES,
  SECURITY_PAYLOADS,
} = require("./Constants");
const { FILE_PATHS, TEST_CONFIG } = require("./FileConstants");
const { ERROR_MESSAGES, SUCCESS_MESSAGES } = require("./MessageConstants");

module.exports = {
  ...endpointTypes,
  TEST_TAGS,
  HTTP_STATUS_CODES,
  SECURITY_PAYLOADS,
  FILE_PATHS,
  TEST_CONFIG,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
};
