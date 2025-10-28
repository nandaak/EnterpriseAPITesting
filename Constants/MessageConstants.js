// Constants/MessageConstants.js
const ERROR_MESSAGES = {
  ID_EXTRACTION_FAILED:
    "Could not extract ID from response - required for comprehensive CRUD testing",
  RESPONSE_VALIDATION_FAILED: "Response validation failed",
  AUTHORIZATION_FAILED: "Authorization security tests failed",
  MALICIOUS_PAYLOAD_FAILED: "Malicious payload tests failed",
  HEALTH_CHECK_FAILED: "Health check failed for endpoint",
};

const SUCCESS_MESSAGES = {
  TEST_COMPLETED: "Test completed successfully",
  LIFECYCLE_COMPLETED: "CRUD lifecycle completed successfully",
  SECURITY_PASSED: "Security tests passed",
  HEALTH_CHECK_PASSED: "Health check passed",
};

module.exports = {
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
};
