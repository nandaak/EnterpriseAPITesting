// test-data/security/malicious-payloads.js

/**
 * Malicious payloads used for security testing.
 */
const MALICIOUS_PAYLOADS = {
  // Common SQL Injection payloads
  SQL_INJECTION: [
    "' OR '1'='1",
    "admin'--",
    '" OR 1=1 --',
    "SELECT * FROM users; --",
    "1; EXEC sp_delete_users",
    "DROP TABLE users; --",
  ],

  // Common Cross-Site Scripting (XSS) payloads
  XSS: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "';--><script>alert('XSS')</script>",
    '" onmouseover="alert(\'XSS\')"',
    "<body onload=alert('XSS')>",
  ],

  // A combination of both for comprehensive input fuzzing
  MIXED_MALICIOUS: [
    "<script>alert('XSS')</script>",
    "' OR '1'='1",
    "admin'--",
    '" OR 1=1 --',
    "<img src=x onerror=alert('XSS')>",
    "SELECT * FROM users; --",
  ],
};

module.exports = MALICIOUS_PAYLOADS;
