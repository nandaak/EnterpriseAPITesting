# API Testing Project - Comprehensive ERP System Test Suite

## 📋 Project Overview

This is a **professional-grade API testing framework** designed for comprehensive validation of an Enterprise Resource Planning (ERP) system. The project implements a complete test automation suite using Jest, focusing on CRUD operations, security testing, performance validation, and API health monitoring.

### Key Objectives

- **Complete CRUD Lifecycle Testing**: Validate Create, Read, Update, and Delete operations across all ERP modules
- **Security Validation**: Test authorization, input validation, SQL injection, XSS, privilege escalation, and IDOR vulnerabilities
- **Performance Testing**: Assess system behavior under malicious load conditions and stress scenarios
- **API Health Monitoring**: Continuous health checks for all API endpoints
- **Automated Test Generation**: Dynamic test generation based on Swagger/OpenAPI specifications

---

## 🎯 Project Summary

The test suite is organized into **5 comprehensive test categories** under `tests/comprehensive-lifecycle/`:

1. **CRUD Validation** - Complete lifecycle testing (Create → View → Edit → View → Delete → View)
2. **API Security** - Authorization, input validation, SQL injection, and XSS protection
3. **Advanced Security** - Business logic flaws, privilege escalation, mass assignment, IDOR, race conditions
4. **Performance & Load** - Malicious load testing, concurrent requests, throughput analysis
5. **API Health Checks** - Individual endpoint health monitoring and availability testing

### Test Coverage

- **75+ Generated Module Tests**: Automated tests for all ERP modules (Assets, Accounting, Sales, Inventory, HR, etc.)
- **Dynamic Schema-Based Testing**: Tests generated from Swagger API documentation
- **Centralized ID Registry**: Tracks all created test data across modules for cleanup and audit
- **HTML Test Reports**: Professional test reports with detailed failure analysis

---

## 📁 Project Structure

```
enterprise-erp-api-testing/
│
├── tests/
│   ├── comprehensive-lifecycle/          # Main test suites
│   │   ├── 1.comprehensive-CRUD-Validation.test.js
│   │   ├── 2.comprehensive-API-Security.test.js
│   │   ├── 3.Advanced-Security-Testing.test.js
│   │   ├── 4.Performance-Malicious-Load.test.js
│   │   └── 5.API-Health-Checks.test.js
│   │
│   ├── generated-modules/                # Auto-generated module tests (75+ files)
│   │   ├── Assets.test.js
│   │   ├── Customer.test.js
│   │   ├── Invoice.test.js
│   │   └── ... (70+ more modules)
│   │
│   └── helpers/                          # Test helper utilities
│       └── moduleIsolationHelper.js
│
├── config/                               # Configuration files
│   ├── api-config.js                     # API client configuration
│   ├── endpoint-config.js                # Endpoint definitions
│   └── modules-config.js                 # Module-specific configurations
│
├── utils/                                # Utility functions
│   ├── api-client.js                     # HTTP client wrapper
│   ├── crud-lifecycle-helper.js          # CRUD operation helpers
│   ├── security-helpers.js               # Security testing utilities
│   ├── advanced-security-helpers.js      # Advanced security tests
│   ├── performance-helpers.js            # Performance testing utilities
│   ├── token-manager.js                  # Authentication token management
│   ├── logger.js                         # Logging utility
│   ├── id-registry-manager.js            # Test data ID tracking
│   └── helper.js                         # General helper functions
│
├── scripts/                              # Automation scripts
│   ├── swagger-integration-tool.js       # Swagger API integration
│   ├── generate-module-tests.js          # Test generation
│   ├── clean-test-artifacts.js           # Cleanup utilities
│   └── test-orchestrator.js              # Test execution orchestration
│
├── Constants/                            # Constants and enums
├── test-data/                            # Test data files
├── html-report/                          # Generated HTML test reports
├── reports/                              # Test execution reports
├── test-results/                         # Test result artifacts
│
├── .env                                  # Environment configuration
├── jest.config.js                        # Jest configuration
├── jest.setup.js                         # Jest setup file
├── jest.globalSetup.js                   # Global test setup
├── package.json                          # Project dependencies
├── swagger-api-docs.json                 # API documentation
└── token.txt                             # Authentication token storage
```

---

## 🚀 Installation

### Prerequisites

- **Node.js** (v14 or higher)
- **npm** (v6 or higher)
- Valid API credentials for the ERP system

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/MohamedSci/enterprise-erp-api-testing.git
   cd enterprise-erp-api-testing
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   
   Edit the `.env` file with your credentials:
   ```env
   LOGIN_URL=https://2026.microtecstage.com/erp
   USEREMAIL=your.email@example.com
   PASSWORD=YourPassword
   API_BASE_URL=https://api.microtecstage.com
   DEBUG=true
   NODE_ENV=test
   ```

4. **Fetch authentication token**
   ```bash
   npm run fetchToken
   ```

5. **Verify setup**
   ```bash
   npm run verify:setup
   ```

---

## 💻 Usage

### Running Individual Test Suites

```bash
# Run CRUD Validation Tests
npm run test:1:crud

# Run API Security Tests
npm run test:2:security

# Run Advanced Security Tests
npm run test:3:advanced-security

# Run Performance Tests
npm run test:4:performance

# Run API Health Checks
npm run test:5:health
```

### Running All Tests

```bash
# Run all comprehensive lifecycle tests
npm run test:all

# Run all tests with verbose output
npm run test:all:verbose

# Run tests sequentially (one after another)
npm run test:all:sequential
```

### Running Generated Module Tests

```bash
# Generate module tests from Swagger
npm run test:generate:modules

# Run all generated module tests
npm run test:generated

# Run with verbose output
npm run test:generated:verbose
```

### Test Management

```bash
# Re-run only failed tests
npm run test:failed

# Run tests with coverage
npm run test:coverage

# Watch mode for development
npm run test:watch

# Debug specific test
npm run test:debug:crud
```

### Cleanup & Maintenance

```bash
# Clean test reports
npm run clean:reports

# Clean test IDs
npm run clean:ids

# Clean cache
npm run clean:cache

# Clean everything
npm run clean:all
```

---

## 📝 Test Suite Specifications

### 1. Comprehensive CRUD Validation (`1.comprehensive-CRUD-Validation.test.js`)

**Purpose**: Validates complete CRUD lifecycle for all ERP modules

**Test Flow**:
```
CREATE → View (verify creation) → EDIT → View (verify update) → DELETE → View (verify deletion - negative test)
```

**Key Features**:
- Centralized ID registry for tracking all created test data
- Module isolation (no cross-module dependencies)
- Automatic cleanup of test data
- Comprehensive state validation at each step

**Code Explanation**:
- Uses `CrudLifecycleHelper` to orchestrate CRUD operations
- Validates HTTP status codes (200, 201, 204, 404)
- Tracks created IDs in `createdIds.json` for audit trails
- Implements retry logic for flaky operations
- Generates detailed HTML reports with pass/fail status

**Example Test Output**:
```
✅ CREATE: Customer created successfully (ID: 12345)
✅ VIEW: Customer retrieved successfully
✅ EDIT: Customer updated successfully
✅ VIEW: Updated customer verified
✅ DELETE: Customer deleted successfully
✅ VIEW (Negative): Confirmed customer no longer exists (404)
```

---

### 2. Comprehensive API Security (`2.comprehensive-API-Security.test.js`)

**Purpose**: Tests security controls across all API endpoints

**Security Tests**:
- **Authorization Testing**: Validates token-based authentication
- **Input Validation**: Tests boundary conditions and invalid inputs
- **SQL Injection**: Attempts common SQL injection patterns
- **XSS Protection**: Tests cross-site scripting vulnerabilities
- **Data Validation**: Ensures proper data type enforcement

**Code Explanation**:
- Uses `SecurityHelpers` for standardized security tests
- Tests with malicious payloads (SQL injection strings, XSS scripts)
- Validates proper error responses (400, 401, 403)
- Checks for information leakage in error messages
- Ensures sensitive data is not exposed

**Malicious Payloads Tested**:
```javascript
- SQL Injection: "' OR '1'='1", "1; DROP TABLE users--"
- XSS: "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"
- Path Traversal: "../../../etc/passwd"
- Command Injection: "; ls -la", "| cat /etc/passwd"
```

---

### 3. Advanced Security Testing (`3.Advanced-Security-Testing.test.js`)

**Purpose**: Tests sophisticated security vulnerabilities

**Advanced Tests**:
- **Business Logic Flaws**: Tests for logic bypass vulnerabilities
- **Privilege Escalation**: Attempts to access unauthorized resources
- **Mass Assignment**: Tests for unintended field updates
- **IDOR (Insecure Direct Object Reference)**: Tests access to other users' data
- **Race Conditions**: Tests concurrent request handling

**Code Explanation**:
- Uses `advanced-security-helpers` for complex attack scenarios
- Simulates multi-user scenarios for privilege testing
- Tests concurrent requests to detect race conditions
- Validates proper authorization at the business logic level
- Checks for horizontal and vertical privilege escalation

**Example Scenarios**:
```javascript
// IDOR Test: Try to access another user's invoice
GET /api/Invoice/123 (with User A's token)
Expected: 403 Forbidden or 404 Not Found

// Mass Assignment: Try to set admin flag
POST /api/User { "name": "Test", "isAdmin": true }
Expected: 400 Bad Request or field ignored

// Race Condition: Concurrent updates
Parallel: UPDATE /api/Inventory/123 (quantity: -1)
Expected: Proper locking, no negative inventory
```

---

### 4. Performance & Malicious Load (`4.Performance-Malicious-Load.test.js`)

**Purpose**: Tests system performance under stress and malicious load

**Performance Metrics**:
- **Response Time**: Average, min, max response times
- **Throughput**: Requests per second
- **Success Rate**: Percentage of successful requests
- **Error Rate**: Percentage of failed requests
- **Concurrent Request Handling**: System behavior under load

**Code Explanation**:
- Uses `performance-helpers` for load generation
- Sends concurrent requests (10-50 simultaneous)
- Measures response times and throughput
- Tests rate limiting and throttling
- Validates graceful degradation under load

**Load Test Configuration**:
```javascript
{
  concurrentRequests: 20,
  totalRequests: 100,
  timeout: 5000,
  expectedSuccessRate: 0.95, // 95% success rate
  maxResponseTime: 2000 // 2 seconds
}
```

**Performance Thresholds**:
- Response Time: < 2000ms (acceptable)
- Success Rate: > 95%
- Throughput: > 10 req/sec
- Error Rate: < 5%

---

### 5. API Health Checks (`5.API-Health-Checks.test.js`)

**Purpose**: Monitors health and availability of all API endpoints

**Health Check Tests**:
- **Endpoint Availability**: Verifies each endpoint responds
- **Response Time**: Measures individual endpoint performance
- **Status Code Validation**: Ensures proper HTTP responses
- **Payload Validation**: Tests with minimal valid payloads
- **Error Handling**: Validates proper error responses

**Code Explanation**:
- Extracts all endpoints from schema
- Tests each endpoint individually
- Generates numbered test cases (001, 002, 003...)
- Measures response times for each endpoint
- Creates comprehensive health report

**Health Check Output**:
```
[001] GET Customer.List - Health Check ✅ (125ms)
[002] POST Customer.Create - Health Check ✅ (234ms)
[003] GET Invoice.View - Health Check ✅ (98ms)
[004] PUT Invoice.Edit - Health Check ⚠️ (1523ms - Slow)
[005] DELETE Invoice.Delete - Health Check ✅ (156ms)
```

**Health Status Indicators**:
- ✅ Healthy: Response < 1000ms, Status 2xx/4xx
- ⚠️ Slow: Response > 1000ms but < 3000ms
- ❌ Failed: Response > 3000ms or 5xx error
- ⏸️ Skipped: Endpoint not configured

---

## 🔧 Configuration Files

### `config/api-config.js`
Configures the API client with base URL, timeout, headers, and authentication token management.

**Key Features**:
- Dynamic token loading from file or environment
- Token validation and expiration checking
- Retry configuration for failed requests
- Request/response interceptors

### `config/modules-config.js`
Defines CRUD endpoints for each ERP module.

**Structure**:
```javascript
{
  "Customer": {
    "CREATE": ["/api/Customer", { name: "Test", email: "test@example.com" }],
    "View": ["/api/Customer/{id}"],
    "EDIT": ["/api/Customer/{id}", { name: "Updated" }],
    "DELETE": ["/api/Customer/{id}"]
  }
}
```

### `jest.config.js`
Jest test runner configuration with HTML reporting.

**Key Settings**:
- Test timeout: 30000ms (30 seconds)
- Test environment: Node.js
- HTML report generation
- Global setup for token validation
- Sequential test execution (`runInBand`)

---

## 🛠️ Utility Files

### `utils/api-client.js`
HTTP client wrapper using Axios with retry logic, error handling, and logging.

### `utils/crud-lifecycle-helper.js`
Orchestrates complete CRUD lifecycle operations with state validation.

### `utils/security-helpers.js`
Provides security testing utilities for authorization, injection, and XSS tests.

### `utils/performance-helpers.js`
Generates load tests and measures performance metrics.

### `utils/token-manager.js`
Manages authentication tokens, including reading, writing, validation, and expiration checking.

### `utils/logger.js`
Centralized logging utility with different log levels (info, warn, error, debug).

### `utils/id-registry-manager.js`
Tracks all created test data IDs for cleanup and audit purposes.

---

## 📊 Test Reports

### HTML Reports
Generated in `html-report/test-report.html` after each test run.

**Report Contents**:
- Test execution summary (passed/failed/skipped)
- Individual test results with timing
- Failure messages and stack traces
- Console logs for debugging
- Module-wise breakdown

### Viewing Reports
```bash
# Open HTML report in browser
start html-report/test-report.html  # Windows
open html-report/test-report.html   # macOS
xdg-open html-report/test-report.html  # Linux
```

---

## 🔐 Authentication

The project uses JWT token-based authentication.

### Token Management

```bash
# Fetch new token
npm run fetchToken

# Validate current token
npm run validate-token

# Check token status
npm run check-token
```

### Token Storage
- Stored in `token.txt` at project root
- Automatically loaded by `api-config.js`
- Validated before each test run
- Refreshed if expired

---

## 🧪 Test Data Management

### ID Registry
All created test data is tracked in `tests/createdIds.json`:

```json
{
  "Customer": [12345, 12346, 12347],
  "Invoice": [98765, 98766],
  "Asset": [55555]
}
```

### Cleanup
```bash
# Clean test IDs
npm run clean:ids

# Clean all test artifacts
npm run clean:all
```

---

## 📈 CI/CD Integration

### Running in CI/CD Pipeline

```bash
# CI-optimized test run
npm run test:ci
```

**CI Configuration**:
- Uses `--runInBand` for sequential execution
- Generates machine-readable reports
- Exits with proper error codes
- Includes retry logic for flaky tests

---

## 🐛 Debugging

### Debug Mode

```bash
# Debug CRUD tests
npm run test:debug:crud

# Debug security tests
npm run test:debug:security

# Watch mode for development
npm run test:watch
```

### Verbose Logging

Set `DEBUG=true` in `.env` for detailed logs.

---

## 📚 Dependencies

### Core Dependencies
- **jest**: Test framework
- **axios**: HTTP client
- **dotenv**: Environment variable management
- **jest-html-reporters**: HTML report generation

### Dev Dependencies
- **@babel/core**: JavaScript transpiler
- **babel-jest**: Jest Babel integration
- **rimraf**: Cross-platform file deletion

---

## 👨‍💻 Author

**Mohamed Said Ibrahim**

---

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests to ensure everything works
5. Submit a pull request

---

## 📞 Support

For issues or questions:
1. Check the HTML test reports for detailed error information
2. Review the logs in the console output
3. Ensure your `.env` file is properly configured
4. Verify your authentication token is valid

---

## 🎓 Best Practices

1. **Always run `npm run fetchToken` before testing** to ensure valid authentication
2. **Use `npm run clean:all` periodically** to remove old test artifacts
3. **Review HTML reports** after each test run for detailed insights
4. **Run tests sequentially** (`npm run test:all:sequential`) for more reliable results
5. **Keep your `.env` file secure** and never commit it to version control

---

## 🔄 Version History

- **v1.3.0**: Current version with comprehensive lifecycle testing
- Enhanced security testing suite
- Performance and load testing
- Automated test generation from Swagger
- Centralized ID registry
- HTML report generation

---

**Happy Testing! 🚀**
