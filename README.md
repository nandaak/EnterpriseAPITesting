# 🚀 Enterprise API Testing Suite

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Test Suites Explained](#test-suites-explained)
- [Code Functions](#code-functions)
- [Test Reports](#test-reports)
- [Troubleshooting](#troubleshooting)

## 🎯 Project Overview

**Enterprise API Testing Suite** is a comprehensive, automated testing framework designed for enterprise-grade ERP systems. Built with Jest and modern testing practices, it provides end-to-end validation of API functionality, security, performance, and reliability across multiple modules.

### 🏆 Objectives

- **Comprehensive Coverage**: Test all API endpoints across the entire ERP system
- **Security Validation**: Identify vulnerabilities and security flaws
- **Performance Benchmarking**: Ensure system stability under load
- **CRUD Lifecycle Testing**: Validate complete data lifecycle operations
- **Health Monitoring**: Continuous endpoint availability checks
- **Automated Reporting**: Generate detailed test execution reports

### 🎯 Key Features

- ✅ **Multi-module testing** with automatic discovery
- ✅ **Comprehensive security testing** (SQL injection, XSS, authorization)
- ✅ **Performance testing** under malicious load conditions
- ✅ **Detailed HTML reporting** with Jest-HTML-Reporters
- ✅ **Token-based authentication** with automatic management
- ✅ **Modular architecture** for easy maintenance and extension
- ✅ **Real-time logging** and progress tracking
- ✅ **Error handling** and graceful degradation

## 🏗️ Project Structure

```
api-testing-project/
├── 📁 tests/
│   └── 📁 comprehensive-lifecycle/
│       ├── 🧪 1.comprehensive-CRUD-Validation.test.js
│       ├── 🛡️ 2.comprehensive-API-Security.test.js
│       ├── 🔒 3.Advanced-Security-Testing.test.js
│       ├── ⚡ 4.Performance-Malicious-Load.test.js
│       └── 🏥 5.API-Health-Checks.test.js
├── 📁 utils/
│   ├── 🔧 crud-lifecycle-helper.js
│   ├── 🛡️ test-helpers.js
│   ├── 🌐 api-client.js
│   ├── 📝 logger.js
│   └── 🎯 test-orchestrator.js
├── 📁 config/
│   ├── ⚙️ modules-config.js
│   └── 📊 constants.js
├── 📄 jest.config.js
├── 📄 jest.setup.js
├── 📄 babel.config.js
├── 📄 package.json
└── 📄 token.txt
```

## ⚙️ Installation

### Prerequisites

- Node.js 16+
- npm or yarn
- Access to target ERP API endpoints

### Step-by-Step Setup

1. **Clone and Install Dependencies**

```bash
git clone <repository-url>
cd api-testing-project
npm install
```

2. **Environment Configuration**

```bash
# Create environment file (if needed)
cp .env.example .env

# Update API configuration in constants.js
# Configure your API base URL and endpoints
```

3. **Authentication Setup**

```bash
# Generate authentication token
npm run fetch-token

# Verify token status
npm run check-token

# Debug token issues (if any)
npm run debug-token
```

4. **Verify Installation**

```bash
npm run verify:setup
```

## 🚀 Configuration

### Jest Configuration (`jest.config.js`)

```javascript
module.exports = {
  testEnvironment: "node",
  testTimeout: 30000,
  verbose: true,
  setupFilesAfterEnv: ["./jest.setup.js"],
  reporters: [
    "default",
    [
      "jest-html-reporters",
      {
        pageTitle: "API Testing Report",
        publicPath: "./html-report",
        filename: "test-report.html",
        expand: true,
        includeFailureMsg: true,
        includeSuiteFailure: true,
      },
    ],
  ],
};
```

### Module Configuration

Update `config/modules-config.js` with your API endpoints:

```javascript
module.exports = {
  schema: {
    Users: {
      Post: ["/api/users", "CREATE user"],
      View: ["/api/users/{id}", "VIEW user"],
      PUT: ["/api/users/{id}", "UPDATE user"],
      DELETE: ["/api/users/{id}", "DELETE user"],
    },
    // Add more modules...
  },
};
```

## 🧪 Running Tests

### Individual Test Suites

```bash
# Run CRUD validation tests
npm run crud-html

# Run security testing
npm run test:security-enhanced

# Run performance testing
npm run test:performance-real

# Run health checks
npx jest tests/comprehensive-lifecycle/5.API-Health-Checks.test.js
```

### Comprehensive Test Execution

```bash
# Run all test modules
npm run test:all-modules

# Run with HTML reporting
npm run test:report

# Run in CI mode
npm run test:ci
```

### Focused Testing

```bash
# Run only failed tests from previous run
npm run test:failed

# Run specific test file with debugging
npm run test-debug

# Run minimal setup (no external dependencies)
npm run test:simple
```

## 📊 Test Suites Explained

### 1. 🧪 Comprehensive CRUD Validation

**File**: `1.comprehensive-CRUD-Validation.test.js`

**Purpose**: Validates complete Create-Read-Update-Delete lifecycle across all API modules

**Test Coverage**:

- ✅ **CREATE Operations**: Resource creation with ID validation
- ✅ **VIEW Operations**: Data retrieval and validation
- ✅ **UPDATE Operations**: Resource modification testing
- ✅ **DELETE Operations**: Resource removal validation
- ✅ **Configuration Validation**: Module endpoint verification

**Key Features**:

- Automatic module discovery
- Dynamic endpoint validation
- Resource ID persistence
- Comprehensive error handling

### 2. 🛡️ Comprehensive API Security

**File**: `2.comprehensive-API-Security.test.js`

**Purpose**: Security vulnerability assessment across all API endpoints

**Security Tests**:

- 🔐 **Authorization Security**: Unauthorized access prevention
- 🦠 **Malicious Payload Protection**: Input validation testing
- 📝 **Data Validation**: Null/empty field rejection
- 💉 **SQL Injection Protection**: Database security testing
- 🕷️ **XSS Protection**: Cross-site scripting prevention

**Security Standards**:

- OWASP Top 10 compliance
- Input sanitization validation
- Authentication bypass testing
- Privilege escalation prevention

### 3. 🔒 Advanced Security Testing

**File**: `3.Advanced-Security-Testing.test.js`

**Purpose**: Advanced security scenarios and business logic vulnerabilities

**Advanced Tests**:

- 💰 **Business Logic Flaws**: Price manipulation, workflow bypass
- 🔄 **Privilege Escalation**: Horizontal/vertical access control
- 📦 **Mass Assignment**: Parameter pollution attacks
- 🔗 **IDOR Vulnerabilities**: Insecure direct object references
- 🏁 **Race Conditions**: Concurrency vulnerability testing

**Focus Areas**:

- Real-world attack simulations
- Business logic vulnerability detection
- Concurrency issue identification
- Access control validation

### 4. ⚡ Performance Under Malicious Load

**File**: `4.Performance-Malicious-Load.test.js`

**Purpose**: Performance and stability testing under attack conditions

**Performance Metrics**:

- ⏱️ **Response Times**: Average, P95, P99 response times
- 📈 **Success Rates**: Request success percentages
- 🚀 **Throughput**: Requests per second capacity
- 📉 **Error Rates**: System failure rates under load
- 🔧 **Error Handling**: Graceful degradation validation

**Load Conditions**:

- Concurrent malicious requests
- High-volume data submission
- System resource utilization
- Memory leak detection

### 5. 🏥 API Health Checks

**File**: `5.API-Health-Checks.test.js`

**Purpose**: Continuous endpoint health monitoring and availability

**Health Checks**:

- 🌐 **Endpoint Accessibility**: HTTP status validation
- ⚡ **Response Times**: Performance benchmarking
- 🔄 **Connectivity**: Network and service availability
- 📊 **Status Monitoring**: Real-time health status
- 🚨 **Alerting**: Failure detection and notification

**Monitoring Features**:

- Automated health dashboards
- Trend analysis and reporting
- Proactive failure detection
- Service level monitoring

## 🔧 Code Functions

### Core Utilities

#### 🎯 CRUD Lifecycle Helper (`utils/crud-lifecycle-helper.js`)

```javascript
class CrudLifecycleHelper {
  /**
   * Initialize helper for specific module
   * @param {string} moduleName - Target module name
   */
  async initialize(moduleName)

  /**
   * Execute CREATE operation test
   * @param {string} operationType - Operation type (Post, PUT, etc.)
   * @returns {object} Created resource details
   */
  async runCreateTest(operationType)

  /**
   * Execute VIEW operation test
   * @param {string} operationType - Operation type (View, GET, etc.)
   * @returns {object} Retrieved resource data
   */
  async runViewTest(operationType)

  /**
   * Validate prerequisites for test execution
   * @param {string} prerequisite - Required precondition
   */
  enforcePrerequisite(prerequisite)
}
```

#### 🛡️ Test Helpers (`utils/test-helpers.js`)

```javascript
class TestHelpers {
  /**
   * Test authorization security across endpoints
   * @param {object} moduleConfig - Module configuration
   * @returns {array} Authorization test results
   */
  static async testAuthorizationSecurity(moduleConfig)

  /**
   * Test malicious payload protection
   * @param {object} moduleConfig - Module configuration
   * @param {string} operationType - Target operation
   * @param {string} moduleName - Module name
   * @returns {array} Payload test results
   */
  static async testMaliciousPayloads(moduleConfig, operationType, moduleName)

  /**
   * Test SQL injection protection
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {array} SQL injection test results
   */
  static async testSQLInjectionProtection(moduleConfig, moduleName)

  /**
   * Test performance under malicious load
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {object} Performance metrics
   */
  static async testPerformanceUnderMaliciousLoad(moduleConfig, moduleName)
}
```

#### 🌐 API Client (`utils/api-client.js`)

```javascript
class ApiClient {
  /**
   * Make HTTP GET request
   * @param {string} url - Target URL
   * @param {object} config - Request configuration
   * @returns {object} Response data
   */
  async get(url, config = {})

  /**
   * Make HTTP POST request
   * @param {string} url - Target URL
   * @param {object} data - Request payload
   * @param {object} config - Request configuration
   * @returns {object} Response data
   */
  async post(url, data = {}, config = {})

  /**
   * Make HTTP PUT request
   * @param {string} url - Target URL
   * @param {object} data - Request payload
   * @param {object} config - Request configuration
   * @returns {object} Response data
   */
  async put(url, data = {}, config = {})

  /**
   * Make HTTP DELETE request
   * @param {string} url - Target URL
   * @param {object} config - Request configuration
   * @returns {object} Response data
   */
  async delete(url, config = {})
}
```

### Configuration Files

#### 📊 Constants (`config/constants.js`)

```javascript
module.exports = {
  // HTTP Status Codes
  HTTP_STATUS_CODES: {
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    INTERNAL_SERVER_ERROR: 500,
  },

  // Test Configuration
  TEST_CONFIG: {
    TIMEOUT: {
      SHORT: 10000,
      MEDIUM: 30000,
      LONG: 60000,
    },
  },

  // File Paths
  FILE_PATHS: {
    SCHEMA_PATH: "./config/schema.json",
    CREATED_ID_TXT: "./created-id.txt",
    CREATED_ID_FILE: "./created-id.json",
  },
};
```

## 📈 Test Reports

### HTML Reporting

After test execution, comprehensive HTML reports are generated in `html-report/test-report.html`:

**Report Features**:

- 📊 Test execution summary
- ✅ Pass/fail status with percentages
- ⏱️ Execution times and performance metrics
- 📝 Detailed failure messages and stack traces
- 🔍 Test suite organization by module
- 📈 Historical trend analysis

### Accessing Reports

```bash
# Generate and view report
npm run test:report

# View existing report (if generated)
open html-report/test-report.html
```

### Report Sections

1. **Executive Summary**: Overall test results and metrics
2. **Test Suite Details**: Individual test case results
3. **Failure Analysis**: Detailed error information
4. **Performance Metrics**: Response times and throughput
5. **Recommendations**: Improvement suggestions

## 🐛 Troubleshooting

### Common Issues

**Authentication Problems**

```bash
# Check token status
npm run check-token

# Regenerate token
npm run fetch-token

# Debug token issues
npm run debug-token
```

**Test Timeouts**

```javascript
// Increase timeout in jest.config.js
testTimeout: 60000, // Increase from 30s to 60s
  // Or for specific tests
  test("long test", async () => {
    // test code
  }, 60000);
```

**Connection Issues**

```bash
# Verify API accessibility
npm run check-token

# Test network connectivity
curl -I https://your-api-domain.com
```

**Memory Issues**

```bash
# Increase Node.js memory limit
node --max-old-space-size=4096 node_modules/.bin/jest
```

### Debugging Tips

1. **Enable Verbose Logging**

```bash
npx jest --verbose --no-cache
```

2. **Run Specific Test File**

```bash
npx jest tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js --verbose
```

3. **Debug Token Issues**

```bash
npm run debug-token-issue
```

4. **Check Test Environment**

```bash
npm run verify:setup
```

## 🤝 Contributing

### Adding New Test Modules

1. Create test file in `tests/comprehensive-lifecycle/`
2. Follow existing naming convention (`6.module-name.test.js`)
3. Implement comprehensive test scenarios
4. Update module configuration in `config/modules-config.js`
5. Add test documentation

### Extending Helpers

1. Add new methods to existing helper classes
2. Maintain backward compatibility
3. Update documentation
4. Add corresponding tests

## 📞 Support

For issues, questions, or contributions:

1. Check troubleshooting section above
2. Review test reports for specific failures
3. Examine console logs for detailed error information
4. Verify configuration and environment setup

---

**🎯 Enterprise API Testing Suite** - Your comprehensive solution for enterprise-grade API testing and validation.
https://chat.deepseek.com/a/chat/s/dd4f583c-7d6e-470a-a518-549ae396fcc8