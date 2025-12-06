# 🚀 Enterprise ERP API Testing Suite

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](https://github.com/your-repo)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)](https://nodejs.org)
[![Jest](https://img.shields.io/badge/jest-28.1.3-red.svg)](https://jestjs.io)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Schema Management](#-schema-management)
- [Running Tests](#-running-tests)
- [Test Suites Explained](#-test-suites-explained)
- [Utility Scripts](#-utility-scripts)
- [API Documentation](#-api-documentation)
- [Test Reports](#-test-reports)
- [Troubleshooting](#-troubleshooting)
- [Best Practices](#-best-practices)
- [Contributing](#-contributing)

---

## 🎯 Project Overview

**Enterprise ERP API Testing Suite** is a comprehensive, production-ready automated testing framework designed for enterprise-grade ERP systems. Built with Jest and modern testing practices, it provides end-to-end validation of API functionality, security, performance, and reliability across 96+ business modules.

### 📊 Project Summary

This testing suite validates a complete ERP system with:
- **96+ Business Modules** across 9 major functional areas
- **1,404+ API Endpoints** with full CRUD lifecycle testing
- **570+ Nested Module Configurations** for granular testing
- **Comprehensive Security Testing** following OWASP Top 10 standards
- **Performance Benchmarking** under normal and malicious load conditions
- **Automated Schema Management** with Swagger integration
- **Real-time Health Monitoring** for continuous availability checks

### 🏆 Objectives

1. **Comprehensive API Coverage**: Test all endpoints across the entire ERP system (General Settings, Accounting, Finance, Sales, Purchase, Inventory, Distribution, HR, Fixed Assets)
2. **Security Validation**: Identify vulnerabilities including SQL injection, XSS, authorization bypass, IDOR, and business logic flaws
3. **Performance Benchmarking**: Ensure system stability under normal and malicious load conditions
4. **CRUD Lifecycle Testing**: Validate complete Create-Read-Update-Delete operations with proper data persistence
5. **Health Monitoring**: Continuous endpoint availability and response time monitoring
6. **Automated Reporting**: Generate detailed HTML reports with metrics, trends, and actionable insights
7. **Schema Synchronization**: Maintain up-to-date API schemas from Swagger documentation
8. **ID Registry Management**: Track and manage resource IDs across test executions

### 🎯 Key Features

- ✅ **Multi-Module Testing**: Automatic discovery and testing of 96+ business modules
- ✅ **Comprehensive Security Testing**: SQL injection, XSS, authorization, IDOR, race conditions, business logic flaws
- ✅ **Performance Testing**: Load testing with concurrent requests and malicious payload handling
- ✅ **Detailed HTML Reporting**: Interactive reports with Jest-HTML-Reporters
- ✅ **Token-Based Authentication**: Automatic token management and refresh
- ✅ **Modular Architecture**: Easy maintenance, extension, and customization
- ✅ **Real-Time Logging**: Progress tracking with detailed execution logs
- ✅ **Error Handling**: Graceful degradation and comprehensive error reporting
- ✅ **Schema Management**: Swagger integration for automatic schema updates
- ✅ **ID Registry System**: Persistent resource ID tracking across test runs
- ✅ **Payload Generation**: Automatic test data generation from Swagger schemas
- ✅ **CI/CD Ready**: Designed for continuous integration pipelines

## �️ Arochitecture

The testing suite follows a modular, layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     Test Execution Layer                     │
│  (Jest Test Runner + HTML Reporters + CI/CD Integration)    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Test Orchestration Layer                  │
│     (Test Orchestrator + Module Discovery + Sequencing)     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      Test Suite Layer                        │
│  CRUD | Security | Advanced Security | Performance | Health │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      Helper Utilities Layer                  │
│  CRUD Helper | Test Helpers | API Client | Logger | Utils   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Data Management Layer                     │
│  Schema Manager | ID Registry | Payload Generator | Config  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      API Integration Layer                   │
│        (Axios HTTP Client + Authentication Manager)         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                         ERP API System                       │
│   (96+ Modules | 1,404+ Endpoints | 9 Functional Areas)    │
└─────────────────────────────────────────────────────────────┘
```

## 🏗️ Project Structure

```
enterprise-erp-api-testing/
│
├── 📁 tests/                                    # Test suites
│   ├── 📁 comprehensive-lifecycle/              # Main test suites
│   │   ├── 🧪 1.comprehensive-CRUD-Validation.test.js
│   │   ├── 🛡️ 2.comprehensive-API-Security.test.js
│   │   ├── 🔒 3.Advanced-Security-Testing.test.js
│   │   ├── ⚡ 4.Performance-Malicious-Load.test.js
│   │   └── 🏥 5.API-Health-Checks.test.js
│   ├── 📁 generated-modules/                    # Auto-generated module tests
│   ├── 🔐 auth-validation.test.js              # Authentication tests
│   └── 🧪 enhanced-crud-suite.test.js          # Enhanced CRUD tests
│
├── 📁 utils/                                    # Utility functions
│   ├── 🔧 crud-lifecycle-helper.js             # CRUD operations helper
│   ├── 🛡️ test-helpers.js                      # Security & test utilities
│   ├── 🌐 api-client.js                        # HTTP client wrapper
│   ├── 📝 logger.js                            # Logging utility
│   ├── 🎯 test-orchestrator.js                 # Test execution orchestrator
│   ├── 📊 show-failures.js                     # Failure report generator
│   └── 🔍 filter-failed-tests.js               # Failed test filter
│
├── 📁 test-helpers/                             # Test helper modules
│   ├── 🔐 auth-helper.js                       # Authentication helper
│   ├── 📋 schema-loader.js                     # Schema loading utility
│   └── 🆔 id-manager.js                        # ID registry manager
│
├── 📁 config/                                   # Configuration files
│   ├── ⚙️ modules-config.js                    # Module configuration
│   └── 📊 Constants.js                         # Global constants
│
├── 📁 test-data/                                # Test data & schemas
│   ├── 📁 Input/                               # API schemas
│   │   ├── 📄 Complete-Standarized-ERP-Api-Schema.json
│   │   ├── 📄 Enhanced-ERP-Api-Schema-Advanced-Fixed.json
│   │   ├── 📄 Enhanced-ERP-Api-Schema-With-Payloads.json
│   │   ├── 📄 Main-Standarized-Backend-Api-Schema.json
│   │   └── 📄 Main-Backend-Api-Schema.json
│   ├── 📁 modules/                             # Individual module schemas (96 files)
│   ├── 📁 security/                            # Security test data
│   │   └── 🛡️ malicious-payloads.js
│   ├── 🆔 id-registry.json                     # Resource ID registry
│   └── 🔧 test-data-generator.js               # Test data generator
│
├── 📁 scripts/                                  # Utility scripts
│   ├── 🔄 advanced-schema-merger.js            # Schema merger tool
│   ├── 📊 swagger-integration-tool.js          # Swagger integration
│   ├── 🔧 advanced-swagger-integration.js      # Advanced Swagger tools
│   ├── 📝 swagger-payload-generator.js         # Payload generator
│   ├── 🔍 schema-enhancement-utility.js        # Schema enhancement
│   ├── 🆔 schema-id-harmonizer.js              # ID harmonization
│   ├── 📋 complete-schema-enhancer.js          # Schema enhancer
│   ├── 🧪 generate-module-tests.js             # Test generator
│   ├── 🔧 comprehensive-error-fixer.js         # Error fixer
│   ├── 📊 advanced-payload-fixer.js            # Payload fixer
│   ├── 📈 final-test-analyzer.js               # Test analyzer
│   ├── 🔍 test-error-analyzer.js               # Error analyzer
│   ├── 📊 analyze-failure-responses.js         # Failure analyzer
│   ├── 🗑️ clean-test-artifacts.js              # Cleanup utility
│   ├── 🔍 query-id-registry.js                 # ID registry query tool
│   └── 📄 README.md                            # Scripts documentation
│
├── 📁 html-report/                              # Test reports
│   └── 📊 test-report.html                     # HTML test report
│
├── 📁 test-results/                             # Test results
│   └── 📊 test-results.json                    # JSON test results
│
├── 📁 backups/                                  # Backup files
│   └── 🗄️ [timestamped backups]
│
├── 📁 docs/                                     # Documentation
│   ├── 📖 AUTHENTICATION-GUIDE.md
│   ├── 📖 SCHEMA-USAGE-INFO.md
│   ├── 📖 SWAGGER-INTEGRATION-GUIDE.md
│   ├── 📖 ID-REGISTRY-SYSTEM-GUIDE.md
│   ├── 📖 DYNAMIC-ENDPOINT-GUIDE.md
│   ├── 📖 TESTING-ENHANCEMENT-COMPLETE.md
│   └── 📖 [50+ documentation files]
│
├── 📄 jest.config.js                            # Jest configuration
├── 📄 jest.setup.js                             # Jest setup
├── 📄 babel.config.js                           # Babel configuration
├── 📄 package.json                              # Project dependencies
├── 📄 .env                                      # Environment variables
├── 📄 token.txt                                 # Authentication token
├── 🆔 createdId.txt                             # Created resource IDs
├── 📄 README.md                                 # This file
└── 📄 LICENSE                                   # License file
```

## 📦 Installation

### Prerequisites

Before installing the testing suite, ensure you have:

- **Node.js**: Version 16.0.0 or higher ([Download](https://nodejs.org))
- **npm**: Version 7.0.0 or higher (comes with Node.js)
- **Git**: For cloning the repository
- **Network Access**: To target ERP API endpoints
- **API Credentials**: Valid username and password for authentication

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
# Clone the repository
git clone <repository-url>
cd enterprise-erp-api-testing

# Or download and extract the ZIP file
```

#### 2. Install Dependencies

```bash
# Install all required packages
npm install

# This will install:
# - Jest (testing framework)
# - Axios (HTTP client)
# - Babel (JavaScript transpiler)
# - Jest HTML Reporters (reporting)
# - Playwright (browser automation)
# - Other development dependencies
```

**Expected Output:**
```
added 847 packages, and audited 848 packages in 45s
✅ Installation complete
```

#### 3. Environment Configuration

Create and configure your environment file:

```bash
# Create .env file (if not exists)
touch .env

# Edit .env file with your API configuration
```

**`.env` Configuration:**
```env
# API Configuration
API_BASE_URL=https://your-erp-api.com
API_VERSION=v1

# Authentication
API_USERNAME=your_username
API_PASSWORD=your_password

# Test Configuration
TEST_TIMEOUT=30000
MAX_RETRIES=3
CONCURRENT_REQUESTS=10

# Logging
LOG_LEVEL=info
ENABLE_DEBUG=false
```

#### 4. Update Constants Configuration

Edit `config/Constants.js` with your specific API details:

```javascript
module.exports = {
  BASE_URL: process.env.API_BASE_URL || 'https://your-erp-api.com',
  API_ENDPOINTS: {
    LOGIN: '/api/auth/login',
    REFRESH_TOKEN: '/api/auth/refresh',
    // ... other endpoints
  },
  // ... other configurations
};
```

#### 5. Authentication Setup

Generate and verify your authentication token:

```bash
# Step 1: Fetch authentication token
npm run fetch-token

# Expected output:
# ✅ Token fetched successfully
# 📝 Token saved to token.txt
# ⏰ Token expires: 2024-12-07T12:00:00Z

# Step 2: Verify token status
npm run check-token

# Expected output:
# ✅ Token is valid
# 👤 User: admin@example.com
# 🔑 Token type: Bearer
# ⏰ Expires in: 23 hours 59 minutes

# Step 3: Debug token issues (if any)
npm run debug-token
```

**Troubleshooting Authentication:**
```bash
# If token fetch fails, debug the issue
npm run debug-token-issue

# Fix token file format issues
npm run fix-token

# Check token status in detail
npm run debug-token-status
```

#### 6. Schema Setup

The project includes multiple schema files. Ensure you're using the correct one:

```bash
# Use the complete standardized schema (recommended)
# File: test-data/Input/Complete-Standarized-ERP-Api-Schema.json

# Or update schemas from Swagger (if available)
npm run swagger:complete
```

#### 7. Verify Installation

Run the verification script to ensure everything is set up correctly:

```bash
npm run verify:setup

# Expected output:
# ✅ Node.js version: v18.17.0
# ✅ npm version: 9.6.7
# ✅ Dependencies installed: 847 packages
# ✅ Configuration files present
# ✅ Token file exists
# ✅ Schema files loaded
# ✅ Setup verified - Run npm run test:report
```

#### 8. Run Initial Test

Verify the setup with a quick test:

```bash
# Run health check tests
npm run test:Health

# Expected output:
# PASS tests/comprehensive-lifecycle/5.API-Health-Checks.test.js
# ✓ API Health Checks (1234ms)
# Test Suites: 1 passed, 1 total
# Tests: 5 passed, 5 total
```

### Installation Verification Checklist

- [ ] Node.js 16+ installed
- [ ] All npm packages installed successfully
- [ ] `.env` file created and configured
- [ ] `config/Constants.js` updated with API details
- [ ] Authentication token generated and valid
- [ ] Schema files present in `test-data/Input/`
- [ ] Verification script passed
- [ ] Initial test run successful

### Common Installation Issues

**Issue: `npm install` fails with permission errors**
```bash
# Solution: Use sudo (Linux/Mac) or run as Administrator (Windows)
sudo npm install
# Or fix npm permissions: https://docs.npmjs.com/resolving-eacces-permissions-errors
```

**Issue: Token fetch fails**
```bash
# Solution: Check API credentials and network connectivity
npm run debug-token-issue
# Verify API_BASE_URL in .env file
# Ensure firewall allows outbound connections
```

**Issue: Schema files missing**
```bash
# Solution: Ensure test-data directory is present
ls -la test-data/Input/
# If missing, restore from backup or regenerate
npm run swagger:complete
```

## ⚙️ Configuration

### Jest Configuration

The project uses Jest as the testing framework with custom configurations.

**`jest.config.js`** - Main configuration:
```javascript
module.exports = {
  testEnvironment: "node",              // Node.js environment for API testing
  testTimeout: 30000,                   // 30 seconds timeout per test
  verbose: true,                        // Detailed test output
  setupFilesAfterEnv: ["./jest.setup.js"], // Setup file
  maxWorkers: 1,                        // Run tests sequentially
  bail: false,                          // Continue on test failures
  
  // HTML Report Configuration
  reporters: [
    "default",                          // Console reporter
    [
      "jest-html-reporters",
      {
        pageTitle: "ERP API Testing Report",
        publicPath: "./html-report",
        filename: "test-report.html",
        expand: true,
        includeFailureMsg: true,
        includeSuiteFailure: true,
        enableMergeData: true,
        dataMergeLevel: 2,
      },
    ],
  ],
  
  // Coverage Configuration (optional)
  collectCoverage: false,
  coverageDirectory: "coverage",
  coverageReporters: ["text", "lcov", "html"],
};
```

**`jest.setup.js`** - Global setup:
```javascript
// Set longer timeout for all tests
jest.setTimeout(30000);

// Global test utilities
global.testConfig = {
  retryAttempts: 3,
  retryDelay: 1000,
};

// Suppress console warnings in tests (optional)
global.console = {
  ...console,
  warn: jest.fn(),
  error: jest.fn(),
};
```

**`babel.config.js`** - Transpilation configuration:
```javascript
module.exports = {
  presets: [
    [
      '@babel/preset-env',
      {
        targets: {
          node: 'current',
        },
      },
    ],
  ],
};
```

### Module Configuration

The testing suite uses schema-based configuration for dynamic module testing.

**Schema Structure:**
```javascript
{
  "Module_Name": {
    "Post": [
      "https://api.example.com/endpoint",
      {
        "field1": "value1",
        "field2": "value2"
      }
    ],
    "View": [
      "https://api.example.com/endpoint/<createdId>",
      {}
    ],
    "PUT": [
      "https://api.example.com/endpoint/<createdId>",
      {
        "field1": "updated_value"
      }
    ],
    "DELETE": [
      "https://api.example.com/endpoint/<createdId>",
      {}
    ]
  }
}
```

**Available Schemas:**

1. **Complete-Standarized-ERP-Api-Schema.json** (Recommended)
   - 96+ modules organized by business function
   - 1,404+ endpoints with full CRUD operations
   - Business-oriented hierarchical structure
   - Complete payload examples

2. **Enhanced-ERP-Api-Schema-Advanced-Fixed.json**
   - Technical API coverage
   - Flat module structure
   - All endpoints with parameters

3. **Enhanced-ERP-Api-Schema-With-Payloads.json**
   - Enhanced with Swagger-generated payloads
   - Realistic test data examples
   - Field validation rules

### Environment Variables

Configure the following environment variables in `.env`:

```env
# ============================================
# API Configuration
# ============================================
API_BASE_URL=https://your-erp-api.com
API_VERSION=v1
API_TIMEOUT=30000

# ============================================
# Authentication
# ============================================
API_USERNAME=admin@example.com
API_PASSWORD=your_secure_password
TOKEN_REFRESH_INTERVAL=3600000  # 1 hour in milliseconds

# ============================================
# Test Configuration
# ============================================
TEST_TIMEOUT=30000              # Test timeout in ms
MAX_RETRIES=3                   # Retry failed requests
RETRY_DELAY=1000                # Delay between retries in ms
CONCURRENT_REQUESTS=10          # Max concurrent requests

# ============================================
# Schema Configuration
# ============================================
SCHEMA_PATH=test-data/Input/Complete-Standarized-ERP-Api-Schema.json
MODULE_SCHEMA_PATH=test-data/modules/
ID_REGISTRY_PATH=test-data/id-registry.json

# ============================================
# Logging Configuration
# ============================================
LOG_LEVEL=info                  # debug | info | warn | error
ENABLE_DEBUG=false              # Enable debug logging
LOG_FILE_PATH=logs/test.log     # Log file path

# ============================================
# Report Configuration
# ============================================
REPORT_PATH=html-report/
REPORT_FILENAME=test-report.html
ENABLE_SCREENSHOTS=false        # Capture screenshots on failure

# ============================================
# Performance Configuration
# ============================================
PERFORMANCE_THRESHOLD_MS=2000   # Response time threshold
LOAD_TEST_DURATION=60000        # Load test duration in ms
LOAD_TEST_REQUESTS=1000         # Total requests for load test

# ============================================
# Security Configuration
# ============================================
ENABLE_SECURITY_TESTS=true      # Enable security testing
ENABLE_SQL_INJECTION_TESTS=true
ENABLE_XSS_TESTS=true
ENABLE_IDOR_TESTS=true

# ============================================
# CI/CD Configuration
# ============================================
CI_MODE=false                   # Enable CI mode
FAIL_ON_ERROR=true              # Fail build on test errors
GENERATE_JUNIT_REPORT=false     # Generate JUnit XML report
```

### Constants Configuration

Edit `config/Constants.js` for application-specific constants:

```javascript
module.exports = {
  // Base URLs
  BASE_URL: process.env.API_BASE_URL || 'https://default-api.com',
  
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
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    INTERNAL_SERVER_ERROR: 500,
    SERVICE_UNAVAILABLE: 503,
  },
  
  // Test Configuration
  TEST_CONFIG: {
    TIMEOUT: {
      SHORT: 10000,
      MEDIUM: 30000,
      LONG: 60000,
      EXTRA_LONG: 120000,
    },
    RETRY: {
      MAX_ATTEMPTS: 3,
      DELAY: 1000,
      BACKOFF_MULTIPLIER: 2,
    },
  },
  
  // File Paths
  FILE_PATHS: {
    SCHEMA_PATH: './test-data/Input/Complete-Standarized-ERP-Api-Schema.json',
    MODULE_SCHEMA_PATH: './test-data/modules/',
    CREATED_ID_TXT: './createdId.txt',
    CREATED_ID_FILE: './created-id.json',
    ID_REGISTRY: './test-data/id-registry.json',
    TOKEN_FILE: './token.txt',
  },
  
  // API Endpoints
  API_ENDPOINTS: {
    LOGIN: '/api/auth/login',
    REFRESH_TOKEN: '/api/auth/refresh',
    LOGOUT: '/api/auth/logout',
    CURRENT_USER: '/api/auth/current-user',
  },
  
  // Security Test Payloads
  SECURITY_PAYLOADS: {
    SQL_INJECTION: [
      "' OR '1'='1",
      "1' OR '1' = '1",
      "admin'--",
      "' UNION SELECT NULL--",
    ],
    XSS: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
    ],
  },
  
  // Performance Thresholds
  PERFORMANCE: {
    RESPONSE_TIME_THRESHOLD: 2000,  // 2 seconds
    SUCCESS_RATE_THRESHOLD: 95,     // 95%
    ERROR_RATE_THRESHOLD: 5,        // 5%
  },
};
```

## 📚 Schema Management

The testing suite uses JSON schemas to define API endpoints and test data. Multiple schema management tools are available.

### Available Schemas

| Schema File | Description | Modules | Endpoints | Use Case |
|------------|-------------|---------|-----------|----------|
| `Complete-Standarized-ERP-Api-Schema.json` | **Recommended** - Complete business-organized schema | 570+ | 1,404+ | Production testing |
| `Enhanced-ERP-Api-Schema-Advanced-Fixed.json` | Technical API coverage with flat structure | 96 | 1,404+ | Development testing |
| `Enhanced-ERP-Api-Schema-With-Payloads.json` | Enhanced with Swagger payloads | 96 | 1,404+ | Payload validation |
| `Main-Standarized-Backend-Api-Schema.json` | Original standardized schema (partial) | ~50 | ~700 | Legacy support |

### Schema Update Commands

```bash
# ============================================
# Swagger Integration
# ============================================

# Fetch latest Swagger documentation
npm run swagger:fetch

# Parse Swagger to schema format
npm run swagger:parse

# Generate payloads from Swagger
npm run swagger:generate

# Update schema with Swagger data
npm run swagger:update

# Validate schema against Swagger
npm run swagger:validate

# Complete Swagger workflow (fetch + parse + generate)
npm run swagger:complete

# ============================================
# Advanced Swagger Operations
# ============================================

# Fetch with advanced options
npm run swagger:advanced:fetch

# Parse with enhanced logic
npm run swagger:advanced:parse

# Generate enhanced schema
npm run swagger:advanced:generate

# Enhance existing schema
npm run swagger:advanced:enhance

# Validate with advanced rules
npm run swagger:advanced:validate

# Generate module-specific schemas
npm run swagger:advanced:modules

# Merge multiple schemas
npm run swagger:advanced:merge

# Show schema statistics
npm run swagger:advanced:stats

# ============================================
# Schema Enhancement
# ============================================

# Validate schema structure
npm run schema:enhance:validate

# Compare two schemas
npm run schema:enhance:compare

# Optimize schema size
npm run schema:enhance:optimize

# Standardize schema format
npm run schema:enhance:standardize

# Detect schema issues
npm run schema:enhance:detect

# Convert schema format
npm run schema:enhance:convert

# Analyze schema coverage
npm run schema:enhance:analyze

# Enhance with payloads
npm run schema:enhance:payloads

# ============================================
# Schema Maintenance
# ============================================

# Update all schemas
npm run schema:update

# Convert URLs to extensions
npm run schema:convert-urls

# Fix non-URL entries
npm run schema:fix-non-urls

# Harmonize IDs across schemas
npm run schema:harmonize:ids

# Complete schema update workflow
npm run schema:complete:update

# Production-ready schema generation
npm run schema:production:ready
```

### Schema Structure Example

```json
{
  "General_Settings": {
    "Master_Data": {
      "Country": {
        "Post": [
          "https://api.example.com/erp-apis/Country/Post",
          {
            "nameAr": "مصر",
            "nameEn": "Egypt",
            "code": "EG",
            "isActive": true
          }
        ],
        "View": [
          "https://api.example.com/erp-apis/Country/View/<createdId>",
          {}
        ],
        "PUT": [
          "https://api.example.com/erp-apis/Country/PUT",
          {
            "id": "<createdId>",
            "nameAr": "مصر المحدثة",
            "nameEn": "Egypt Updated"
          }
        ],
        "DELETE": [
          "https://api.example.com/erp-apis/Country/DELETE/<createdId>",
          {}
        ]
      }
    }
  }
}
```

### Working with Schemas

**Load Schema in Tests:**
```javascript
const schema = require('./test-data/Input/Complete-Standarized-ERP-Api-Schema.json');

// Access specific module
const countryModule = schema.General_Settings.Master_Data.Country;

// Get endpoint URL
const createUrl = countryModule.Post[0];
const createPayload = countryModule.Post[1];
```

**Generate Module Tests:**
```bash
# Generate test files for all modules
npm run test:generate:modules

# Run generated tests
npm run test:generated

# Complete workflow
npm run test:complete:suite
```

## 🧪 Running Tests

### Quick Start

```bash
# Run all tests with HTML report (Recommended)
npm run test:report

# Run all tests in CI mode
npm run test:ci

# Run all test modules sequentially
npm run test:all-modules
```

### Individual Test Suites

#### 1. CRUD Validation Tests

```bash
# Run CRUD tests with HTML report
npm run test:CRUD

# Run CRUD tests with detailed output
npm run crud-html

# Run CRUD tests in minimal mode
npm run crud-minimal

# Debug CRUD tests
npm run test-debug
```

**What it tests:**
- Create operations for all modules
- View/Read operations with ID validation
- Update operations with data modification
- Delete operations with cleanup
- Configuration validation

**Expected Duration:** 15-30 minutes (depending on module count)

#### 2. Security Tests

```bash
# Run comprehensive security tests
npm run test:Security

# Run advanced security tests
npx jest tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js --verbose
```

**What it tests:**
- Authorization bypass attempts
- SQL injection protection
- XSS (Cross-Site Scripting) protection
- Malicious payload handling
- Input validation
- IDOR vulnerabilities
- Business logic flaws
- Race conditions

**Expected Duration:** 20-40 minutes

#### 3. Performance Tests

```bash
# Run performance tests
npm run test:Performance

# Run with custom load parameters
npx jest tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js --verbose
```

**What it tests:**
- Response time under normal load
- Response time under malicious load
- Concurrent request handling
- System stability
- Error rate monitoring
- Throughput measurement

**Expected Duration:** 10-20 minutes

#### 4. Health Check Tests

```bash
# Run health check tests
npm run test:Health

# Run with monitoring
npx jest tests/comprehensive-lifecycle/5.API-Health-Checks.test.js --verbose
```

**What it tests:**
- Endpoint accessibility
- Response time benchmarks
- Service availability
- Network connectivity
- Status code validation

**Expected Duration:** 5-10 minutes

### Comprehensive Test Execution

```bash
# ============================================
# Full Test Suite Execution
# ============================================

# Run all tests sequentially with reports
npm run test:all-sequential

# Run all tests with orchestration
npm run test:orchestrated

# Run all modules with detailed reporting
npm run test:all-modules

# Run with HTML report generation
npm run test:html

# Run in CI/CD mode
npm run test:ci

# ============================================
# Enhanced Test Suites
# ============================================

# Run enhanced CRUD suite
npm run test:enhanced

# Run enhanced CRUD with verbose output
npm run test:enhanced:verbose

# Run authentication validation
npm run test:auth

# Run auth validation (quick mode)
npm run test:auth:quick

# Run auth + enhanced tests
npm run test:with:auth
```

### Focused Testing

```bash
# ============================================
# Failed Test Management
# ============================================

# Run only failed tests from previous run
npm run test:failed

# Rerun last failed tests
npm run test:rerun-failed

# Show failures only (no passing tests)
npm run test:failures-only

# Generate failed test report
npm run report:failed

# ============================================
# Debugging & Development
# ============================================

# Run with debugging enabled
npm run test-debug

# Run specific test file
npx jest tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js --verbose

# Run with no cache
npx jest --no-cache --verbose

# Run with coverage
npx jest --coverage

# Run in watch mode (for development)
npx jest --watch

# Run with specific test name pattern
npx jest -t "Country module"

# ============================================
# Quick Testing
# ============================================

# Run simple test (minimal dependencies)
npm run test:simple

# Run without Babel transpilation
npm run test:no-babel

# Fail fast (stop on first failure)
npm run test:fail-fast

# Quick fail (bail on error)
npm run test:quick-fail
```

### Test Execution Options

```bash
# ============================================
# Jest CLI Options
# ============================================

# Run tests in band (sequentially)
npx jest --runInBand

# Run with verbose output
npx jest --verbose

# Run with silent mode
npx jest --silent

# Run with specific config
npx jest --config=jest.config.js

# Run with timeout override
npx jest --testTimeout=60000

# Run with max workers
npx jest --maxWorkers=4

# Run with bail (stop after N failures)
npx jest --bail=1

# Run with detect open handles
npx jest --detectOpenHandles

# Run with force exit
npx jest --forceExit

# ============================================
# Filtering Tests
# ============================================

# Run tests matching pattern
npx jest --testPathPattern=CRUD

# Run tests with name matching
npx jest -t "CREATE operation"

# Run only changed tests
npx jest --onlyChanged

# Run tests related to changed files
npx jest --findRelatedTests

# ============================================
# Output & Reporting
# ============================================

# Generate JSON output
npx jest --json --outputFile=test-results.json

# Generate JUnit XML report
npx jest --reporters=jest-junit

# Update snapshots
npx jest --updateSnapshot

# Clear cache before running
npx jest --clearCache
```

### Running Specific Modules

```bash
# Run tests for specific module
npx jest -t "Country module" --verbose

# Run tests for specific operation
npx jest -t "CREATE operation" --verbose

# Run tests for specific business area
npx jest -t "General_Settings" --verbose

# Run generated module tests
npm run test:generated

# Generate and run module tests
npm run test:complete:suite
```

### Test Execution Best Practices

1. **First Time Running Tests:**
   ```bash
   # Ensure token is valid
   npm run check-token
   
   # Run health checks first
   npm run test:Health
   
   # Then run CRUD tests
   npm run test:CRUD
   ```

2. **Daily Testing:**
   ```bash
   # Quick validation
   npm run test:Health
   
   # Full suite with report
   npm run test:report
   ```

3. **Before Deployment:**
   ```bash
   # Complete validation
   npm run test:all-sequential
   
   # Security validation
   npm run test:Security
   
   # Performance validation
   npm run test:Performance
   ```

4. **Debugging Failures:**
   ```bash
   # Run failed tests only
   npm run test:failed
   
   # Debug specific test
   npm run test-debug
   
   # Analyze failures
   npm run analyze:failures
   ```

5. **CI/CD Pipeline:**
   ```bash
   # Set CI mode
   export CI_MODE=true
   
   # Run in CI mode
   npm run test:ci
   
   # Generate reports
   npm run test:report
   ```

## 🔬 Test Suites Explained

### 1. 🧪 Comprehensive CRUD Validation

**File**: `tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js`

**Purpose**: Validates complete Create-Read-Update-Delete lifecycle across all 96+ API modules

**Test Coverage**:

- ✅ **CREATE Operations (Post)**: Resource creation with automatic ID capture and validation
- ✅ **VIEW Operations (View/GET)**: Data retrieval, response validation, and field verification
- ✅ **UPDATE Operations (PUT/EDIT)**: Resource modification with data integrity checks
- ✅ **DELETE Operations (DELETE)**: Resource removal with cleanup validation
- ✅ **Configuration Validation**: Module endpoint structure and format verification
- ✅ **Prerequisite Enforcement**: Ensures proper test execution order
- ✅ **ID Registry Management**: Persistent ID tracking across test runs

**Test Flow**:
```
1. Configuration Validation
   ↓
2. CREATE Operation (capture ID)
   ↓
3. VIEW Operation (verify creation)
   ↓
4. UPDATE Operation (modify data)
   ↓
5. VIEW Operation (verify update)
   ↓
6. DELETE Operation (cleanup)
   ↓
7. Verify Deletion (404 expected)
```

**Key Features**:

- **Automatic Module Discovery**: Dynamically loads all modules from schema
- **Dynamic Endpoint Validation**: Validates URL structure and parameters
- **Resource ID Persistence**: Saves created IDs to registry for reuse
- **Comprehensive Error Handling**: Graceful failure with detailed error messages
- **Prerequisite Enforcement**: Ensures CREATE before UPDATE/DELETE
- **Parallel Execution Support**: Can run multiple modules concurrently
- **Detailed Logging**: Step-by-step execution logs

**Example Output**:
```
✓ Country module - Configuration validation (45ms)
✓ Country module - CREATE operation (1234ms)
✓ Country module - VIEW operation (567ms)
✓ Country module - UPDATE operation (890ms)
✓ Country module - DELETE operation (456ms)

Test Suites: 1 passed, 1 total
Tests: 96 passed, 96 total
Time: 45.678s
```

**Command**: `npm run test:CRUD`

### 2. 🛡️ Comprehensive API Security

**File**: `tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js`

**Purpose**: Comprehensive security vulnerability assessment across all API endpoints following OWASP Top 10 standards

**Security Test Categories**:

#### 🔐 Authorization Security
- **Unauthorized Access Prevention**: Tests API endpoints without authentication token
- **Token Validation**: Verifies proper token validation and rejection of invalid tokens
- **Session Management**: Tests session timeout and token expiration
- **Expected Result**: All endpoints should return 401 Unauthorized

#### 🦠 Malicious Payload Protection
- **Injection Attacks**: Tests SQL injection, NoSQL injection, command injection
- **Buffer Overflow**: Tests oversized payloads and field length limits
- **Format String Attacks**: Tests format string vulnerabilities
- **Expected Result**: All malicious payloads should be rejected with 400 Bad Request

#### 📝 Data Validation
- **Null/Empty Field Rejection**: Tests required field validation
- **Type Validation**: Tests incorrect data types (string instead of number, etc.)
- **Range Validation**: Tests out-of-range values
- **Format Validation**: Tests invalid formats (email, phone, date, etc.)
- **Expected Result**: Invalid data should be rejected with 400/422 status

#### 💉 SQL Injection Protection
- **Classic SQL Injection**: `' OR '1'='1`, `admin'--`, `1' OR '1' = '1`
- **Union-Based Injection**: `' UNION SELECT NULL--`
- **Blind SQL Injection**: Time-based and boolean-based attacks
- **Stored Procedure Injection**: Tests stored procedure vulnerabilities
- **Expected Result**: All SQL injection attempts should be sanitized or rejected

#### 🕷️ XSS (Cross-Site Scripting) Protection
- **Reflected XSS**: `<script>alert('XSS')</script>`
- **Stored XSS**: Persistent XSS in database fields
- **DOM-Based XSS**: `javascript:alert('XSS')`
- **Event Handler XSS**: `<img src=x onerror=alert('XSS')>`
- **Expected Result**: All XSS payloads should be sanitized or escaped

**Security Standards Compliance**:

- ✅ **OWASP Top 10 2021**: Covers all major vulnerability categories
- ✅ **Input Sanitization**: Validates proper input cleaning
- ✅ **Authentication Bypass**: Tests for authentication vulnerabilities
- ✅ **Privilege Escalation**: Tests for unauthorized access to resources
- ✅ **Security Headers**: Validates security-related HTTP headers
- ✅ **Rate Limiting**: Tests for rate limiting and throttling

**Test Execution**:
```javascript
// For each module:
1. Test Authorization (no token)
2. Test Malicious Payloads (SQL injection, XSS)
3. Test Data Validation (null, empty, invalid)
4. Test Input Sanitization
5. Generate Security Report
```

**Example Output**:
```
Security Testing Results:
✓ Authorization: 96/96 endpoints properly secured
✓ SQL Injection: 96/96 endpoints protected
✓ XSS Protection: 96/96 endpoints sanitized
✓ Data Validation: 96/96 endpoints validated
⚠ Warnings: 3 endpoints with weak validation

Security Score: 98.5%
```

**Command**: `npm run test:Security`

### 3. 🔒 Advanced Security Testing

**File**: `tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js`

**Purpose**: Advanced security scenarios, business logic vulnerabilities, and real-world attack simulations

**Advanced Security Test Categories**:

#### 💰 Business Logic Flaws
- **Price Manipulation**: Tests negative prices, zero prices, excessive discounts
- **Workflow Bypass**: Tests skipping approval steps, status manipulation
- **Quantity Manipulation**: Tests negative quantities, inventory bypass
- **Date Manipulation**: Tests backdating, future dating, date range bypass
- **Expected Result**: Business rules should be enforced server-side

**Test Cases**:
```javascript
// Price manipulation
{ price: -1000 }           // Negative price
{ price: 0, discount: 100 } // Zero price with discount
{ originalPrice: 100, salePrice: 1000 } // Sale price > original

// Workflow bypass
{ status: 'approved' }     // Skip approval workflow
{ approvalLevel: 999 }     // Bypass approval levels
```

#### 🔄 Privilege Escalation
- **Horizontal Escalation**: Access other users' resources at same privilege level
- **Vertical Escalation**: Access admin functions with user privileges
- **Role Manipulation**: Attempt to change own role/permissions
- **Branch Access**: Access resources from unauthorized branches
- **Expected Result**: All privilege escalation attempts should be blocked

**Test Cases**:
```javascript
// Horizontal escalation
GET /api/users/other-user-id  // Access another user's data

// Vertical escalation
POST /api/admin/settings      // User accessing admin endpoint
PUT /api/users/{id}/role      // User changing own role
```

#### 📦 Mass Assignment
- **Parameter Pollution**: Inject unauthorized fields in requests
- **Hidden Field Manipulation**: Modify fields not in UI
- **Nested Object Injection**: Inject malicious nested objects
- **Array Manipulation**: Inject unauthorized array elements
- **Expected Result**: Only whitelisted fields should be accepted

**Test Cases**:
```javascript
// Mass assignment
{
  name: "John",
  email: "john@example.com",
  role: "admin",              // Unauthorized field
  isActive: true,             // Hidden field
  permissions: ["all"]        // Injected field
}
```

#### 🔗 IDOR (Insecure Direct Object References)
- **Sequential ID Enumeration**: Access resources by guessing IDs
- **UUID Prediction**: Test UUID predictability
- **Reference Manipulation**: Modify object references in requests
- **Indirect Object References**: Test indirect reference vulnerabilities
- **Expected Result**: All object access should be authorized

**Test Cases**:
```javascript
// IDOR testing
GET /api/invoices/1          // Try sequential IDs
GET /api/invoices/2
GET /api/invoices/3
// Should only return user's own invoices
```

#### 🏁 Race Conditions
- **Concurrent Modifications**: Multiple simultaneous updates
- **Double Spending**: Concurrent payment processing
- **Inventory Race**: Concurrent stock deduction
- **Approval Race**: Concurrent approval requests
- **Expected Result**: Proper locking and transaction handling

**Test Cases**:
```javascript
// Race condition testing
Promise.all([
  updateInventory(itemId, -10),  // Concurrent stock deduction
  updateInventory(itemId, -10),
  updateInventory(itemId, -10)
]);
// Should handle concurrency properly
```

#### 🎭 Additional Advanced Tests
- **Session Fixation**: Test session hijacking vulnerabilities
- **CSRF (Cross-Site Request Forgery)**: Test CSRF token validation
- **Clickjacking**: Test X-Frame-Options header
- **Information Disclosure**: Test error messages for sensitive data
- **API Rate Limiting**: Test rate limiting bypass attempts

**Test Execution Flow**:
```
1. Business Logic Tests (per module)
2. Privilege Escalation Tests (cross-user)
3. Mass Assignment Tests (parameter injection)
4. IDOR Tests (object reference manipulation)
5. Race Condition Tests (concurrent requests)
6. Generate Advanced Security Report
```

**Example Output**:
```
Advanced Security Testing Results:
✓ Business Logic: 45/48 tests passed (3 warnings)
✓ Privilege Escalation: 24/24 tests passed
✓ Mass Assignment: 36/36 tests passed
✓ IDOR Protection: 48/48 tests passed
✓ Race Conditions: 12/12 tests passed

Critical Issues: 0
High Issues: 0
Medium Issues: 3
Low Issues: 5

Overall Security Score: 96.8%
```

**Command**: `npx jest tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js --verbose`

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

#### 📊 Constants (`config/Constants.js`)

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


## 🛠️ Utility Scripts

The project includes comprehensive utility scripts for schema management, testing, analysis, and maintenance.

### Authentication Scripts

```bash
# Fetch new authentication token
npm run fetchToken
npm run fetch-token

# Check token validity and status
npm run check-token

# Debug token issues
npm run debug-token
npm run debug-token-status
npm run debug-token-issue

# Fix token file format
npm run fix-token
```

### ID Registry Management

```bash
# Show registry statistics
npm run registry:stats

# List all registered IDs
npm run registry:list

# Generate registry report
npm run registry:report

# Export registry data
npm run registry:export

# Show active IDs
npm run registry:active

# Show recently created IDs
npm run registry:recent
```

### Cleanup & Maintenance

```bash
# Clean test reports
npm run clean:reports

# Clean ID registry files
npm run clean:ids

# Clean Jest cache
npm run clean:cache

# Clean all artifacts
npm run clean:all

# Clean with backup
npm run clean:backup

# Fresh start (clean everything)
npm run clean:fresh
```

### Test Analysis & Fixing

```bash
# Analyze test results
npm run analyze:tests

# Analyze test errors
npm run analyze:errors

# Analyze failure responses
npm run analyze:failures

# Fix comprehensive errors
npm run fix:comprehensive

# Fix payload issues
npm run fix:payloads:advanced

# Run all fixes
npm run fix:all
```

### Development Scripts

```bash
# Install Babel dependencies
npm run install-deps

# Verify setup
npm run verify:setup
```

---

## 📖 API Documentation

### Core Utility Classes

#### CrudLifecycleHelper

**Location**: `utils/crud-lifecycle-helper.js`

**Purpose**: Manages complete CRUD lifecycle testing for API modules

**Key Methods**:

```javascript
class CrudLifecycleHelper {
  /**
   * Initialize helper for specific module
   * @param {string} moduleName - Target module name
   * @param {object} moduleConfig - Module configuration from schema
   */
  async initialize(moduleName, moduleConfig)

  /**
   * Execute CREATE operation test
   * @param {string} operationType - Operation type (Post, PUT, etc.)
   * @returns {Promise<object>} Created resource details with ID
   */
  async runCreateTest(operationType)

  /**
   * Execute VIEW operation test
   * @param {string} operationType - Operation type (View, GET, etc.)
   * @param {string} createdId - ID of resource to view
   * @returns {Promise<object>} Retrieved resource data
   */
  async runViewTest(operationType, createdId)

  /**
   * Execute UPDATE operation test
   * @param {string} operationType - Operation type (PUT, EDIT, etc.)
   * @param {string} createdId - ID of resource to update
   * @returns {Promise<object>} Updated resource data
   */
  async runUpdateTest(operationType, createdId)

  /**
   * Execute DELETE operation test
   * @param {string} operationType - Operation type (DELETE)
   * @param {string} createdId - ID of resource to delete
   * @returns {Promise<boolean>} Deletion success status
   */
  async runDeleteTest(operationType, createdId)

  /**
   * Validate prerequisites for test execution
   * @param {string} prerequisite - Required precondition
   * @throws {Error} If prerequisite not met
   */
  enforcePrerequisite(prerequisite)

  /**
   * Save created ID to registry
   * @param {string} moduleName - Module name
   * @param {string} id - Created resource ID
   */
  saveCreatedId(moduleName, id)

  /**
   * Get created ID from registry
   * @param {string} moduleName - Module name
   * @returns {string|null} Created ID or null
   */
  getCreatedId(moduleName)
}
```

**Usage Example**:
```javascript
const helper = new CrudLifecycleHelper();
await helper.initialize('Country', countryModuleConfig);

// CREATE
const createResult = await helper.runCreateTest('Post');
const createdId = createResult.id;

// VIEW
const viewResult = await helper.runViewTest('View', createdId);

// UPDATE
const updateResult = await helper.runUpdateTest('PUT', createdId);

// DELETE
await helper.runDeleteTest('DELETE', createdId);
```

#### TestHelpers

**Location**: `utils/test-helpers.js`

**Purpose**: Provides security testing and validation utilities

**Key Methods**:

```javascript
class TestHelpers {
  /**
   * Test authorization security across endpoints
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} Authorization test results
   */
  static async testAuthorizationSecurity(moduleConfig, moduleName)

  /**
   * Test malicious payload protection
   * @param {object} moduleConfig - Module configuration
   * @param {string} operationType - Target operation
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} Payload test results
   */
  static async testMaliciousPayloads(moduleConfig, operationType, moduleName)

  /**
   * Test SQL injection protection
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} SQL injection test results
   */
  static async testSQLInjectionProtection(moduleConfig, moduleName)

  /**
   * Test XSS protection
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} XSS test results
   */
  static async testXSSProtection(moduleConfig, moduleName)

  /**
   * Test performance under malicious load
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @param {number} concurrentRequests - Number of concurrent requests
   * @returns {Promise<object>} Performance metrics
   */
  static async testPerformanceUnderMaliciousLoad(moduleConfig, moduleName, concurrentRequests = 10)

  /**
   * Test IDOR vulnerabilities
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} IDOR test results
   */
  static async testIDORVulnerabilities(moduleConfig, moduleName)

  /**
   * Test business logic flaws
   * @param {object} moduleConfig - Module configuration
   * @param {string} moduleName - Module name
   * @returns {Promise<array>} Business logic test results
   */
  static async testBusinessLogicFlaws(moduleConfig, moduleName)
}
```

#### ApiClient

**Location**: `utils/api-client.js`

**Purpose**: HTTP client wrapper with authentication and error handling

**Key Methods**:

```javascript
class ApiClient {
  /**
   * Make HTTP GET request
   * @param {string} url - Target URL
   * @param {object} config - Request configuration
   * @returns {Promise<object>} Response data
   */
  async get(url, config = {})

  /**
   * Make HTTP POST request
   * @param {string} url - Target URL
   * @param {object} data - Request payload
   * @param {object} config - Request configuration
   * @returns {Promise<object>} Response data
   */
  async post(url, data = {}, config = {})

  /**
   * Make HTTP PUT request
   * @param {string} url - Target URL
   * @param {object} data - Request payload
   * @param {object} config - Request configuration
   * @returns {Promise<object>} Response data
   */
  async put(url, data = {}, config = {})

  /**
   * Make HTTP DELETE request
   * @param {string} url - Target URL
   * @param {object} config - Request configuration
   * @returns {Promise<object>} Response data
   */
  async delete(url, config = {})

  /**
   * Get authentication token
   * @returns {Promise<string>} Authentication token
   */
  async getToken()

  /**
   * Refresh authentication token
   * @returns {Promise<string>} New authentication token
   */
  async refreshToken()

  /**
   * Set authentication token
   * @param {string} token - Authentication token
   */
  setToken(token)
}
```

---


## 📊 Test Reports

### HTML Report Generation

After test execution, comprehensive HTML reports are automatically generated.

**Report Location**: `html-report/test-report.html`

**Report Features**:

- 📊 **Executive Summary**: Overall test results, pass/fail rates, execution time
- ✅ **Test Suite Details**: Individual test case results with status
- ⏱️ **Performance Metrics**: Response times, throughput, success rates
- 📝 **Failure Analysis**: Detailed error messages, stack traces, request/response data
- 🔍 **Test Organization**: Hierarchical view by module and test suite
- 📈 **Historical Trends**: Compare results across test runs
- 🎯 **Coverage Metrics**: Endpoint coverage, module coverage
- 🔗 **Interactive Navigation**: Expandable sections, search, filtering

### Accessing Reports

```bash
# Generate and view report
npm run test:report

# View existing report (Windows)
start html-report/test-report.html

# View existing report (Mac)
open html-report/test-report.html

# View existing report (Linux)
xdg-open html-report/test-report.html
```

### Report Sections

#### 1. Executive Summary
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Test Execution Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Test Suites:     5
Passed:                5 (100%)
Failed:                0 (0%)

Total Tests:           480
Passed:                456 (95.0%)
Failed:                24 (5.0%)
Skipped:               0 (0%)

Execution Time:        45m 32s
Start Time:            2024-12-06 10:00:00
End Time:              2024-12-06 10:45:32
```

#### 2. Test Suite Breakdown
```
✓ CRUD Validation          96/96 tests passed   (15m 23s)
✓ API Security             96/96 tests passed   (18m 45s)
✓ Advanced Security        48/48 tests passed   (8m 12s)
⚠ Performance Testing      12/12 tests passed   (2m 34s) - 3 warnings
✓ Health Checks            5/5 tests passed     (0m 38s)
```

#### 3. Module-Level Results
```
General_Settings
  ✓ Country                 5/5 passed
  ✓ Branch                  5/5 passed
  ✓ Currency                5/5 passed
  ⚠ User                    4/5 passed - 1 warning

Accounting
  ✓ ChartOfAccounts         5/5 passed
  ✓ JournalEntry            5/5 passed
  ✗ AccountingReports       3/5 passed - 2 failures
```

#### 4. Failure Details
```
❌ AccountingReports - Trial Balance Export
   Expected: 200 OK
   Received: 500 Internal Server Error
   
   Request:
   POST /api/accounting/reports/trial-balance/export
   {
     "startDate": "2024-01-01",
     "endDate": "2024-12-31",
     "format": "pdf"
   }
   
   Response:
   {
     "error": "Database connection timeout",
     "code": "DB_TIMEOUT"
   }
   
   Stack Trace:
   at TestHelpers.testAccountingReports (test-helpers.js:234)
   at Object.<anonymous> (2.comprehensive-API-Security.test.js:156)
```

#### 5. Performance Metrics
```
Response Time Distribution:
< 500ms:    234 requests (48.8%)
500-1000ms: 156 requests (32.5%)
1000-2000ms: 67 requests (14.0%)
> 2000ms:    23 requests (4.8%)

Average Response Time: 876ms
P95 Response Time:     1834ms
P99 Response Time:     2456ms
```

#### 6. Security Summary
```
Security Test Results:
✓ Authorization:       96/96 endpoints secured
✓ SQL Injection:       96/96 endpoints protected
✓ XSS Protection:      96/96 endpoints sanitized
✓ IDOR Protection:     48/48 tests passed
⚠ Business Logic:      45/48 tests passed (3 warnings)

Overall Security Score: 97.8%
```

### JSON Report

For programmatic access, JSON reports are also generated:

**Location**: `test-results/test-results.json`

```json
{
  "numTotalTestSuites": 5,
  "numPassedTestSuites": 5,
  "numFailedTestSuites": 0,
  "numTotalTests": 480,
  "numPassedTests": 456,
  "numFailedTests": 24,
  "testResults": [
    {
      "name": "CRUD Validation",
      "status": "passed",
      "duration": 923000,
      "tests": [...]
    }
  ],
  "startTime": 1701864000000,
  "endTime": 1701866732000,
  "success": false
}
```

### Custom Report Generation

```bash
# Generate JSON report
npx jest --json --outputFile=test-results/custom-report.json

# Generate JUnit XML report (for CI/CD)
npx jest --reporters=jest-junit

# Generate coverage report
npx jest --coverage
```

---

## 🐛 Troubleshooting

### Common Issues & Solutions

#### 1. Authentication Problems

**Issue**: Token fetch fails or returns 401 Unauthorized

```bash
# Solution 1: Check credentials
# Verify username and password in .env file

# Solution 2: Check token status
npm run check-token

# Solution 3: Regenerate token
npm run fetch-token

# Solution 4: Debug token issues
npm run debug-token-issue

# Solution 5: Fix token file format
npm run fix-token
```

**Issue**: Token expires during test execution

```bash
# Solution: Increase token expiration time in API settings
# Or implement automatic token refresh in tests
```

#### 2. Test Timeouts

**Issue**: Tests fail with timeout errors

```javascript
// Solution 1: Increase timeout in jest.config.js
module.exports = {
  testTimeout: 60000, // Increase from 30s to 60s
};

// Solution 2: Increase timeout for specific test
test('long running test', async () => {
  // test code
}, 60000); // 60 second timeout

// Solution 3: Increase timeout globally in jest.setup.js
jest.setTimeout(60000);
```

#### 3. Connection Issues

**Issue**: Cannot connect to API endpoints

```bash
# Solution 1: Verify API accessibility
curl -I https://your-api-domain.com

# Solution 2: Check network connectivity
ping your-api-domain.com

# Solution 3: Verify firewall settings
# Ensure outbound connections are allowed

# Solution 4: Check API base URL in .env
# Verify API_BASE_URL is correct

# Solution 5: Test with simple request
npm run test:Health
```

#### 4. Schema Loading Errors

**Issue**: Cannot load schema files

```bash
# Solution 1: Verify schema files exist
ls -la test-data/Input/

# Solution 2: Regenerate schemas
npm run swagger:complete

# Solution 3: Use alternative schema
# Edit test files to use different schema path

# Solution 4: Restore from backup
cp backups/latest-schema.json test-data/Input/
```

#### 5. Memory Issues

**Issue**: Tests fail with out of memory errors

```bash
# Solution 1: Increase Node.js memory limit
node --max-old-space-size=4096 node_modules/.bin/jest

# Solution 2: Run tests sequentially
npx jest --runInBand

# Solution 3: Reduce concurrent requests
# Edit test configuration to lower concurrency

# Solution 4: Clear Jest cache
npm run clean:cache
npx jest --clearCache
```

#### 6. Module Not Found Errors

**Issue**: Cannot find module errors

```bash
# Solution 1: Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Solution 2: Install missing dependencies
npm run install-deps

# Solution 3: Clear cache and reinstall
npm run clean:cache
npm install
```

#### 7. Test Failures

**Issue**: Tests fail unexpectedly

```bash
# Solution 1: Run failed tests only
npm run test:failed

# Solution 2: Analyze failures
npm run analyze:failures

# Solution 3: Fix common errors
npm run fix:comprehensive

# Solution 4: Debug specific test
npm run test-debug

# Solution 5: Check test data
# Verify test data in schema is valid
```

#### 8. Report Generation Issues

**Issue**: HTML report not generated

```bash
# Solution 1: Verify reporter configuration
# Check jest.config.js reporters section

# Solution 2: Reinstall reporter package
npm install --save-dev jest-html-reporters

# Solution 3: Clear report directory
npm run clean:reports

# Solution 4: Run with explicit report generation
npm run test:html
```

### Debugging Tips

#### 1. Enable Verbose Logging

```bash
# Run with verbose output
npx jest --verbose

# Run with debug logging
DEBUG=* npx jest

# Run with no cache
npx jest --no-cache --verbose
```

#### 2. Run Specific Tests

```bash
# Run specific test file
npx jest tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js

# Run specific test by name
npx jest -t "Country module"

# Run specific test suite
npx jest --testNamePattern="CRUD"
```

#### 3. Inspect Test Data

```bash
# View schema structure
node -e "console.log(JSON.stringify(require('./test-data/Input/Complete-Standarized-ERP-Api-Schema.json'), null, 2))"

# View ID registry
cat test-data/id-registry.json

# View created IDs
cat createdId.txt
```

#### 4. Check Environment

```bash
# Verify Node.js version
node --version

# Verify npm version
npm --version

# Verify dependencies
npm list

# Verify setup
npm run verify:setup
```

#### 5. Network Debugging

```bash
# Test API connectivity
curl -X GET https://your-api-domain.com/api/health

# Test authentication
curl -X POST https://your-api-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Test with token
curl -X GET https://your-api-domain.com/api/users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Getting Help

If you continue to experience issues:

1. **Check Documentation**: Review relevant documentation files in `docs/` directory
2. **Review Logs**: Check test execution logs for detailed error information
3. **Analyze Reports**: Review HTML reports for failure patterns
4. **Check Issues**: Search for similar issues in project repository
5. **Contact Support**: Reach out to development team with:
   - Error messages
   - Test execution logs
   - Environment details (Node version, OS, etc.)
   - Steps to reproduce

---

## 🎯 Best Practices

### Test Execution

1. **Always verify token before running tests**
   ```bash
   npm run check-token
   ```

2. **Run health checks first**
   ```bash
   npm run test:Health
   ```

3. **Run tests sequentially for stability**
   ```bash
   npx jest --runInBand
   ```

4. **Use appropriate timeouts**
   - Short tests: 10s
   - Medium tests: 30s
   - Long tests: 60s

5. **Clean up test artifacts regularly**
   ```bash
   npm run clean:all
   ```

### Schema Management

1. **Keep schemas up to date**
   ```bash
   npm run swagger:complete
   ```

2. **Use Complete-Standarized schema for production**
   ```javascript
   const schema = require('./test-data/Input/Complete-Standarized-ERP-Api-Schema.json');
   ```

3. **Backup schemas before updates**
   ```bash
   npm run clean:backup
   ```

4. **Validate schemas after changes**
   ```bash
   npm run schema:enhance:validate
   ```

### Security Testing

1. **Run security tests regularly**
   ```bash
   npm run test:Security
   ```

2. **Review security reports carefully**
   - Check for authorization bypasses
   - Verify input validation
   - Monitor for new vulnerabilities

3. **Test with realistic attack scenarios**
   - Use actual malicious payloads
   - Test business logic flaws
   - Verify error handling

### Performance Testing

1. **Establish performance baselines**
   - Document acceptable response times
   - Set threshold alerts
   - Monitor trends over time

2. **Test under realistic load**
   - Simulate actual user behavior
   - Test peak load scenarios
   - Verify graceful degradation

3. **Monitor resource utilization**
   - CPU usage
   - Memory consumption
   - Network bandwidth

### CI/CD Integration

1. **Run tests in CI pipeline**
   ```yaml
   # Example GitHub Actions workflow
   - name: Run API Tests
     run: npm run test:ci
   ```

2. **Generate reports for each build**
   ```bash
   npm run test:report
   ```

3. **Fail build on critical errors**
   ```bash
   export FAIL_ON_ERROR=true
   npm run test:ci
   ```

4. **Archive test reports**
   - Save HTML reports as artifacts
   - Store JSON reports for analysis
   - Track trends over time

---

## 🤝 Contributing

### Adding New Test Modules

1. **Create test file** in `tests/comprehensive-lifecycle/`
   ```bash
   touch tests/comprehensive-lifecycle/6.new-test-suite.test.js
   ```

2. **Follow naming convention**: `N.descriptive-name.test.js`

3. **Implement test scenarios**:
   ```javascript
   describe('New Test Suite', () => {
     test('should test something', async () => {
       // Test implementation
     });
   });
   ```

4. **Update module configuration** in schema files

5. **Add documentation** to README.md

6. **Run tests** to verify
   ```bash
   npx jest tests/comprehensive-lifecycle/6.new-test-suite.test.js
   ```

### Extending Helpers

1. **Add new methods** to existing helper classes
2. **Maintain backward compatibility**
3. **Update JSDoc documentation**
4. **Add corresponding tests**
5. **Update API documentation** in README.md

### Code Style

- Use ES6+ features
- Follow existing code patterns
- Add comprehensive comments
- Use meaningful variable names
- Handle errors gracefully

### Testing Guidelines

- Write clear test descriptions
- Use appropriate assertions
- Handle async operations properly
- Clean up test data
- Document expected behavior

---

## 📞 Support & Contact

### Documentation

- **Project README**: This file
- **API Documentation**: `docs/` directory
- **Schema Documentation**: `test-data/Input/` directory
- **Script Documentation**: `scripts/README.md`

### Resources

- **Authentication Guide**: `docs/AUTHENTICATION-GUIDE.md`
- **Schema Usage**: `docs/SCHEMA-USAGE-INFO.md`
- **Swagger Integration**: `docs/SWAGGER-INTEGRATION-GUIDE.md`
- **ID Registry System**: `docs/ID-REGISTRY-SYSTEM-GUIDE.md`
- **Testing Enhancement**: `docs/TESTING-ENHANCEMENT-COMPLETE.md`

### Getting Help

For issues, questions, or contributions:

1. **Check troubleshooting section** above
2. **Review test reports** for specific failures
3. **Examine console logs** for detailed error information
4. **Verify configuration** and environment setup
5. **Search documentation** for relevant information

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎉 Acknowledgments

- **Jest**: Testing framework
- **Axios**: HTTP client
- **Babel**: JavaScript transpiler
- **Jest HTML Reporters**: Report generation

---

**🎯 Enterprise ERP API Testing Suite** - Your comprehensive solution for enterprise-grade API testing and validation.

**Version**: 1.3.0  
**Last Updated**: December 6, 2024  
**Maintained by**: Development Team

---

**Quick Links**:
- [Installation](#-installation)
- [Running Tests](#-running-tests)
- [Test Reports](#-test-reports)
- [Troubleshooting](#-troubleshooting)
- [API Documentation](#-api-documentation)
