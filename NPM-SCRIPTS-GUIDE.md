# 📚 NPM Scripts Guide

Complete reference for all npm scripts in the Enterprise ERP API Testing Suite.

---

## 🚀 Quick Start Commands

```bash
# Run all tests with HTML report (Recommended)
npm run test:all

# Run all tests with verbose output
npm run test:all:verbose

# Run specific test suite
npm run test:1:crud
npm run test:2:security
npm run test:3:advanced-security
npm run test:4:performance
npm run test:5:health
```

---

## 📋 Table of Contents

- [Individual Test Suites](#-individual-test-suites)
- [Run All Tests](#-run-all-tests)
- [Test Management](#-test-management)
- [Debugging & Development](#-debugging--development)
- [Authentication](#-authentication)
- [Schema Management](#-schema-management)
- [ID Registry](#-id-registry)
- [Swagger Integration](#-swagger-integration)
- [Analysis & Fixing](#-analysis--fixing)
- [Cleanup & Maintenance](#-cleanup--maintenance)
- [Legacy Commands](#-legacy-commands)

---

## 🧪 Individual Test Suites

### Test Suite 1: CRUD Validation

```bash
# Run CRUD validation with HTML report
npm run test:1:crud

# Run with verbose output
npm run test:1:crud:verbose

# Debug CRUD tests
npm run test:debug:crud
```

**What it tests**: Complete Create-Read-Update-Delete lifecycle for all 96+ modules

**Duration**: ~15-30 minutes

**Report**: `html-report/test-report.html`

---

### Test Suite 2: API Security

```bash
# Run security tests with HTML report
npm run test:2:security

# Run with verbose output
npm run test:2:security:verbose

# Debug security tests
npm run test:debug:security
```

**What it tests**: Authorization, SQL injection, XSS, malicious payloads, data validation

**Duration**: ~20-40 minutes

**Report**: `html-report/test-report.html`

---

### Test Suite 3: Advanced Security

```bash
# Run advanced security tests with HTML report
npm run test:3:advanced-security

# Run with verbose output
npm run test:3:advanced-security:verbose
```

**What it tests**: Business logic flaws, IDOR, privilege escalation, race conditions, mass assignment

**Duration**: ~8-15 minutes

**Report**: `html-report/test-report.html`

---

### Test Suite 4: Performance Testing

```bash
# Run performance tests with HTML report
npm run test:4:performance

# Run with verbose output
npm run test:4:performance:verbose
```

**What it tests**: Response times, throughput, success rates, error rates under load

**Duration**: ~10-20 minutes

**Report**: `html-report/test-report.html`

---

### Test Suite 5: Health Checks

```bash
# Run health check tests with HTML report
npm run test:5:health

# Run with verbose output
npm run test:5:health:verbose
```

**What it tests**: Endpoint accessibility, response times, service availability

**Duration**: ~5-10 minutes

**Report**: `html-report/test-report.html`

---

## 🎯 Run All Tests

### Parallel Execution (Faster)

```bash
# Run all test suites in parallel with HTML report
npm run test:all

# Run with verbose output
npm run test:all:verbose
```

**Duration**: ~30-45 minutes (all suites in parallel)

**Report**: Single consolidated HTML report

---

### Sequential Execution (More Stable)

```bash
# Run all test suites sequentially
npm run test:all:sequential

# Run sequentially with verbose output
npm run test:all:sequential:verbose
```

**Duration**: ~60-90 minutes (one suite at a time)

**Report**: Separate HTML report for each suite

**Use when**: You need stable execution or have resource constraints

---

### CI/CD Execution

```bash
# Run in CI mode (optimized for CI/CD pipelines)
npm run test:ci
```

**Features**:
- Optimized for CI environments
- Proper exit codes
- Minimal console output
- HTML report generation

---

## 🔧 Test Management

### Failed Test Management

```bash
# Run only failed tests from previous run
npm run test:failed

# Rerun last failed tests
npm run test:rerun-failed

# Show failures only (no passing tests)
npm run test:failures-only

# Generate failed test report
npm run report:failed
```

---

### Test Execution Control

```bash
# Fail fast (stop on first failure)
npm run test:fail-fast

# Quick fail (bail on error)
npm run test:quick-fail

# Orchestrated test execution
npm run test:orchestrated
```

---

### Test Reporting

```bash
# Generate HTML report
npm run test:html

# Generate comprehensive report
npm run test:report

# Generate test coverage report
npm run test:coverage
```

---

## 🐛 Debugging & Development

### Debug Individual Tests

```bash
# Debug CRUD tests
npm run test:debug:crud

# Debug security tests
npm run test:debug:security

# General debug mode
npm run test:debug
```

**Features**:
- Verbose output
- No cache
- Detect open handles
- Detailed error messages

---

### Development Mode

```bash
# Watch mode (auto-rerun on file changes)
npm run test:watch

# Run without Babel transpilation
npm run test:no-babel

# Run simple test (minimal dependencies)
npm run test:simple
```

---

### Coverage Analysis

```bash
# Generate code coverage report
npm run test:coverage
```

**Output**: `coverage/` directory with HTML report

---

## 🔐 Authentication

### Token Management

```bash
# Fetch new authentication token
npm run fetch-token

# Check token validity
npm run check-token

# Debug token issues
npm run debug-token

# Debug token status
npm run debug-token-status

# Debug token issue details
npm run debug-token-issue

# Fix token file format
npm run fix-token
```

---

### Authentication Workflow

```bash
# Complete authentication workflow
npm run fetch-token && npm run check-token
```

---

## 📚 Schema Management

### Basic Schema Operations

```bash
# Update all schemas
npm run schema:update

# Convert URLs to extensions
npm run schema:convert-urls

# Fix non-URL entries
npm run schema:fix-non-urls

# Merge schemas
npm run schema:merge
```

---

### Schema Enhancement

```bash
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

# Harmonize IDs across schemas
npm run schema:harmonize:ids
```

---

### Complete Schema Workflows

```bash
# Complete schema update workflow
npm run schema:complete:update

# Production-ready schema generation
npm run schema:production:ready
```

**Production workflow includes**:
1. Fetch Swagger documentation
2. Generate enhanced schema
3. Generate module schemas
4. Enhance with payloads
5. Harmonize IDs

---

## 🆔 ID Registry

### Registry Operations

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

---

## 📖 Swagger Integration

### Basic Swagger Operations

```bash
# Fetch Swagger documentation
npm run swagger:fetch

# Parse Swagger to schema format
npm run swagger:parse

# Generate schema from Swagger
npm run swagger:generate

# Update schema with Swagger data
npm run swagger:update

# Validate schema against Swagger
npm run swagger:validate

# Generate payloads from Swagger
npm run swagger:generate:payloads

# Complete Swagger workflow
npm run swagger:complete
```

---

### Advanced Swagger Operations

```bash
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
```

---

## 📊 Analysis & Fixing

### Test Analysis

```bash
# Analyze test results
npm run analyze:tests

# Analyze test errors
npm run analyze:errors

# Analyze failure responses
npm run analyze:failures

# Run all analysis
npm run analyze:all
```

---

### Automated Fixing

```bash
# Fix comprehensive errors
npm run fix:comprehensive

# Fix payload issues
npm run fix:payloads:advanced

# Run all fixes
npm run fix:all
```

**Fix workflow includes**:
1. Comprehensive error fixing
2. Advanced payload fixing
3. Test analysis

---

## 🧹 Cleanup & Maintenance

### Cleanup Operations

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

---

### Setup & Verification

```bash
# Verify setup
npm run verify:setup

# Install dependencies
npm run install-deps
```

---

## 🔄 Legacy Commands

### Backward Compatibility

These commands are maintained for backward compatibility:

```bash
# Legacy test commands
npm run test:CRUD          # → npm run test:1:crud:verbose
npm run test:Security      # → npm run test:2:security:verbose
npm run test:Performance   # → npm run test:4:performance:verbose
npm run test:Health        # → npm run test:5:health:verbose

# Legacy CRUD commands
npm run crud               # → npm run test:1:crud
npm run crud-html          # → npm run test:1:crud
npm run test-debug         # → npm run test:debug:crud

# Legacy execution
npm run test:all-modules   # → node run-all-tests-with-report.js
```

---

## 🎯 Enhanced Test Suites

### Enhanced CRUD Suite

```bash
# Run enhanced CRUD suite
npm run test:enhanced

# Run with verbose output
npm run test:enhanced:verbose
```

---

### Authentication Tests

```bash
# Run authentication validation
npm run test:auth

# Quick authentication test
npm run test:auth:quick

# Run auth + enhanced tests
npm run test:with:auth
```

---

### Generated Module Tests

```bash
# Generate test files for all modules
npm run test:generate:modules

# Run generated tests
npm run test:generated

# Run with verbose output
npm run test:generated:verbose

# Complete workflow (generate + run)
npm run test:complete:suite
```

---

## 📖 Command Patterns

### Naming Convention

```
npm run <category>:<action>[:<modifier>]

Examples:
- test:1:crud              # Test suite 1 (CRUD)
- test:1:crud:verbose      # Test suite 1 with verbose output
- schema:enhance:validate  # Schema enhancement validation
- swagger:advanced:fetch   # Advanced Swagger fetch
```

---

### Common Modifiers

- `:verbose` - Detailed output
- `:quick` - Fast execution
- `:debug` - Debug mode
- `:all` - All items
- `:advanced` - Advanced features

---

## 🚀 Recommended Workflows

### Daily Testing

```bash
# 1. Verify token
npm run check-token

# 2. Run health checks
npm run test:5:health

# 3. Run all tests
npm run test:all
```

---

### Before Deployment

```bash
# 1. Clean artifacts
npm run clean:all

# 2. Update schemas
npm run schema:production:ready

# 3. Run all tests sequentially
npm run test:all:sequential

# 4. Analyze results
npm run analyze:all
```

---

### Debugging Failures

```bash
# 1. Run failed tests only
npm run test:failed

# 2. Analyze failures
npm run analyze:failures

# 3. Fix issues
npm run fix:all

# 4. Rerun failed tests
npm run test:rerun-failed
```

---

### CI/CD Pipeline

```bash
# 1. Verify setup
npm run verify:setup

# 2. Run in CI mode
npm run test:ci

# 3. Generate reports
npm run test:report

# 4. Analyze results
npm run analyze:all
```

---

## 📞 Support

For issues or questions about npm scripts:

1. Check this guide for command reference
2. Review README.md for detailed documentation
3. Check package.json for script definitions
4. Run `npm run verify:setup` to verify installation

---

**Last Updated**: December 6, 2024  
**Version**: 1.3.0  
**Total Scripts**: 100+
