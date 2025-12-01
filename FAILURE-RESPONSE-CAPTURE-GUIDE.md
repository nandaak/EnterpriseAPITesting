# 📊 Failure Response Capture System

**Automatically captures and analyzes failed API responses (400, 500)**

---

## 🎯 Overview

The Failure Response Capture System automatically logs all failed API responses with status codes 400 and 500 during test execution, saving them to `failure_response.json` for analysis.

---

## ✨ Features

- ✅ **Automatic Capture** - Logs failures during test execution
- ✅ **Detailed Information** - Captures URL, method, status, response, and payload
- ✅ **Smart Analysis** - Identifies patterns and common errors
- ✅ **Actionable Insights** - Provides fix recommendations
- ✅ **Easy Access** - Simple JSON format for review

---

## 🚀 Quick Start

### 1. Run Tests (Failures Auto-Captured)
```bash
npm run test:enhanced
```

### 2. Analyze Failures
```bash
npm run analyze:failures
```

### 3. Review Results
```bash
# View captured failures
cat failure_response.json | jq

# View analysis
cat failure_analysis.json | jq
```

---

## 📁 Output Files

### `failure_response.json`
**Format:**
```json
{
  "POST /erp-apis/Currency": {
    "method": "POST",
    "url": "/erp-apis/Currency",
    "statusCode": 400,
    "timestamp": "2025-12-01T14:30:00.000Z",
    "response": {
      "message": "Validation failed",
      "errors": ["Field 'code' is required"]
    },
    "requestPayload": {
      "name": "Test Currency",
      "nameAr": "عملة تجريبية"
    }
  }
}
```

**Key Structure:**
- **Key:** `METHOD URL` (e.g., "POST /erp-apis/Currency")
- **Value:** Complete failure details including request and response

### `failure_response_report.json`
**Comprehensive report with:**
- Timestamp
- Statistics (total, by status code)
- All failure details

### `failure_analysis.json`
**Analysis results with:**
- Summary statistics
- Top error messages
- Validation errors
- Recommendations

---

## 🔍 How It Works

### 1. Automatic Capture During Tests

The system intercepts all API errors in the test suite:

```javascript
// In tests/enhanced-crud-suite.test.js
catch (error) {
  // Automatically logs 400 and 500 errors
  if (error.response && (error.response.status === 400 || error.response.status === 404 || error.response.status === 500)) {
    failureLogger.logFailure(
      'POST',                    // HTTP method
      url,                       // API endpoint
      error.response.status,     // Status code
      error.response.data,       // Response data
      payload                    // Request payload
    );
  }
}
```

### 2. Captured for All CRUD Operations

- ✅ **CREATE (POST)** - Captures payload and response
- ✅ **READ (GET)** - Captures URL and response
- ✅ **UPDATE (PUT)** - Captures payload and response
- ✅ **DELETE** - Captures URL and response

### 3. Real-time Logging

During test execution, you'll see:
```
[WARN] Failure logged: POST /erp-apis/Currency - Status 400
[WARN] Failure logged: POST /erp-apis/Tax - Status 500
```

### 4. Summary at End

After all tests complete:
```
📊 Failure Response Summary:
   Total failures logged: 45
   400 Bad Request: 30
   500 Server Error: 15
   Unique URLs: 38
   Report saved: failure_response.json
```

---

## 📊 Analysis Features

### Run Analysis
```bash
npm run analyze:failures
```

### Output Includes:

#### 1. **Summary Statistics**
```
Total Failures: 45
   400 Bad Request: 30
   500 Server Error: 15

By HTTP Method:
   POST: 35 failures
   PUT: 8 failures
   GET: 2 failures
```

#### 2. **Top Error Messages**
```
1. "Validation failed: Field 'code' is required"
   Occurrences: 12
   Examples: POST /erp-apis/Currency, POST /erp-apis/Tax, ...

2. "Internal server error"
   Occurrences: 8
   Examples: POST /erp-apis/JournalEntry, ...
```

#### 3. **Validation Errors**
```
1. POST /erp-apis/Currency
   Message: Field 'code' is required
   Payload fields: name, nameAr

2. POST /erp-apis/Customer
   Message: Field 'email' is invalid
   Payload fields: name, nameAr, code
```

#### 4. **400 Bad Request Breakdown**
```
1. POST /erp-apis/Currency
   Error: Validation failed: Field 'code' is required
   Payload: {"name":"Test Currency","nameAr":"عملة تجريبية"}

2. POST /erp-apis/Tax
   Error: Field 'percentage' must be a number
   Payload: {"name":"Test Tax","percentage":"15"}
```

#### 5. **500 Server Error Breakdown**
```
1. POST /erp-apis/JournalEntry
   Error: Internal server error

2. POST /erp-apis/Invoice
   Error: Database connection failed
```

#### 6. **Recommendations**
```
1. 400 Bad Request Fixes:
   → Review validation error messages
   → Add missing required fields to payloads
   → Check field types and formats

2. 500 Server Error Fixes:
   → Check backend logs for details
   → Verify prerequisite data exists
   → Contact backend team if needed
```

---

## 💡 Usage Examples

### Example 1: Find All 400 Errors
```bash
# View all 400 errors
cat failure_response.json | jq 'to_entries | map(select(.value.statusCode == 400))'
```

### Example 2: Find Specific Module Failures
```bash
# Find Currency module failures
cat failure_response.json | jq 'to_entries | map(select(.key | contains("Currency")))'
```

### Example 3: Extract Error Messages
```bash
# Get all unique error messages
cat failure_response.json | jq '[.[] | .response.message] | unique'
```

### Example 4: Find Missing Fields
```bash
# Find validation errors
cat failure_response.json | jq 'to_entries | map(select(.value.response.message | contains("required")))'
```

---

## 🔧 Integration

### In Your Tests

The failure logger is automatically integrated. No additional code needed!

### Manual Usage

If you want to use it in custom scripts:

```javascript
const { getFailureLogger } = require('./utils/failure-response-logger');

const failureLogger = getFailureLogger();

// Log a failure
failureLogger.logFailure(
  'POST',
  '/erp-apis/Currency',
  400,
  { message: 'Validation failed' },
  { name: 'Test' }
);

// Get statistics
const stats = failureLogger.getStats();
console.log(`Total failures: ${stats.total}`);

// Generate report
const report = failureLogger.generateReport();
console.log(`Report saved: ${report.reportPath}`);
```

---

## 📋 API Reference

### FailureResponseLogger Class

#### Methods

**`logFailure(method, url, statusCode, responseData, requestPayload)`**
- Logs a failed API response
- Only logs 400 and 500 status codes
- Automatically saves to file

**`getAll()`**
- Returns all logged failures

**`getByStatus(statusCode)`**
- Returns failures filtered by status code

**`getStats()`**
- Returns statistics object:
  ```javascript
  {
    total: 45,
    status400: 30,
    status500: 15,
    uniqueUrls: 38,
    uniqueMethods: 4
  }
  ```

**`generateReport()`**
- Generates comprehensive report
- Saves to `failure_response_report.json`
- Returns report path and stats

**`clear()`**
- Clears all logged failures
- Resets the file

---

## 🎯 Common Use Cases

### Use Case 1: Fix 400 Errors

1. **Run tests:**
   ```bash
   npm run test:enhanced
   ```

2. **Analyze failures:**
   ```bash
   npm run analyze:failures
   ```

3. **Review 400 errors:**
   ```bash
   cat failure_response.json | jq 'to_entries | map(select(.value.statusCode == 400))'
   ```

4. **Identify missing fields:**
   - Look at error messages
   - Compare with request payloads
   - Add missing fields to schema

5. **Re-run tests:**
   ```bash
   npm run test:enhanced
   ```

### Use Case 2: Debug 500 Errors

1. **Find 500 errors:**
   ```bash
   cat failure_response.json | jq 'to_entries | map(select(.value.statusCode == 500))'
   ```

2. **Review error messages:**
   - Check for patterns
   - Identify common causes

3. **Check backend logs:**
   - Correlate with timestamps
   - Find root causes

4. **Fix backend issues or prerequisites**

### Use Case 3: Improve Payloads

1. **Analyze validation errors:**
   ```bash
   npm run analyze:failures
   ```

2. **Extract required fields:**
   - Review error messages
   - Note missing fields

3. **Update payload templates:**
   - Add required fields
   - Fix field types

4. **Verify improvements:**
   ```bash
   npm run test:enhanced
   npm run analyze:failures
   ```

---

## 📊 Sample Output

### During Test Execution
```
[INFO] Testing CREATE for Currency
[WARN] Failure logged: POST /erp-apis/Currency - Status 400
[ERROR] CREATE failed for Currency: Request failed with status code 400

[INFO] Testing CREATE for Tax
[WARN] Failure logged: POST /erp-apis/Tax - Status 500
[ERROR] CREATE failed for Tax: Request failed with status code 500
```

### After Tests Complete
```
📊 Failure Response Summary:
   Total failures logged: 45
   400 Bad Request: 30
   500 Server Error: 15
   Unique URLs: 38
   Report saved: failure_response.json
   Detailed report: failure_response_report.json
```

### Analysis Output
```
🔍 Failure Response Analyzer
======================================================================

✅ Loaded 45 failure responses

📊 Analysis Results:

Total Failures: 45
   400 Bad Request: 30
   500 Server Error: 15

📋 By HTTP Method:
   POST: 35 failures
   PUT: 8 failures
   GET: 2 failures

🔝 Top Error Messages:

1. "Validation failed: Field 'code' is required"
   Occurrences: 12
   Examples: POST /erp-apis/Currency, POST /erp-apis/Tax, POST /erp-apis/Bank

2. "Internal server error"
   Occurrences: 8
   Examples: POST /erp-apis/JournalEntry, POST /erp-apis/Invoice
```

---

## 🚀 Commands Reference

```bash
# Run tests (auto-captures failures)
npm run test:enhanced

# Analyze captured failures
npm run analyze:failures

# View raw failures
cat failure_response.json | jq

# View analysis
cat failure_analysis.json | jq

# Clear failures (start fresh)
rm failure_response.json failure_response_report.json failure_analysis.json
```

---

## 💡 Tips & Best Practices

### 1. **Run Analysis After Every Test**
```bash
npm run test:enhanced && npm run analyze:failures
```

### 2. **Focus on 400 Errors First**
- Easier to fix
- Usually payload issues
- Quick wins

### 3. **Group Similar Errors**
- Look for patterns
- Fix multiple at once
- Use analysis output

### 4. **Keep Historical Data**
```bash
# Backup before new test run
cp failure_response.json failure_response_backup_$(date +%Y%m%d).json
```

### 5. **Share with Team**
- failure_response.json is human-readable
- Easy to share and discuss
- Contains all needed context

---

## 🎉 Benefits

- ✅ **No Manual Logging** - Automatic capture
- ✅ **Complete Context** - Request + Response
- ✅ **Easy Analysis** - Built-in analyzer
- ✅ **Actionable** - Clear recommendations
- ✅ **Trackable** - Historical comparison
- ✅ **Shareable** - JSON format

---

## 📚 Related Documentation

- **PROFESSIONAL-TEST-FIXING-COMPLETE.md** - Overall test fixing guide
- **QUICK-FIX-REFERENCE.md** - Quick commands
- **EXECUTIVE-SUMMARY.md** - Executive overview

---

**Your API failures are now automatically captured and analyzed!** 📊✅🎉

---

**Created:** December 1, 2025  
**Version:** 1.0  
**Status:** Production Ready
