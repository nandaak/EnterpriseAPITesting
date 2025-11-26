# Swagger API Integration Guide

## Overview

This guide explains how to professionally integrate and utilize the comprehensive ERP modules backend APIs from the Swagger documentation source into your test framework.

**Swagger API Source:** `https://microtecsaudi.com:2032/gateway/swagger/docs/v1/erp-apis`

---

## 🎯 Goals

1. ✅ Fetch comprehensive API documentation from Swagger
2. ✅ Parse and understand API structure
3. ✅ Generate/update test data schemas automatically
4. ✅ Maintain consistency with backend APIs
5. ✅ Enable comprehensive ERP module testing

---

## 🚀 Quick Start

### Step 1: Fetch Swagger Documentation
```bash
npm run swagger:fetch
```

This downloads the complete API documentation from the Swagger endpoint.

### Step 2: Parse API Structure
```bash
npm run swagger:parse
```

This analyzes the Swagger docs and shows you the API structure, modules, and endpoints.

### Step 3: Generate Test Schemas
```bash
npm run swagger:generate
```

This creates comprehensive test schemas based on the Swagger documentation.

### Step 4: Validate Schemas
```bash
npm run swagger:validate
```

This validates your schema structure and format.

---

## 📚 Available Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `npm run swagger:fetch` | Fetch Swagger API docs | First step |
| `npm run swagger:parse` | Parse and analyze APIs | After fetch |
| `npm run swagger:generate` | Generate test schemas | Create new schemas |
| `npm run swagger:update` | Update existing schemas | Refresh schemas |
| `npm run swagger:validate` | Validate schema structure | Check schemas |

---

## 🔧 Swagger Integration Tool

### Features

1. **Fetch Swagger Documentation**
   - Downloads API docs from live endpoint
   - Validates JSON structure
   - Shows API information

2. **Parse API Structure**
   - Extracts all endpoints
   - Groups by modules/tags
   - Shows endpoint counts
   - Saves parsed data

3. **Generate Test Schemas**
   - Creates comprehensive schemas
   - Organizes by modules
   - Includes all CRUD operations
   - Ready for testing

4. **Update Existing Schemas**
   - Backs up current schemas
   - Merges new endpoints
   - Preserves existing data
   - Safe updates

5. **Validate Schemas**
   - Checks structure
   - Validates format
   - Reports issues
   - Ensures quality

---

## 📊 Workflow

### Complete Integration Workflow

```bash
# 1. Fetch Swagger documentation
npm run swagger:fetch

# 2. Parse to see structure
npm run swagger:parse

# 3. Generate new schemas
npm run swagger:generate

# 4. Validate generated schemas
npm run swagger:validate

# 5. Run tests with new schemas
npm test
```

### Update Existing Schemas Workflow

```bash
# 1. Fetch latest Swagger docs
npm run swagger:fetch

# 2. Update existing schemas
npm run swagger:update

# 3. Validate updated schemas
npm run swagger:validate

# 4. Run tests
npm test
```

---

## 📁 File Structure

### Generated Files

```
project-root/
├── swagger-api-docs.json              # Downloaded Swagger documentation
├── swagger-parsed.json                # Parsed API structure
├── test-data/Input/
│   ├── Main-Backend-Api-Schema.json           # Existing schema
│   ├── Main-Standarized-Backend-Api-Schema.json  # Existing schema
│   └── Generated-Backend-Api-Schema.json      # NEW: Generated from Swagger
└── backups/schemas/                   # Schema backups
    ├── Main-Backend-Api-Schema.json.TIMESTAMP.backup
    └── Main-Standarized-Backend-Api-Schema.json.TIMESTAMP.backup
```

---

## 🎓 Understanding Swagger Integration

### What is Swagger?

Swagger (OpenAPI) is a specification for describing REST APIs. It provides:
- Complete API documentation
- Endpoint definitions
- Request/response schemas
- Parameter specifications
- Authentication requirements

### Why Integrate Swagger?

1. **Accuracy** - Always up-to-date with backend
2. **Completeness** - All endpoints documented
3. **Automation** - Generate schemas automatically
4. **Consistency** - Single source of truth
5. **Efficiency** - Save manual work

### How It Works

```
Swagger API Docs
      │
      ▼
Fetch & Parse
      │
      ▼
Extract Endpoints
      │
      ▼
Generate Schemas
      │
      ▼
Test Framework
```

---

## 📖 Detailed Command Usage

### Fetch Command

```bash
npm run swagger:fetch
```

**What it does:**
- Connects to Swagger endpoint
- Downloads API documentation
- Saves to `swagger-api-docs.json`
- Validates JSON structure
- Shows API information

**Output:**
```
📥 Fetching Swagger API documentation...

URL: https://microtecsaudi.com:2032/gateway/swagger/docs/v1/erp-apis
✅ Swagger docs downloaded successfully
   File: swagger-api-docs.json
   Size: 1234.56 KB
   Version: 3.0.1
   Title: ERP APIs
   Paths: 500
```

### Parse Command

```bash
npm run swagger:parse
```

**What it does:**
- Reads `swagger-api-docs.json`
- Extracts API information
- Groups endpoints by module
- Counts operations
- Saves parsed data

**Output:**
```
📖 Parsing Swagger documentation...

API Information:
  Title: ERP APIs
  Version: 1.0.0
  Description: Comprehensive ERP System APIs

Total Endpoints: 500

Modules/Tags: 15
  Accounting: 50 endpoints
  Finance: 45 endpoints
  Inventory: 60 endpoints
  Sales: 55 endpoints
  Purchasing: 50 endpoints
  ...

✅ Parsed data saved to: swagger-parsed.json
```

### Generate Command

```bash
npm run swagger:generate
```

**What it does:**
- Reads Swagger documentation
- Generates complete test schemas
- Organizes by modules
- Creates CRUD operations
- Saves to `Generated-Backend-Api-Schema.json`

**Output:**
```
🏗️  Generating complete test schemas...

✅ Generated schema saved to: test-data/Input/Generated-Backend-Api-Schema.json
   Modules: 15
```

### Update Command

```bash
npm run swagger:update
```

**What it does:**
- Backs up existing schemas
- Reads Swagger documentation
- Merges new endpoints
- Preserves existing data
- Updates schema files

**Output:**
```
🔄 Updating existing schemas...

Creating backups...
  ✓ Backed up: Main-Backend-Api-Schema.json
  ✓ Backed up: Main-Standarized-Backend-Api-Schema.json

Updating: Main-Backend-Api-Schema.json
  Processing: Main-Backend-Api-Schema.json

Updating: Main-Standarized-Backend-Api-Schema.json
  Processing: Main-Standarized-Backend-Api-Schema.json

✅ Schema update complete
```

### Validate Command

```bash
npm run swagger:validate
```

**What it does:**
- Checks schema structure
- Validates format
- Reports issues
- Ensures quality

**Output:**
```
✔️  Validating schemas...

Validating: Main-Backend-Api-Schema.json
  ✅ Valid

Validating: Main-Standarized-Backend-Api-Schema.json
  ✅ Valid

✅ Validation passed
```

---

## 🔍 Advanced Usage

### Custom Swagger URL

Edit `scripts/swagger-integration-tool.js`:

```javascript
const CONFIG = {
  swaggerUrl: 'https://your-custom-url.com/swagger/docs',
  // ... other config
};
```

### Manual Tool Usage

```bash
# Show help
node scripts/swagger-integration-tool.js help

# Fetch docs
node scripts/swagger-integration-tool.js fetch

# Parse docs
node scripts/swagger-integration-tool.js parse

# Generate schemas
node scripts/swagger-integration-tool.js generate

# Update schemas
node scripts/swagger-integration-tool.js update

# Validate schemas
node scripts/swagger-integration-tool.js validate
```

---

## 💡 Best Practices

### 1. Regular Updates
```bash
# Weekly: Fetch latest API docs
npm run swagger:fetch
npm run swagger:update
npm run swagger:validate
```

### 2. Backup Before Updates
```bash
# Automatic backups are created
# But you can also manually backup
cp test-data/Input/Main-Backend-Api-Schema.json backups/
```

### 3. Validate After Changes
```bash
# Always validate after updates
npm run swagger:validate
```

### 4. Review Generated Schemas
```bash
# Check generated schemas before using
cat test-data/Input/Generated-Backend-Api-Schema.json
```

### 5. Test After Integration
```bash
# Run tests after schema updates
npm test
```

---

## 🎯 Use Cases

### 1. Initial Setup
```bash
# First time setup
npm run swagger:fetch
npm run swagger:generate
npm run swagger:validate
npm test
```

### 2. Add New Module
```bash
# When backend adds new module
npm run swagger:fetch
npm run swagger:update
npm test
```

### 3. Update Endpoints
```bash
# When endpoints change
npm run swagger:fetch
npm run swagger:update
npm run swagger:validate
npm test
```

### 4. Verify Coverage
```bash
# Check API coverage
npm run swagger:parse
npm run registry:stats
```

### 5. Troubleshooting
```bash
# If tests fail
npm run swagger:validate
npm run swagger:fetch
npm run swagger:update
```

---

## 🔧 Troubleshooting

### Issue: Cannot fetch Swagger docs

**Symptoms:**
```
❌ Error fetching Swagger docs: connect ECONNREFUSED
```

**Solutions:**
1. Check network connection
2. Verify Swagger URL is accessible
3. Check firewall settings
4. Try manual download:
   ```bash
   curl -k https://microtecsaudi.com:2032/gateway/swagger/docs/v1/erp-apis > swagger-api-docs.json
   ```

### Issue: Parse fails

**Symptoms:**
```
❌ Error parsing Swagger docs: Unexpected token
```

**Solutions:**
1. Re-fetch Swagger docs
2. Validate JSON manually
3. Check file encoding

### Issue: Schema validation fails

**Symptoms:**
```
❌ Issues found:
   - Module X must be an object
```

**Solutions:**
1. Review schema structure
2. Check for syntax errors
3. Compare with working schema
4. Regenerate schema

### Issue: Generated schema incomplete

**Symptoms:**
- Missing endpoints
- Missing modules

**Solutions:**
1. Re-fetch Swagger docs
2. Check Swagger completeness
3. Review parse output
4. Manual verification

---

## 📊 Schema Structure

### Generated Schema Format

```json
{
  "Module_Name": {
    "Sub_Module": {
      "Operation_Name": {
        "POST": [
          "/api/endpoint/path",
          {
            "payload": "data"
          }
        ],
        "GET": [
          "/api/endpoint/path",
          {}
        ],
        "PUT": [
          "/api/endpoint/<createdId>",
          {
            "id": "<createdId>",
            "payload": "data"
          }
        ],
        "DELETE": [
          "/api/endpoint/<createdId>",
          {}
        ]
      }
    }
  }
}
```

### Example

```json
{
  "Accounting": {
    "Master_Data": {
      "Chart_of_Accounts": {
        "POST": [
          "/erp-apis/ChartOfAccounts/AddAccount",
          {
            "name": "Test Account",
            "accountCode": "1001"
          }
        ],
        "GET": [
          "/erp-apis/ChartOfAccounts/GetAccountDetails?id=<createdId>",
          {}
        ]
      }
    }
  }
}
```

---

## 🚀 Next Steps

### After Integration

1. **Review Generated Schemas**
   ```bash
   cat test-data/Input/Generated-Backend-Api-Schema.json
   ```

2. **Update Test Data**
   - Add realistic test payloads
   - Configure test parameters
   - Set up test scenarios

3. **Run Tests**
   ```bash
   npm test
   ```

4. **Monitor Coverage**
   ```bash
   npm run registry:stats
   ```

5. **Iterate**
   - Update schemas as needed
   - Add more test cases
   - Improve coverage

---

## 📚 Related Documentation

- **Dynamic Endpoints:** `DYNAMIC-ENDPOINT-GUIDE.md`
- **ID Registry:** `ID-REGISTRY-SYSTEM-GUIDE.md`
- **ID Type Management:** `ID-TYPE-MANAGEMENT-GUIDE.md`
- **Cleanup System:** `CLEANUP-GUIDE.md`

---

## ✨ Summary

### What You Get

- ✅ **Automated schema generation** from Swagger
- ✅ **Always up-to-date** with backend APIs
- ✅ **Comprehensive coverage** of all endpoints
- ✅ **Easy updates** with simple commands
- ✅ **Validation** to ensure quality
- ✅ **Backup protection** for safety

### Quick Commands

```bash
npm run swagger:fetch      # Fetch API docs
npm run swagger:parse      # Analyze structure
npm run swagger:generate   # Create schemas
npm run swagger:update     # Update schemas
npm run swagger:validate   # Check quality
```

### Workflow

```bash
# Complete workflow
npm run swagger:fetch && npm run swagger:generate && npm run swagger:validate && npm test
```

---

**Version:** 1.0.0  
**Last Updated:** November 26, 2025  
**Status:** ✅ Ready to Use

---

**Note:** This is a foundational tool. The Swagger integration can be further enhanced based on your specific API structure and testing needs. The tool provides the framework for professional API integration and can be customized as needed.
