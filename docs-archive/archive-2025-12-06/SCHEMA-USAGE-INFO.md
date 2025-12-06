# 📊 Schema Usage Information

## Input Schema Used by CRUD Test Suite

### 📁 Schema File
```
test-data/Input/Main-Standarized-Backend-Api-Schema.json
```

### 📋 Configuration Location
**File:** `Constants/FileConstants.js`

```javascript
STANDARIZED_SCHEMA_PATH: path.join(
  __dirname,
  "..",
  "test-data",
  "Input",
  "Main-Standarized-Backend-Api-Schema.json"
)
```

### 📊 Schema Statistics

**File Size:** ~99 KB

**Top-Level Modules:** 9
1. General_Settings
2. Accounting
3. Finance
4. Sales
5. Purchase
6. Inventory
7. Distribution
8. Human_Resources
9. Fixed_Assets

**Total Testable Modules:** 79 (non-report modules)

### 🔍 How It's Used

The CRUD test suite (`tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js`) uses this schema through:

1. **ModulesConfig** (`config/modules-config.js`)
   - Loads the standardized schema
   - Extracts all modules with CRUD operations
   - Provides module configurations to tests

2. **Test Discovery**
   - Recursively traverses the schema structure
   - Identifies modules with valid endpoints (Post, PUT, DELETE, View, EDIT)
   - Generates test suites for each module

3. **Test Execution**
   - Uses endpoint URLs from schema
   - Uses payload templates from schema
   - Executes complete 6-phase CRUD lifecycle

### 📝 Schema Structure Example

```json
{
  "General_Settings": {
    "Master_Data": {
      "Discount_Policy": {
        "Post": [
          "/erp-apis/DiscountPolicy",
          {
            "name": "string",
            "nameAr": "string",
            "discountPercentage": 1,
            "userIds": []
          }
        ],
        "PUT": [
          "/erp-apis/DiscountPolicy",
          {
            "id": "<createdId>",
            "name": "string",
            "nameAr": "string",
            "discountPercentage": 1,
            "userIds": []
          }
        ],
        "DELETE": ["/erp-apis/DiscountPolicy/<createdId>"],
        "View": ["/erp-apis/DiscountPolicy/<createdId>"],
        "EDIT": ["/erp-apis/DiscountPolicy/<createdId>"]
      }
    }
  }
}
```

### 🎯 Key Features

1. **Standardized Format**
   - Consistent structure across all modules
   - Clear operation definitions (Post, PUT, DELETE, View, EDIT)
   - Payload templates included

2. **ID Correlation**
   - Uses `<createdId>` placeholder
   - Automatically replaced with actual IDs during tests
   - Enables complete CRUD lifecycle testing

3. **Bilingual Support**
   - English fields (name)
   - Arabic fields (nameAr)
   - Supports internationalization testing

### 📂 Related Files

**Schema Files:**
- `test-data/Input/Main-Backend-Api-Schema.json` - Original schema
- `test-data/Input/Main-Standarized-Backend-Api-Schema.json` - **USED** ✅
- `test-data/Input/Enhanced-ERP-Api-Schema-Advanced-Fixed.json` - Enhanced schema (used by other tests)

**Configuration:**
- `Constants/FileConstants.js` - Schema path configuration
- `config/modules-config.js` - Schema loader and parser

**Tests:**
- `tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js` - CRUD test suite

### 🔄 Schema Update Process

If you need to update the schema:

1. **Edit the schema file:**
   ```
   test-data/Input/Main-Standarized-Backend-Api-Schema.json
   ```

2. **Schema will be automatically reloaded** on next test run

3. **Verify changes:**
   ```bash
   npm run test:CRUD
   ```

### 📊 Module Distribution

**By Category:**
- General Settings: ~16 modules
- Accounting: ~4 modules
- Finance: ~8 modules
- Sales: ~15 modules
- Purchase: ~6 modules
- Inventory: ~13 modules
- Distribution: ~3 modules
- Human Resources: ~1 module
- Fixed Assets: ~4 modules

**Total:** 79 testable modules (excluding Reports)

---

**Last Updated:** December 6, 2025  
**Schema Version:** Standardized  
**Status:** ✅ Active
