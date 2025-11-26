# Schema Management Scripts

This directory contains scripts for managing API endpoint schemas and converting between full URLs and dynamic extensions.

## 📜 Available Scripts

### 1. `update-all-schemas.js` (Recommended)
**Master script that runs all updates in sequence**

```bash
node scripts/update-all-schemas.js
# or
npm run schema:update
```

**What it does:**
1. Converts full URLs to extensions
2. Fixes incorrectly converted non-URL values
3. Provides comprehensive reporting

**Use when:**
- Initial migration from hardcoded URLs
- After manually editing schemas with full URLs
- Regular maintenance to ensure consistency

---

### 2. `update-schemas-to-extensions.js`
**Converts full URLs to relative extensions**

```bash
node scripts/update-schemas-to-extensions.js
# or
npm run schema:convert-urls
```

**What it does:**
- Finds all full URLs in schemas
- Extracts the path extension (removes base URL)
- Updates schemas with relative paths

**Example:**
```
Before: https://microtecsaudi.com:2032/erp-apis/JournalEntry
After:  /erp-apis/JournalEntry
```

**Use when:**
- Converting hardcoded URLs to extensions
- Migrating from old schema format
- Standardizing URL format across schemas

---

### 3. `fix-schema-non-urls.js`
**Fixes incorrectly converted non-URL values**

```bash
node scripts/fix-schema-non-urls.js
# or
npm run schema:fix-non-urls
```

**What it does:**
- Identifies values that shouldn't be URL extensions
- Removes incorrect `/` prefixes from:
  - GUIDs (e.g., `/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
  - Dates (e.g., `/2027-01-01`)
  - Simple strings (e.g., `/support`, `/happytesting`)

**Example:**
```
Before: /e15567cc-a567-45ed-b96b-02ad216bd2c4
After:  e15567cc-a567-45ed-b96b-02ad216bd2c4
```

**Use when:**
- After running URL conversion script
- Cleaning up incorrectly formatted values
- Ensuring data integrity in schemas

---

## 🎯 Quick Start

### First Time Setup
```bash
# Run the master script to convert all schemas
npm run schema:update
```

### Regular Maintenance
```bash
# Check if schemas need updates
npm run schema:update

# If no changes needed, you'll see:
# "No fixes needed" or "0 URLs converted"
```

---

## 📊 Script Output

### Successful Execution
```
🚀 Starting comprehensive schema update process...
============================================================

📝 STEP 1: Converting full URLs to extensions

📄 Processing: test-data/Input/Main-Standarized-Backend-Api-Schema.json
  ✓ https://microtecsaudi.com:2032/erp-apis/DiscountPolicy → /erp-apis/DiscountPolicy
  ✅ Updated 217 URLs in test-data/Input/Main-Standarized-Backend-Api-Schema.json

------------------------------------------------------------
Step 1 Summary:
   Files processed: 3
   Successfully updated: 3
   Failed: 0
   Total URLs converted: 440
------------------------------------------------------------

📝 STEP 2: Fixing incorrectly converted non-URL values

📄 Processing: test-data/Input/Main-Standarized-Backend-Api-Schema.json
  ✓ Fixed: /2027-01-01 → 2027-01-01
  ✅ Fixed 12 values in test-data/Input/Main-Standarized-Backend-Api-Schema.json

------------------------------------------------------------
Step 2 Summary:
   Files processed: 3
   Successfully processed: 3
   Failed: 0
   Total values fixed: 24
------------------------------------------------------------

============================================================
✅ FINAL SUMMARY:
   Total schema files: 3
   URLs converted to extensions: 440
   Non-URL values fixed: 24
   Overall status: ✅ SUCCESS
============================================================
```

---

## 🔧 How Scripts Work

### URL Detection
Scripts identify URLs by checking for:
- `http://` or `https://` prefix
- Known base URLs (e.g., `https://microtecsaudi.com:2032`)

### Extension Extraction
```javascript
// Input
"https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/GetTree"

// Process
1. Detect base URL: "https://microtecsaudi.com:2032"
2. Extract extension: "/erp-apis/ChartOfAccounts/GetTree"
3. Update schema with extension

// Output
"/erp-apis/ChartOfAccounts/GetTree"
```

### Non-URL Detection
Scripts identify non-URLs by pattern matching:
- **GUIDs:** `/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/`
- **Dates:** `/\d{4}-\d{2}-\d{2}/`
- **Simple words:** `/^\/[a-z]+$/` (single word with no slashes)

---

## 📁 Schema Files

Scripts process these files:
- `test-data/Input/Main-Standarized-Backend-Api-Schema.json`
- `test-data/Input/Main-Backend-Api-Schema.json`
- `test-data/Input/JL-Backend-Api-Schema.json`

---

## ⚙️ Configuration

### Base URLs to Remove
Scripts automatically remove these base URLs:
```javascript
const BASE_URLS = [
  'https://microtecsaudi.com:2032',
  'http://microtecsaudi.com:2032',
  'https://happytesting.microtecdev.com:2050',
  'http://happytesting.microtecdev.com:2050'
];
```

### Adding New Base URLs
Edit the `BASE_URLS` array in `update-schemas-to-extensions.js`:
```javascript
const BASE_URLS = [
  'https://microtecsaudi.com:2032',
  'https://your-new-base-url.com:port',  // Add here
];
```

---

## 🧪 Testing Scripts

### Test Individual Script
```bash
# Test URL conversion
node scripts/update-schemas-to-extensions.js

# Test non-URL fixing
node scripts/fix-schema-non-urls.js

# Test master script
node scripts/update-all-schemas.js
```

### Verify Results
```bash
# Check a schema file
cat test-data/Input/JL-Backend-Api-Schema.json

# Should see extensions like:
# "/erp-apis/JournalEntry"
# Not full URLs like:
# "https://microtecsaudi.com:2032/erp-apis/JournalEntry"
```

---

## 🚨 Error Handling

### Common Errors

#### File Not Found
```
⚠️  File not found: test-data/Input/schema.json
```
**Solution:** Verify file path is correct

#### Invalid JSON
```
❌ Error processing schema.json: Unexpected token
```
**Solution:** Fix JSON syntax in schema file

#### Permission Denied
```
❌ Error: EACCES: permission denied
```
**Solution:** Check file permissions

---

## 📝 Script Modules

### Exported Functions

Each script exports functions for programmatic use:

```javascript
// update-schemas-to-extensions.js
const { extractUrlExtension, processSchemaObject, updateSchemaFile } = require('./scripts/update-schemas-to-extensions');

// fix-schema-non-urls.js
const { fixValue, isValidApiEndpoint, fixSchemaFile } = require('./scripts/fix-schema-non-urls');

// update-all-schemas.js
const { main } = require('./scripts/update-all-schemas');
```

### Usage Example
```javascript
const { updateSchemaFile } = require('./scripts/update-schemas-to-extensions');

// Update a specific schema
const result = updateSchemaFile('test-data/Input/custom-schema.json');
console.log(`Updated ${result.updated} URLs`);
```

---

## 🔄 Workflow

### Recommended Workflow

1. **Initial Setup**
   ```bash
   npm run schema:update
   ```

2. **Verify Changes**
   ```bash
   git diff test-data/Input/
   ```

3. **Test Application**
   ```bash
   npm test
   ```

4. **Commit Changes**
   ```bash
   git add test-data/Input/
   git commit -m "Convert schemas to dynamic endpoints"
   ```

---

## 📚 Related Documentation

- **Complete Guide:** `../DYNAMIC-ENDPOINT-GUIDE.md`
- **Quick Reference:** `../QUICK-ENDPOINT-REFERENCE.md`
- **Implementation Summary:** `../ENDPOINT-UPDATE-SUMMARY.md`

---

## 💡 Tips

1. **Always backup** schemas before running scripts
2. **Review changes** with `git diff` before committing
3. **Test thoroughly** after schema updates
4. **Run scripts regularly** to maintain consistency
5. **Use master script** (`update-all-schemas.js`) for best results

---

## 🆘 Support

If you encounter issues:
1. Check script output for error messages
2. Verify schema file JSON syntax
3. Review related documentation
4. Contact development team

---

**Last Updated:** November 26, 2025  
**Version:** 1.0.0
