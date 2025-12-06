# Dynamic Endpoint Configuration Guide

## Overview

This project now supports **dynamic endpoint configuration**, allowing you to change the backend API base URL without modifying any code or test files. All API endpoints are stored as **URL extensions** in the JSON schemas, and the base URL is configured in the `.env` file.

## How It Works

### Before (Hardcoded URLs)
```json
{
  "Post": [
    "https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/GetTree",
    { "payload": "data" }
  ]
}
```

### After (Dynamic Extensions)
```json
{
  "Post": [
    "/erp-apis/ChartOfAccounts/GetTree",
    { "payload": "data" }
  ]
}
```

The base URL (`https://microtecsaudi.com:2032`) is now configured in `.env`:
```env
ENDPOINT=https://microtecsaudi.com:2032
```

## Configuration

### Environment Variables

Edit the `.env` file in the project root:

```env
# Dynamic endpoint base URL - all API extensions will be appended to this
ENDPOINT=https://microtecsaudi.com:2032

# Alternative: Use API_BASE_URL (fallback if ENDPOINT is not set)
API_BASE_URL=https://microtecsaudi.com:2032

# Login URL (separate from API endpoint)
LOGIN_URL=https://happytesting.microtecdev.com:2050/erp/login

# Credentials
USEREMAIL=your-email@example.com
PASSWORD=your-password

# Debug settings
DEBUG=true
NODE_ENV=test
```

### Changing the Endpoint

To switch to a different backend environment:

1. **Development Environment:**
   ```env
   ENDPOINT=https://dev.microtecsaudi.com:2032
   ```

2. **Staging Environment:**
   ```env
   ENDPOINT=https://staging.microtecsaudi.com:2032
   ```

3. **Production Environment:**
   ```env
   ENDPOINT=https://microtecsaudi.com:2032
   ```

4. **Local Development:**
   ```env
   ENDPOINT=http://localhost:3000
   ```

**No code changes required!** Just update the `.env` file and restart your tests.

## JSON Schema Structure

### Schema Files

All API endpoints are defined in these JSON schema files:

- `test-data/Input/Main-Standarized-Backend-Api-Schema.json`
- `test-data/Input/Main-Backend-Api-Schema.json`
- `test-data/Input/JL-Backend-Api-Schema.json`

### Schema Format

Each API operation is defined as an array with two elements:

```json
{
  "Module_Name": {
    "Operation_Type": [
      "/api/endpoint/path",           // URL extension (relative path)
      { "payload": "data" }            // Request payload
    ]
  }
}
```

### Example Schema Entry

```json
{
  "Accounting": {
    "Master_Data": {
      "Chart_of_Accounts": {
        "Post": [
          "/erp-apis/ChartOfAccounts/AddAccount",
          {
            "name": "Test Account",
            "accountCode": "1001"
          }
        ],
        "PUT": [
          "/erp-apis/ChartOfAccounts/EditAccount",
          {
            "id": "<createdId>",
            "name": "Updated Account"
          }
        ],
        "DELETE": [
          "/erp-apis/ChartOfAccounts/<createdId>",
          {}
        ],
        "View": [
          "/erp-apis/ChartOfAccounts/GetAccountDetails?id=<createdId>",
          {}
        ]
      }
    }
  }
}
```

## URL Construction

The API client automatically constructs full URLs:

```javascript
// In your test or code:
const endpoint = "/erp-apis/ChartOfAccounts/GetTree";

// API client automatically constructs:
// https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/GetTree
//        ↑ from .env ENDPOINT          ↑ from schema
```

### How It Works Internally

1. **Schema provides:** `/erp-apis/ChartOfAccounts/GetTree`
2. **Environment provides:** `https://microtecsaudi.com:2032`
3. **API client combines:** `https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/GetTree`

## Migration Scripts

### Update Existing Schemas

If you have schemas with full URLs that need to be converted to extensions:

```bash
# Convert all URLs to extensions
node scripts/update-schemas-to-extensions.js

# Fix any incorrectly converted values (GUIDs, dates, etc.)
node scripts/fix-schema-non-urls.js

# Or run both in sequence:
node scripts/update-all-schemas.js
```

### Script Details

#### `update-schemas-to-extensions.js`
- Converts full URLs to relative extensions
- Removes base URLs like `https://microtecsaudi.com:2032`
- Preserves query parameters and path variables

#### `fix-schema-non-urls.js`
- Fixes incorrectly converted non-URL values
- Restores GUIDs, dates, and simple strings
- Ensures only valid API endpoints have the `/` prefix

#### `update-all-schemas.js`
- Master script that runs both updates
- Provides comprehensive summary
- Validates all changes

## API Client Usage

### Automatic URL Construction

The API client (`utils/api-client.js`) automatically handles URL construction:

```javascript
const apiClient = require('./utils/api-client');

// Extension from schema
const endpoint = '/erp-apis/JournalEntry';

// Automatically constructs full URL using ENDPOINT from .env
await apiClient.get(endpoint);
// Actual request: GET https://microtecsaudi.com:2032/erp-apis/JournalEntry

await apiClient.post(endpoint, payload);
// Actual request: POST https://microtecsaudi.com:2032/erp-apis/JournalEntry
```

### Backward Compatibility

The API client still supports full URLs for backward compatibility:

```javascript
// Full URL (legacy support)
await apiClient.get('https://microtecsaudi.com:2032/erp-apis/JournalEntry');

// Extension (recommended)
await apiClient.get('/erp-apis/JournalEntry');

// Both work identically!
```

## Testing

### Running Tests with Different Endpoints

1. **Update `.env` file:**
   ```env
   ENDPOINT=https://staging.microtecsaudi.com:2032
   ```

2. **Run tests:**
   ```bash
   npm test
   ```

3. **All tests automatically use the new endpoint!**

### Environment-Specific Testing

Create multiple `.env` files for different environments:

```bash
.env.development
.env.staging
.env.production
```

Load the appropriate file before running tests:

```bash
# Copy environment-specific config
cp .env.staging .env

# Run tests
npm test
```

## Best Practices

### 1. Always Use Extensions in Schemas

✅ **Good:**
```json
{
  "Post": ["/erp-apis/ChartOfAccounts/AddAccount", {}]
}
```

❌ **Bad:**
```json
{
  "Post": ["https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/AddAccount", {}]
}
```

### 2. Keep Base URL in .env

✅ **Good:**
```env
ENDPOINT=https://microtecsaudi.com:2032
```

❌ **Bad:**
Hardcoding URLs in code or test files

### 3. Use Consistent Extension Format

All extensions should:
- Start with `/`
- Include the full path after the base URL
- Preserve query parameters
- Use `<createdId>` for dynamic IDs

Examples:
```
/erp-apis/JournalEntry
/erp-apis/ChartOfAccounts/GetTree
/erp-apis/JournalEntry/<createdId>
/erp-apis/JournalEntry/View?Id=<createdId>
```

### 4. Document Environment URLs

Maintain a list of valid endpoints for your team:

```markdown
## Available Endpoints

- **Development:** https://dev.microtecsaudi.com:2032
- **Staging:** https://staging.microtecsaudi.com:2032
- **Production:** https://microtecsaudi.com:2032
- **Local:** http://localhost:3000
```

## Troubleshooting

### Issue: Tests failing with 404 errors

**Solution:** Check that `ENDPOINT` in `.env` is correct and accessible.

```bash
# Test the endpoint
curl https://microtecsaudi.com:2032/erp-apis/JournalEntry
```

### Issue: URLs not being constructed correctly

**Solution:** Verify that extensions in schemas start with `/`:

```json
// Correct
"/erp-apis/JournalEntry"

// Incorrect
"erp-apis/JournalEntry"
```

### Issue: Some URLs still hardcoded

**Solution:** Run the migration scripts:

```bash
node scripts/update-all-schemas.js
```

### Issue: GUIDs or dates converted to extensions

**Solution:** Run the fix script:

```bash
node scripts/fix-schema-non-urls.js
```

## Migration Checklist

- [ ] Update `.env` file with `ENDPOINT` variable
- [ ] Run `node scripts/update-all-schemas.js` to convert schemas
- [ ] Verify all schemas use extensions (not full URLs)
- [ ] Test with current endpoint
- [ ] Test with alternative endpoint
- [ ] Update documentation for your team
- [ ] Commit changes to version control

## Benefits

✅ **Flexibility:** Switch environments instantly by changing one variable  
✅ **Maintainability:** No need to update hundreds of URLs across files  
✅ **Consistency:** All tests use the same base URL configuration  
✅ **Simplicity:** Clear separation between base URL and API paths  
✅ **Scalability:** Easy to add new environments or endpoints  

## Support

For questions or issues:
1. Check this guide
2. Review the migration scripts in `scripts/`
3. Examine `utils/api-client.js` for implementation details
4. Contact the development team

---

**Last Updated:** November 26, 2025  
**Version:** 1.0.0
