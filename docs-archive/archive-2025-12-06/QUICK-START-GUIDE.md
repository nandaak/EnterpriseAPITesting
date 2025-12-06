# 🚀 Quick Start Guide - Refactored Framework

## What Changed?

All API schema keys have been updated from HTTP methods to semantic operations:

```javascript
// OLD (HTTP Methods)
moduleConfig.Post    // ❌
moduleConfig.PUT     // ❌
moduleConfig.GET     // ❌

// NEW (Semantic Operations)
moduleConfig.CREATE  // ✅ Create new resource
moduleConfig.EDIT    // ✅ Update existing resource
moduleConfig.View    // ✅ View single resource
moduleConfig.LookUP  // ✅ List/search resources
moduleConfig.EXPORT  // ✅ Export data
moduleConfig.PRINT   // ✅ Print/PDF
moduleConfig.DELETE  // ✅ Delete resource
```

## Quick Reference

| Operation | Use When | Example |
|-----------|----------|---------|
| **CREATE** | Adding new resource | `POST /api/customer` |
| **EDIT** | Updating resource | `PUT /api/customer` |
| **View** | Getting by ID | `GET /api/customer/123` |
| **LookUP** | Listing/searching | `GET /api/customers` |
| **EXPORT** | Exporting data | `GET /api/customers/export` |
| **PRINT** | Printing | `GET /api/invoice/print` |
| **DELETE** | Deleting | `DELETE /api/customer/123` |

## Using in Tests

### Before
```javascript
const endpoint = moduleConfig.Post[0];
await apiClient.post(moduleConfig.Post[0], payload);
```

### After
```javascript
const endpoint = moduleConfig.CREATE[0];
await apiClient.post(moduleConfig.CREATE[0], payload);
```

## Running Tests

All tests work exactly as before:

```bash
npm test
```

## Documentation

- **MASTER-REFACTORING-REPORT.md** - Complete overview
- **SCHEMA-TRANSFORMATION-GUIDE.md** - Detailed guide
- **TEST-REFACTORING-COMPLETE.md** - Test changes

## Status

✅ All schemas refactored  
✅ All tests updated  
✅ All utilities aligned  
✅ 100% verified  
✅ Production ready

---

**Questions?** Check the comprehensive documentation files!
