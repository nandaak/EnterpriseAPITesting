# ID Registry System - Complete Guide

## Overview

The **Enhanced ID Registry System** maintains a comprehensive, centralized record of all created resource IDs across all ERP modules during testing. This system provides complete lifecycle tracking, analytics, and querying capabilities.

---

## 📁 File Structure

### Registry Files

| File | Purpose | Format | Overwrite Behavior |
|------|---------|--------|-------------------|
| `tests/createdIds.json` | **Complete registry** of ALL IDs from ALL modules | JSON | ❌ Never overwrites - appends all IDs |
| `tests/createdId.json` | Current/latest ID for active module | JSON | ✅ Overwrites on each CREATE |
| `createdId.txt` | Simple text file with current ID | Text | ✅ Overwrites on each CREATE |

### Key Difference

- **`createdIds.json`**: Complete history - **NEVER overwrites**, maintains ALL IDs ever created
- **`createdId.json`** & **`createdId.txt`**: Current ID only - **overwrites** with each new CREATE

---

## 🎯 Features

### 1. Complete ID History
- ✅ Every created ID is permanently recorded
- ✅ Never loses historical data
- ✅ Maintains complete audit trail

### 2. Module Organization
- ✅ IDs grouped by module
- ✅ Per-module statistics
- ✅ Module-level querying

### 3. Lifecycle Tracking
- ✅ Created timestamp
- ✅ Updated count and timestamps
- ✅ Deleted status and timestamp
- ✅ View count and last viewed

### 4. ID Type Detection
- ✅ Automatic type detection (UUID, numeric, etc.)
- ✅ Format validation
- ✅ Type-specific metadata

### 5. Analytics & Statistics
- ✅ ID type distribution
- ✅ Module distribution
- ✅ Activity timeline
- ✅ Most active modules

### 6. Query & Search
- ✅ Filter by module
- ✅ Filter by status (active/deleted)
- ✅ Filter by ID type
- ✅ Time-based queries

---

## 📊 Registry Structure

### Complete Registry (`tests/createdIds.json`)

```json
{
  "metadata": {
    "version": "2.0.0",
    "created": "2025-11-26T...",
    "lastUpdated": "2025-11-26T...",
    "totalModules": 15,
    "totalIds": 150,
    "totalActive": 120,
    "totalDeleted": 30
  },
  "modules": {
    "Accounting.Master_Data.Chart_of_Accounts": {
      "moduleName": "Accounting.Master_Data.Chart_of_Accounts",
      "moduleDisplayName": "Accounting → Master Data → Chart Of Accounts",
      "ids": [
        {
          "id": "a331f1a1-32cb-4aed-40ab-08de0c2835e1",
          "idType": "uuid",
          "idFormat": "uuid-v4",
          "module": "Accounting.Master_Data.Chart_of_Accounts",
          "createdAt": "2025-11-26T10:30:00.000Z",
          "lifecycle": {
            "created": "2025-11-26T10:30:00.000Z",
            "updated": "2025-11-26T10:35:00.000Z",
            "deleted": null,
            "viewedCount": 3,
            "updateCount": 1
          },
          "status": "active",
          "testInfo": { ... },
          "apiInfo": { ... }
        }
      ],
      "totalCreated": 10,
      "totalActive": 8,
      "totalDeleted": 2,
      "currentId": "a331f1a1-32cb-4aed-40ab-08de0c2835e1"
    }
  },
  "allIds": [
    // Complete flat list of ALL ID objects from ALL modules
    { "id": "...", "module": "...", ... },
    { "id": "...", "module": "...", ... }
  ],
  "statistics": {
    "idTypeDistribution": {
      "uuid": 100,
      "numeric": 30,
      "string": 20
    },
    "moduleDistribution": { ... },
    "mostActiveModule": "Accounting.Master_Data.Chart_of_Accounts"
  }
}
```

### Current ID (`tests/createdId.json`)

```json
{
  "id": "a331f1a1-32cb-4aed-40ab-08de0c2835e1",
  "module": "Accounting.Master_Data.Chart_of_Accounts",
  "timestamp": "2025-11-26T10:30:00.000Z",
  "type": "uuid",
  "length": 36
}
```

### Simple Text (`createdId.txt`)

```
a331f1a1-32cb-4aed-40ab-08de0c2835e1
```

---

## 🚀 Usage

### Automatic Usage (During Tests)

The registry is automatically updated during CRUD tests:

```javascript
// CREATE phase - ID automatically added to registry
const result = await crudHelper.runCreateTest();
// ✅ ID saved to:
//    - tests/createdIds.json (appended to complete list)
//    - tests/createdId.json (overwritten with current)
//    - createdId.txt (overwritten with current)

// UPDATE phase - lifecycle automatically updated
await crudHelper.runUpdateTest();
// ✅ Update count incremented in registry

// VIEW phase - view count automatically incremented
await crudHelper.runInitialViewTest();
// ✅ View count incremented in registry

// DELETE phase - status automatically updated
await crudHelper.runDeleteTest();
// ✅ Status changed to 'deleted' in registry
```

### Manual Usage (Programmatic)

```javascript
const IDRegistryEnhanced = require('./utils/id-registry-enhanced');
const registry = new IDRegistryEnhanced();

// Add new ID
const result = registry.addID({
  id: 'a331f1a1-32cb-4aed-40ab-08de0c2835e1',
  modulePath: 'Accounting.Master_Data.Chart_of_Accounts',
  responseData: apiResponse.data,
  testPhase: 'CREATE'
});

// Update lifecycle
registry.updateIDLifecycle(id, modulePath);

// Mark as deleted
registry.markIDAsDeleted(id, modulePath);

// Record view
registry.recordView(id, modulePath);

// Query IDs
const allIds = registry.getAllIDs();
const moduleIds = registry.getModuleIDs(modulePath);
const activeIds = registry.getAllIDs({ status: 'active' });

// Get statistics
const stats = registry.getStatistics();

// Generate report
const report = registry.generateReport();

// Export registry
registry.exportRegistry('./my-export.json');
```

---

## 🔍 Query Tool

### Command Line Interface

```bash
# Show statistics
npm run registry:stats

# List all IDs
npm run registry:list

# Generate comprehensive report
npm run registry:report

# Export registry
npm run registry:export

# Show active IDs only
npm run registry:active

// Show recent activity
npm run registry:recent
```

### Advanced Queries

```bash
# Show IDs for specific module
node scripts/query-id-registry.js module "Accounting.Master_Data.Chart_of_Accounts"

# List with filters
node scripts/query-id-registry.js list status=active

# Show recent 20 activities
node scripts/query-id-registry.js recent 20

# Export to custom path
node scripts/query-id-registry.js export ./exports/registry-backup.json

# Show help
node scripts/query-id-registry.js help
```

---

## 📊 Example Outputs

### Statistics

```
📊 Registry Statistics

Overall:
  Total Modules: 15
  Total IDs: 150
  Active IDs: 120
  Deleted IDs: 30
  Last Updated: 2025-11-26T15:30:00.000Z

ID Type Distribution:
  uuid: 100
  numeric: 30
  string: 20

Top 10 Modules by ID Count:
  1. Accounting → Master Data → Chart Of Accounts
     Total: 25, Active: 20, Deleted: 5
  2. Finance → Master Data → Treasury Definition
     Total: 20, Active: 18, Deleted: 2
  ...
```

### List All IDs

```
📋 All IDs

Found 150 IDs:

1. ID: a331f1a1-32cb-4aed-40ab-08de0c2835e1
   Type: uuid (uuid-v4)
   Module: Accounting → Master Data → Chart Of Accounts
   Created: 2025-11-26T10:30:00.000Z
   Status: active
   Views: 3

2. ID: 12345
   Type: numeric (integer)
   Module: Finance → Master Data → Payment Terms
   Created: 2025-11-26T11:00:00.000Z
   Status: deleted
   Views: 2
...
```

### Module IDs

```
📦 IDs for Module: Accounting.Master_Data.Chart_of_Accounts

Found 25 IDs:

1. ID: a331f1a1-32cb-4aed-40ab-08de0c2835e1
   Type: uuid (uuid-v4)
   Created: 2025-11-26T10:30:00.000Z
   Status: active
   Updates: 2
   Views: 3

2. ID: b442g2b2-43dc-5bfe-51bc-19ef1d3946f2
   Type: uuid (uuid-v4)
   Created: 2025-11-26T10:35:00.000Z
   Status: deleted
   Updates: 1
   Views: 2
   Deleted: 2025-11-26T10:40:00.000Z
...
```

---

## 💡 Use Cases

### 1. Audit Trail
Track all resources created during testing for compliance and debugging.

```bash
npm run registry:report
# Review complete history of all created resources
```

### 2. Test Cleanup
Identify active resources that need cleanup.

```bash
npm run registry:active
# Shows all resources still active in the system
```

### 3. Module Analysis
Analyze which modules are most tested.

```bash
npm run registry:stats
# See module distribution and activity
```

### 4. Debugging
Find specific IDs and their lifecycle.

```bash
node scripts/query-id-registry.js module "Accounting.Master_Data.Chart_of_Accounts"
# See all IDs created for this module
```

### 5. Reporting
Generate reports for test coverage.

```bash
npm run registry:report
# Creates comprehensive JSON report
```

### 6. Data Export
Export registry for external analysis.

```bash
npm run registry:export
# Exports complete registry to JSON file
```

---

## 🔧 Integration

### In CRUD Tests

The registry is automatically integrated into the CRUD lifecycle:

```javascript
// CREATE
const createResult = await crudHelper.runCreateTest();
// ✅ ID automatically added to registry with full metadata

// UPDATE
await crudHelper.runUpdateTest();
// ✅ Lifecycle automatically updated (update count++)

// VIEW
await crudHelper.runInitialViewTest();
// ✅ View count automatically incremented

// DELETE
await crudHelper.runDeleteTest();
// ✅ Status automatically changed to 'deleted'
```

### Custom Integration

```javascript
const IDRegistryEnhanced = require('./utils/id-registry-enhanced');
const registry = new IDRegistryEnhanced();

// In your custom test
test('Custom resource creation', async () => {
  const response = await api.post('/resource', data);
  const id = response.data.id;

  // Add to registry
  registry.addID({
    id: id,
    modulePath: 'Custom.Module.Path',
    responseData: response.data,
    testPhase: 'CREATE',
    additionalMetadata: {
      customField: 'value'
    }
  });
});
```

---

## 📈 Benefits

### 1. Complete History
- ✅ Never lose track of created resources
- ✅ Complete audit trail
- ✅ Historical analysis

### 2. Better Debugging
- ✅ Track resource lifecycle
- ✅ Identify orphaned resources
- ✅ Analyze test patterns

### 3. Test Coverage
- ✅ See which modules are tested
- ✅ Identify gaps in testing
- ✅ Track test activity

### 4. Resource Management
- ✅ Identify active resources
- ✅ Plan cleanup operations
- ✅ Monitor resource creation

### 5. Analytics
- ✅ ID type distribution
- ✅ Module activity patterns
- ✅ Test execution trends

---

## 🎓 Best Practices

### 1. Regular Exports
```bash
# Export registry regularly for backup
npm run registry:export
```

### 2. Monitor Active Resources
```bash
# Check for orphaned resources
npm run registry:active
```

### 3. Review Statistics
```bash
# Review test coverage
npm run registry:stats
```

### 4. Module-Specific Analysis
```bash
# Analyze specific modules
node scripts/query-id-registry.js module "Your.Module.Path"
```

### 5. Cleanup Planning
```bash
# Identify resources for cleanup
npm run registry:active
# Then manually clean up active resources
```

---

## 🔍 Troubleshooting

### Issue: Registry file is large
**Solution:** This is normal - the registry maintains complete history. Export and archive periodically.

### Issue: Can't find specific ID
**Solution:** Use the query tool with filters:
```bash
node scripts/query-id-registry.js list status=active
```

### Issue: Module not showing in stats
**Solution:** Ensure tests have run for that module and IDs were created.

### Issue: Duplicate IDs in registry
**Solution:** This is expected - the same ID can appear multiple times if created in different test runs.

---

## 📞 Support

### Documentation
- **This Guide:** Complete registry system documentation
- **ID Type Management:** `ID-TYPE-MANAGEMENT-GUIDE.md`
- **Dynamic Endpoints:** `DYNAMIC-ENDPOINT-GUIDE.md`

### Code
- **Enhanced Registry:** `utils/id-registry-enhanced.js`
- **Query Tool:** `scripts/query-id-registry.js`
- **CRUD Helper:** `utils/crud-lifecycle-helper.js`

---

## ✨ Summary

The Enhanced ID Registry System provides:

- ✅ **Complete history** of all created IDs (never overwrites)
- ✅ **Current ID tracking** for active operations (overwrites)
- ✅ **Lifecycle tracking** (created, updated, deleted, viewed)
- ✅ **Module organization** with statistics
- ✅ **Query capabilities** with filters
- ✅ **Analytics and reporting** tools
- ✅ **Export functionality** for external analysis
- ✅ **Automatic integration** with CRUD tests

**Key Files:**
- `tests/createdIds.json` - Complete registry (NEVER overwrites)
- `tests/createdId.json` - Current ID (overwrites)
- `createdId.txt` - Simple current ID (overwrites)

**Quick Commands:**
```bash
npm run registry:stats    # View statistics
npm run registry:list     # List all IDs
npm run registry:report   # Generate report
npm run registry:export   # Export registry
npm run registry:active   # Show active IDs
npm run registry:recent   # Show recent activity
```

---

**Version:** 2.0.0  
**Last Updated:** November 26, 2025  
**Status:** ✅ Production Ready
