# ID Registry System - Quick Reference

## 🎯 Quick Commands

### View Statistics
```bash
node utils/id-registry-manager.js stats
```

### Cleanup Old IDs
```bash
# Keep last 10 IDs per module
node utils/id-registry-manager.js cleanup 10
```

### Search for ID
```bash
node utils/id-registry-manager.js search "your-id-here"
```

### View Module IDs
```bash
node utils/id-registry-manager.js module "Module.Name"
```

### Export Registry
```bash
node utils/id-registry-manager.js export
```

## 📁 File Locations

| File | Location | Purpose |
|------|----------|---------|
| **Current ID** | `./createdId.txt` | Active ID for UPDATE/DELETE/VIEW |
| **Legacy** | `./tests/createdId.json` | Backward compatibility |
| **Registry** | `./tests/createdIds.json` | Complete history (all modules) |

## 🔄 How IDs Flow

### CREATE
```
API Response → createdId.txt → createdId.json → createdIds.json (append)
```

### UPDATE/DELETE/VIEW
```
Read: createdId.txt → fallback: createdId.json → fallback: createdIds.json
```

### DELETE
```
Clear: createdId.txt + createdId.json
Update: createdIds.json (mark as deleted, keep history)
```

## 💡 Key Features

✅ **No Overwrites** - All IDs preserved in registry  
✅ **Backward Compatible** - Existing tests work unchanged  
✅ **Complete History** - Track all created resources  
✅ **Easy Management** - CLI tools for maintenance  
✅ **Module Tracking** - Per-module ID organization  

## 🚀 Common Tasks

### Check Registry Health
```bash
node utils/id-registry-manager.js stats
```

### Find Which Module Created an ID
```bash
node utils/id-registry-manager.js search "17987a69"
```

### Clean Up After Testing
```bash
node utils/id-registry-manager.js cleanup 5
```

### Export for Analysis
```bash
node utils/id-registry-manager.js export ./reports/registry.json
```

## 📊 Registry Structure

```json
{
  "modules": {
    "ModuleName": {
      "ids": [...],           // All created IDs
      "currentId": "...",     // Active ID (null if deleted)
      "totalCreated": 5,      // Count
      "lastCreated": "...",   // Timestamp
      "lastDeleted": "..."    // Timestamp
    }
  },
  "metadata": {
    "totalModules": 10,
    "lastUpdated": "..."
  }
}
```

## 🔧 Troubleshooting

### Registry Not Found
→ Will be created automatically on first CREATE

### Corrupted Registry
```bash
cp tests/createdIds.json tests/createdIds.backup.json
rm tests/createdIds.json
# Run tests again
```

### Missing IDs
→ Check test logs for write errors  
→ Verify `tests/` directory permissions

## 📚 Full Documentation

See [ID-REGISTRY-SYSTEM.md](./ID-REGISTRY-SYSTEM.md) for complete details.

---

**Version**: 5.0.0 | **Author**: Mohamed Said Ibrahim
