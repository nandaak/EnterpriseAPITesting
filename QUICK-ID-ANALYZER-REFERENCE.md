# ID Registry Analyzer - Quick Reference

## 🚀 Quick Commands

### View Statistics
```bash
node utils/id-registry-analyzer.js stats
```

### View ID Details
```bash
node utils/id-registry-analyzer.js details <module-name> <id>
```

### Find IDs
```bash
# All active IDs
node utils/id-registry-analyzer.js find --status active

# All deleted IDs
node utils/id-registry-analyzer.js find --status deleted

# By format
node utils/id-registry-analyzer.js find --format UUID-v4

# By module
node utils/id-registry-analyzer.js find --module Finance

# Completed full cycle
node utils/id-registry-analyzer.js find --completed true

# Combine filters
node utils/id-registry-analyzer.js find --status active --format UUID-v4
```

### Export Report
```bash
# Default location
node utils/id-registry-analyzer.js export

# Custom location
node utils/id-registry-analyzer.js export ./reports/registry.json
```

## 📊 What You Get

### Statistics Output
- Total modules and IDs
- Active vs deleted counts
- Completed cycles
- ID format distribution
- Per-module details

### ID Details Output
- Basic information
- Complete lifecycle
- Update history
- Test run info
- Metadata

### Find Results
- Matching IDs list
- Module information
- Status and format
- View counts
- Creation dates

## 🎯 Common Tasks

### Check Test Cleanup
```bash
# Should show 0 active IDs after tests
node utils/id-registry-analyzer.js find --status active
```

### Verify Full Cycles
```bash
# All IDs should complete full cycle
node utils/id-registry-analyzer.js find --completed true
```

### Monthly Report
```bash
# Export for records
node utils/id-registry-analyzer.js export ./reports/monthly-$(date +%Y%m).json
```

### Debug Specific ID
```bash
# Get complete details
node utils/id-registry-analyzer.js details "Module.Name" "id-value"
```

## 📁 File Locations

- **Registry**: `tests/createdIds.json`
- **Analyzer**: `utils/id-registry-analyzer.js`
- **Documentation**: `docs/ENHANCED-ID-REGISTRY-SYSTEM.md`

## 💡 Tips

- Run `stats` after each test run
- Export reports before major changes
- Use `find` to verify cleanup
- Check `details` for debugging

---

**Version**: 6.0.0 | **Author**: Mohamed Said Ibrahim
