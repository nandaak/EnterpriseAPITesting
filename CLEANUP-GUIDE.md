# Test Cleanup Guide

## Overview

Comprehensive cleanup system for test artifacts, reports, and ID files to prepare for fresh test runs.

---

## 🧹 Quick Commands

### Clean Everything (Recommended)
```bash
npm run clean:fresh
```
Cleans: Reports + ID files + Cache

### Clean Specific Items
```bash
npm run clean:reports    # Clean only test reports
npm run clean:ids        # Clean only ID files
npm run clean:cache      # Clean only Jest cache
npm run clean:all        # Clean everything
```

### Clean with Backup
```bash
npm run clean:backup     # Clean everything + backup ID registry
```

---

## 📁 What Gets Cleaned

### Reports (`npm run clean:reports`)
- ✅ `jest-html-reporters-attach/` - Jest HTML report attachments
- ✅ `html-report/` - HTML test reports
- ✅ `coverage/` - Code coverage reports
- ✅ `test-results/` - Test result files
- ✅ `test-results.json` - JSON test results
- ✅ `id-registry-report.json` - ID registry reports
- ✅ `id-registry-export.json` - ID registry exports

### ID Files (`npm run clean:ids`)
- ✅ `tests/createdId.json` - Current ID (JSON format)
- ✅ `tests/createdIds.json` - **Complete ID registry** (all IDs)
- ✅ `createdId.txt` - Current ID (text format)

### Cache (`npm run clean:cache`)
- ✅ Jest cache directory

---

## ⚠️ Important Notes

### ID Registry Cleanup

**`tests/createdIds.json` contains your complete ID history!**

When you run `npm run clean:ids` or `npm run clean:all`:
- ❌ **ALL ID history will be deleted**
- ❌ **Cannot be recovered** (unless backed up)
- ✅ **Use `npm run clean:backup`** to backup before cleaning

### Backup Before Cleaning

```bash
# Recommended: Backup before cleaning
npm run clean:backup

# This creates: backups/createdIds-backup-YYYY-MM-DDTHH-MM-SS.json
```

---

## 🎯 Use Cases

### 1. Fresh Test Run
```bash
# Clean everything for a fresh start
npm run clean:fresh

# Then run tests
npm test
```

### 2. Clean Reports Only
```bash
# Keep ID history, clean only reports
npm run clean:reports

# Then run tests
npm test
```

### 3. Reset ID Registry
```bash
# Backup first, then clean IDs
npm run clean:backup

# Or clean IDs only
npm run clean:ids

# Then run tests to create new IDs
npm test
```

### 4. Clear Jest Cache
```bash
# If tests behaving strangely
npm run clean:cache

# Then run tests
npm test
```

### 5. Complete Reset
```bash
# Backup, then clean everything
npm run clean:backup

# Verify backup created
ls backups/

# Then run fresh tests
npm test
```

---

## 🔧 Advanced Usage

### Custom Cleanup Script

```bash
# Clean specific items
node scripts/clean-test-artifacts.js --reports --ids

# Clean with backup
node scripts/clean-test-artifacts.js --all --backup

# Clean only reports
node scripts/clean-test-artifacts.js --reports

# Clean only IDs
node scripts/clean-test-artifacts.js --ids

# Show help
node scripts/clean-test-artifacts.js --help
```

### Available Options

| Option | Description |
|--------|-------------|
| `--all` | Clean everything (default if no options) |
| `--reports` | Clean only test reports |
| `--ids` | Clean only ID files |
| `--cache` | Clean only Jest cache |
| `--backup` | Backup ID registry before cleaning |
| `--help` | Show help message |

---

## 📊 Example Outputs

### Clean All
```bash
$ npm run clean:fresh

🧹 Test Artifacts Cleanup Tool
============================================================

📊 Cleaning test reports...

  ✓ Removed: jest-html-reporters-attach/
  ✓ Removed: html-report/
  ✓ Removed: coverage/
  ℹ️  Not found: test-results/
  ✓ Removed: test-results.json

🆔 Cleaning ID files...

  ✓ Removed: tests/createdId.json (Current ID (JSON))
  ✓ Removed: tests/createdIds.json (Complete ID Registry)
  ✓ Removed: createdId.txt (Current ID (Text))

🗑️  Cleaning Jest cache...

  ✓ Jest cache cleared

============================================================

✅ Cleanup complete! Cleaned: reports, ID files, cache
🚀 Ready for fresh test run!
```

### Clean with Backup
```bash
$ npm run clean:backup

🧹 Test Artifacts Cleanup Tool
============================================================

💾 Backing up ID registry...

  ✓ Registry backed up to: backups/createdIds-backup-2025-11-26T15-30-00-000Z.json

📊 Cleaning test reports...
  ...

🆔 Cleaning ID files...
  ...

============================================================

✅ Cleanup complete! Cleaned: reports, ID files, cache
🚀 Ready for fresh test run!
```

---

## 💡 Best Practices

### 1. Backup Before Major Cleanup
```bash
# Always backup before cleaning IDs
npm run clean:backup
```

### 2. Clean Reports Regularly
```bash
# Clean reports after each test run
npm run clean:reports
npm test
```

### 3. Periodic Full Cleanup
```bash
# Weekly: backup and clean everything
npm run clean:backup
npm run clean:fresh
npm test
```

### 4. Keep ID History
```bash
# If you want to keep ID history, clean only reports
npm run clean:reports
npm test
```

### 5. Export Before Cleaning
```bash
# Export registry before cleaning
npm run registry:export

# Then clean
npm run clean:fresh
```

---

## 🔄 Workflow Examples

### Daily Testing Workflow
```bash
# 1. Clean reports from previous run
npm run clean:reports

# 2. Run tests
npm test

# 3. Review reports
npm run registry:stats
```

### Weekly Reset Workflow
```bash
# 1. Export current registry
npm run registry:export

# 2. Backup and clean everything
npm run clean:backup

# 3. Run fresh tests
npm test

# 4. Review new registry
npm run registry:stats
```

### Before Important Test Run
```bash
# 1. Backup current state
npm run clean:backup
npm run registry:export

# 2. Clean everything
npm run clean:fresh

# 3. Run tests
npm test

# 4. Generate reports
npm run registry:report
```

---

## 📦 Backup Management

### Backup Location
```
backups/
  ├── createdIds-backup-2025-11-26T10-00-00-000Z.json
  ├── createdIds-backup-2025-11-26T11-00-00-000Z.json
  └── createdIds-backup-2025-11-26T12-00-00-000Z.json
```

### Restore from Backup
```bash
# Copy backup to restore
cp backups/createdIds-backup-YYYY-MM-DDTHH-MM-SS.json tests/createdIds.json

# Verify restoration
npm run registry:stats
```

### Clean Old Backups
```bash
# Manually remove old backups
rm backups/createdIds-backup-2025-11-20*.json

# Or keep only recent backups
ls -t backups/ | tail -n +6 | xargs -I {} rm backups/{}
```

---

## ⚠️ Warnings

### ⚠️ ID Registry Deletion
**Warning:** `npm run clean:ids` or `npm run clean:all` will delete your complete ID history!

**Solution:** Always use `npm run clean:backup` first.

### ⚠️ Cannot Undo
**Warning:** Cleanup operations cannot be undone.

**Solution:** Backup important data before cleaning.

### ⚠️ Active Resources
**Warning:** Cleaning IDs doesn't delete actual resources in the API.

**Solution:** Use `npm run registry:active` to see active resources before cleaning.

---

## 🆘 Troubleshooting

### Issue: Files not deleted
**Solution:** Check file permissions or close any programs using the files.

### Issue: Backup failed
**Solution:** Ensure `backups/` directory is writable.

### Issue: Cache not cleared
**Solution:** Run `npx jest --clearCache` manually.

### Issue: Need to recover deleted IDs
**Solution:** Restore from backup in `backups/` directory.

---

## 📚 Related Commands

### Test Commands
```bash
npm test                 # Run all tests
npm run test:CRUD        # Run CRUD tests
npm run test:Security    # Run security tests
```

### Registry Commands
```bash
npm run registry:stats   # View registry statistics
npm run registry:export  # Export registry
npm run registry:report  # Generate report
```

### Cleanup Commands
```bash
npm run clean:reports    # Clean reports only
npm run clean:ids        # Clean IDs only
npm run clean:cache      # Clean cache only
npm run clean:all        # Clean everything
npm run clean:fresh      # Clean everything
npm run clean:backup     # Clean with backup
```

---

## ✨ Summary

### Quick Reference

| Command | Cleans | Backup | Use When |
|---------|--------|--------|----------|
| `npm run clean:reports` | Reports only | No | After each test run |
| `npm run clean:ids` | IDs only | No | Reset ID tracking |
| `npm run clean:cache` | Cache only | No | Jest issues |
| `npm run clean:all` | Everything | No | Fresh start |
| `npm run clean:fresh` | Everything | No | Fresh start |
| `npm run clean:backup` | Everything | Yes | Safe fresh start |

### Recommended Workflow
```bash
# 1. Backup (if needed)
npm run clean:backup

# 2. Clean
npm run clean:fresh

# 3. Test
npm test

# 4. Review
npm run registry:stats
```

---

**Version:** 1.0.0  
**Last Updated:** November 26, 2025  
**Status:** ✅ Ready to Use
