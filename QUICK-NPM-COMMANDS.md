# ⚡ Quick NPM Commands Reference

Fast reference for the most commonly used npm scripts.

---

## 🚀 Most Used Commands

```bash
# Run all tests with HTML report
npm run test:all

# Run specific test suite
npm run test:1:crud              # CRUD Validation
npm run test:2:security          # API Security
npm run test:3:advanced-security # Advanced Security
npm run test:4:performance       # Performance Testing
npm run test:5:health            # Health Checks

# Check authentication
npm run check-token

# Clean everything
npm run clean:all
```

---

## 📊 Test Execution

| Command | Description | Duration |
|---------|-------------|----------|
| `npm run test:all` | Run all tests (parallel) | ~30-45 min |
| `npm run test:all:sequential` | Run all tests (sequential) | ~60-90 min |
| `npm run test:1:crud` | CRUD validation | ~15-30 min |
| `npm run test:2:security` | Security testing | ~20-40 min |
| `npm run test:3:advanced-security` | Advanced security | ~8-15 min |
| `npm run test:4:performance` | Performance testing | ~10-20 min |
| `npm run test:5:health` | Health checks | ~5-10 min |

---

## 🔐 Authentication

```bash
npm run fetch-token          # Get new token
npm run check-token          # Verify token
npm run debug-token          # Debug token issues
```

---

## 🐛 Debugging

```bash
npm run test:debug:crud      # Debug CRUD tests
npm run test:debug:security  # Debug security tests
npm run test:failed          # Run only failed tests
npm run test:watch           # Watch mode
```

---

## 📚 Schema Management

```bash
npm run schema:merge                # Merge schemas
npm run schema:production:ready     # Production workflow
npm run swagger:complete            # Complete Swagger workflow
```

---

## 🧹 Cleanup

```bash
npm run clean:reports        # Clean test reports
npm run clean:cache          # Clean Jest cache
npm run clean:all            # Clean everything
```

---

## 📈 Analysis

```bash
npm run analyze:tests        # Analyze test results
npm run analyze:failures     # Analyze failures
npm run fix:all              # Fix all issues
```

---

## 🎯 Quick Workflows

### First Time Setup
```bash
npm install
npm run verify:setup
npm run fetch-token
npm run test:5:health
```

### Daily Testing
```bash
npm run check-token
npm run test:all
```

### Before Deployment
```bash
npm run clean:all
npm run test:all:sequential
npm run analyze:all
```

### Debugging Failures
```bash
npm run test:failed
npm run analyze:failures
npm run fix:all
```

---

## 📖 Full Documentation

- **Complete Guide**: `NPM-SCRIPTS-GUIDE.md`
- **Project README**: `README.md`
- **Package Scripts**: `package.json`

---

**Tip**: Add `:verbose` to any test command for detailed output
```bash
npm run test:1:crud:verbose
npm run test:all:verbose
```
