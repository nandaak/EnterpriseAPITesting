# ⚡ Quick Start Card

## Professional ERP API Testing Framework

**Version:** 2.2 | **Status:** ✅ Production Ready

---

## 🚀 One Command to Rule Them All

```bash
npm run schema:production:ready
```

**This does everything:**
1. ✅ Fetches latest Swagger (96 modules, 784 endpoints)
2. ✅ Generates comprehensive schemas
3. ✅ Creates 96 module files
4. ✅ Adds real payloads (306 payloads)
5. ✅ Harmonizes IDs with <createdId> (903 operations)

---

## 📊 What You Have

| Feature | Count | Status |
|---------|-------|--------|
| ERP Modules | 96 | ✅ |
| API Endpoints | 784 | ✅ |
| Real Payloads | 306 | ✅ |
| Module Schemas | 96 files | ✅ |
| Tools | 5 professional | ✅ |
| Documentation | 8 guides | ✅ |
| NPM Scripts | 50+ | ✅ |

---

## 🎯 Essential Commands

### Update Everything
```bash
npm run schema:production:ready     # Complete update
```

### Individual Steps
```bash
npm run swagger:advanced:fetch      # Get Swagger
npm run swagger:advanced:generate   # Create schemas
npm run swagger:advanced:modules    # Module files
npm run schema:enhance:payloads     # Add payloads
npm run schema:harmonize:ids        # Fix IDs
```

### Validation
```bash
npm run schema:enhance:validate     # Validate all
npm run schema:enhance:analyze      # Analyze coverage
npm run swagger:advanced:stats      # Show stats
```

### Testing
```bash
npm test                            # Run tests
npm run test:CRUD                   # CRUD tests
npm run registry:stats              # ID tracking
```

---

## 📁 Key Files

### Schemas (Use These!)
```
test-data/Input/
├── Main-Backend-Api-Schema.json              ← Use this!
├── Main-Standarized-Backend-Api-Schema.json
├── Enhanced-ERP-Api-Schema.json
└── Enhanced-ERP-Api-Schema-With-Payloads.json

test-data/modules/
└── Module-*.json (96 files)                  ← Or these!
```

### Documentation (Read These!)
```
MASTER-ENHANCEMENT-SUMMARY.md                 ← Start here!
QUICK-ERP-API-REFERENCE.md                    ← Daily use
COMPREHENSIVE-ERP-API-ENHANCEMENT-GUIDE.md    ← Deep dive
```

---

## 💻 Quick Test Example

```javascript
const schema = require('./test-data/Input/Main-Backend-Api-Schema.json');

describe('Discount Policy CRUD', () => {
  let createdId;

  test('CREATE', async () => {
    const [url, payload] = schema.General_Settings.Master_Data.Discount_Policy.Post;
    payload.name = 'Test';
    const response = await api.post(url, payload);
    createdId = response.data.id;
  });

  test('UPDATE', async () => {
    const [url, payload] = schema.General_Settings.Master_Data.Discount_Policy.PUT;
    payload.id = createdId;  // Replace <createdId>
    await api.put(url, payload);
  });

  test('DELETE', async () => {
    const [url] = schema.General_Settings.Master_Data.Discount_Policy.DELETE;
    const finalUrl = url.replace('<createdId>', createdId);
    await api.delete(finalUrl);
  });
});
```

---

## 🎨 Schema Structure

```json
{
  "Module_Name": {
    "Sub_Module": {
      "Operation_Name": {
        "POST": ["/erp-apis/endpoint", { real_payload }],
        "PUT": ["/erp-apis/endpoint", { id: "<createdId>" }],
        "DELETE": ["/erp-apis/endpoint/<createdId>", {}],
        "GET": ["/erp-apis/endpoint/<createdId>", {}]
      }
    }
  }
}
```

---

## 🔗 Key Features

✅ **Real Payloads** - Extracted from Swagger  
✅ **<createdId>** - Dynamic ID placeholders  
✅ **CRUD Correlation** - Proper test flow  
✅ **96 Modules** - Complete coverage  
✅ **784 Endpoints** - All documented  
✅ **One Command** - Complete update  

---

## 📚 Documentation Quick Links

| Document | Purpose |
|----------|---------|
| [MASTER-ENHANCEMENT-SUMMARY.md](MASTER-ENHANCEMENT-SUMMARY.md) | Complete overview |
| [QUICK-ERP-API-REFERENCE.md](QUICK-ERP-API-REFERENCE.md) | Command reference |
| [PAYLOAD-ENHANCEMENT-COMPLETE.md](PAYLOAD-ENHANCEMENT-COMPLETE.md) | Payload guide |
| [SCHEMA-HARMONIZATION-COMPLETE.md](SCHEMA-HARMONIZATION-COMPLETE.md) | ID correlation |

---

## 🆘 Need Help?

```bash
# Tool help
node scripts/advanced-swagger-integration.js help
node scripts/schema-enhancement-utility.js help

# View all commands
npm run

# Validate everything
npm run schema:enhance:validate
```

---

## ✅ Status Check

Run these to verify everything works:

```bash
# 1. Check schemas exist
ls test-data/Input/*.json

# 2. Check modules exist
ls test-data/modules/ | wc -l  # Should be 96

# 3. Validate schemas
npm run schema:enhance:validate

# 4. Show statistics
npm run swagger:advanced:stats
```

---

## 🎯 Daily Workflow

**Morning:**
```bash
npm run schema:enhance:validate
```

**Development:**
```bash
npm test
```

**Weekly:**
```bash
npm run schema:production:ready
```

---

## 🎉 You're Ready!

Everything is set up and ready to use:

✅ Schemas with real payloads  
✅ CRUD test correlation  
✅ Complete automation  
✅ Professional tools  
✅ Comprehensive docs  

**Start testing now!** 🚀

---

**Quick Reference Card v2.2**  
**Last Updated:** November 26, 2025
