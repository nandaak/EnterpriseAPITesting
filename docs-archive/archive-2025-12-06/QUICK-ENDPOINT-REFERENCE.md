# Quick Endpoint Reference Card

## 🚀 Quick Start

### Change Backend URL
Edit `.env` file:
```env
ENDPOINT=https://your-new-endpoint.com:2032
```

That's it! All tests will use the new endpoint.

---

## 📝 Schema Format

### Correct Format (Use This)
```json
{
  "Post": ["/erp-apis/ChartOfAccounts/AddAccount", { "data": "here" }]
}
```

### Incorrect Format (Don't Use)
```json
{
  "Post": ["https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/AddAccount", {}]
}
```

---

## 🔧 Migration Commands

### Convert All Schemas
```bash
node scripts/update-all-schemas.js
```

### Convert URLs Only
```bash
node scripts/update-schemas-to-extensions.js
```

### Fix Non-URLs
```bash
node scripts/fix-schema-non-urls.js
```

---

## 🌍 Environment Examples

### Development
```env
ENDPOINT=https://dev.microtecsaudi.com:2032
```

### Staging
```env
ENDPOINT=https://staging.microtecsaudi.com:2032
```

### Production
```env
ENDPOINT=https://microtecsaudi.com:2032
```

### Local
```env
ENDPOINT=http://localhost:3000
```

---

## ✅ Extension Rules

1. **Always start with `/`**
   ```
   ✅ /erp-apis/JournalEntry
   ❌ erp-apis/JournalEntry
   ```

2. **Include full path**
   ```
   ✅ /erp-apis/ChartOfAccounts/GetTree
   ❌ /GetTree
   ```

3. **Preserve query params**
   ```
   ✅ /erp-apis/JournalEntry/View?Id=<createdId>
   ```

4. **Use <createdId> for dynamic IDs**
   ```
   ✅ /erp-apis/JournalEntry/<createdId>
   ```

---

## 🔍 Troubleshooting

| Problem | Solution |
|---------|----------|
| 404 errors | Check `ENDPOINT` in `.env` |
| Wrong URLs | Run `node scripts/update-all-schemas.js` |
| GUIDs converted | Run `node scripts/fix-schema-non-urls.js` |
| Tests not using new endpoint | Restart test process |

---

## 📂 Schema Files

- `test-data/Input/Main-Standarized-Backend-Api-Schema.json`
- `test-data/Input/Main-Backend-Api-Schema.json`
- `test-data/Input/JL-Backend-Api-Schema.json`

---

## 💡 Key Files

| File | Purpose |
|------|---------|
| `.env` | Configure base URL |
| `config/api-config.js` | Reads ENDPOINT from .env |
| `utils/api-client.js` | Constructs full URLs |
| `scripts/update-all-schemas.js` | Migration script |

---

## 🎯 Quick Test

1. Update `.env`:
   ```env
   ENDPOINT=https://staging.example.com:2032
   ```

2. Run tests:
   ```bash
   npm test
   ```

3. Verify logs show new endpoint

---

**Need more details?** See `DYNAMIC-ENDPOINT-GUIDE.md`
