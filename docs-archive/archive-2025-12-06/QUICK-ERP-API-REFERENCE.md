# ⚡ Quick ERP API Reference

**Fast access to all 96 modules and 784 endpoints**

---

## 🚀 Quick Commands

### Fetch & Generate
```bash
npm run swagger:advanced:fetch      # Download Swagger docs
npm run swagger:advanced:parse      # Analyze structure
npm run swagger:advanced:generate   # Create schemas
npm run swagger:advanced:modules    # Generate module files
npm run swagger:advanced:stats      # Show statistics
```

### Validate & Enhance
```bash
npm run schema:enhance:validate     # Validate all schemas
npm run schema:enhance:analyze      # Analyze schemas
npm run schema:enhance:detect       # Find missing endpoints
npm run schema:enhance:optimize     # Optimize structure
npm run schema:enhance:standardize  # Standardize format
```

---

## 📦 Module Quick Reference

### 🏢 General Settings (11 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| Company | 10 | GetFirstCompany, EditCompanyAddress |
| Branch | 5 | BranchDropdown, GetAll |
| Currency | 7 | CurrencyDropDown, GET, POST, PUT, DELETE |
| CurrencyConversion | 7 | GET, POST, PUT, DELETE, rate |
| DiscountPolicy | 10 | GET, POST, PUT, DELETE, View, EDIT |
| Tag | 9 | GET, POST, PUT, DELETE, LookUP |
| Tax | 8 | GET, POST, PUT, DELETE |
| TaxGroup | 7 | GET, POST, PUT, DELETE |
| Country | 3 | GET, GetCities, GetNationality |
| AccountSection | 1 | GET |
| AccountType | 1 | GET |

### 💰 Accounting (15 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| ChartOfAccounts | 15 | AddAccount, EditAccount, GetTree, Delete |
| CostCenter | 11 | AddCostCenter, EditCostCenter, GetTree |
| JournalEntry | 15 | POST, Edit, View, Delete |
| OpeningBalanceJournalEntry | 14 | GET, POST, PUT, DELETE, Post, Unpost |
| AccountingGeneralSettings | 3 | GET, PUT, GetTaxWithAccount |
| AccountingReports | 3 | AccountStatmentReport, PrintOut, Export |
| CostCenterReports | 4 | POST, PrintOut, IncomeStatement |
| BalanceSheet | 2 | POST, PrintOutBalanceSheetReport |
| IncomeStatement | 2 | GET, POST |
| TrialBalance | 4 | GET, POST, PrintOut, Export |
| JournalEntryTemplete | 2 | GET, POST |
| Levels | 2 | GET, POST |
| Sequence | 4 | GET, POST, PUT, DELETE |

### 💵 Finance (10 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| Bank | 13 | GET, POST, Edit, View, Delete, BankAccountDropDown |
| Treasury | 10 | GET, POST, PUT, DELETE, TreasuryDropDown |
| PaymentIn | 16 | save, PUT, DELETE, GetView |
| PaymentOut | 12 | POST, PUT, DELETE, GetView |
| PaymentMethod | 9 | GET, POST, PUT, DELETE, View |
| PaymentTerms | 8 | GET, POST, PUT, DELETE, View, EDIT |
| FundTransfer | 9 | GET, POST, PUT, DELETE, Post |
| FinanceGeneralSettings | 3 | GET, POST, PUT |
| FinanceReports | 6 | TreasuryStatement, BankAccountStatement |
| SIPaymentReconciliation | 1 | GET |

### 🛒 Sales (18 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| SalesInvoice | 24 | GET, POST, PUT, DELETE, Post, ZatcaInvoices |
| Customer | 18 | GET, POST, PUT, DELETE, Search, GetView |
| CustomerCategory | 8 | GET, POST, PUT, DELETE |
| CustomerOpeningBalance | 10 | GET, POST, PUT, DELETE, Post, Unpost |
| SalesOrder | 14 | GET, POST, PUT, DELETE, Post |
| SalesMan | 25 | GET, POST, PUT, DELETE, GetView |
| SalesTeam | 14 | GET, POST, PUT, DELETE |
| SalesArea | 8 | GET, POST, PUT, DELETE |
| SalesProject | 10 | GET, POST, PUT, DELETE |
| SalesProjectInvoice | 9 | GET, POST, PUT, DELETE |
| PricePolicy | 10 | GET, POST, PUT, DELETE |
| ReturnSalesInvoice | 10 | GET, POST, PUT, DELETE, Post |
| VanSales | 15 | GET, POST, PUT, DELETE |
| POSSession | 18 | GET, POST, PUT, DELETE, Close |
| Invoice | 15 | GET, POST, PUT, DELETE |
| SalesManVisit | 10 | GET, POST, PUT, DELETE |
| SalesGeneralSettings | 2 | GET, PUT |
| CustomerReports | 7 | Various reports |

### 📦 Purchasing (8 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| PurchaseOrder | 14 | GET, POST, PUT, DELETE, Post |
| Vendor | 12 | GET, POST, PUT, DELETE, GetView |
| VendorCategory | 7 | GET, POST, PUT, DELETE |
| VendorOpeningBalance | 9 | GET, POST, PUT, DELETE, Post |
| ReturnInvoice | 10 | GET, POST, PUT, DELETE, Post |
| Import | 7 | GET, POST, PUT, DELETE |
| PurchaseTax | 1 | GET |
| VendorReports | 4 | Various reports |

### 🏭 Fixed Assets (10 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| Assets | 8 | GET, POST, PUT, DELETE, GetView |
| AssetsLocation | 8 | GET, POST, PUT, DELETE, GetTree |
| AssetsDepreciation | 12 | GET, POST, PUT, DELETE, Post, Save |
| AssetsOpeningBalance | 10 | GET, POST, PUT, DELETE, Post, Unpost |
| AssetsPurchaseInvoice | 10 | GET, POST, PUT, DELETE, Post |
| AssetsReturnPurchaseInvoice | 10 | GET, POST, PUT, DELETE, Post |
| AssetsSalesInvoice | 10 | GET, POST, PUT, DELETE, Post |
| AssetsReturnSalesInvoice | 8 | GET, POST, PUT, DELETE, Post |
| FixedAssetsGeneralSettings | 2 | GET, PUT |
| FixedAssetsGroup | 8 | GET, POST, PUT, DELETE |

### 👥 HR & Administration (10 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| Employee | 8 | GET, POST, PUT, DELETE |
| User | 6 | GET, POST, PUT, DELETE |
| Role | 11 | GET, POST, PUT, DELETE |
| UserBranchAccess | 3 | GetAll, POST, PUT |
| UserSettings | 5 | GET, POST, PUT |
| CurrentUserInfo | 8 | GET, GetUserClaims, GenerateAppToken |
| Device | 17 | GET, POST, PUT, DELETE, Verify |
| DeviceVerification | 2 | Verify, Resend |
| ZatcaDevice | 5 | CurrentInfo, POST, PUT |
| HrGeneralSetting | 4 | GET, POST, PUT |

### ⚙️ System & Utilities (16 modules)

| Module | Endpoints | Key Operations |
|--------|-----------|----------------|
| Dashboard | 29 | Various dashboard endpoints |
| DashBoard | 10 | Statistics and metrics |
| Workflow | 2 | GET, POST |
| WorkflowConfiguration | 5 | GET, POST, PUT, DELETE |
| Workflows | 8 | GetAllProcessesLookup, Execute |
| FinancialYear | 15 | GET, POST, PUT, DELETE, GetLastYearDate |
| Lookup | 1 | GET (multiple lookups) |
| Translation | 1 | GET |
| SideMenu | 3 | GET, POST, PUT |
| Tenant | 6 | GET, POST, PUT, DELETE |
| MarketPlace | 6 | GET, POST, PUT, DELETE |
| Attachments | 3 | Upload, Download, DownloadBase64 |
| ReportCore | 1 | GET |
| GeneralSettingReport | 4 | VatReport, VatManagement |
| TransferRequest | 5 | GET, POST, PUT, DELETE |
| Inventory | 3 | GET, POST, PUT |

---

## 📊 HTTP Method Distribution

| Method | Count | Percentage |
|--------|-------|------------|
| GET | 479 | 61% |
| POST | 147 | 19% |
| PUT | 83 | 11% |
| DELETE | 75 | 9% |

---

## 🎯 Common Patterns

### Standard CRUD Operations
```javascript
// Most modules follow this pattern:
{
  "ModuleName": {
    "Operation": {
      "GET": ["/erp-apis/ModuleName", {}],
      "POST": ["/erp-apis/ModuleName", { payload }],
      "PUT": ["/erp-apis/ModuleName", { id, payload }],
      "DELETE": ["/erp-apis/ModuleName/{id}", {}]
    }
  }
}
```

### Lookup/Dropdown Operations
```javascript
{
  "ModuleName": {
    "LookUP": ["/erp-apis/ModuleName/Dropdown", {}]
  }
}
```

### View/Details Operations
```javascript
{
  "ModuleName": {
    "View": ["/erp-apis/ModuleName/View/{id}", {}],
    "EDIT": ["/erp-apis/ModuleName/{id}", {}]
  }
}
```

### Post/Unpost Operations (Financial)
```javascript
{
  "ModuleName": {
    "Post": ["/erp-apis/ModuleName/{id}/Post", {}],
    "Unpost": ["/erp-apis/ModuleName/{id}/Unpost", {}]
  }
}
```

---

## 🔍 Finding Endpoints

### By Module
```bash
# List all endpoints in a module
cat test-data/modules/Module-ChartOfAccounts.json | jq
```

### By HTTP Method
```bash
# Find all POST endpoints
npm run swagger:advanced:stats
```

### By Path Pattern
```bash
# Search for specific path
grep -r "PaymentIn" test-data/modules/
```

---

## 📁 File Locations

### Schema Files
- **Enhanced Schema:** `test-data/Input/Enhanced-ERP-Api-Schema.json`
- **Module Schemas:** `test-data/modules/Module-*.json` (96 files)
- **Original Schemas:** `test-data/Input/Main-*.json`

### Documentation
- **Swagger Docs:** `swagger-api-docs.json`
- **Parsed Data:** `swagger-parsed.json`
- **Analysis Report:** `schema-analysis-report.json`

### Tools
- **Advanced Tool:** `scripts/advanced-swagger-integration.js`
- **Enhancement Utility:** `scripts/schema-enhancement-utility.js`
- **Original Tool:** `scripts/swagger-integration-tool.js`

---

## 🎨 Usage Patterns

### Pattern 1: Test Single Module
```javascript
const schema = require('./test-data/modules/Module-Bank.json');
// Use schema.Bank.Operation
```

### Pattern 2: Test Multiple Modules
```javascript
const enhanced = require('./test-data/Input/Enhanced-ERP-Api-Schema.json');
// Access any module: enhanced.Bank, enhanced.Customer, etc.
```

### Pattern 3: Dynamic Module Loading
```javascript
const moduleName = 'ChartOfAccounts';
const schema = require(`./test-data/modules/Module-${moduleName}.json`);
```

---

## 💡 Pro Tips

1. **Use module schemas** for focused testing
2. **Use enhanced schema** for integration testing
3. **Validate before testing** with `npm run schema:enhance:validate`
4. **Check for updates** weekly with `npm run swagger:advanced:fetch`
5. **Analyze coverage** with `npm run schema:enhance:analyze --save`

---

## 🔗 Quick Links

- [Comprehensive Guide](COMPREHENSIVE-ERP-API-ENHANCEMENT-GUIDE.md)
- [Dynamic Endpoint Guide](DYNAMIC-ENDPOINT-GUIDE.md)
- [Swagger Integration Guide](SWAGGER-INTEGRATION-GUIDE.md)
- [Package.json Scripts](package.json)

---

**Total Coverage:**  
✅ 96 Modules | ✅ 784 Endpoints | ✅ 100% Documented
