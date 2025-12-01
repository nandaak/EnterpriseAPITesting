/**
 * Comprehensive Schema Enhancement Script
 * Enhances ALL failing module schemas with data from old standardized schema
 */

const fs = require('fs');
const path = require('path');

// Load schemas
const oldSchemaPath = path.join(__dirname, '../test-data/Input/Main-Standarized-Backend-Api-Schema.json');
const oldSchema = JSON.parse(fs.readFileSync(oldSchemaPath, 'utf8'));

// Comprehensive mapping - maps new module names to old schema paths
const moduleMapping = {
  // General Settings - Master Data
  'DiscountPolicy': ['General_Settings', 'Master_Data', 'Discount_Policy'],
  'FinancialYear': ['General_Settings', 'Master_Data', 'Financial_Calendar'],
  'CurrencyConversion': ['General_Settings', 'Master_Data', 'Currency_Conversion'],
  'Tag': ['General_Settings', 'Master_Data', 'Tags_Definition'],
  
  // Accounting - Master Data
  'ChartOfAccounts': ['Accounting', 'Master_Data', 'Chart_of_Accounts'],
  'CostCenter': ['Accounting', 'Master_Data', 'Cost_Center_Definition'],
  
  // Accounting - Transaction
  'JournalEntry': ['Accounting', 'Transaction', 'Journal_Entry'],
  
  // Finance - Master Data
  'Treasury': ['Finance', 'Master_Data', 'Treasury_Definition'],
  'Bank': ['Finance', 'Master_Data', 'Bank_Definition'],
  'PaymentTerms': ['Finance', 'Master_Data', 'Payment_Terms'],
  
  // Finance - Transaction
  'PaymentIn': ['Finance', 'Transaction', 'Payment_IN'],
  'PaymentOut': ['Finance', 'Transaction', 'Payment_OUT'],
  'FundTransfer': ['Finance', 'Transaction', 'Fund_Transfer'],
  
  // Sales - Master Data
  'CustomerCategory': ['Sales', 'Master_Data', 'Customer_Category'],
  'Customer': ['Sales', 'Master_Data', 'Customer_Definition'],
};

// Additional modules that need generic enhancement
const genericModules = [
  'Assets', 'AssetsDepreciation', 'AssetsLocation', 'AssetsOpeningBalance',
  'AssetsReturnPurchaseInvoice', 'AssetsReturnSalesInvoice', 'AssetsSalesInvoice',
  'Attachments', 'Branch', 'Currency', 'CurrentUserInfo', 'CustomerOpeningBalance',
  'Device', 'Employee', 'FixedAssetsGroup', 'HrGeneralSetting', 'Import',
  'Invoice', 'Levels', 'MarketPlace', 'OpeningBalanceJournalEntry', 'PaymentMethod',
  'POSSession', 'PurchaseOrder', 'ReturnInvoice', 'ReturnSalesInvoice', 'Role',
  'SalesInvoice', 'SalesMan', 'SalesManVisit', 'SalesOrder', 'SalesProject',
  'SalesProjectInvoice', 'Sequence', 'Tax', 'TaxGroup', 'TransferRequest',
  'User', 'UserSettings', 'VanSales', 'Vendor', 'VendorCategory',
  'VendorOpeningBalance', 'WorkflowConfiguration', 'Workflows', 'ZatcaDevice'
];

function getOldSchemaData(modulePath) {
  let current = oldSchema;
  for (const key of modulePath) {
    if (!current[key]) return null;
    current = current[key];
  }
  return current;
}

function generateRealisticData(schema) {
  const result = {};
  
  for (const [key, value] of Object.entries(schema)) {
    if (key === 'id' || key.toLowerCase().includes('id')) {
      result[key] = value; // Keep ID placeholders as-is
    } else if (typeof value === 'string') {
      if (value === 'string') {
        if (key.toLowerCase().includes('email')) {
          result[key] = `test${Date.now()}@example.com`;
        } else if (key.toLowerCase().includes('phone')) {
          result[key] = '+966501234567';
        } else if (key.toLowerCase().includes('code')) {
          result[key] = `CODE${Math.floor(Math.random() * 10000)}`;
        } else if (key.toLowerCase().includes('ar') || key.includes('Ar')) {
          result[key] = `اختبار ${Math.floor(Math.random() * 1000)}`;
        } else {
          result[key] = `Test ${key} ${Math.floor(Math.random() * 1000)}`;
        }
      } else {
        result[key] = value;
      }
    } else if (typeof value === 'number' && value === 1) {
      if (key.toLowerCase().includes('percentage') || key.toLowerCase().includes('rate')) {
        result[key] = 15;
      } else if (key.toLowerCase().includes('amount') || key.toLowerCase().includes('balance')) {
        result[key] = 1000;
      } else if (key.toLowerCase().includes('quantity')) {
        result[key] = 10;
      } else {
        result[key] = 1;
      }
    } else if (Array.isArray(value)) {
      result[key] = value;
    } else if (typeof value === 'object' && value !== null) {
      result[key] = generateRealisticData(value);
    } else {
      result[key] = value;
    }
  }
  
  return result;
}

function enhanceModuleSchema(moduleName, useMapping = true) {
  const modulePath = path.join(__dirname, `../test-data/modules/Module-${moduleName}.json`);
  
  if (!fs.existsSync(modulePath)) {
    console.log(`⚠️  Module file not found: ${moduleName}`);
    return false;
  }

  const moduleData = JSON.parse(fs.readFileSync(modulePath, 'utf8'));
  let updated = false;

  if (useMapping) {
    const oldPath = moduleMapping[moduleName];
    
    if (!oldPath) {
      return false;
    }

    const oldData = getOldSchemaData(oldPath);
    
    if (!oldData) {
      console.log(`⚠️  Old schema data not found for: ${moduleName}`);
      return false;
    }

    const moduleKey = Object.keys(moduleData)[0];
    const operations = moduleData[moduleKey];

    for (const opKey in operations) {
      const operation = operations[opKey];
      
      if (operation.POST && oldData.Post) {
        const oldPayload = oldData.Post[1];
        if (oldPayload && Object.keys(oldPayload).length > 0) {
          operation.POST[1] = oldPayload;
          updated = true;
        }
      }

      if (operation.PUT && oldData.PUT) {
        const oldPayload = oldData.PUT[1];
        if (oldPayload && Object.keys(oldPayload).length > 0) {
          operation.PUT[1] = oldPayload;
          updated = true;
        }
      }
    }
  } else {
    // Generic enhancement for modules without direct mapping
    const moduleKey = Object.keys(moduleData)[0];
    const operations = moduleData[moduleKey];

    for (const opKey in operations) {
      const operation = operations[opKey];
      
      if (operation.POST && operation.POST[1]) {
        const enhanced = generateRealisticData(operation.POST[1]);
        operation.POST[1] = enhanced;
        updated = true;
      }

      if (operation.PUT && operation.PUT[1]) {
        const enhanced = generateRealisticData(operation.PUT[1]);
        operation.PUT[1] = enhanced;
        updated = true;
      }
    }
  }

  if (updated) {
    fs.writeFileSync(modulePath, JSON.stringify(moduleData, null, 2));
    return true;
  }

  return false;
}

// Main execution
console.log('🚀 Starting comprehensive schema enhancement...\n');
console.log('=' .repeat(70));

let successCount = 0;
let failCount = 0;

// First, enhance modules with direct mapping
console.log('\n📋 Phase 1: Enhancing modules with old schema mapping...\n');
for (const moduleName of Object.keys(moduleMapping)) {
  console.log(`📦 ${moduleName.padEnd(30)} `, { end: '' });
  if (enhanceModuleSchema(moduleName, true)) {
    console.log('✅');
    successCount++;
  } else {
    console.log('❌');
    failCount++;
  }
}

// Then, enhance remaining modules generically
console.log('\n📋 Phase 2: Enhancing remaining modules with realistic data...\n');
for (const moduleName of genericModules) {
  console.log(`📦 ${moduleName.padEnd(30)} `, { end: '' });
  if (enhanceModuleSchema(moduleName, false)) {
    console.log('✅');
    successCount++;
  } else {
    console.log('❌');
    failCount++;
  }
}

console.log('\n' + '='.repeat(70));
console.log(`\n📊 Enhancement Summary:`);
console.log(`   ✅ Successfully enhanced: ${successCount} modules`);
console.log(`   ❌ Failed: ${failCount} modules`);
console.log(`\n${'='.repeat(70)}\n`);
