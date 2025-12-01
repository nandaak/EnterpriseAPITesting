/**
 * Schema Enhancement Script
 * Enhances new module schemas with realistic data from the old standardized schema
 */

const fs = require('fs');
const path = require('path');

// Load the old standardized schema
const oldSchemaPath = path.join(__dirname, '../test-data/Input/Main-Standarized-Backend-Api-Schema.json');
const oldSchema = JSON.parse(fs.readFileSync(oldSchemaPath, 'utf8'));

// Mapping of new module names to old schema paths
const moduleMapping = {
  'Bank': ['Finance', 'Master_Data', 'Bank_Definition'],
  'Treasury': ['Finance', 'Master_Data', 'Treasury_Definition'],
  'DiscountPolicy': ['General_Settings', 'Master_Data', 'Discount_Policy'],
  'CustomerCategory': ['Sales', 'Master_Data', 'Customer_Category'],
  'Customer': ['Sales', 'Master_Data', 'Customer_Definition'],
  'FinancialYear': ['General_Settings', 'Master_Data', 'Financial_Calendar'],
  'CurrencyConversion': ['General_Settings', 'Master_Data', 'Currency_Conversion'],
  'Tag': ['General_Settings', 'Master_Data', 'Tags_Definition'],
  'ChartOfAccounts': ['Accounting', 'Master_Data', 'Chart_of_Accounts'],
  'CostCenter': ['Accounting', 'Master_Data', 'Cost_Center_Definition'],
  'JournalEntry': ['Accounting', 'Transaction', 'Journal_Entry'],
  'PaymentIn': ['Finance', 'Transaction', 'Payment_IN'],
  'PaymentOut': ['Finance', 'Transaction', 'Payment_OUT'],
  'FundTransfer': ['Finance', 'Transaction', 'Fund_Transfer'],
  'PaymentTerms': ['Finance', 'Master_Data', 'Payment_Terms'],
};

function getOldSchemaData(modulePath) {
  let current = oldSchema;
  for (const key of modulePath) {
    if (!current[key]) return null;
    current = current[key];
  }
  return current;
}

function enhanceModuleSchema(moduleName) {
  const modulePath = path.join(__dirname, `../test-data/modules/Module-${moduleName}.json`);
  
  if (!fs.existsSync(modulePath)) {
    console.log(`⚠️  Module file not found: ${moduleName}`);
    return false;
  }

  const moduleData = JSON.parse(fs.readFileSync(modulePath, 'utf8'));
  const oldPath = moduleMapping[moduleName];
  
  if (!oldPath) {
    console.log(`⚠️  No mapping found for: ${moduleName}`);
    return false;
  }

  const oldData = getOldSchemaData(oldPath);
  
  if (!oldData) {
    console.log(`⚠️  Old schema data not found for: ${moduleName}`);
    return false;
  }

  let updated = false;

  // Find POST operation in new schema
  const moduleKey = Object.keys(moduleData)[0];
  const operations = moduleData[moduleKey];

  for (const opKey in operations) {
    const operation = operations[opKey];
    
    // Update POST operation
    if (operation.POST && oldData.Post) {
      const oldPayload = oldData.Post[1];
      if (oldPayload && Object.keys(oldPayload).length > 0) {
        operation.POST[1] = oldPayload;
        updated = true;
        console.log(`✅ Updated POST for ${moduleName}`);
      }
    }

    // Update PUT operation
    if (operation.PUT && oldData.PUT) {
      const oldPayload = oldData.PUT[1];
      if (oldPayload && Object.keys(oldPayload).length > 0) {
        operation.PUT[1] = oldPayload;
        updated = true;
        console.log(`✅ Updated PUT for ${moduleName}`);
      }
    }
  }

  if (updated) {
    fs.writeFileSync(modulePath, JSON.stringify(moduleData, null, 2));
    console.log(`💾 Saved ${moduleName}`);
    return true;
  }

  return false;
}

// Main execution
console.log('🚀 Starting schema enhancement from old standardized schema...\n');

const failedModules = [
  'Bank', 'Treasury', 'DiscountPolicy', 'CustomerCategory', 'Customer',
  'FinancialYear', 'CurrencyConversion', 'Tag', 'ChartOfAccounts',
  'CostCenter', 'JournalEntry', 'PaymentIn', 'PaymentOut', 'FundTransfer',
  'PaymentTerms'
];

let successCount = 0;
let failCount = 0;

for (const moduleName of failedModules) {
  console.log(`\n📦 Processing: ${moduleName}`);
  if (enhanceModuleSchema(moduleName)) {
    successCount++;
  } else {
    failCount++;
  }
}

console.log(`\n${'='.repeat(60)}`);
console.log(`✅ Successfully enhanced: ${successCount} modules`);
console.log(`❌ Failed: ${failCount} modules`);
console.log(`${'='.repeat(60)}\n`);
