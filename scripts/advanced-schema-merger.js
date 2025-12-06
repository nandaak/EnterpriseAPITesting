#!/usr/bin/env node
/**
 * Advanced ERP Schema Merger
 * Professional tool to merge Enhanced schema into Standardized schema
 * with complete business logic mapping and 100% endpoint coverage
 */

const fs = require('fs');
const path = require('path');

console.log('🏗️  Advanced ERP Schema Merger\n');
console.log('='.repeat(80));

const CONFIG = {
  enhancedSchema: 'test-data/Input/Enhanced-ERP-Api-Schema-Advanced-Fixed.json',
  standardizedSchema: 'test-data/Input/Main-Standarized-Backend-Api-Schema.json',
  outputSchema: 'test-data/Input/Complete-Standarized-ERP-Api-Schema.json',
  mappingReport: 'complete-schema-mapping-report.json'
};

// Load schemas
console.log('📖 Loading schemas...');
const enhanced = JSON.parse(fs.readFileSync(CONFIG.enhancedSchema, 'utf8'));
const standardized = JSON.parse(fs.readFileSync(CONFIG.standardizedSchema, 'utf8'));

console.log(`✅ Enhanced: ${Object.keys(enhanced).length} modules`);
console.log(`✅ Standardized: ${countNestedModules(standardized)} modules`);

// Deep clone standardized schema as base
const complete = JSON.parse(JSON.stringify(standardized));

// Initialize missing sections
initializeMissingSections(complete);

// Comprehensive module mapping with business logic
const businessMapping = {
  // === GENERAL SETTINGS ===
  'Country': {
    path: 'General_Settings.Master_Data.Country',
    description: 'Country master data management'
  },
  'Sequence': {
    path: 'General_Settings.Master_Data.Sequence',
    description: 'Numbering sequence configuration'
  },
  'Levels': {
    path: 'General_Settings.Master_Data.Levels',
    description: 'Chart of accounts level configuration'
  },
  'Translation': {
    path: 'General_Settings.Master_Data.Translation',
    description: 'Multi-language translation management'
  },
  'Branch': {
    path: 'General_Settings.Master_Data.Branch',
    description: 'Company branch management'
  },
  'HrGeneralSetting': {
    path: 'General_Settings.Master_Data.HR_General_Settings',
    description: 'HR-specific general settings and sequences'
  },
  'Import': {
    path: 'General_Settings.Master_Data.Import_Export',
    description: 'Data import/export management'
  },
  'SideMenu': {
    path: 'General_Settings.Master_Data.Side_Menu',
    description: 'Application menu configuration'
  },
  'Lookup': {
    path: 'General_Settings.Master_Data.Lookup',
    description: 'System lookup services'
  },
  'Attachments': {
    path: 'General_Settings.Master_Data.Attachments',
    description: 'Document attachment management'
  },
  
  // Administration
  'User': {
    path: 'General_Settings.Administration.User_Management',
    description: 'Complete user management'
  },
  'Role': {
    path: 'General_Settings.Administration.Role_Management',
    description: 'Role and permission management'
  },
  'UserSettings': {
    path: 'General_Settings.Administration.User_Settings',
    description: 'User preference settings'
  },
  'UserBranchAccess': {
    path: 'General_Settings.Administration.User_Branch_Access',
    description: 'User branch access control'
  },
  'DeviceVerification': {
    path: 'General_Settings.Administration.Device_Verification',
    description: 'Device authentication and verification'
  },
  'Tenant': {
    path: 'General_Settings.Administration.Tenant_Management',
    description: 'Multi-tenant management'
  },
  'Workflows': {
    path: 'General_Settings.Administration.Workflows',
    description: 'Workflow execution and management'
  },
  'CurrentUserInfo': {
    path: 'General_Settings.Administration.Current_User_Info',
    description: 'Current user session and token management'
  },
  
  // === ACCOUNTING ===
  'AccountSection': {
    path: 'Accounting.Master_Data.Account_Section',
    description: 'Chart of accounts section definition'
  },
  'AccountType': {
    path: 'Accounting.Master_Data.Account_Type',
    description: 'Account type classification'
  },
  'JournalEntryTemplete': {
    path: 'Accounting.Master_Data.Journal_Entry_Template',
    description: 'Recurring journal entry templates'
  },
  'JournalEntry': {
    path: 'Accounting.Transaction.Journal_Entry',
    description: 'General journal entry transactions'
  },
  'OpeningBalanceJournalEntry': {
    path: 'Accounting.Transaction.Opening_Balance_Journal_Entry',
    description: 'Opening balance journal entries'
  },
  
  // Accounting Reports
  'AccountingReports': {
    path: 'Accounting.Reports.Accounting_Reports',
    description: 'Comprehensive accounting reports'
  },
  'TrialBalance': {
    path: 'Accounting.Reports.Trial_Balance',
    description: 'Trial balance reports with variants'
  },
  'BalanceSheet': {
    path: 'Accounting.Reports.Balance_Sheet',
    description: 'Balance sheet financial statements'
  },
  'IncomeStatement': {
    path: 'Accounting.Reports.Income_Statement',
    description: 'Income statement reports'
  },
  'CostCenterReports': {
    path: 'Accounting.Reports.Cost_Center_Reports',
    description: 'Cost center analysis reports'
  },
  
  // === FINANCE ===
  'FinanceGeneralSettings': {
    path: 'Finance.Master_Data.Finance_General_Settings',
    description: 'Finance module configuration'
  },
  'PaymentMethod': {
    path: 'Finance.Master_Data.Payment_Method',
    description: 'Payment method configuration'
  },
  'CurrencyConversion': {
    path: 'Finance.Master_Data.Currency_Conversion',
    description: 'Currency exchange rate management'
  },
  'PaymentIn': {
    path: 'Finance.Transaction.Payment_In',
    description: 'Customer payment receipts'
  },
  'PaymentOut': {
    path: 'Finance.Transaction.Payment_Out',
    description: 'Vendor payment disbursements'
  },
  'FundTransfer': {
    path: 'Finance.Transaction.Fund_Transfer',
    description: 'Inter-account fund transfers'
  },
  'SIPaymentReconciliation': {
    path: 'Finance.Transaction.SI_Payment_Reconciliation',
    description: 'Sales invoice payment reconciliation'
  },
  'FinanceReports': {
    path: 'Finance.Reports.Finance_Reports',
    description: 'Treasury and bank account statements'
  },
  
  // === SALES ===
  'SalesGeneralSettings': {
    path: 'Sales.Master_Data.Sales_General_Settings',
    description: 'Sales module configuration'
  },
  'SalesArea': {
    path: 'Sales.Master_Data.Sales_Area',
    description: 'Sales territory management'
  },
  'PricePolicy': {
    path: 'Sales.Master_Data.Price_Policy',
    description: 'Customer pricing policies'
  },
  'SalesProject': {
    path: 'Sales.Master_Data.Sales_Project',
    description: 'Project-based sales management'
  },
  'DiscountPolicy': {
    path: 'Sales.Master_Data.Discount_Policy',
    description: 'Customer discount policies'
  },
  'SalesTeam': {
    path: 'Sales.Master_Data.Sales_Team',
    description: 'Sales team management'
  },
  'SalesMan': {
    path: 'Sales.Master_Data.Sales_Man',
    description: 'Sales representative management'
  },
  'SalesInvoice': {
    path: 'Sales.Transaction.Sales_Invoice',
    description: 'Customer sales invoicing'
  },
  'ReturnSalesInvoice': {
    path: 'Sales.Transaction.Return_Sales_Invoice',
    description: 'Sales return processing'
  },
  'SalesManVisit': {
    path: 'Sales.Transaction.SalesMan_Visit',
    description: 'Sales representative visit management'
  },
  'SalesOrder': {
    path: 'Sales.Transaction.Sales_Order',
    description: 'Customer sales order management'
  },
  'SalesProjectInvoice': {
    path: 'Sales.Transaction.Sales_Project_Invoice',
    description: 'Project-based invoicing'
  },
  'CustomerOpeningBalance': {
    path: 'Sales.Transaction.Customer_Opening_Balance',
    description: 'Customer opening balance entry'
  },
  'POSSession': {
    path: 'Sales.Transaction.POS_Session',
    description: 'Point of sale session management'
  },
  'VanSales': {
    path: 'Sales.Transaction.Van_Sales',
    description: 'Mobile van sales operations'
  },
  'CustomerReports': {
    path: 'Sales.Reports.Customer_Reports',
    description: 'Customer statements and analysis'
  },
  'DashBoard': {
    path: 'Sales.Reports.Dashboard',
    description: 'Sales dashboard and KPIs'
  },
  
  // === PURCHASE ===
  'PurchaseTax': {
    path: 'Purchase.Master_Data.Purchase_Tax',
    description: 'Purchase tax configuration'
  },
  'VendorCategory': {
    path: 'Purchase.Master_Data.Vendor_Category',
    description: 'Vendor classification'
  },
  'PurchaseOrder': {
    path: 'Purchase.Transaction.Purchase_Order',
    description: 'Vendor purchase order management'
  },
  'ReturnInvoice': {
    path: 'Purchase.Transaction.Return_Invoice',
    description: 'Purchase return processing'
  },
  'VendorOpeningBalance': {
    path: 'Purchase.Transaction.Vendor_Opening_Balance',
    description: 'Vendor opening balance entry'
  },
  'VendorReports': {
    path: 'Purchase.Reports.Vendor_Reports',
    description: 'Vendor statements and analysis'
  },
  
  // === INVENTORY ===
  'Item': {
    path: 'Inventory.Master_Data.Item_Definition',
    description: 'Complete item master data'
  },
  'ReorderRules': {
    path: 'Inventory.Master_Data.Reorder_Rules',
    description: 'Inventory reorder point management'
  },
  'AttributeDefinition': {
    path: 'Inventory.Master_Data.Attribute_Definition',
    description: 'Item attribute definitions'
  },
  'ItemCategory': {
    path: 'Inventory.Master_Data.Item_Category',
    description: 'Item category hierarchy'
  },
  'UOM': {
    path: 'Inventory.Master_Data.UOM',
    description: 'Unit of measure management'
  },
  'Warehouse': {
    path: 'Inventory.Master_Data.Warehouse',
    description: 'Warehouse definition and accounts'
  },
  'StockIn': {
    path: 'Inventory.Transaction.Stock_In',
    description: 'Inventory receipt transactions'
  },
  'StockOut': {
    path: 'Inventory.Transaction.Stock_Out',
    description: 'Inventory issue transactions'
  },
  'StockTransfer': {
    path: 'Inventory.Transaction.Stock_Transfer',
    description: 'Inter-warehouse stock transfers'
  },
  'InventoryCount': {
    path: 'Inventory.Transaction.Inventory_Count',
    description: 'Physical inventory count'
  },
  'InventoryOpeningBalance': {
    path: 'Inventory.Transaction.Inventory_Opening_Balance',
    description: 'Inventory opening balance entry'
  },
  'ItemReports': {
    path: 'Inventory.Reports.Item_Reports',
    description: 'Item card and inventory reports'
  },
  
  // === DISTRIBUTION ===
  'Device': {
    path: 'Distribution.Master_Data.Device_Management',
    description: 'Mobile device management'
  },
  'MarketPlace': {
    path: 'Distribution.Master_Data.Market_Place',
    description: 'Marketplace configuration'
  },
  'TransferRequest': {
    path: 'Distribution.Transaction.Transfer_Request',
    description: 'Stock transfer request processing'
  },
  
  // === HUMAN RESOURCES ===
  'Employee': {
    path: 'Human_Resources.Master_Data.Employee',
    description: 'Employee master data management'
  },
  
  // === FIXED ASSETS ===
  'FixedAssetsGeneralSettings': {
    path: 'Fixed_Assets.Master_Data.Fixed_Assets_General_Settings',
    description: 'Fixed assets module configuration'
  },
  'FixedAssetsGroup': {
    path: 'Fixed_Assets.Master_Data.Fixed_Assets_Groups',
    description: 'Asset group classification'
  },
  'Assets': {
    path: 'Fixed_Assets.Master_Data.Assets',
    description: 'Fixed asset master data'
  },
  'AssetsLocation': {
    path: 'Fixed_Assets.Master_Data.Assets_Location',
    description: 'Asset location management'
  },
  'AssetsOpeningBalance': {
    path: 'Fixed_Assets.Transaction.Assets_Opening_Balance',
    description: 'Asset opening balance entry'
  },
  'AssetsPurchaseInvoice': {
    path: 'Fixed_Assets.Transaction.Assets_Purchase_Invoice',
    description: 'Asset purchase invoicing'
  },
  'AssetsReturnPurchaseInvoice': {
    path: 'Fixed_Assets.Transaction.Assets_Return_Purchase_Invoice',
    description: 'Asset purchase return processing'
  },
  'AssetsSalesInvoice': {
    path: 'Fixed_Assets.Transaction.Assets_Sales_Invoice',
    description: 'Asset disposal invoicing'
  },
  'AssetsReturnSalesInvoice': {
    path: 'Fixed_Assets.Transaction.Assets_Return_Sales_Invoice',
    description: 'Asset sales return processing'
  },
  'AssetsDepreciation': {
    path: 'Fixed_Assets.Transaction.Assets_Depreciation',
    description: 'Asset depreciation calculation and posting'
  },
  'AssetsDepreciationReport': {
    path: 'Fixed_Assets.Reports.Assets_Depreciation_Report',
    description: 'Depreciation analysis reports'
  },
  
  // === SPECIAL MODULES ===
  'ZatcaDevice': {
    path: 'General_Settings.Administration.Zatca_Device',
    description: 'Saudi ZATCA e-invoicing device management'
  }
};

// Process enhanced schema
console.log('\n🔄 Processing enhanced schema modules...\n');

let stats = {
  added: 0,
  updated: 0,
  skipped: 0,
  mapped: 0,
  unmapped: []
};

Object.entries(enhanced).forEach(([moduleName, moduleData]) => {
  const mapping = businessMapping[moduleName];
  
  if (!mapping) {
    console.log(`⚠️  Unmapped module: ${moduleName}`);
    stats.unmapped.push(moduleName);
    stats.skipped++;
    return;
  }
  
  console.log(`📦 Processing: ${moduleName} → ${mapping.path}`);
  
  // Navigate to target path
  const pathParts = mapping.path.split('.');
  let current = complete;
  
  // Create nested structure if needed
  for (let i = 0; i < pathParts.length - 1; i++) {
    if (!current[pathParts[i]]) {
      current[pathParts[i]] = {};
    }
    current = current[pathParts[i]];
  }
  
  const targetKey = pathParts[pathParts.length - 1];
  
  // Initialize target if needed
  if (!current[targetKey]) {
    current[targetKey] = {};
  }
  
  // Merge operations
  const result = mergeOperations(current[targetKey], moduleData, moduleName);
  stats.added += result.added;
  stats.updated += result.updated;
  stats.mapped++;
});

// Handle unmapped modules by intelligent placement
console.log('\n🤖 Handling unmapped modules with intelligent placement...');
stats.unmapped.forEach(moduleName => {
  const moduleData = enhanced[moduleName];
  const placement = intelligentPlacement(moduleName, moduleData);
  
  if (placement) {
    console.log(`🎯 Auto-placed: ${moduleName} → ${placement}`);
    setNestedValue(complete, placement, moduleData);
    stats.added += countOperations(moduleData);
  }
});

// Save complete schema
console.log('\n💾 Saving complete schema...');
fs.writeFileSync(CONFIG.outputSchema, JSON.stringify(complete, null, 2));

// Generate comprehensive report
const report = {
  timestamp: new Date().toISOString(),
  source: {
    enhanced: CONFIG.enhancedSchema,
    standardized: CONFIG.standardizedSchema
  },
  output: CONFIG.outputSchema,
  statistics: {
    ...stats,
    totalModulesInComplete: countNestedModules(complete),
    coveragePercentage: ((stats.mapped / Object.keys(enhanced).length) * 100).toFixed(1)
  },
  businessMapping,
  unmappedModules: stats.unmapped
};

fs.writeFileSync(CONFIG.mappingReport, JSON.stringify(report, null, 2));

// Display results
console.log('\n' + '='.repeat(80));
console.log('✅ Advanced Schema Merger Complete!\n');
console.log('📊 Final Statistics:');
console.log(`   Operations added: ${stats.added}`);
console.log(`   Operations updated: ${stats.updated}`);
console.log(`   Modules mapped: ${stats.mapped}`);
console.log(`   Modules skipped: ${stats.skipped}`);
console.log(`   Coverage: ${report.statistics.coveragePercentage}%`);
console.log(`   Total modules in complete schema: ${report.statistics.totalModulesInComplete}`);

if (stats.unmapped.length > 0) {
  console.log(`\n⚠️  Unmapped modules: ${stats.unmapped.join(', ')}`);
}

console.log(`\n📁 Files generated:`);
console.log(`   Complete schema: ${CONFIG.outputSchema}`);
console.log(`   Mapping report: ${CONFIG.mappingReport}`);

console.log('\n🚀 Next steps:');
console.log('   1. Review the complete schema');
console.log('   2. Update test configuration to use new schema');
console.log('   3. Run comprehensive tests');

// Helper functions
function countNestedModules(obj, depth = 0) {
  if (depth > 10) return 0;
  let count = 0;
  
  Object.values(obj).forEach(value => {
    if (value && typeof value === 'object') {
      if (hasOperations(value)) {
        count++;
      } else {
        count += countNestedModules(value, depth + 1);
      }
    }
  });
  
  return count;
}

function hasOperations(obj) {
  const ops = ['Post', 'PUT', 'DELETE', 'View', 'EDIT', 'GET', 'LookUP'];
  return ops.some(op => obj[op] && Array.isArray(obj[op]));
}

function initializeMissingSections(schema) {
  const modules = ['General_Settings', 'Accounting', 'Finance', 'Sales', 'Purchase', 'Inventory', 'Distribution', 'Human_Resources', 'Fixed_Assets'];
  const sections = ['Master_Data', 'Transaction', 'Reports'];
  
  modules.forEach(module => {
    if (!schema[module]) schema[module] = {};
    sections.forEach(section => {
      if (!schema[module][section]) schema[module][section] = {};
    });
  });
}

function mergeOperations(target, source, moduleName) {
  let added = 0, updated = 0;
  
  Object.entries(source).forEach(([key, value]) => {
    if (Array.isArray(value) && value.length >= 1) {
      // This is an operation
      if (!target[key]) {
        target[key] = value;
        added++;
        console.log(`    ✅ Added operation: ${key}`);
      } else {
        // Update existing operation
        target[key] = value;
        updated++;
        console.log(`    🔄 Updated operation: ${key}`);
      }
    } else if (typeof value === 'object' && value !== null) {
      // Nested operations
      if (!target[key]) target[key] = {};
      const result = mergeOperations(target[key], value, moduleName);
      added += result.added;
      updated += result.updated;
    }
  });
  
  return { added, updated };
}

function intelligentPlacement(moduleName, moduleData) {
  // Intelligent placement based on module name patterns
  const name = moduleName.toLowerCase();
  
  if (name.includes('report') || name.includes('dashboard')) {
    return 'General_Settings.Reports.' + moduleName;
  }
  if (name.includes('setting') || name.includes('config')) {
    return 'General_Settings.Master_Data.' + moduleName;
  }
  if (name.includes('user') || name.includes('role') || name.includes('auth')) {
    return 'General_Settings.Administration.' + moduleName;
  }
  if (name.includes('account') || name.includes('journal')) {
    return 'Accounting.Master_Data.' + moduleName;
  }
  if (name.includes('payment') || name.includes('bank') || name.includes('treasury')) {
    return 'Finance.Master_Data.' + moduleName;
  }
  if (name.includes('sales') || name.includes('customer') || name.includes('invoice')) {
    return 'Sales.Master_Data.' + moduleName;
  }
  if (name.includes('purchase') || name.includes('vendor')) {
    return 'Purchase.Master_Data.' + moduleName;
  }
  if (name.includes('inventory') || name.includes('item') || name.includes('stock')) {
    return 'Inventory.Master_Data.' + moduleName;
  }
  if (name.includes('asset')) {
    return 'Fixed_Assets.Master_Data.' + moduleName;
  }
  
  // Default to General Settings
  return 'General_Settings.Master_Data.' + moduleName;
}

function setNestedValue(obj, path, value) {
  const parts = path.split('.');
  let current = obj;
  
  for (let i = 0; i < parts.length - 1; i++) {
    if (!current[parts[i]]) current[parts[i]] = {};
    current = current[parts[i]];
  }
  
  current[parts[parts.length - 1]] = value;
}

function countOperations(obj) {
  let count = 0;
  Object.values(obj).forEach(value => {
    if (Array.isArray(value)) count++;
    else if (typeof value === 'object' && value !== null) {
      count += countOperations(value);
    }
  });
  return count;
}
