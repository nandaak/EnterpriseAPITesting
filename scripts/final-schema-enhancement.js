/**
 * Final Schema Enhancement - Replace all placeholder values with realistic data
 */

const fs = require('fs');
const path = require('path');

function generateRealisticValue(key, value, context = {}) {
  // Handle IDs - keep as-is if it's a placeholder
  if (key === 'id' || key === 'Id' || key === 'ID') {
    return value;
  }
  
  if (key.toLowerCase().endsWith('id') && typeof value === 'string' && value.includes('createdId')) {
    return value; // Keep <createdId> placeholders
  }

  // Handle strings
  if (value === 'string' || (typeof value === 'string' && value.trim() === 'string')) {
    const lowerKey = key.toLowerCase();
    
    if (lowerKey.includes('email')) {
      return `test${Math.floor(Math.random() * 10000)}@example.com`;
    }
    if (lowerKey.includes('phone') || lowerKey.includes('mobile') || lowerKey.includes('fax')) {
      return `+966${Math.floor(Math.random() * 1000000000)}`;
    }
    if (lowerKey.includes('code')) {
      return `CODE${Math.floor(Math.random() * 100000)}`;
    }
    if (lowerKey.includes('iban')) {
      return `SA${Math.floor(Math.random() * 1000000000000000000000)}`;
    }
    if (lowerKey.includes('account') && lowerKey.includes('number')) {
      return `ACC${Math.floor(Math.random() * 1000000000000)}`;
    }
    if (lowerKey.includes('reference') || lowerKey.includes('refrence')) {
      return `REF${Math.floor(Math.random() * 100000)}`;
    }
    if (lowerKey.includes('description') || lowerKey.includes('note')) {
      return `Test description ${Math.floor(Math.random() * 1000)}`;
    }
    if (lowerKey.includes('address')) {
      return `Test Address ${Math.floor(Math.random() * 1000)}, Riyadh, Saudi Arabia`;
    }
    if (key.includes('Ar') || key.includes('ar') || lowerKey.includes('arabic')) {
      return `اختبار ${Math.floor(Math.random() * 10000)}`;
    }
    if (lowerKey.includes('name')) {
      return `Test ${key} ${Math.floor(Math.random() * 10000)}`;
    }
    if (lowerKey.includes('url') || lowerKey.includes('link')) {
      return `https://example.com/test${Math.floor(Math.random() * 1000)}`;
    }
    
    // Default string
    return `Test${key}${Math.floor(Math.random() * 10000)}`;
  }

  // Handle numbers
  if (value === 1 || (typeof value === 'number' && value === 1)) {
    const lowerKey = key.toLowerCase();
    
    if (lowerKey.includes('percentage') || lowerKey.includes('percent') || lowerKey.includes('rate')) {
      return 15;
    }
    if (lowerKey.includes('amount') || lowerKey.includes('balance') || lowerKey.includes('price') || lowerKey.includes('cost')) {
      return 1000;
    }
    if (lowerKey.includes('quantity') || lowerKey.includes('qty')) {
      return 10;
    }
    if (lowerKey.includes('discount')) {
      return 5;
    }
    if (lowerKey.includes('tax') || lowerKey.includes('vat')) {
      return 15;
    }
    
    // Keep as 1 for IDs and other numeric fields
    return 1;
  }

  // Handle dates
  if (typeof value === 'string' && (value.includes('2025') || value.includes('T') && value.includes('Z'))) {
    return value; // Keep date strings as-is
  }

  // Handle booleans
  if (typeof value === 'boolean') {
    return value;
  }

  // Handle arrays
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return value; // Keep empty arrays
    }
    return value.map((item, index) => enhanceValue(item, `${key}[${index}]`));
  }

  // Handle objects
  if (typeof value === 'object' && value !== null) {
    return enhanceValue(value, key);
  }

  return value;
}

function enhanceValue(obj, parentKey = '') {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item, index) => enhanceValue(item, `${parentKey}[${index}]`));
  }

  const enhanced = {};
  for (const [key, value] of Object.entries(obj)) {
    enhanced[key] = generateRealisticValue(key, value, { parentKey });
  }
  return enhanced;
}

function enhanceModuleFile(modulePath) {
  const moduleData = JSON.parse(fs.readFileSync(modulePath, 'utf8'));
  const moduleName = path.basename(modulePath, '.json').replace('Module-', '');
  
  let updated = false;

  for (const moduleKey in moduleData) {
    const operations = moduleData[moduleKey];
    
    for (const opKey in operations) {
      const operation = operations[opKey];
      
      // Enhance POST payload
      if (operation.POST && operation.POST[1]) {
        const originalPayload = JSON.stringify(operation.POST[1]);
        operation.POST[1] = enhanceValue(operation.POST[1]);
        const newPayload = JSON.stringify(operation.POST[1]);
        
        if (originalPayload !== newPayload) {
          updated = true;
        }
      }

      // Enhance PUT payload
      if (operation.PUT && operation.PUT[1]) {
        const originalPayload = JSON.stringify(operation.PUT[1]);
        operation.PUT[1] = enhanceValue(operation.PUT[1]);
        const newPayload = JSON.stringify(operation.PUT[1]);
        
        if (originalPayload !== newPayload) {
          updated = true;
        }
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
console.log('🚀 Final Schema Enhancement - Replacing placeholder values\n');
console.log('='.repeat(70));

const modulesDir = path.join(__dirname, '../test-data/modules');
const moduleFiles = fs.readdirSync(modulesDir).filter(f => f.startsWith('Module-') && f.endsWith('.json'));

let successCount = 0;
let skippedCount = 0;

for (const file of moduleFiles) {
  const moduleName = file.replace('Module-', '').replace('.json', '');
  const modulePath = path.join(modulesDir, file);
  
  process.stdout.write(`📦 ${moduleName.padEnd(35)} `);
  
  if (enhanceModuleFile(modulePath)) {
    console.log('✅');
    successCount++;
  } else {
    console.log('⏭️  (no changes)');
    skippedCount++;
  }
}

console.log('\n' + '='.repeat(70));
console.log(`\n📊 Enhancement Summary:`);
console.log(`   ✅ Enhanced: ${successCount} modules`);
console.log(`   ⏭️  Skipped: ${skippedCount} modules`);
console.log(`   📁 Total: ${moduleFiles.length} modules`);
console.log(`\n${'='.repeat(70)}\n`);
