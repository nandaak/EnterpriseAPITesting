#!/usr/bin/env node
/**
 * Advanced Payload Fixer
 * Analyzes 400/500 errors and creates better payloads
 */

const fs = require('fs');

console.log('🔧 Advanced Payload Fixer\n');
console.log('='.repeat(70));

// Load the enhanced schema
const schemaPath = 'test-data/Input/Enhanced-ERP-Api-Schema-With-Payloads.json';
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

console.log(`\n📖 Loaded schema: ${Object.keys(schema).length} modules`);

// Common payload patterns that work
const workingPatterns = {
  // Modules that need minimal data
  minimal: {
    pattern: {
      name: 'Test Item',
      nameAr: 'عنصر تجريبي'
    },
    modules: ['Tag', 'Currency', 'Tax']
  },
  
  // Modules that need code
  withCode: {
    pattern: {
      code: 'TEST001',
      name: 'Test Item',
      nameAr: 'عنصر تجريبي'
    },
    modules: ['Bank', 'Treasury', 'Customer', 'Vendor']
  },
  
  // Modules that need IDs
  withIds: {
    pattern: {
      name: 'Test Item',
      nameAr: 'عنصر تجريبي',
      currencyId: 1,
      companyId: 1
    },
    modules: ['ChartOfAccounts', 'CostCenter']
  },
  
  // Complex modules
  complex: {
    pattern: {
      code: 'TEST001',
      name: 'Test Item',
      nameAr: 'عنصر تجريبي',
      date: new Date().toISOString().split('T')[0],
      currencyId: 1,
      items: [],
      details: []
    },
    modules: ['Invoice', 'SalesOrder', 'PurchaseOrder']
  }
};

// Analyze and fix payloads
let fixedCount = 0;
let enhancedCount = 0;

Object.keys(schema).forEach(moduleName => {
  const module = schema[moduleName];
  
  Object.keys(module).forEach(operationName => {
    const operation = module[operationName];
    
    if (operation.POST) {
      const [url, payload] = operation.POST;
      
      // Check if payload needs enhancement
      if (!payload || Object.keys(payload).length === 0) {
        // Empty payload - add basic pattern
        const basicPayload = {
          name: `Test ${moduleName}`,
          nameAr: `${moduleName} تجريبي`
        };
        
        operation.POST = [url, basicPayload];
        fixedCount++;
        
      } else if (Object.keys(payload).length < 3) {
        // Minimal payload - enhance it
        const enhanced = { ...payload };
        
        // Add missing common fields
        if (!enhanced.name && !enhanced.code) {
          enhanced.name = `Test ${moduleName}`;
        }
        
        if (enhanced.name && !enhanced.nameAr) {
          enhanced.nameAr = `${enhanced.name} عربي`;
        }
        
        // Initialize arrays
        Object.keys(enhanced).forEach(key => {
          if (key.toLowerCase().includes('ids') || 
              key.toLowerCase().includes('items') ||
              key.toLowerCase().includes('details')) {
            if (!Array.isArray(enhanced[key])) {
              enhanced[key] = [];
            }
          }
        });
        
        operation.POST = [url, enhanced];
        enhancedCount++;
      }
    }
    
    // Same for PUT
    if (operation.PUT) {
      const [url, payload] = operation.PUT;
      
      if (!payload || Object.keys(payload).length === 0) {
        const basicPayload = {
          name: `Updated ${moduleName}`,
          nameAr: `${moduleName} محدث`
        };
        
        operation.PUT = [url, basicPayload];
        fixedCount++;
      }
    }
  });
});

// Save enhanced schema
const outputPath = 'test-data/Input/Enhanced-ERP-Api-Schema-Advanced-Fixed.json';
fs.writeFileSync(outputPath, JSON.stringify(schema, null, 2));

console.log(`\n✅ Payload Enhancement Complete:`);
console.log(`   Fixed empty payloads: ${fixedCount}`);
console.log(`   Enhanced minimal payloads: ${enhancedCount}`);
console.log(`   Total improvements: ${fixedCount + enhancedCount}`);
console.log(`\n📁 Saved: ${outputPath}`);

// Generate module-specific payload recommendations
const recommendations = {
  timestamp: new Date().toISOString(),
  improvements: fixedCount + enhancedCount,
  recommendations: [
    {
      category: 'High Priority',
      modules: ['Currency', 'Tax', 'Bank', 'Treasury'],
      suggestion: 'These modules need basic name/code fields'
    },
    {
      category: 'Medium Priority',
      modules: ['Customer', 'Vendor', 'ChartOfAccounts'],
      suggestion: 'These modules need additional ID references'
    },
    {
      category: 'Complex',
      modules: ['Invoice', 'SalesOrder', 'JournalEntry'],
      suggestion: 'These modules need detailed line items and dates'
    }
  ]
};

fs.writeFileSync('payload-recommendations.json', JSON.stringify(recommendations, null, 2));
console.log(`\n📋 Recommendations saved: payload-recommendations.json`);

console.log('\n🚀 Next Steps:');
console.log('   1. Update schema adapter to use advanced-fixed schema');
console.log('   2. Re-run tests');
console.log('   3. Analyze remaining failures');
