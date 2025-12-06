#!/usr/bin/env node
/**
 * Diagnose Test Issue
 * Check why CRUD test has no tests
 */

const modulesConfig = require('../config/modules-config');

console.log('🔍 Diagnosing Test Issue\n');
console.log('='.repeat(70));

// Check if schema exists
console.log('\n1. Schema Status:');
console.log(`   Schema exists: ${!!modulesConfig.schema}`);
console.log(`   Schema type: ${typeof modulesConfig.schema}`);

if (modulesConfig.schema) {
  console.log(`   Schema keys: ${Object.keys(modulesConfig.schema).length}`);
  console.log(`   Top-level keys: ${Object.keys(modulesConfig.schema).slice(0, 5).join(', ')}`);
}

// Check modules
console.log('\n2. Modules Status:');
console.log(`   Modules exists: ${!!modulesConfig.modules}`);
console.log(`   Modules type: ${typeof modulesConfig.modules}`);

if (modulesConfig.modules) {
  console.log(`   Total modules: ${Object.keys(modulesConfig.modules).length}`);
  console.log(`   Sample modules: ${Object.keys(modulesConfig.modules).slice(0, 5).join(', ')}`);
}

// Check for testable modules
console.log('\n3. Testable Modules Check:');

const hasEndpoints = (moduleConfig) => {
  if (!moduleConfig || typeof moduleConfig !== 'object') return false;
  const endpointTypes = ['Post', 'PUT', 'DELETE', 'View', 'EDIT', 'LookUP', 'Commit', 'GET'];
  return endpointTypes.some(operationType => 
    moduleConfig[operationType] && 
    Array.isArray(moduleConfig[operationType]) && 
    moduleConfig[operationType][0] && 
    moduleConfig[operationType][0] !== 'URL_HERE'
  );
};

const isValidUrl = (string) => {
  if (!string || string === 'URL_HERE') return false;
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
};

let testableCount = 0;
let nonTestableCount = 0;

const checkModules = (modules, path = '') => {
  Object.entries(modules).forEach(([key, value]) => {
    const currentPath = path ? `${path}.${key}` : key;
    
    if (typeof value === 'object' && value !== null) {
      if (hasEndpoints(value)) {
        testableCount++;
        console.log(`   ✅ Testable: ${currentPath}`);
        
        // Show available operations
        const ops = Object.keys(value).filter(k => 
          Array.isArray(value[k]) && value[k][0] && isValidUrl(value[k][0])
        );
        console.log(`      Operations: ${ops.join(', ')}`);
      } else {
        // Check if it has nested modules
        const hasNested = Object.values(value).some(v => typeof v === 'object' && v !== null);
        if (hasNested) {
          checkModules(value, currentPath);
        } else {
          nonTestableCount++;
        }
      }
    }
  });
};

if (modulesConfig.schema) {
  checkModules(modulesConfig.schema);
}

console.log('\n4. Summary:');
console.log(`   Testable modules: ${testableCount}`);
console.log(`   Non-testable: ${nonTestableCount}`);

if (testableCount === 0) {
  console.log('\n❌ ISSUE FOUND: No testable modules detected!');
  console.log('   Possible causes:');
  console.log('   1. Schema structure doesn\'t match expected format');
  console.log('   2. All URLs are invalid or "URL_HERE"');
  console.log('   3. Module operations are not in expected format');
} else {
  console.log('\n✅ Testable modules found - test should work');
}

console.log('\n' + '='.repeat(70));
