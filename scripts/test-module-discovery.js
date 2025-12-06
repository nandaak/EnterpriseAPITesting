#!/usr/bin/env node
/**
 * Test Module Discovery
 * Simulate what the test does to find modules
 */

const modulesConfig = require('../config/modules-config');

console.log('🔍 Testing Module Discovery Logic\n');
console.log('='.repeat(70));

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

let discoveredModules = [];

const runCompleteCRUDLifecycleOnAllModules = (modules, parentPath = '') => {
  Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
    if (typeof moduleConfig !== 'object' || moduleConfig === null) return;

    const moduleHasEndpoints = hasEndpoints(moduleConfig);

    if (moduleHasEndpoints) {
      const fullModuleName = parentPath ? `${parentPath}.${moduleName}` : moduleName;
      
      if (!fullModuleName.includes('Reports')) {
        discoveredModules.push(fullModuleName);
        console.log(`✅ Discovered: ${fullModuleName}`);
      } else {
        console.log(`⏸️  Skipped (Reports): ${fullModuleName}`);
      }
    }

    // Recursively test nested modules
    if (typeof moduleConfig === 'object' && !hasEndpoints(moduleConfig)) {
      runCompleteCRUDLifecycleOnAllModules(
        moduleConfig,
        parentPath ? `${parentPath}.${moduleName}` : moduleName
      );
    }
  });
};

console.log('\n📋 Starting module discovery...\n');

// Run discovery
runCompleteCRUDLifecycleOnAllModules(modulesConfig.schema || modulesConfig);

console.log('\n' + '='.repeat(70));
console.log(`\n📊 Summary:`);
console.log(`   Total modules discovered: ${discoveredModules.length}`);
console.log(`   Non-report modules: ${discoveredModules.filter(m => !m.includes('Reports')).length}`);

if (discoveredModules.length === 0) {
  console.log('\n❌ NO MODULES DISCOVERED!');
  console.log('   This explains why the test has no tests.');
} else {
  console.log('\n✅ Modules discovered - test should generate tests');
  console.log('\nFirst 10 modules:');
  discoveredModules.slice(0, 10).forEach((m, i) => {
    console.log(`   ${i + 1}. ${m}`);
  });
}
