// check-empty-urls.js - Find modules with empty URL strings
const fs = require('fs');
const path = require('path');

const schemaPath = path.join(__dirname, 'test-data', 'Input', 'Main-Standarized-Backend-Api-Schema.json');

console.log('\n🔍 Checking for Empty URLs in Schema\n');
console.log('='.repeat(70));

try {
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  
  let totalModules = 0;
  let modulesWithEmptyUrls = [];
  let totalEmptyUrls = 0;
  
  function checkModule(obj, path = []) {
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = [...path, key];
      
      if (value && typeof value === 'object') {
        // Check if this is a module with operations
        const operations = ['Post', 'PUT', 'DELETE', 'View', 'Get', 'EDIT', 'Lookup', 'CREATE'];
        const hasOperations = operations.some(op => value[op]);
        
        if (hasOperations) {
          totalModules++;
          const modulePath = currentPath.join('.');
          let emptyUrlsInModule = [];
          
          // Check each operation
          for (const op of operations) {
            if (value[op] && Array.isArray(value[op])) {
              const url = value[op][0];
              if (url === '' || (typeof url === 'string' && url.trim() === '')) {
                emptyUrlsInModule.push(op);
                totalEmptyUrls++;
              }
            }
          }
          
          if (emptyUrlsInModule.length > 0) {
            modulesWithEmptyUrls.push({
              module: modulePath,
              emptyOperations: emptyUrlsInModule
            });
          }
        }
        
        // Recurse deeper
        checkModule(value, currentPath);
      }
    }
  }
  
  checkModule(schema);
  
  console.log(`\n📊 Summary:`);
  console.log(`   Total Modules: ${totalModules}`);
  console.log(`   Modules with Empty URLs: ${modulesWithEmptyUrls.length}`);
  console.log(`   Total Empty URLs: ${totalEmptyUrls}`);
  
  if (modulesWithEmptyUrls.length > 0) {
    console.log(`\n❌ Modules with Empty URLs:\n`);
    modulesWithEmptyUrls.forEach((item, index) => {
      console.log(`${index + 1}. ${item.module}`);
      console.log(`   Empty operations: ${item.emptyOperations.join(', ')}`);
    });
  } else {
    console.log(`\n✅ No modules with empty URLs found!`);
  }
  
  console.log('\n' + '='.repeat(70) + '\n');
  
} catch (error) {
  console.error('❌ Error:', error.message);
  process.exit(1);
}
