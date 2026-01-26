// find-url-here.js - Find URL_HERE and empty strings in schema
const fs = require('fs');
const path = require('path');

const schemaPath = path.join(__dirname, 'test-data', 'Input', 'Main-Standarized-Backend-Api-Schema.json');

console.log('\n🔍 Finding URL_HERE and Empty URLs in Schema\n');
console.log('='.repeat(70));

try {
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  
  let totalFound = 0;
  const findings = [];
  
  function checkModule(obj, path = []) {
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = [...path, key];
      
      if (value && typeof value === 'object') {
        // Check if this is a module with operations
        const operations = ['Post', 'PUT', 'DELETE', 'View', 'Get', 'EDIT', 'Lookup', 'CREATE'];
        
        for (const op of operations) {
          if (value[op] && Array.isArray(value[op])) {
            const url = value[op][0];
            if (url === '' || url === 'URL_HERE') {
              totalFound++;
              findings.push({
                module: currentPath.join('.'),
                operation: op,
                value: url === '' ? '(empty string)' : 'URL_HERE'
              });
            }
          }
        }
        
        // Recurse deeper
        checkModule(value, currentPath);
      }
    }
  }
  
  checkModule(schema);
  
  console.log(`\n📊 Summary:`);
  console.log(`   Total URL_HERE or empty strings found: ${totalFound}`);
  
  if (totalFound > 0) {
    console.log(`\n❌ Found ${totalFound} problematic URLs:\n`);
    findings.forEach((item, index) => {
      console.log(`${index + 1}. ${item.module}.${item.operation} = ${item.value}`);
    });
  } else {
    console.log(`\n✅ No URL_HERE or empty strings found!`);
  }
  
  console.log('\n' + '='.repeat(70) + '\n');
  
} catch (error) {
  console.error('❌ Error:', error.message);
  process.exit(1);
}
