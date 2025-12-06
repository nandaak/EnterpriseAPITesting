const fs = require('fs');
const path = require('path');

// Valid keys according to the requirements
const VALID_KEYS = ['CREATE', 'EDIT', 'DELETE', 'View', 'LookUP', 'EXPORT', 'PRINT'];

// HTTP method variations to detect
const HTTP_METHODS = {
  POST: ['POST', 'Post', 'post'],
  PUT: ['PUT', 'Put', 'put'],
  GET: ['GET', 'Get', 'get'],
  DELETE: ['DELETE', 'Delete', 'delete']
};

// Function to normalize method name
function normalizeMethod(key) {
  for (const [standard, variations] of Object.entries(HTTP_METHODS)) {
    if (variations.includes(key)) {
      return standard;
    }
  }
  return key;
}

// Function to determine the correct key based on API context
function determineCorrectKey(apiPath, method, payload, params, currentKey) {
  const urlLower = apiPath.toLowerCase();
  const hasId = /<createdId>/.test(apiPath) || /\{id\}/i.test(apiPath) || /\/\d+/.test(apiPath) || /__id_/i.test(apiPath);
  
  // Normalize the method
  const normalizedMethod = normalizeMethod(method);
  
  // Rule 1: CREATE - POST method with payload for adding new resource
  if (normalizedMethod === 'POST' && !urlLower.includes('/post') && !urlLower.includes('/unpost')) {
    return 'CREATE';
  }
  
  // Rule 2: EDIT - PUT method with payload for editing existing resource
  if (normalizedMethod === 'PUT') {
    return 'EDIT';
  }
  
  // Rule 3: DELETE - DELETE method
  if (normalizedMethod === 'DELETE') {
    return 'DELETE';
  }
  
  // For GET methods, we need more context
  if (normalizedMethod === 'GET') {
    // Rule 7: EXPORT - GET with "export" in URL
    if (urlLower.includes('export')) {
      return 'EXPORT';
    }
    
    // Rule 8: PRINT - GET with "print" in URL
    if (urlLower.includes('print')) {
      return 'PRINT';
    }
    
    // Rule 4: View - GET with ID in URL or params
    if (hasId || (params && Array.isArray(params) && params.some(p => /^id$/i.test(p)))) {
      return 'View';
    }
    
    // Rule 5: EDIT - GET for loading resource for edit screens (GetById, GetByIdView, etc.)
    if (urlLower.includes('getbyid') || urlLower.includes('getforupdate') || 
        urlLower.includes('getedit') || urlLower.includes('getview')) {
      return 'EDIT';
    }
    
    // Rule 6: LookUP - GET for dropdowns, filters, multiselect
    if (urlLower.includes('dropdown') || urlLower.includes('lookup') || 
        urlLower.includes('filter') || urlLower.includes('search') ||
        urlLower.includes('getall') || urlLower.includes('list')) {
      return 'LookUP';
    }
    
    // Default for GET with pagination or search params
    if (params && Array.isArray(params) && params.some(p => /page|search|filter/i.test(p))) {
      return 'LookUP';
    }
  }
  
  // Special case: POST with /Post or /Unpost in URL (posting/unposting documents)
  if (normalizedMethod === 'POST' && (urlLower.includes('/post') || urlLower.includes('/unpost'))) {
    return 'CREATE'; // These are actions, treat as CREATE
  }
  
  // If current key is valid, keep it
  if (VALID_KEYS.includes(currentKey)) {
    return currentKey;
  }
  
  // Default fallback based on method
  if (normalizedMethod === 'GET') return 'LookUP';
  if (normalizedMethod === 'POST') return 'CREATE';
  if (normalizedMethod === 'PUT') return 'EDIT';
  if (normalizedMethod === 'DELETE') return 'DELETE';
  
  return currentKey;
}

// Function to recursively process nested schema structure
function processNestedSchema(obj, path = []) {
  let changes = [];
  
  if (!obj || typeof obj !== 'object') {
    return changes;
  }
  
  // Check if this object contains endpoint definitions
  const keys = Object.keys(obj);
  const hasHttpMethods = keys.some(k => {
    const normalized = normalizeMethod(k);
    return ['POST', 'PUT', 'GET', 'DELETE'].includes(normalized);
  });
  
  if (hasHttpMethods && Array.isArray(obj[keys[0]])) {
    // This is an endpoint definition
    for (const currentKey of keys) {
      const normalized = normalizeMethod(currentKey);
      if (['POST', 'PUT', 'GET', 'DELETE'].includes(normalized) && Array.isArray(obj[currentKey])) {
        const [apiPath, payload] = obj[currentKey];
        const params = obj.parameters || [];
        
        // Determine the correct key
        const correctKey = determineCorrectKey(apiPath, currentKey, payload, params, currentKey);
        
        // If the key needs to be changed
        if (correctKey !== currentKey) {
          changes.push({
            path: path.join('.'),
            oldKey: currentKey,
            newKey: correctKey,
            apiPath: apiPath,
            method: normalized
          });
          
          // Replace the key
          obj[correctKey] = obj[currentKey];
          delete obj[currentKey];
        }
      }
    }
  } else {
    // Recurse into nested objects
    for (const [key, value] of Object.entries(obj)) {
      if (value && typeof value === 'object') {
        const nestedChanges = processNestedSchema(value, [...path, key]);
        changes = changes.concat(nestedChanges);
      }
    }
  }
  
  return changes;
}

// Function to process a single schema file
function processSchemaFile(filePath) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Processing: ${path.basename(filePath)}`);
  console.log('='.repeat(80));
  
  try {
    const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const changes = processNestedSchema(schema);
    
    // Save the fixed schema
    fs.writeFileSync(filePath, JSON.stringify(schema, null, 2), 'utf8');
    
    if (changes.length > 0) {
      console.log(`\n✅ Changes made:`);
      changes.forEach(change => {
        console.log(`  ✓ ${change.path}: ${change.oldKey} → ${change.newKey}`);
      });
    }
    
    console.log(`\n✅ Completed: ${changes.length} changes made`);
    
    return {
      fileName: path.basename(filePath),
      changesCount: changes.length,
      changes: changes,
      success: true
    };
    
  } catch (error) {
    console.error(`\n❌ Error processing ${path.basename(filePath)}: ${error.message}`);
    return {
      fileName: path.basename(filePath),
      changesCount: 0,
      changes: [],
      success: false,
      error: error.message
    };
  }
}

// Main execution
function main() {
  const inputDir = path.join(__dirname, 'test-data', 'Input');
  const files = fs.readdirSync(inputDir).filter(f => f.endsWith('.json'));
  
  console.log('\n' + '█'.repeat(80));
  console.log('  ENHANCED SCHEMA REFACTORING TOOL');
  console.log('  Applying Professional Key Standardization Rules');
  console.log('  (Handles nested structures and method variations)');
  console.log('█'.repeat(80));
  console.log(`\nFound ${files.length} schema files to process\n`);
  
  const results = [];
  let totalChanges = 0;
  
  for (const file of files) {
    const filePath = path.join(inputDir, file);
    const result = processSchemaFile(filePath);
    results.push(result);
    totalChanges += result.changesCount;
  }
  
  // Generate comprehensive report
  console.log('\n' + '█'.repeat(80));
  console.log('  REFACTORING SUMMARY');
  console.log('█'.repeat(80));
  
  const successCount = results.filter(r => r.success).length;
  const failureCount = results.filter(r => !r.success).length;
  
  console.log(`\n📊 Overall Statistics:`);
  console.log(`   Total Files Processed: ${files.length}`);
  console.log(`   ✅ Successful: ${successCount}`);
  console.log(`   ❌ Failed: ${failureCount}`);
  console.log(`   📝 Total Changes: ${totalChanges}`);
  
  console.log(`\n📋 File-by-File Breakdown:`);
  results.forEach(result => {
    const status = result.success ? '✅' : '❌';
    console.log(`   ${status} ${result.fileName}: ${result.changesCount} changes`);
  });
  
  // Save comprehensive report
  const reportPath = path.join(__dirname, 'schema-refactoring-final-report.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    totalFiles: files.length,
    successCount,
    failureCount,
    totalChanges,
    results,
    rules: {
      CREATE: 'POST method for adding new resources',
      EDIT: 'PUT method for updating existing resources',
      DELETE: 'DELETE method',
      View: 'GET method with ID for viewing specific resource',
      LookUP: 'GET method for dropdowns, filters, lists',
      EXPORT: 'GET method with "export" in URL',
      PRINT: 'GET method with "print" in URL'
    }
  }, null, 2), 'utf8');
  
  console.log(`\n📄 Detailed report saved to: schema-refactoring-final-report.json`);
  
  console.log('\n' + '█'.repeat(80));
  console.log('  ✨ REFACTORING COMPLETE ✨');
  console.log('█'.repeat(80) + '\n');
}

main();
