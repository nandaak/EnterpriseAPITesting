const fs = require('fs');
const path = require('path');

// Read the schema file
const schemaPath = path.join(__dirname, 'test-data', 'Input', 'Enhanced-ERP-Api-Schema-Advanced-Fixed.json');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

// Valid keys according to the requirements
const VALID_KEYS = ['CREATE', 'EDIT', 'DELETE', 'View', 'LookUP', 'EXPORT', 'PRINT'];

// Function to determine the correct key based on API context
function determineCorrectKey(apiPath, method, payload, params, currentKey) {
  const urlLower = apiPath.toLowerCase();
  const hasId = /<createdId>/.test(apiPath) || /\{id\}/i.test(apiPath) || /\/\d+/.test(apiPath);
  
  // Rule 1: CREATE - POST method with payload for adding new resource
  if (method === 'POST' && !urlLower.includes('/post') && !urlLower.includes('/unpost')) {
    return 'CREATE';
  }
  
  // Rule 2: EDIT - PUT method with payload for editing existing resource
  if (method === 'PUT') {
    return 'EDIT';
  }
  
  // Rule 3: DELETE - DELETE method
  if (method === 'DELETE') {
    return 'DELETE';
  }
  
  // For GET methods, we need more context
  if (method === 'GET') {
    // Rule 7: EXPORT - GET with "export" in URL
    if (urlLower.includes('export')) {
      return 'EXPORT';
    }
    
    // Rule 8: PRINT - GET with "print" in URL
    if (urlLower.includes('print')) {
      return 'PRINT';
    }
    
    // Rule 4: View - GET with ID in URL or params
    if (hasId || (params && params.some(p => /^id$/i.test(p)))) {
      return 'View';
    }
    
    // Rule 5: EDIT - GET for loading resource for edit screens (GetById, GetByIdView, etc.)
    if (urlLower.includes('getbyid') || urlLower.includes('getforupdate') || urlLower.includes('getedit')) {
      return 'EDIT';
    }
    
    // Rule 6: LookUP - GET for dropdowns, filters, multiselect
    if (urlLower.includes('dropdown') || urlLower.includes('lookup') || 
        urlLower.includes('filter') || urlLower.includes('search') ||
        urlLower.includes('getall') || urlLower.includes('list')) {
      return 'LookUP';
    }
    
    // Default for GET with pagination or search params
    if (params && params.some(p => /page|search|filter/i.test(p))) {
      return 'LookUP';
    }
  }
  
  // Special case: POST with /Post or /Unpost in URL (posting/unposting documents)
  if (method === 'POST' && (urlLower.includes('/post') || urlLower.includes('/unpost'))) {
    return 'CREATE'; // These are actions, treat as CREATE
  }
  
  // If current key is valid, keep it
  if (VALID_KEYS.includes(currentKey)) {
    return currentKey;
  }
  
  // Default fallback based on method
  if (method === 'GET') return 'LookUP';
  if (method === 'POST') return 'CREATE';
  if (method === 'PUT') return 'EDIT';
  if (method === 'DELETE') return 'DELETE';
  
  return currentKey;
}

// Process the schema
let changesCount = 0;
const changeLog = [];

for (const [moduleName, endpoints] of Object.entries(schema)) {
  for (const [endpointKey, endpointData] of Object.entries(endpoints)) {
    // Find the HTTP method key (POST, PUT, GET, DELETE, etc.)
    const currentKeys = Object.keys(endpointData).filter(k => 
      !['summary', 'parameters'].includes(k)
    );
    
    for (const currentKey of currentKeys) {
      if (Array.isArray(endpointData[currentKey])) {
        const [apiPath, payload] = endpointData[currentKey];
        const params = endpointData.parameters || [];
        
        // Determine the correct key
        const correctKey = determineCorrectKey(apiPath, currentKey, payload, params, currentKey);
        
        // If the key needs to be changed
        if (correctKey !== currentKey && !VALID_KEYS.includes(currentKey)) {
          changeLog.push({
            module: moduleName,
            endpoint: endpointKey,
            oldKey: currentKey,
            newKey: correctKey,
            apiPath: apiPath,
            method: currentKey
          });
          
          // Replace the key
          endpointData[correctKey] = endpointData[currentKey];
          delete endpointData[currentKey];
          changesCount++;
          
          console.log(`✓ ${moduleName}.${endpointKey}: ${currentKey} → ${correctKey}`);
        }
      }
    }
  }
}

// Save the fixed schema
fs.writeFileSync(schemaPath, JSON.stringify(schema, null, 2), 'utf8');

// Save the change log
const logPath = path.join(__dirname, 'schema-key-fixes-log.json');
fs.writeFileSync(logPath, JSON.stringify({
  totalChanges: changesCount,
  changes: changeLog,
  timestamp: new Date().toISOString()
}, null, 2), 'utf8');

console.log(`\n✅ Schema fixed successfully!`);
console.log(`📊 Total changes made: ${changesCount}`);
console.log(`📝 Change log saved to: schema-key-fixes-log.json`);
