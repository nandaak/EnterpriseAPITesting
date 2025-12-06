const fs = require('fs');
const path = require('path');

// Valid keys according to the requirements
const VALID_KEYS = ['CREATE', 'EDIT', 'DELETE', 'View', 'LookUP', 'EXPORT', 'PRINT'];

// Function to determine the correct key based on API context
function determineCorrectKey(apiPath, method, payload, params, currentKey) {
  const urlLower = apiPath.toLowerCase();
  const hasId = /<createdId>/.test(apiPath) || /\{id\}/i.test(apiPath) || /\/\d+/.test(apiPath) || /__id_/i.test(apiPath);
  
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

// Function to process a single schema file
function processSchemaFile(filePath) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Processing: ${path.basename(filePath)}`);
  console.log('='.repeat(80));
  
  try {
    const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    let changesCount = 0;
    const changeLog = [];
    
    for (const [moduleName, endpoints] of Object.entries(schema)) {
      if (!endpoints || typeof endpoints !== 'object') continue;
      
      for (const [endpointKey, endpointData] of Object.entries(endpoints)) {
        if (!endpointData || typeof endpointData !== 'object') continue;
        
        // Find the HTTP method key (POST, PUT, GET, DELETE, etc.)
        const currentKeys = Object.keys(endpointData).filter(k => 
          !['summary', 'parameters', 'description', 'tags', 'responses'].includes(k)
        );
        
        for (const currentKey of currentKeys) {
          if (Array.isArray(endpointData[currentKey])) {
            const [apiPath, payload] = endpointData[currentKey];
            const params = endpointData.parameters || [];
            
            // Determine the correct key
            const correctKey = determineCorrectKey(apiPath, currentKey, payload, params, currentKey);
            
            // If the key needs to be changed
            if (correctKey !== currentKey) {
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
              
              console.log(`  ✓ ${moduleName}.${endpointKey}: ${currentKey} → ${correctKey}`);
            }
          }
        }
      }
    }
    
    // Save the fixed schema
    fs.writeFileSync(filePath, JSON.stringify(schema, null, 2), 'utf8');
    
    console.log(`\n✅ Completed: ${changesCount} changes made`);
    
    return {
      fileName: path.basename(filePath),
      changesCount,
      changes: changeLog,
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
  console.log('  SCHEMA REFACTORING TOOL');
  console.log('  Applying Professional Key Standardization Rules');
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
  const reportPath = path.join(__dirname, 'schema-refactoring-report.json');
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
  
  console.log(`\n📄 Detailed report saved to: schema-refactoring-report.json`);
  
  // Create a summary markdown file
  const summaryMd = generateSummaryMarkdown(results, totalChanges);
  const summaryPath = path.join(__dirname, 'SCHEMA-REFACTORING-SUMMARY.md');
  fs.writeFileSync(summaryPath, summaryMd, 'utf8');
  
  console.log(`📄 Summary document saved to: SCHEMA-REFACTORING-SUMMARY.md`);
  
  console.log('\n' + '█'.repeat(80));
  console.log('  ✨ REFACTORING COMPLETE ✨');
  console.log('█'.repeat(80) + '\n');
}

function generateSummaryMarkdown(results, totalChanges) {
  const successCount = results.filter(r => r.success).length;
  const failureCount = results.filter(r => !r.success).length;
  
  let md = `# Schema Refactoring Summary\n\n`;
  md += `**Date**: ${new Date().toISOString()}\n\n`;
  md += `## Overview\n\n`;
  md += `Successfully refactored **${successCount} out of ${results.length}** schema files with **${totalChanges} total changes**.\n\n`;
  
  md += `## Statistics\n\n`;
  md += `| Metric | Count |\n`;
  md += `|--------|-------|\n`;
  md += `| Total Files | ${results.length} |\n`;
  md += `| Successfully Processed | ${successCount} |\n`;
  md += `| Failed | ${failureCount} |\n`;
  md += `| Total Key Changes | ${totalChanges} |\n\n`;
  
  md += `## Files Processed\n\n`;
  results.forEach(result => {
    const status = result.success ? '✅' : '❌';
    md += `### ${status} ${result.fileName}\n\n`;
    if (result.success) {
      md += `- **Changes Made**: ${result.changesCount}\n`;
      md += `- **Status**: Successfully refactored\n\n`;
    } else {
      md += `- **Status**: Failed\n`;
      md += `- **Error**: ${result.error}\n\n`;
    }
  });
  
  md += `## Transformation Rules Applied\n\n`;
  md += `### 1. CREATE\n`;
  md += `- **Rule**: POST method for adding new resources\n`;
  md += `- **Example**: \`POST /erp-apis/Customer\` → **CREATE**\n\n`;
  
  md += `### 2. EDIT\n`;
  md += `- **Rule**: PUT method for updating existing resources\n`;
  md += `- **Example**: \`PUT /erp-apis/Customer\` → **EDIT**\n\n`;
  
  md += `### 3. DELETE\n`;
  md += `- **Rule**: DELETE method\n`;
  md += `- **Example**: \`DELETE /erp-apis/Customer/<id>\` → **DELETE**\n\n`;
  
  md += `### 4. View\n`;
  md += `- **Rule**: GET method with ID for viewing specific resource\n`;
  md += `- **Example**: \`GET /erp-apis/Customer/<id>\` → **View**\n\n`;
  
  md += `### 5. LookUP\n`;
  md += `- **Rule**: GET method for dropdowns, filters, lists, search\n`;
  md += `- **Example**: \`GET /erp-apis/Customer/GetCustomerDropDown\` → **LookUP**\n\n`;
  
  md += `### 6. EXPORT\n`;
  md += `- **Rule**: GET method with "export" in URL\n`;
  md += `- **Example**: \`GET /erp-apis/Customer/Export\` → **EXPORT**\n\n`;
  
  md += `### 7. PRINT\n`;
  md += `- **Rule**: GET method with "print" in URL\n`;
  md += `- **Example**: \`GET /erp-apis/Invoice/PrintOutInvoice\` → **PRINT**\n\n`;
  
  md += `## Next Steps\n\n`;
  md += `All schema files have been standardized with semantic keys that accurately represent the API operations. `;
  md += `The schemas are now ready for use in testing and documentation.\n\n`;
  
  md += `## Files Generated\n\n`;
  md += `1. **Updated Schema Files** - All files in \`test-data/Input/\` directory\n`;
  md += `2. **schema-refactoring-report.json** - Detailed JSON report with all changes\n`;
  md += `3. **SCHEMA-REFACTORING-SUMMARY.md** - This summary document\n`;
  
  return md;
}

// Run the main function
main();
