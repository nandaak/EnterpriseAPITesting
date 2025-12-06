const fs = require('fs');
const path = require('path');

/**
 * COMPREHENSIVE TEST FILE REFACTORING SCRIPT
 * 
 * Purpose: Update all test files and utilities to use new semantic schema keys
 * 
 * Transformations:
 * - "Post" → "CREATE"
 * - "PUT" → "EDIT"
 * - "GET" → "View" or "LookUP" (context-dependent)
 * - "DELETE" → "DELETE" (no change)
 * - "EDIT" → "EDIT" (no change)
 * - "View" → "View" (no change)
 * 
 * Files to update:
 * - tests/comprehensive-lifecycle/*.test.js
 * - utils/crud-lifecycle-helper.js
 * - utils/helper.js
 * - test-helpers/*.js
 */

// Mapping of old keys to new keys
const KEY_MAPPINGS = {
  'Post': 'CREATE',
  'PUT': 'EDIT',
  'GET': 'View', // Default, will be context-aware
  'DELETE': 'DELETE',
  'EDIT': 'EDIT',
  'View': 'View',
  'LookUP': 'LookUP',
  'EXPORT': 'EXPORT',
  'PRINT': 'PRINT'
};

// Patterns to replace
const REPLACEMENT_PATTERNS = [
  // Direct property access
  { pattern: /moduleConfig\.Post/g, replacement: 'moduleConfig.CREATE' },
  { pattern: /moduleConfig\.PUT/g, replacement: 'moduleConfig.EDIT' },
  { pattern: /moduleConfig\.GET/g, replacement: 'moduleConfig.View' },
  { pattern: /moduleConfig\.DELETE/g, replacement: 'moduleConfig.DELETE' },
  { pattern: /moduleConfig\.EDIT/g, replacement: 'moduleConfig.EDIT' },
  { pattern: /moduleConfig\.View/g, replacement: 'moduleConfig.View' },
  
  // Array access
  { pattern: /moduleConfig\["Post"\]/g, replacement: 'moduleConfig["CREATE"]' },
  { pattern: /moduleConfig\['Post'\]/g, replacement: "moduleConfig['CREATE']" },
  { pattern: /moduleConfig\["PUT"\]/g, replacement: 'moduleConfig["EDIT"]' },
  { pattern: /moduleConfig\['PUT'\]/g, replacement: "moduleConfig['EDIT']" },
  { pattern: /moduleConfig\["GET"\]/g, replacement: 'moduleConfig["View"]' },
  { pattern: /moduleConfig\['GET'\]/g, replacement: "moduleConfig['View']" },
  
  // String literals in conditions
  { pattern: /"Post"/g, replacement: '"CREATE"' },
  { pattern: /'Post'/g, replacement: "'CREATE'" },
  { pattern: /"PUT"/g, replacement: '"EDIT"' },
  { pattern: /'PUT'/g, replacement: "'EDIT'" },
  
  // Comments and documentation
  { pattern: /Post endpoint/g, replacement: 'CREATE endpoint' },
  { pattern: /PUT endpoint/g, replacement: 'EDIT endpoint' },
  { pattern: /POST endpoint/g, replacement: 'CREATE endpoint' },
  { pattern: /Post operation/g, replacement: 'CREATE operation' },
  { pattern: /PUT operation/g, replacement: 'EDIT operation' },
  { pattern: /POST operation/g, replacement: 'CREATE operation' },
  
  // Function parameters and variables
  { pattern: /operationKey = "Post"/g, replacement: 'operationKey = "CREATE"' },
  { pattern: /operationKey = 'Post'/g, replacement: "operationKey = 'CREATE'" },
  { pattern: /operationType === "Post"/g, replacement: 'operationType === "CREATE"' },
  { pattern: /operationType === 'Post'/g, replacement: "operationType === 'CREATE'" },
  { pattern: /operationType === "PUT"/g, replacement: 'operationType === "EDIT"' },
  { pattern: /operationType === 'PUT'/g, replacement: "operationType === 'EDIT'" },
  
  // Array includes
  { pattern: /\["Post", "View"\]/g, replacement: '["CREATE", "View"]' },
  { pattern: /\['Post', 'View'\]/g, replacement: "['CREATE', 'View']" },
  { pattern: /\["Post", "PUT"\]/g, replacement: '["CREATE", "EDIT"]' },
  { pattern: /\['Post', 'PUT'\]/g, replacement: "['CREATE', 'EDIT']" },
  
  // HTTP method comments
  { pattern: /HTTP operations \(Post, PUT/g, replacement: 'HTTP operations (CREATE, EDIT' },
  { pattern: /operations: Post, PUT/g, replacement: 'operations: CREATE, EDIT' },
];

// Context-aware replacements for GET
const GET_CONTEXT_PATTERNS = [
  // GET for viewing single resource (with ID)
  { pattern: /moduleConfig\.GET.*<createdId>/g, replacement: 'moduleConfig.View' },
  { pattern: /moduleConfig\.GET.*\{id\}/g, replacement: 'moduleConfig.View' },
  
  // GET for lists/lookups
  { pattern: /moduleConfig\.GET.*DropDown/g, replacement: 'moduleConfig.LookUP' },
  { pattern: /moduleConfig\.GET.*List/g, replacement: 'moduleConfig.LookUP' },
  { pattern: /moduleConfig\.GET.*Search/g, replacement: 'moduleConfig.LookUP' },
  
  // GET for export
  { pattern: /moduleConfig\.GET.*Export/g, replacement: 'moduleConfig.EXPORT' },
  
  // GET for print
  { pattern: /moduleConfig\.GET.*Print/g, replacement: 'moduleConfig.PRINT' },
];

function refactorFile(filePath) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Refactoring: ${path.basename(filePath)}`);
  console.log('='.repeat(80));
  
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const originalContent = content;
    let changesCount = 0;
    const changes = [];
    
    // Apply all replacement patterns
    REPLACEMENT_PATTERNS.forEach(({ pattern, replacement }) => {
      const matches = content.match(pattern);
      if (matches) {
        content = content.replace(pattern, replacement);
        changesCount += matches.length;
        changes.push({
          pattern: pattern.toString(),
          replacement,
          count: matches.length
        });
      }
    });
    
    // Apply context-aware GET replacements
    GET_CONTEXT_PATTERNS.forEach(({ pattern, replacement }) => {
      const matches = content.match(pattern);
      if (matches) {
        content = content.replace(pattern, replacement);
        changesCount += matches.length;
        changes.push({
          pattern: pattern.toString(),
          replacement,
          count: matches.length
        });
      }
    });
    
    // Save if changes were made
    if (content !== originalContent) {
      fs.writeFileSync(filePath, content, 'utf8');
      console.log(`✅ Changes made: ${changesCount}`);
      changes.forEach(change => {
        console.log(`  ✓ ${change.pattern} → ${change.replacement} (${change.count} times)`);
      });
    } else {
      console.log(`ℹ️  No changes needed`);
    }
    
    return {
      fileName: path.basename(filePath),
      changesCount,
      changes,
      success: true
    };
    
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    return {
      fileName: path.basename(filePath),
      changesCount: 0,
      changes: [],
      success: false,
      error: error.message
    };
  }
}

function main() {
  console.log('\n' + '█'.repeat(80));
  console.log('  TEST FILE REFACTORING TOOL');
  console.log('  Updating to New Semantic Schema Keys');
  console.log('█'.repeat(80));
  
  // Files to refactor
  const filesToRefactor = [
    // Test files
    'tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js',
    'tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js',
    'tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js',
    'tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js',
    'tests/comprehensive-lifecycle/5.API-Health-Checks.test.js',
    
    // Utility files
    'utils/crud-lifecycle-helper.js',
    'utils/helper.js',
    
    // Test helpers
    'test-helpers/crud-test-helper.js',
    'test-helpers/security-test-helper.js',
  ];
  
  const results = [];
  let totalChanges = 0;
  
  console.log(`\nProcessing ${filesToRefactor.length} files...\n`);
  
  filesToRefactor.forEach(filePath => {
    const fullPath = path.join(__dirname, filePath);
    if (fs.existsSync(fullPath)) {
      const result = refactorFile(fullPath);
      results.push(result);
      totalChanges += result.changesCount;
    } else {
      console.log(`\n⚠️  File not found: ${filePath}`);
      results.push({
        fileName: path.basename(filePath),
        changesCount: 0,
        changes: [],
        success: false,
        error: 'File not found'
      });
    }
  });
  
  // Summary
  console.log('\n' + '█'.repeat(80));
  console.log('  REFACTORING SUMMARY');
  console.log('█'.repeat(80));
  
  const successCount = results.filter(r => r.success).length;
  const failureCount = results.filter(r => !r.success).length;
  
  console.log(`\n📊 Overall Statistics:`);
  console.log(`   Total Files Processed: ${filesToRefactor.length}`);
  console.log(`   ✅ Successful: ${successCount}`);
  console.log(`   ❌ Failed: ${failureCount}`);
  console.log(`   📝 Total Changes: ${totalChanges}`);
  
  console.log(`\n📋 File-by-File Results:`);
  results.forEach(result => {
    const status = result.success ? '✅' : '❌';
    console.log(`   ${status} ${result.fileName}: ${result.changesCount} changes`);
  });
  
  // Save report
  const reportPath = path.join(__dirname, 'test-refactoring-report.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    totalFiles: filesToRefactor.length,
    successCount,
    failureCount,
    totalChanges,
    results,
    keyMappings: KEY_MAPPINGS
  }, null, 2), 'utf8');
  
  console.log(`\n📄 Report saved to: test-refactoring-report.json`);
  
  console.log('\n' + '█'.repeat(80));
  console.log('  ✨ REFACTORING COMPLETE ✨');
  console.log('█'.repeat(80) + '\n');
}

main();
