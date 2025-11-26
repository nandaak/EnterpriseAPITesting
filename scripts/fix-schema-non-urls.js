// scripts/fix-schema-non-urls.js
/**
 * Fix incorrectly converted non-URL strings in schemas
 * Reverts GUIDs, dates, and other non-URL strings that were mistakenly prefixed with /
 */

const fs = require('fs');
const path = require('path');

const SCHEMA_FILES = [
  'test-data/Input/Main-Standarized-Backend-Api-Schema.json',
  'test-data/Input/Main-Backend-Api-Schema.json',
  'test-data/Input/JL-Backend-Api-Schema.json'
];

/**
 * Check if a string is a valid API endpoint extension
 */
function isValidApiEndpoint(str) {
  if (!str || typeof str !== 'string') return false;
  
  // Should not convert these patterns:
  // - GUIDs: /xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  // - Dates: /2027-01-01
  // - Simple names: /support, /happytesting
  
  // Valid API endpoints should contain "apis" or start with specific patterns
  if (str.includes('-apis/') || str.includes('/api/')) {
    return true;
  }
  
  // Check if it's a GUID pattern
  if (/^\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str)) {
    return false;
  }
  
  // Check if it's a date pattern
  if (/^\/\d{4}-\d{2}-\d{2}/.test(str)) {
    return false;
  }
  
  // Check if it's a simple word (branch name, etc.)
  if (/^\/[a-z]+$/i.test(str) && !str.includes('/')) {
    return false;
  }
  
  return false;
}

/**
 * Fix a value that was incorrectly converted
 */
function fixValue(value) {
  if (typeof value !== 'string') return value;
  
  // If it starts with / but is not a valid API endpoint, remove the /
  if (value.startsWith('/') && !isValidApiEndpoint(value)) {
    return value.substring(1);
  }
  
  return value;
}

/**
 * Recursively process schema object to fix incorrectly converted values
 */
function processSchemaObject(obj, stats) {
  if (Array.isArray(obj)) {
    // Process arrays - first element might be a URL
    if (obj.length > 0 && typeof obj[0] === 'string') {
      const original = obj[0];
      const fixed = fixValue(original);
      
      if (original !== fixed) {
        obj[0] = fixed;
        stats.fixed++;
        console.log(`  ✓ Fixed: ${original} → ${fixed}`);
      }
    }
    
    // Process remaining array elements
    obj.forEach(item => {
      if (typeof item === 'object' && item !== null) {
        processSchemaObject(item, stats);
      }
    });
  } else if (typeof obj === 'object' && obj !== null) {
    // Process object properties
    Object.keys(obj).forEach(key => {
      if (typeof obj[key] === 'string') {
        const original = obj[key];
        const fixed = fixValue(original);
        if (original !== fixed) {
          obj[key] = fixed;
          stats.fixed++;
          console.log(`  ✓ Fixed property '${key}': ${original} → ${fixed}`);
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        processSchemaObject(obj[key], stats);
      }
    });
  }
}

/**
 * Fix a single schema file
 */
function fixSchemaFile(filePath) {
  console.log(`\n📄 Processing: ${filePath}`);
  
  try {
    const fullPath = path.join(process.cwd(), filePath);
    
    if (!fs.existsSync(fullPath)) {
      console.log(`  ⚠️  File not found: ${filePath}`);
      return { success: false, fixed: 0 };
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const schema = JSON.parse(content);

    const stats = { fixed: 0 };
    processSchemaObject(schema, stats);

    if (stats.fixed > 0) {
      fs.writeFileSync(fullPath, JSON.stringify(schema, null, 2), 'utf8');
      console.log(`  ✅ Fixed ${stats.fixed} values in ${filePath}`);
    } else {
      console.log(`  ℹ️  No fixes needed in ${filePath}`);
    }

    return { success: true, fixed: stats.fixed };

  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
    return { success: false, fixed: 0, error: error.message };
  }
}

/**
 * Main execution
 */
function main() {
  console.log('🔧 Fixing incorrectly converted non-URL values in schemas...\n');

  const results = {
    total: 0,
    success: 0,
    failed: 0,
    totalFixes: 0
  };

  SCHEMA_FILES.forEach(file => {
    results.total++;
    const result = fixSchemaFile(file);
    
    if (result.success) {
      results.success++;
      results.totalFixes += result.fixed;
    } else {
      results.failed++;
    }
  });

  console.log('\n' + '='.repeat(60));
  console.log('📊 Summary:');
  console.log(`   Total files processed: ${results.total}`);
  console.log(`   Successfully processed: ${results.success}`);
  console.log(`   Failed: ${results.failed}`);
  console.log(`   Total values fixed: ${results.totalFixes}`);
  console.log('='.repeat(60));

  if (results.failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { fixValue, isValidApiEndpoint, fixSchemaFile };
