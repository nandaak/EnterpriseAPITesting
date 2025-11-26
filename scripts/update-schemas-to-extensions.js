// scripts/update-schemas-to-extensions.js
/**
 * Script to update all JSON schemas to use URL extensions only
 * Converts full URLs like "https://microtecsaudi.com:2032/erp-apis/ChartOfAccounts/GetTree"
 * to extensions like "/erp-apis/ChartOfAccounts/GetTree"
 * 
 * This allows the base URL to be dynamic from the .env file
 */

const fs = require('fs');
const path = require('path');

// Base URLs to remove
const BASE_URLS = [
  'https://microtecsaudi.com:2032',
  'http://microtecsaudi.com:2032',
  'https://happytesting.microtecdev.com:2050',
  'http://happytesting.microtecdev.com:2050'
];

// Schema files to update
const SCHEMA_FILES = [
  'test-data/Input/Main-Standarized-Backend-Api-Schema.json',
  'test-data/Input/Main-Backend-Api-Schema.json',
  'test-data/Input/JL-Backend-Api-Schema.json'
];

/**
 * Extract URL extension from full URL
 */
function extractUrlExtension(url) {
  if (!url || typeof url !== 'string') {
    return url;
  }

  // If it's already a relative URL or URL_HERE, return as is
  if (url === 'URL_HERE' || url.startsWith('/')) {
    return url;
  }

  // Remove base URL if present
  let extension = url;
  for (const baseUrl of BASE_URLS) {
    if (url.startsWith(baseUrl)) {
      extension = url.substring(baseUrl.length);
      break;
    }
  }

  // Ensure it starts with /
  if (!extension.startsWith('/')) {
    extension = '/' + extension;
  }

  return extension;
}

/**
 * Recursively process schema object to update URLs
 */
function processSchemaObject(obj, stats) {
  if (Array.isArray(obj)) {
    // Process arrays - first element might be a URL
    if (obj.length > 0 && typeof obj[0] === 'string') {
      const original = obj[0];
      const extension = extractUrlExtension(original);
      
      if (original !== extension) {
        obj[0] = extension;
        stats.updated++;
        console.log(`  ✓ ${original} → ${extension}`);
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
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        processSchemaObject(obj[key], stats);
      }
    });
  }
}

/**
 * Update a single schema file
 */
function updateSchemaFile(filePath) {
  console.log(`\n📄 Processing: ${filePath}`);
  
  try {
    // Read the file
    const fullPath = path.join(process.cwd(), filePath);
    
    if (!fs.existsSync(fullPath)) {
      console.log(`  ⚠️  File not found: ${filePath}`);
      return { success: false, updated: 0 };
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const schema = JSON.parse(content);

    // Track statistics
    const stats = { updated: 0 };

    // Process the schema
    processSchemaObject(schema, stats);

    // Write back to file
    fs.writeFileSync(fullPath, JSON.stringify(schema, null, 2), 'utf8');

    console.log(`  ✅ Updated ${stats.updated} URLs in ${filePath}`);
    return { success: true, updated: stats.updated };

  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
    return { success: false, updated: 0, error: error.message };
  }
}

/**
 * Main execution
 */
function main() {
  console.log('🚀 Starting schema URL update process...\n');
  console.log('Converting full URLs to extensions for dynamic endpoint support\n');

  const results = {
    total: 0,
    success: 0,
    failed: 0,
    totalUpdates: 0
  };

  SCHEMA_FILES.forEach(file => {
    results.total++;
    const result = updateSchemaFile(file);
    
    if (result.success) {
      results.success++;
      results.totalUpdates += result.updated;
    } else {
      results.failed++;
    }
  });

  console.log('\n' + '='.repeat(60));
  console.log('📊 Summary:');
  console.log(`   Total files processed: ${results.total}`);
  console.log(`   Successfully updated: ${results.success}`);
  console.log(`   Failed: ${results.failed}`);
  console.log(`   Total URLs converted: ${results.totalUpdates}`);
  console.log('='.repeat(60));

  if (results.failed > 0) {
    process.exit(1);
  }
}

// Run the script
if (require.main === module) {
  main();
}

module.exports = { extractUrlExtension, processSchemaObject, updateSchemaFile };
