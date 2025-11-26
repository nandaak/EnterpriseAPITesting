#!/usr/bin/env node
// scripts/update-all-schemas.js
/**
 * Master script to update all JSON schemas to use URL extensions
 * 
 * This script:
 * 1. Converts full URLs to extensions (e.g., https://example.com/api/endpoint → /api/endpoint)
 * 2. Fixes any incorrectly converted non-URL values (GUIDs, dates, etc.)
 * 
 * Usage: node scripts/update-all-schemas.js
 */

const { updateSchemaFile } = require('./update-schemas-to-extensions');
const { fixSchemaFile } = require('./fix-schema-non-urls');

const SCHEMA_FILES = [
  'test-data/Input/Main-Standarized-Backend-Api-Schema.json',
  'test-data/Input/Main-Backend-Api-Schema.json',
  'test-data/Input/JL-Backend-Api-Schema.json'
];

async function main() {
  console.log('🚀 Starting comprehensive schema update process...\n');
  console.log('=' .repeat(60));
  
  // Step 1: Convert URLs to extensions
  console.log('\n📝 STEP 1: Converting full URLs to extensions\n');
  const updateResults = {
    total: 0,
    success: 0,
    failed: 0,
    totalUpdates: 0
  };

  SCHEMA_FILES.forEach(file => {
    updateResults.total++;
    const result = updateSchemaFile(file);
    
    if (result.success) {
      updateResults.success++;
      updateResults.totalUpdates += result.updated;
    } else {
      updateResults.failed++;
    }
  });

  console.log('\n' + '-'.repeat(60));
  console.log('Step 1 Summary:');
  console.log(`   Files processed: ${updateResults.total}`);
  console.log(`   Successfully updated: ${updateResults.success}`);
  console.log(`   Failed: ${updateResults.failed}`);
  console.log(`   Total URLs converted: ${updateResults.totalUpdates}`);
  console.log('-'.repeat(60));

  // Step 2: Fix incorrectly converted values
  console.log('\n📝 STEP 2: Fixing incorrectly converted non-URL values\n');
  const fixResults = {
    total: 0,
    success: 0,
    failed: 0,
    totalFixes: 0
  };

  SCHEMA_FILES.forEach(file => {
    fixResults.total++;
    const result = fixSchemaFile(file);
    
    if (result.success) {
      fixResults.success++;
      fixResults.totalFixes += result.fixed;
    } else {
      fixResults.failed++;
    }
  });

  console.log('\n' + '-'.repeat(60));
  console.log('Step 2 Summary:');
  console.log(`   Files processed: ${fixResults.total}`);
  console.log(`   Successfully processed: ${fixResults.success}`);
  console.log(`   Failed: ${fixResults.failed}`);
  console.log(`   Total values fixed: ${fixResults.totalFixes}`);
  console.log('-'.repeat(60));

  // Final summary
  console.log('\n' + '='.repeat(60));
  console.log('✅ FINAL SUMMARY:');
  console.log(`   Total schema files: ${SCHEMA_FILES.length}`);
  console.log(`   URLs converted to extensions: ${updateResults.totalUpdates}`);
  console.log(`   Non-URL values fixed: ${fixResults.totalFixes}`);
  console.log(`   Overall status: ${updateResults.failed === 0 && fixResults.failed === 0 ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log('='.repeat(60));
  console.log('\n💡 Next steps:');
  console.log('   1. Update ENDPOINT in .env file to change the base URL');
  console.log('   2. All tests will automatically use the new endpoint');
  console.log('   3. No code changes needed - dynamic endpoint support is active!\n');

  if (updateResults.failed > 0 || fixResults.failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error('❌ Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { main };
