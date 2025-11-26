#!/usr/bin/env node
// scripts/clean-test-artifacts.js
/**
 * Comprehensive Test Artifacts Cleanup Script
 * 
 * Cleans various test artifacts to prepare for fresh test runs
 * 
 * Usage:
 *   node scripts/clean-test-artifacts.js [options]
 * 
 * Options:
 *   --all          Clean everything (reports + IDs + cache)
 *   --reports      Clean only test reports
 *   --ids          Clean only ID files
 *   --cache        Clean only Jest cache
 *   --backup       Backup ID registry before cleaning
 *   --help         Show this help message
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  all: args.includes('--all'),
  reports: args.includes('--reports'),
  ids: args.includes('--ids'),
  cache: args.includes('--cache'),
  backup: args.includes('--backup'),
  help: args.includes('--help')
};

// If no specific options, default to --all
if (!options.reports && !options.ids && !options.cache && !options.help) {
  options.all = true;
}

console.log('🧹 Test Artifacts Cleanup Tool\n');
console.log('='.repeat(60));

if (options.help) {
  showHelp();
  process.exit(0);
}

// Backup ID registry if requested
if (options.backup && (options.ids || options.all)) {
  backupIDRegistry();
}

let cleaned = [];

// Clean reports
if (options.reports || options.all) {
  cleanReports();
  cleaned.push('reports');
}

// Clean ID files
if (options.ids || options.all) {
  cleanIDFiles();
  cleaned.push('ID files');
}

// Clean cache
if (options.cache || options.all) {
  cleanCache();
  cleaned.push('cache');
}

console.log('='.repeat(60));
console.log(`\n✅ Cleanup complete! Cleaned: ${cleaned.join(', ')}`);
console.log('🚀 Ready for fresh test run!\n');

// ============================================================================
// CLEANUP FUNCTIONS
// ============================================================================

function cleanReports() {
  console.log('\n📊 Cleaning test reports...\n');

  const reportDirs = [
    'jest-html-reporters-attach',
    'html-report',
    'coverage',
    'test-results'
  ];

  reportDirs.forEach(dir => {
    const dirPath = path.join(process.cwd(), dir);
    if (fs.existsSync(dirPath)) {
      try {
        fs.rmSync(dirPath, { recursive: true, force: true });
        console.log(`  ✓ Removed: ${dir}/`);
      } catch (error) {
        console.log(`  ✗ Failed to remove: ${dir}/ (${error.message})`);
      }
    } else {
      console.log(`  ℹ️  Not found: ${dir}/`);
    }
  });

  // Clean individual report files
  const reportFiles = [
    'test-results.json',
    'id-registry-report.json',
    'id-registry-export.json'
  ];

  reportFiles.forEach(file => {
    const filePath = path.join(process.cwd(), file);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
        console.log(`  ✓ Removed: ${file}`);
      } catch (error) {
        console.log(`  ✗ Failed to remove: ${file} (${error.message})`);
      }
    }
  });
}

function cleanIDFiles() {
  console.log('\n🆔 Cleaning ID files...\n');

  const idFiles = [
    { path: 'tests/createdId.json', desc: 'Current ID (JSON)' },
    { path: 'tests/createdIds.json', desc: 'Complete ID Registry' },
    { path: 'createdId.txt', desc: 'Current ID (Text)' }
  ];

  idFiles.forEach(({ path: filePath, desc }) => {
    const fullPath = path.join(process.cwd(), filePath);
    if (fs.existsSync(fullPath)) {
      try {
        fs.unlinkSync(fullPath);
        console.log(`  ✓ Removed: ${filePath} (${desc})`);
      } catch (error) {
        console.log(`  ✗ Failed to remove: ${filePath} (${error.message})`);
      }
    } else {
      console.log(`  ℹ️  Not found: ${filePath}`);
    }
  });
}

function cleanCache() {
  console.log('\n🗑️  Cleaning Jest cache...\n');

  try {
    execSync('npx jest --clearCache', { stdio: 'inherit' });
    console.log('  ✓ Jest cache cleared');
  } catch (error) {
    console.log('  ✗ Failed to clear Jest cache');
  }
}

function backupIDRegistry() {
  console.log('\n💾 Backing up ID registry...\n');

  const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
  
  if (!fs.existsSync(registryPath)) {
    console.log('  ℹ️  No registry file to backup');
    return;
  }

  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(process.cwd(), 'backups');
    
    // Create backups directory if it doesn't exist
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }

    const backupPath = path.join(backupDir, `createdIds-backup-${timestamp}.json`);
    fs.copyFileSync(registryPath, backupPath);
    
    console.log(`  ✓ Registry backed up to: backups/createdIds-backup-${timestamp}.json`);
  } catch (error) {
    console.log(`  ✗ Failed to backup registry: ${error.message}`);
  }
}

function showHelp() {
  console.log('\n📖 Test Artifacts Cleanup Tool - Help\n');
  console.log('Usage: node scripts/clean-test-artifacts.js [options]\n');
  console.log('Options:');
  console.log('  --all          Clean everything (reports + IDs + cache)');
  console.log('  --reports      Clean only test reports and coverage');
  console.log('  --ids          Clean only ID files (createdId.json, createdIds.json, createdId.txt)');
  console.log('  --cache        Clean only Jest cache');
  console.log('  --backup       Backup ID registry before cleaning');
  console.log('  --help         Show this help message');
  console.log('\nExamples:');
  console.log('  node scripts/clean-test-artifacts.js');
  console.log('  node scripts/clean-test-artifacts.js --all');
  console.log('  node scripts/clean-test-artifacts.js --reports');
  console.log('  node scripts/clean-test-artifacts.js --ids --backup');
  console.log('  node scripts/clean-test-artifacts.js --reports --ids');
  console.log('\nFiles cleaned:');
  console.log('  Reports:');
  console.log('    - jest-html-reporters-attach/');
  console.log('    - html-report/');
  console.log('    - coverage/');
  console.log('    - test-results/');
  console.log('    - test-results.json');
  console.log('    - id-registry-report.json');
  console.log('    - id-registry-export.json');
  console.log('  IDs:');
  console.log('    - tests/createdId.json (current ID)');
  console.log('    - tests/createdIds.json (complete registry)');
  console.log('    - createdId.txt (simple text ID)');
  console.log('  Cache:');
  console.log('    - Jest cache');
  console.log('\nNote: If no options specified, defaults to --all');
}
