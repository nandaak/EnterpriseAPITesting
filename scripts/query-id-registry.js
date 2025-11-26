#!/usr/bin/env node
// scripts/query-id-registry.js
/**
 * Query and Report Tool for ID Registry
 * 
 * Provides various queries and reports on the complete ID registry
 * 
 * Usage:
 *   node scripts/query-id-registry.js [command] [options]
 * 
 * Commands:
 *   stats              - Show registry statistics
 *   list               - List all IDs
 *   module <name>      - Show IDs for specific module
 *   export             - Export complete registry
 *   report             - Generate comprehensive report
 *   active             - Show only active IDs
 *   deleted            - Show only deleted IDs
 *   recent [count]     - Show recent activity
 */

const IDRegistryEnhanced = require('../utils/id-registry-enhanced');
const fs = require('fs');
const path = require('path');

const registry = new IDRegistryEnhanced();

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0] || 'stats';
const options = args.slice(1);

console.log('🔍 ID Registry Query Tool\n');
console.log('='.repeat(60));

switch (command) {
  case 'stats':
    showStatistics();
    break;

  case 'list':
    listAllIDs(options);
    break;

  case 'module':
    showModuleIDs(options[0]);
    break;

  case 'export':
    exportRegistry(options[0]);
    break;

  case 'report':
    generateReport();
    break;

  case 'active':
    listActiveIDs();
    break;

  case 'deleted':
    listDeletedIDs();
    break;

  case 'recent':
    showRecentActivity(parseInt(options[0]) || 10);
    break;

  case 'help':
    showHelp();
    break;

  default:
    console.log(`❌ Unknown command: ${command}`);
    console.log('Run "node scripts/query-id-registry.js help" for usage information');
}

console.log('='.repeat(60));

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

function showStatistics() {
  console.log('\n📊 Registry Statistics\n');

  const stats = registry.getStatistics();

  if (!stats) {
    console.log('❌ Failed to load statistics');
    return;
  }

  console.log('Overall:');
  console.log(`  Total Modules: ${stats.metadata.totalModules}`);
  console.log(`  Total IDs: ${stats.metadata.totalIds}`);
  console.log(`  Active IDs: ${stats.metadata.totalActive}`);
  console.log(`  Deleted IDs: ${stats.metadata.totalDeleted}`);
  console.log(`  Last Updated: ${stats.metadata.lastUpdated}`);

  console.log('\nID Type Distribution:');
  const idTypes = stats.statistics.idTypeDistribution || {};
  Object.keys(idTypes).forEach(type => {
    console.log(`  ${type}: ${idTypes[type]}`);
  });

  console.log('\nTop 10 Modules by ID Count:');
  stats.modules
    .sort((a, b) => b.totalCreated - a.totalCreated)
    .slice(0, 10)
    .forEach((mod, index) => {
      console.log(`  ${index + 1}. ${mod.displayName}`);
      console.log(`     Total: ${mod.totalCreated}, Active: ${mod.totalActive}, Deleted: ${mod.totalDeleted}`);
    });
}

function listAllIDs(filters = []) {
  console.log('\n📋 All IDs\n');

  const filterObj = {};
  filters.forEach(filter => {
    const [key, value] = filter.split('=');
    if (key && value) {
      filterObj[key] = value;
    }
  });

  const ids = registry.getAllIDs(filterObj);

  if (ids.length === 0) {
    console.log('No IDs found');
    return;
  }

  console.log(`Found ${ids.length} IDs:\n`);

  ids.forEach((idObj, index) => {
    console.log(`${index + 1}. ID: ${idObj.id}`);
    console.log(`   Type: ${idObj.idType} (${idObj.idFormat})`);
    console.log(`   Module: ${idObj.moduleDisplayName}`);
    console.log(`   Created: ${idObj.createdAt}`);
    console.log(`   Status: ${idObj.status}`);
    console.log(`   Views: ${idObj.lifecycle.viewedCount || 0}`);
    console.log('');
  });
}

function showModuleIDs(modulePath) {
  if (!modulePath) {
    console.log('❌ Please specify a module path');
    console.log('Example: node scripts/query-id-registry.js module "Accounting.Master_Data.Chart_of_Accounts"');
    return;
  }

  console.log(`\n📦 IDs for Module: ${modulePath}\n`);

  const ids = registry.getModuleIDs(modulePath);

  if (ids.length === 0) {
    console.log('No IDs found for this module');
    return;
  }

  console.log(`Found ${ids.length} IDs:\n`);

  ids.forEach((idObj, index) => {
    console.log(`${index + 1}. ID: ${idObj.id}`);
    console.log(`   Type: ${idObj.idType} (${idObj.idFormat})`);
    console.log(`   Created: ${idObj.createdAt}`);
    console.log(`   Status: ${idObj.status}`);
    console.log(`   Updates: ${idObj.lifecycle.updateCount || 0}`);
    console.log(`   Views: ${idObj.lifecycle.viewedCount || 0}`);
    if (idObj.lifecycle.deleted) {
      console.log(`   Deleted: ${idObj.lifecycle.deleted}`);
    }
    console.log('');
  });
}

function exportRegistry(outputPath) {
  const defaultPath = path.join(process.cwd(), 'id-registry-export.json');
  const exportPath = outputPath || defaultPath;

  console.log(`\n💾 Exporting Registry to: ${exportPath}\n`);

  const data = registry.exportRegistry(exportPath);

  if (data) {
    console.log('✅ Export successful!');
    console.log(`   Total Modules: ${data.metadata.totalModules}`);
    console.log(`   Total IDs: ${data.metadata.totalIds}`);
    console.log(`   File Size: ${(JSON.stringify(data).length / 1024).toFixed(2)} KB`);
  } else {
    console.log('❌ Export failed');
  }
}

function generateReport() {
  console.log('\n📄 Comprehensive Report\n');

  const report = registry.generateReport();

  if (!report) {
    console.log('❌ Failed to generate report');
    return;
  }

  console.log('Summary:');
  console.log(`  Total Modules: ${report.summary.totalModules}`);
  console.log(`  Total IDs: ${report.summary.totalIDs}`);
  console.log(`  Active IDs: ${report.summary.activeIDs}`);
  console.log(`  Deleted IDs: ${report.summary.deletedIDs}`);
  console.log(`  Last Updated: ${report.summary.lastUpdated}`);

  console.log('\nID Type Distribution:');
  Object.keys(report.idTypeDistribution).forEach(type => {
    const count = report.idTypeDistribution[type];
    const percentage = ((count / report.summary.totalIDs) * 100).toFixed(1);
    console.log(`  ${type}: ${count} (${percentage}%)`);
  });

  console.log('\nTop 10 Modules:');
  report.topModules.forEach((mod, index) => {
    console.log(`  ${index + 1}. ${mod.displayName} (${mod.count} IDs)`);
  });

  console.log('\nRecent Activity (Last 10):');
  report.recentActivity.slice(0, 10).forEach((activity, index) => {
    console.log(`  ${index + 1}. ${activity.id} - ${activity.module}`);
    console.log(`     ${activity.timestamp} (${activity.status})`);
  });

  // Save report to file
  const reportPath = path.join(process.cwd(), 'id-registry-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
  console.log(`\n✅ Full report saved to: ${reportPath}`);
}

function listActiveIDs() {
  console.log('\n✅ Active IDs\n');

  const ids = registry.getAllIDs({ status: 'active' });

  if (ids.length === 0) {
    console.log('No active IDs found');
    return;
  }

  console.log(`Found ${ids.length} active IDs:\n`);

  ids.forEach((idObj, index) => {
    console.log(`${index + 1}. ${idObj.id} (${idObj.idType})`);
    console.log(`   Module: ${idObj.moduleDisplayName}`);
    console.log(`   Created: ${idObj.createdAt}`);
    console.log('');
  });
}

function listDeletedIDs() {
  console.log('\n🗑️  Deleted IDs\n');

  const ids = registry.getAllIDs({ status: 'deleted' });

  if (ids.length === 0) {
    console.log('No deleted IDs found');
    return;
  }

  console.log(`Found ${ids.length} deleted IDs:\n`);

  ids.forEach((idObj, index) => {
    console.log(`${index + 1}. ${idObj.id} (${idObj.idType})`);
    console.log(`   Module: ${idObj.moduleDisplayName}`);
    console.log(`   Created: ${idObj.createdAt}`);
    console.log(`   Deleted: ${idObj.lifecycle.deleted}`);
    console.log('');
  });
}

function showRecentActivity(count = 10) {
  console.log(`\n🕐 Recent Activity (Last ${count})\n`);

  const allIds = registry.getAllIDs();
  const recent = allIds
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, count);

  if (recent.length === 0) {
    console.log('No activity found');
    return;
  }

  recent.forEach((idObj, index) => {
    console.log(`${index + 1}. ${idObj.id} (${idObj.idType})`);
    console.log(`   Module: ${idObj.moduleDisplayName}`);
    console.log(`   Created: ${idObj.createdAt}`);
    console.log(`   Status: ${idObj.status}`);
    console.log('');
  });
}

function showHelp() {
  console.log('\n📖 ID Registry Query Tool - Help\n');
  console.log('Usage: node scripts/query-id-registry.js [command] [options]\n');
  console.log('Commands:');
  console.log('  stats              - Show registry statistics');
  console.log('  list [filters]     - List all IDs (filters: status=active, module=Name)');
  console.log('  module <name>      - Show IDs for specific module');
  console.log('  export [path]      - Export complete registry to JSON file');
  console.log('  report             - Generate comprehensive report');
  console.log('  active             - Show only active IDs');
  console.log('  deleted            - Show only deleted IDs');
  console.log('  recent [count]     - Show recent activity (default: 10)');
  console.log('  help               - Show this help message');
  console.log('\nExamples:');
  console.log('  node scripts/query-id-registry.js stats');
  console.log('  node scripts/query-id-registry.js list status=active');
  console.log('  node scripts/query-id-registry.js module "Accounting.Master_Data.Chart_of_Accounts"');
  console.log('  node scripts/query-id-registry.js export ./my-export.json');
  console.log('  node scripts/query-id-registry.js recent 20');
}
