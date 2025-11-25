// utils/id-registry-analyzer.js - Advanced ID Registry Analysis Tool
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Advanced analyzer for the enhanced ID registry
 * Provides detailed insights into ID objects and lifecycle tracking
 */
class IdRegistryAnalyzer {
  constructor() {
    this.registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
  }

  /**
   * Get the complete registry
   */
  getRegistry() {
    try {
      if (!fs.existsSync(this.registryPath)) {
        return null;
      }
      return JSON.parse(fs.readFileSync(this.registryPath, 'utf8'));
    } catch (error) {
      logger.error(`Failed to read registry: ${error.message}`);
      return null;
    }
  }

  /**
   * Get all ID objects for a module
   */
  getModuleIdObjects(moduleName) {
    const registry = this.getRegistry();
    if (!registry || !registry.modules[moduleName]) {
      return [];
    }
    return registry.modules[moduleName].idObjects || [];
  }

  /**
   * Get lifecycle statistics for a module
   */
  getModuleLifecycleStats(moduleName) {
    const idObjects = this.getModuleIdObjects(moduleName);
    
    const stats = {
      total: idObjects.length,
      active: 0,
      deleted: 0,
      completedFullCycle: 0,
      averageViews: 0,
      totalUpdates: 0,
      idFormats: {},
      lifecyclePhases: {
        created: 0,
        viewed: 0,
        updated: 0,
        deleted: 0
      }
    };

    let totalViews = 0;

    idObjects.forEach(obj => {
      // Count by lifecycle status
      if (obj.lifecycle.deleted) {
        stats.deleted++;
      } else {
        stats.active++;
      }

      if (obj.lifecycle.completedFullCycle) {
        stats.completedFullCycle++;
      }

      // Count views
      totalViews += obj.lifecycle.viewedCount || 0;

      // Count updates
      if (obj.lifecycle.updates) {
        stats.totalUpdates += obj.lifecycle.updates.length;
      }

      // Count ID formats
      const format = obj.format || 'unknown';
      stats.idFormats[format] = (stats.idFormats[format] || 0) + 1;

      // Count lifecycle phases
      if (obj.lifecycle.created) stats.lifecyclePhases.created++;
      if (obj.lifecycle.lastViewed) stats.lifecyclePhases.viewed++;
      if (obj.lifecycle.updated) stats.lifecyclePhases.updated++;
      if (obj.lifecycle.deleted) stats.lifecyclePhases.deleted++;
    });

    stats.averageViews = idObjects.length > 0 ? 
      (totalViews / idObjects.length).toFixed(2) : 0;

    return stats;
  }

  /**
   * Get comprehensive statistics
   */
  getComprehensiveStats() {
    const registry = this.getRegistry();
    if (!registry) {
      return null;
    }

    const stats = {
      overview: {
        totalModules: Object.keys(registry.modules).length,
        totalIds: registry.metadata.totalIds || 0,
        registryCreated: registry.metadata.created,
        lastUpdated: registry.metadata.lastUpdated
      },
      modules: {},
      globalStats: {
        totalActive: 0,
        totalDeleted: 0,
        totalCompletedCycles: 0,
        totalViews: 0,
        totalUpdates: 0,
        idFormats: {},
        averageIdsPerModule: 0
      }
    };

    Object.keys(registry.modules).forEach(moduleName => {
      const moduleStats = this.getModuleLifecycleStats(moduleName);
      stats.modules[moduleName] = moduleStats;

      // Aggregate global stats
      stats.globalStats.totalActive += moduleStats.active;
      stats.globalStats.totalDeleted += moduleStats.deleted;
      stats.globalStats.totalCompletedCycles += moduleStats.completedFullCycle;
      stats.globalStats.totalUpdates += moduleStats.totalUpdates;

      // Aggregate ID formats
      Object.entries(moduleStats.idFormats).forEach(([format, count]) => {
        stats.globalStats.idFormats[format] = 
          (stats.globalStats.idFormats[format] || 0) + count;
      });
    });

    stats.globalStats.averageIdsPerModule = stats.overview.totalModules > 0 ?
      (stats.overview.totalIds / stats.overview.totalModules).toFixed(2) : 0;

    return stats;
  }

  /**
   * Display comprehensive statistics
   */
  displayComprehensiveStats() {
    const stats = this.getComprehensiveStats();
    if (!stats) {
      console.log('❌ No registry data available');
      return;
    }

    console.log('\n' + '='.repeat(80));
    console.log('📊 ENHANCED ID REGISTRY - COMPREHENSIVE ANALYSIS');
    console.log('='.repeat(80));

    // Overview
    console.log('\n📋 OVERVIEW:');
    console.log(`   Total Modules: ${stats.overview.totalModules}`);
    console.log(`   Total IDs Created: ${stats.overview.totalIds}`);
    console.log(`   Registry Created: ${stats.overview.registryCreated}`);
    console.log(`   Last Updated: ${stats.overview.lastUpdated}`);

    // Global Statistics
    console.log('\n🌍 GLOBAL STATISTICS:');
    console.log(`   Active IDs: ${stats.globalStats.totalActive}`);
    console.log(`   Deleted IDs: ${stats.globalStats.totalDeleted}`);
    console.log(`   Completed Full Cycles: ${stats.globalStats.totalCompletedCycles}`);
    console.log(`   Total Updates Recorded: ${stats.globalStats.totalUpdates}`);
    console.log(`   Average IDs per Module: ${stats.globalStats.averageIdsPerModule}`);

    // ID Formats
    console.log('\n🔢 ID FORMATS:');
    Object.entries(stats.globalStats.idFormats).forEach(([format, count]) => {
      console.log(`   ${format}: ${count}`);
    });

    // Module Details
    console.log('\n📦 MODULE DETAILS:');
    Object.entries(stats.modules).forEach(([moduleName, moduleStats]) => {
      const status = moduleStats.active > 0 ? '✅ ACTIVE' : '🗑️  ALL DELETED';
      console.log(`\n   ${status} - ${moduleName}`);
      console.log(`      Total IDs: ${moduleStats.total}`);
      console.log(`      Active: ${moduleStats.active} | Deleted: ${moduleStats.deleted}`);
      console.log(`      Completed Full Cycles: ${moduleStats.completedFullCycle}`);
      console.log(`      Average Views per ID: ${moduleStats.averageViews}`);
      console.log(`      Total Updates: ${moduleStats.totalUpdates}`);
      
      if (Object.keys(moduleStats.idFormats).length > 0) {
        console.log(`      ID Formats: ${Object.entries(moduleStats.idFormats)
          .map(([f, c]) => `${f}(${c})`).join(', ')}`);
      }
    });

    console.log('\n' + '='.repeat(80) + '\n');
  }

  /**
   * Get detailed ID object information
   */
  getIdObjectDetails(moduleName, idValue) {
    const idObjects = this.getModuleIdObjects(moduleName);
    const idObj = idObjects.find(obj => obj.id === idValue);
    
    if (!idObj) {
      return null;
    }

    return {
      id: idObj.id,
      module: idObj.module,
      moduleDisplayName: idObj.moduleDisplayName,
      format: idObj.format,
      created: idObj.lifecycle.created,
      updated: idObj.lifecycle.updated,
      deleted: idObj.lifecycle.deleted,
      viewedCount: idObj.lifecycle.viewedCount || 0,
      lastViewed: idObj.lifecycle.lastViewed,
      updates: idObj.lifecycle.updates || [],
      completedFullCycle: idObj.lifecycle.completedFullCycle || false,
      testRun: idObj.testRun,
      metadata: idObj.metadata
    };
  }

  /**
   * Display detailed ID object information
   */
  displayIdObjectDetails(moduleName, idValue) {
    const details = this.getIdObjectDetails(moduleName, idValue);
    
    if (!details) {
      console.log(`❌ ID object not found: ${idValue} in module ${moduleName}`);
      return;
    }

    console.log('\n' + '='.repeat(80));
    console.log('🔍 ID OBJECT DETAILS');
    console.log('='.repeat(80));
    console.log(`\n📋 Basic Information:`);
    console.log(`   ID: ${details.id}`);
    console.log(`   Module: ${details.moduleDisplayName}`);
    console.log(`   Format: ${details.format}`);
    console.log(`   Status: ${details.deleted ? '🗑️  DELETED' : '✅ ACTIVE'}`);

    console.log(`\n🔄 Lifecycle:`);
    console.log(`   Created: ${details.created}`);
    console.log(`   Updated: ${details.updated || 'Never'}`);
    console.log(`   Deleted: ${details.deleted || 'Not deleted'}`);
    console.log(`   Viewed: ${details.viewedCount} times`);
    console.log(`   Last Viewed: ${details.lastViewed || 'Never'}`);
    console.log(`   Completed Full Cycle: ${details.completedFullCycle ? 'Yes' : 'No'}`);

    if (details.updates.length > 0) {
      console.log(`\n✏️  Updates (${details.updates.length}):`);
      details.updates.forEach((update, index) => {
        console.log(`   ${index + 1}. ${update.timestamp}`);
      });
    }

    console.log(`\n🧪 Test Run Information:`);
    console.log(`   Timestamp: ${details.testRun.timestamp}`);
    console.log(`   Phase: ${details.testRun.testPhase}`);
    console.log(`   Module Status: ${details.testRun.moduleStatus}`);

    console.log(`\n📊 Metadata:`);
    console.log(`   Creation Method: ${details.metadata.creationMethod}`);
    console.log(`   API Endpoint: ${details.metadata.apiEndpoint || 'N/A'}`);
    console.log(`   Test Suite: ${details.metadata.testSuite}`);

    console.log('\n' + '='.repeat(80) + '\n');
  }

  /**
   * Export registry to detailed report
   */
  exportDetailedReport(outputPath = null) {
    const stats = this.getComprehensiveStats();
    const registry = this.getRegistry();
    
    if (!stats || !registry) {
      console.log('❌ No data to export');
      return null;
    }

    const report = {
      generatedAt: new Date().toISOString(),
      statistics: stats,
      modules: {}
    };

    // Add detailed module information
    Object.keys(registry.modules).forEach(moduleName => {
      const moduleData = registry.modules[moduleName];
      report.modules[moduleName] = {
        displayName: moduleData.moduleDisplayName,
        summary: {
          totalCreated: moduleData.totalCreated,
          totalDeleted: moduleData.totalDeleted,
          currentId: moduleData.currentId,
          firstCreated: moduleData.firstCreated,
          lastCreated: moduleData.lastCreated,
          lastDeleted: moduleData.lastDeleted
        },
        statistics: moduleData.statistics,
        idObjects: moduleData.idObjects
      };
    });

    const output = outputPath || path.join(process.cwd(), 'tests', 'registry-detailed-report.json');
    fs.writeFileSync(output, JSON.stringify(report, null, 2));
    
    console.log(`✅ Detailed report exported to: ${output}`);
    return output;
  }

  /**
   * Find IDs by criteria
   */
  findIds(criteria) {
    const registry = this.getRegistry();
    if (!registry) return [];

    const results = [];

    Object.entries(registry.modules).forEach(([moduleName, moduleData]) => {
      if (!moduleData.idObjects) return;

      moduleData.idObjects.forEach(idObj => {
        let matches = true;

        // Filter by status
        if (criteria.status === 'active' && idObj.lifecycle.deleted) {
          matches = false;
        }
        if (criteria.status === 'deleted' && !idObj.lifecycle.deleted) {
          matches = false;
        }

        // Filter by format
        if (criteria.format && idObj.format !== criteria.format) {
          matches = false;
        }

        // Filter by module
        if (criteria.module && !moduleName.includes(criteria.module)) {
          matches = false;
        }

        // Filter by completed cycle
        if (criteria.completedCycle !== undefined && 
            idObj.lifecycle.completedFullCycle !== criteria.completedCycle) {
          matches = false;
        }

        if (matches) {
          results.push({
            module: moduleName,
            moduleDisplayName: idObj.moduleDisplayName,
            id: idObj.id,
            format: idObj.format,
            created: idObj.lifecycle.created,
            deleted: idObj.lifecycle.deleted,
            viewedCount: idObj.lifecycle.viewedCount || 0,
            completedFullCycle: idObj.lifecycle.completedFullCycle || false
          });
        }
      });
    });

    return results;
  }
}

// CLI interface when run directly
if (require.main === module) {
  const analyzer = new IdRegistryAnalyzer();
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'stats':
    case 'statistics':
      analyzer.displayComprehensiveStats();
      break;
    
    case 'details':
      const moduleName = args[1];
      const idValue = args[2];
      if (!moduleName || !idValue) {
        console.log('❌ Usage: node id-registry-analyzer.js details <module> <id>');
        break;
      }
      analyzer.displayIdObjectDetails(moduleName, idValue);
      break;
    
    case 'export':
      const outputPath = args[1];
      analyzer.exportDetailedReport(outputPath);
      break;
    
    case 'find':
      const criteria = {};
      for (let i = 1; i < args.length; i += 2) {
        const key = args[i].replace('--', '');
        const value = args[i + 1];
        
        if (key === 'status') criteria.status = value;
        if (key === 'format') criteria.format = value;
        if (key === 'module') criteria.module = value;
        if (key === 'completed') criteria.completedCycle = value === 'true';
      }
      
      const results = analyzer.findIds(criteria);
      console.log(`\n🔍 Found ${results.length} matching IDs:\n`);
      results.forEach(result => {
        const status = result.deleted ? '🗑️  DELETED' : '✅ ACTIVE';
        const cycle = result.completedFullCycle ? '[FULL CYCLE]' : '';
        console.log(`   ${status} ${result.id} ${cycle}`);
        console.log(`      Module: ${result.moduleDisplayName}`);
        console.log(`      Format: ${result.format} | Views: ${result.viewedCount}`);
        console.log(`      Created: ${result.created}`);
        console.log('');
      });
      break;
    
    default:
      console.log('\n📋 ID Registry Analyzer - Advanced Analysis Tool');
      console.log('\nUsage:');
      console.log('   node utils/id-registry-analyzer.js stats');
      console.log('      Display comprehensive statistics');
      console.log('');
      console.log('   node utils/id-registry-analyzer.js details <module> <id>');
      console.log('      Show detailed information for specific ID');
      console.log('');
      console.log('   node utils/id-registry-analyzer.js export [path]');
      console.log('      Export detailed report to JSON');
      console.log('');
      console.log('   node utils/id-registry-analyzer.js find [options]');
      console.log('      Find IDs by criteria');
      console.log('      Options: --status active|deleted');
      console.log('               --format UUID-v4|Numeric|etc');
      console.log('               --module <module-name>');
      console.log('               --completed true|false');
      console.log('');
  }
}

module.exports = IdRegistryAnalyzer;
