// utils/id-registry-manager.js - Centralized ID Registry Management Utility
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

/**
 * Utility class for managing the centralized ID registry
 * Provides methods to query, analyze, and maintain the registry
 */
class IdRegistryManager {
  constructor() {
    this.registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
  }

  /**
   * Get the complete registry
   */
  getRegistry() {
    try {
      if (!fs.existsSync(this.registryPath)) {
        return this.createEmptyRegistry();
      }
      return JSON.parse(fs.readFileSync(this.registryPath, 'utf8'));
    } catch (error) {
      logger.error(`Failed to read registry: ${error.message}`);
      return this.createEmptyRegistry();
    }
  }

  /**
   * Create an empty registry structure
   */
  createEmptyRegistry() {
    return {
      modules: {},
      metadata: {
        created: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        totalModules: 0,
        description: "Centralized storage for all created resource IDs across all tested modules"
      }
    };
  }

  /**
   * Get all IDs for a specific module
   */
  getModuleIds(moduleName) {
    const registry = this.getRegistry();
    return registry.modules[moduleName]?.ids || [];
  }

  /**
   * Get the current active ID for a module
   */
  getCurrentId(moduleName) {
    const registry = this.getRegistry();
    return registry.modules[moduleName]?.currentId || null;
  }

  /**
   * Get all modules in the registry
   */
  getAllModules() {
    const registry = this.getRegistry();
    return Object.keys(registry.modules);
  }

  /**
   * Get comprehensive statistics
   */
  getStatistics() {
    const registry = this.getRegistry();
    const stats = {
      totalModules: Object.keys(registry.modules).length,
      totalIds: 0,
      activeIds: 0,
      deletedIds: 0,
      modules: []
    };

    Object.entries(registry.modules).forEach(([moduleName, moduleData]) => {
      stats.totalIds += moduleData.totalCreated || 0;
      if (moduleData.currentId) {
        stats.activeIds++;
      } else {
        stats.deletedIds++;
      }

      stats.modules.push({
        name: moduleName,
        totalCreated: moduleData.totalCreated || 0,
        currentId: moduleData.currentId || null,
        hasActiveId: !!moduleData.currentId,
        firstCreated: moduleData.firstCreated || null,
        lastCreated: moduleData.lastCreated || null,
        lastDeleted: moduleData.lastDeleted || null
      });
    });

    return stats;
  }

  /**
   * Display formatted statistics
   */
  displayStatistics() {
    const stats = this.getStatistics();
    
    console.log('\n' + '='.repeat(70));
    console.log('📊 CENTRALIZED ID REGISTRY STATISTICS');
    console.log('='.repeat(70));
    console.log(`📁 Registry Location: ${this.registryPath}`);
    console.log(`📦 Total Modules: ${stats.totalModules}`);
    console.log(`🆔 Total IDs Created: ${stats.totalIds}`);
    console.log(`✅ Active IDs: ${stats.activeIds}`);
    console.log(`🗑️  Deleted IDs: ${stats.deletedIds}`);
    console.log('='.repeat(70));
    
    if (stats.modules.length > 0) {
      console.log('\n📋 MODULE DETAILS:');
      stats.modules.forEach(module => {
        const status = module.hasActiveId ? '✅ ACTIVE' : '🗑️  DELETED';
        console.log(`\n   ${status} - ${module.name}`);
        console.log(`      Total Created: ${module.totalCreated}`);
        console.log(`      Current ID: ${module.currentId || 'None'}`);
        console.log(`      First Created: ${module.firstCreated || 'N/A'}`);
        console.log(`      Last Created: ${module.lastCreated || 'N/A'}`);
        if (module.lastDeleted) {
          console.log(`      Last Deleted: ${module.lastDeleted}`);
        }
      });
    }
    
    console.log('\n' + '='.repeat(70) + '\n');
  }

  /**
   * Clean up old IDs (keep only last N per module)
   */
  cleanupOldIds(keepCount = 10) {
    try {
      const registry = this.getRegistry();
      let totalRemoved = 0;

      Object.keys(registry.modules).forEach(moduleName => {
        const moduleData = registry.modules[moduleName];
        if (moduleData.ids && moduleData.ids.length > keepCount) {
          const removed = moduleData.ids.length - keepCount;
          moduleData.ids = moduleData.ids.slice(-keepCount);
          moduleData.totalCreated = moduleData.ids.length;
          totalRemoved += removed;
        }
      });

      if (totalRemoved > 0) {
        registry.metadata.lastUpdated = new Date().toISOString();
        fs.writeFileSync(this.registryPath, JSON.stringify(registry, null, 2));
        logger.info(`✅ Cleaned up ${totalRemoved} old IDs from registry`);
      } else {
        logger.info('✅ No cleanup needed - all modules within limits');
      }

      return totalRemoved;
    } catch (error) {
      logger.error(`Failed to cleanup registry: ${error.message}`);
      return 0;
    }
  }

  /**
   * Export registry to a readable format
   */
  exportToReadable(outputPath = null) {
    try {
      const registry = this.getRegistry();
      const stats = this.getStatistics();
      
      const readable = {
        summary: {
          totalModules: stats.totalModules,
          totalIds: stats.totalIds,
          activeIds: stats.activeIds,
          deletedIds: stats.deletedIds,
          lastUpdated: registry.metadata.lastUpdated
        },
        modules: stats.modules
      };

      const output = outputPath || path.join(process.cwd(), 'tests', 'registry-report.json');
      fs.writeFileSync(output, JSON.stringify(readable, null, 2));
      
      logger.info(`✅ Registry exported to: ${output}`);
      return output;
    } catch (error) {
      logger.error(`Failed to export registry: ${error.message}`);
      return null;
    }
  }

  /**
   * Search for IDs across all modules
   */
  searchId(searchTerm) {
    const registry = this.getRegistry();
    const results = [];

    Object.entries(registry.modules).forEach(([moduleName, moduleData]) => {
      if (moduleData.ids) {
        moduleData.ids.forEach(idEntry => {
          if (idEntry.id.includes(searchTerm)) {
            results.push({
              module: moduleName,
              id: idEntry.id,
              timestamp: idEntry.timestamp,
              isCurrent: idEntry.id === moduleData.currentId
            });
          }
        });
      }
    });

    return results;
  }
}

// CLI interface when run directly
if (require.main === module) {
  const manager = new IdRegistryManager();
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'stats':
    case 'statistics':
      manager.displayStatistics();
      break;
    
    case 'cleanup':
      const keepCount = parseInt(args[1]) || 10;
      console.log(`\n🧹 Cleaning up registry (keeping last ${keepCount} IDs per module)...`);
      const removed = manager.cleanupOldIds(keepCount);
      console.log(`✅ Removed ${removed} old IDs\n`);
      break;
    
    case 'export':
      const outputPath = args[1];
      console.log('\n📤 Exporting registry...');
      const exported = manager.exportToReadable(outputPath);
      if (exported) {
        console.log(`✅ Exported to: ${exported}\n`);
      }
      break;
    
    case 'search':
      const searchTerm = args[1];
      if (!searchTerm) {
        console.log('❌ Please provide a search term');
        break;
      }
      console.log(`\n🔍 Searching for: ${searchTerm}`);
      const results = manager.searchId(searchTerm);
      if (results.length > 0) {
        console.log(`\n✅ Found ${results.length} matches:`);
        results.forEach(result => {
          const status = result.isCurrent ? '[CURRENT]' : '[HISTORICAL]';
          console.log(`   ${status} ${result.module}`);
          console.log(`      ID: ${result.id}`);
          console.log(`      Created: ${result.timestamp}`);
        });
      } else {
        console.log('❌ No matches found');
      }
      console.log('');
      break;
    
    case 'module':
      const moduleName = args[1];
      if (!moduleName) {
        console.log('❌ Please provide a module name');
        break;
      }
      const moduleIds = manager.getModuleIds(moduleName);
      console.log(`\n📦 Module: ${moduleName}`);
      console.log(`   Total IDs: ${moduleIds.length}`);
      if (moduleIds.length > 0) {
        console.log('\n   IDs:');
        moduleIds.forEach((idEntry, index) => {
          console.log(`      ${index + 1}. ${idEntry.id} (${idEntry.timestamp})`);
        });
      }
      console.log('');
      break;
    
    default:
      console.log('\n📋 ID Registry Manager - Usage:');
      console.log('   node utils/id-registry-manager.js stats          - Display statistics');
      console.log('   node utils/id-registry-manager.js cleanup [N]    - Keep only last N IDs per module');
      console.log('   node utils/id-registry-manager.js export [path]  - Export to readable format');
      console.log('   node utils/id-registry-manager.js search <term>  - Search for IDs');
      console.log('   node utils/id-registry-manager.js module <name>  - View module IDs');
      console.log('');
  }
}

module.exports = IdRegistryManager;
