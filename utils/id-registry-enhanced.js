// utils/id-registry-enhanced.js
/**
 * Enhanced ID Registry Management System
 * 
 * Provides comprehensive management of all created IDs across all ERP modules
 * Maintains:
 * - tests/createdId.json (current/latest ID for active module)
 * - createdId.txt (simple text file with current ID)
 * - tests/createdIds.json (complete registry of ALL IDs from ALL modules)
 * 
 * Features:
 * - Complete history of all created IDs
 * - Module-based organization
 * - Lifecycle tracking (created, updated, deleted, viewed)
 * - Statistics and analytics
 * - Query and search capabilities
 * - Export and reporting
 * 
 * @version 2.0.0
 * @author Professional Enhancement Team
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger');
const IDTypeManager = require('./id-type-manager');

class IDRegistryEnhanced {
  constructor() {
    this.registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
    this.legacyPath = path.join(process.cwd(), 'tests', 'createdId.json');
    this.txtPath = path.join(process.cwd(), 'createdId.txt');
  }

  /**
   * Initialize registry with proper structure
   */
  initializeRegistry() {
    const registry = {
      metadata: {
        version: '2.0.0',
        created: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        totalModules: 0,
        totalIds: 0,
        totalActive: 0,
        totalDeleted: 0,
        description: 'Centralized registry for all created resource IDs across all ERP modules'
      },
      modules: {},
      allIds: [], // Complete flat list of all ID objects
      statistics: {
        idTypeDistribution: {},
        moduleDistribution: {},
        creationTimeline: [],
        averageIdLength: 0,
        mostActiveModule: null,
        recentActivity: []
      }
    };

    return registry;
  }

  /**
   * Load existing registry or create new one
   */
  loadRegistry() {
    try {
      if (fs.existsSync(this.registryPath)) {
        const data = fs.readFileSync(this.registryPath, 'utf8');
        const registry = JSON.parse(data);
        
        // Ensure allIds array exists (for backward compatibility)
        if (!registry.allIds) {
          registry.allIds = [];
        }
        
        // Ensure statistics exists
        if (!registry.statistics) {
          registry.statistics = {
            idTypeDistribution: {},
            moduleDistribution: {},
            creationTimeline: [],
            averageIdLength: 0,
            mostActiveModule: null,
            recentActivity: []
          };
        }
        
        return registry;
      }
      
      return this.initializeRegistry();
    } catch (error) {
      logger.error(`Failed to load registry: ${error.message}`);
      return this.initializeRegistry();
    }
  }

  /**
   * Save registry to file
   */
  saveRegistry(registry) {
    try {
      fs.writeFileSync(this.registryPath, JSON.stringify(registry, null, 2), 'utf8');
      return true;
    } catch (error) {
      logger.error(`Failed to save registry: ${error.message}`);
      return false;
    }
  }

  /**
   * Add new ID to registry with complete metadata
   * 
   * @param {Object} params - ID parameters
   * @param {string} params.id - The ID value
   * @param {string} params.modulePath - Module path (e.g., "Accounting.Master_Data.Chart_of_Accounts")
   * @param {Object} params.responseData - Original API response data
   * @param {string} params.testPhase - Current test phase
   * @param {Object} params.additionalMetadata - Any additional metadata
   */
  addID(params) {
    const {
      id,
      modulePath,
      responseData = null,
      testPhase = 'CREATE',
      additionalMetadata = {}
    } = params;

    try {
      const registry = this.loadRegistry();
      const timestamp = new Date().toISOString();

      // Detect ID type
      const idDetection = IDTypeManager.detectIDType(id);

      // Create comprehensive ID object
      const idObject = {
        // Core ID information
        id: id,
        idType: idDetection.type,
        idFormat: idDetection.format,
        idMetadata: idDetection.metadata,
        
        // Module information
        module: modulePath,
        moduleDisplayName: this.formatModuleName(modulePath),
        
        // Timestamps
        timestamp: timestamp,
        createdAt: timestamp,
        
        // Lifecycle tracking
        lifecycle: {
          created: timestamp,
          updated: null,
          deleted: null,
          viewedCount: 0,
          lastViewed: null,
          updateCount: 0,
          lastUpdated: null
        },
        
        // Test information
        testInfo: {
          phase: testPhase,
          suite: 'comprehensive-CRUD-Validation',
          timestamp: timestamp
        },
        
        // API information
        apiInfo: {
          endpoint: additionalMetadata.endpoint || null,
          method: 'POST',
          responseStatus: additionalMetadata.responseStatus || null
        },
        
        // Data snapshot (sanitized)
        dataSnapshot: responseData ? this.sanitizeData(responseData) : null,
        
        // Status
        status: 'active',
        
        // Additional metadata
        metadata: additionalMetadata
      };

      // Initialize module if doesn't exist
      if (!registry.modules[modulePath]) {
        registry.modules[modulePath] = {
          moduleName: modulePath,
          moduleDisplayName: this.formatModuleName(modulePath),
          ids: [],
          firstCreated: timestamp,
          lastCreated: timestamp,
          lastDeleted: null,
          totalCreated: 0,
          totalDeleted: 0,
          totalActive: 0,
          currentId: null,
          statistics: {
            idTypes: {},
            averageIdLength: 0,
            creationTimes: []
          }
        };
      }

      // Add to module's ID list
      registry.modules[modulePath].ids.push(idObject);
      registry.modules[modulePath].lastCreated = timestamp;
      registry.modules[modulePath].totalCreated++;
      registry.modules[modulePath].totalActive++;
      registry.modules[modulePath].currentId = id;

      // Update module statistics
      this.updateModuleStatistics(registry.modules[modulePath], idObject);

      // Add to complete flat list (allIds)
      registry.allIds.push(idObject);

      // Update global metadata
      registry.metadata.lastUpdated = timestamp;
      registry.metadata.totalModules = Object.keys(registry.modules).length;
      registry.metadata.totalIds = registry.allIds.length;
      registry.metadata.totalActive = registry.allIds.filter(obj => obj.status === 'active').length;
      registry.metadata.totalDeleted = registry.allIds.filter(obj => obj.status === 'deleted').length;

      // Update global statistics
      this.updateGlobalStatistics(registry);

      // Save registry
      this.saveRegistry(registry);

      // Also save to legacy files for backward compatibility
      this.saveLegacyFiles(id, modulePath, idObject);

      logger.info(`✅ ID added to registry: ${id} (${idDetection.type}) for module ${modulePath}`);
      logger.debug(`📊 Total IDs in registry: ${registry.metadata.totalIds}`);

      return {
        success: true,
        idObject: idObject,
        registryStats: {
          totalIds: registry.metadata.totalIds,
          totalModules: registry.metadata.totalModules,
          moduleIdCount: registry.modules[modulePath].totalCreated
        }
      };

    } catch (error) {
      logger.error(`Failed to add ID to registry: ${error.message}`);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update ID lifecycle (for UPDATE operations)
   */
  updateIDLifecycle(id, modulePath, updateData = {}) {
    try {
      const registry = this.loadRegistry();
      const timestamp = new Date().toISOString();

      // Find the ID in module
      const module = registry.modules[modulePath];
      if (!module) {
        logger.warn(`Module ${modulePath} not found in registry`);
        return false;
      }

      // Find the ID object
      const idObj = module.ids.find(obj => obj.id === id);
      if (!idObj) {
        logger.warn(`ID ${id} not found in module ${modulePath}`);
        return false;
      }

      // Update lifecycle
      idObj.lifecycle.updated = timestamp;
      idObj.lifecycle.lastUpdated = timestamp;
      idObj.lifecycle.updateCount = (idObj.lifecycle.updateCount || 0) + 1;

      // Update in allIds array
      const allIdObj = registry.allIds.find(obj => obj.id === id && obj.module === modulePath);
      if (allIdObj) {
        allIdObj.lifecycle = idObj.lifecycle;
      }

      // Update metadata
      registry.metadata.lastUpdated = timestamp;

      // Save
      this.saveRegistry(registry);

      logger.debug(`✅ ID lifecycle updated: ${id} (update count: ${idObj.lifecycle.updateCount})`);
      return true;

    } catch (error) {
      logger.error(`Failed to update ID lifecycle: ${error.message}`);
      return false;
    }
  }

  /**
   * Mark ID as deleted
   */
  markIDAsDeleted(id, modulePath) {
    try {
      const registry = this.loadRegistry();
      const timestamp = new Date().toISOString();

      // Find and update in module
      const module = registry.modules[modulePath];
      if (module) {
        const idObj = module.ids.find(obj => obj.id === id);
        if (idObj) {
          idObj.status = 'deleted';
          idObj.lifecycle.deleted = timestamp;
          module.totalDeleted++;
          module.totalActive--;
          module.lastDeleted = timestamp;
          module.currentId = null;
        }
      }

      // Update in allIds array
      const allIdObj = registry.allIds.find(obj => obj.id === id && obj.module === modulePath);
      if (allIdObj) {
        allIdObj.status = 'deleted';
        allIdObj.lifecycle.deleted = timestamp;
      }

      // Update global metadata
      registry.metadata.totalActive = registry.allIds.filter(obj => obj.status === 'active').length;
      registry.metadata.totalDeleted = registry.allIds.filter(obj => obj.status === 'deleted').length;
      registry.metadata.lastUpdated = timestamp;

      // Save
      this.saveRegistry(registry);

      logger.info(`✅ ID marked as deleted: ${id} from module ${modulePath}`);
      return true;

    } catch (error) {
      logger.error(`Failed to mark ID as deleted: ${error.message}`);
      return false;
    }
  }

  /**
   * Record VIEW operation
   */
  recordView(id, modulePath) {
    try {
      const registry = this.loadRegistry();
      const timestamp = new Date().toISOString();

      // Update in module
      const module = registry.modules[modulePath];
      if (module) {
        const idObj = module.ids.find(obj => obj.id === id);
        if (idObj) {
          idObj.lifecycle.viewedCount = (idObj.lifecycle.viewedCount || 0) + 1;
          idObj.lifecycle.lastViewed = timestamp;
        }
      }

      // Update in allIds
      const allIdObj = registry.allIds.find(obj => obj.id === id && obj.module === modulePath);
      if (allIdObj) {
        allIdObj.lifecycle.viewedCount = (allIdObj.lifecycle.viewedCount || 0) + 1;
        allIdObj.lifecycle.lastViewed = timestamp;
      }

      // Save
      this.saveRegistry(registry);

      return true;

    } catch (error) {
      logger.error(`Failed to record view: ${error.message}`);
      return false;
    }
  }

  /**
   * Get all IDs (complete flat list)
   */
  getAllIDs(filters = {}) {
    try {
      const registry = this.loadRegistry();
      let ids = [...registry.allIds];

      // Apply filters
      if (filters.module) {
        ids = ids.filter(obj => obj.module === filters.module);
      }

      if (filters.status) {
        ids = ids.filter(obj => obj.status === filters.status);
      }

      if (filters.idType) {
        ids = ids.filter(obj => obj.idType === filters.idType);
      }

      if (filters.since) {
        ids = ids.filter(obj => new Date(obj.timestamp) >= new Date(filters.since));
      }

      return ids;

    } catch (error) {
      logger.error(`Failed to get all IDs: ${error.message}`);
      return [];
    }
  }

  /**
   * Get IDs for specific module
   */
  getModuleIDs(modulePath) {
    try {
      const registry = this.loadRegistry();
      const module = registry.modules[modulePath];
      
      return module ? module.ids : [];

    } catch (error) {
      logger.error(`Failed to get module IDs: ${error.message}`);
      return [];
    }
  }

  /**
   * Get registry statistics
   */
  getStatistics() {
    try {
      const registry = this.loadRegistry();
      
      return {
        metadata: registry.metadata,
        statistics: registry.statistics,
        modules: Object.keys(registry.modules).map(modulePath => ({
          module: modulePath,
          displayName: registry.modules[modulePath].moduleDisplayName,
          totalCreated: registry.modules[modulePath].totalCreated,
          totalActive: registry.modules[modulePath].totalActive,
          totalDeleted: registry.modules[modulePath].totalDeleted,
          currentId: registry.modules[modulePath].currentId
        }))
      };

    } catch (error) {
      logger.error(`Failed to get statistics: ${error.message}`);
      return null;
    }
  }

  /**
   * Export complete registry as JSON
   */
  exportRegistry(outputPath = null) {
    try {
      const registry = this.loadRegistry();
      
      if (outputPath) {
        fs.writeFileSync(outputPath, JSON.stringify(registry, null, 2), 'utf8');
        logger.info(`✅ Registry exported to: ${outputPath}`);
      }
      
      return registry;

    } catch (error) {
      logger.error(`Failed to export registry: ${error.message}`);
      return null;
    }
  }

  /**
   * Export all IDs as simple list
   */
  exportAllIDsList(outputPath = null) {
    try {
      const registry = this.loadRegistry();
      const simpleList = registry.allIds.map(obj => ({
        id: obj.id,
        type: obj.idType,
        module: obj.moduleDisplayName,
        created: obj.createdAt,
        status: obj.status
      }));

      if (outputPath) {
        fs.writeFileSync(outputPath, JSON.stringify(simpleList, null, 2), 'utf8');
        logger.info(`✅ ID list exported to: ${outputPath}`);
      }

      return simpleList;

    } catch (error) {
      logger.error(`Failed to export ID list: ${error.message}`);
      return [];
    }
  }

  /**
   * Generate report
   */
  generateReport() {
    try {
      const registry = this.loadRegistry();
      const stats = this.getStatistics();

      const report = {
        summary: {
          totalModules: registry.metadata.totalModules,
          totalIDs: registry.metadata.totalIds,
          activeIDs: registry.metadata.totalActive,
          deletedIDs: registry.metadata.totalDeleted,
          lastUpdated: registry.metadata.lastUpdated
        },
        idTypeDistribution: registry.statistics.idTypeDistribution,
        moduleDistribution: registry.statistics.moduleDistribution,
        topModules: this.getTopModules(registry, 10),
        recentActivity: registry.statistics.recentActivity.slice(0, 20),
        modules: stats.modules
      };

      return report;

    } catch (error) {
      logger.error(`Failed to generate report: ${error.message}`);
      return null;
    }
  }

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  /**
   * Format module name for display
   */
  formatModuleName(modulePath) {
    if (!modulePath) return '';
    return modulePath.split('.').map(part => 
      part.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    ).join(' → ');
  }

  /**
   * Sanitize data for storage
   */
  sanitizeData(data) {
    if (!data || typeof data !== 'object') return null;

    try {
      const sanitized = JSON.parse(JSON.stringify(data));
      
      // Remove sensitive fields
      const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'authorization'];
      const removeSensitive = (obj) => {
        if (typeof obj !== 'object' || obj === null) return;
        
        Object.keys(obj).forEach(key => {
          if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
            obj[key] = '[REDACTED]';
          } else if (typeof obj[key] === 'object') {
            removeSensitive(obj[key]);
          }
        });
      };
      
      removeSensitive(sanitized);
      
      // Limit size
      const limitSize = (obj) => {
        if (typeof obj !== 'object' || obj === null) return;
        
        Object.keys(obj).forEach(key => {
          if (typeof obj[key] === 'string' && obj[key].length > 100) {
            obj[key] = obj[key].substring(0, 100) + '... [truncated]';
          } else if (typeof obj[key] === 'object') {
            limitSize(obj[key]);
          }
        });
      };
      
      limitSize(sanitized);
      
      return sanitized;
    } catch (error) {
      return null;
    }
  }

  /**
   * Update module statistics
   */
  updateModuleStatistics(module, idObject) {
    // Update ID types
    if (!module.statistics.idTypes) {
      module.statistics.idTypes = {};
    }
    module.statistics.idTypes[idObject.idType] = 
      (module.statistics.idTypes[idObject.idType] || 0) + 1;

    // Update average ID length
    const totalLength = module.ids.reduce((sum, obj) => sum + (obj.id.length || 0), 0);
    module.statistics.averageIdLength = (totalLength / module.ids.length).toFixed(2);

    // Track creation times (keep last 10)
    if (!module.statistics.creationTimes) {
      module.statistics.creationTimes = [];
    }
    module.statistics.creationTimes.push(idObject.timestamp);
    if (module.statistics.creationTimes.length > 10) {
      module.statistics.creationTimes = module.statistics.creationTimes.slice(-10);
    }
  }

  /**
   * Update global statistics
   */
  updateGlobalStatistics(registry) {
    // ID type distribution
    registry.statistics.idTypeDistribution = {};
    registry.allIds.forEach(obj => {
      registry.statistics.idTypeDistribution[obj.idType] = 
        (registry.statistics.idTypeDistribution[obj.idType] || 0) + 1;
    });

    // Module distribution
    registry.statistics.moduleDistribution = {};
    Object.keys(registry.modules).forEach(modulePath => {
      registry.statistics.moduleDistribution[modulePath] = 
        registry.modules[modulePath].totalCreated;
    });

    // Average ID length
    const totalLength = registry.allIds.reduce((sum, obj) => sum + (obj.id.length || 0), 0);
    registry.statistics.averageIdLength = registry.allIds.length > 0 
      ? (totalLength / registry.allIds.length).toFixed(2) 
      : 0;

    // Most active module
    let maxCount = 0;
    let mostActive = null;
    Object.keys(registry.modules).forEach(modulePath => {
      if (registry.modules[modulePath].totalCreated > maxCount) {
        maxCount = registry.modules[modulePath].totalCreated;
        mostActive = modulePath;
      }
    });
    registry.statistics.mostActiveModule = mostActive;

    // Recent activity (keep last 50)
    if (!registry.statistics.recentActivity) {
      registry.statistics.recentActivity = [];
    }
    registry.statistics.recentActivity = registry.allIds
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 50)
      .map(obj => ({
        id: obj.id,
        module: obj.moduleDisplayName,
        timestamp: obj.timestamp,
        status: obj.status
      }));
  }

  /**
   * Get top modules by ID count
   */
  getTopModules(registry, limit = 10) {
    return Object.keys(registry.modules)
      .map(modulePath => ({
        module: modulePath,
        displayName: registry.modules[modulePath].moduleDisplayName,
        count: registry.modules[modulePath].totalCreated
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Save to legacy files for backward compatibility
   */
  saveLegacyFiles(id, modulePath, idObject) {
    try {
      // Save to createdId.txt
      fs.writeFileSync(this.txtPath, id, 'utf8');

      // Save to createdId.json
      const legacyObject = {
        id: id,
        module: modulePath,
        timestamp: idObject.timestamp,
        type: idObject.idType,
        length: id.length
      };
      fs.writeFileSync(this.legacyPath, JSON.stringify(legacyObject, null, 2), 'utf8');

      return true;
    } catch (error) {
      logger.error(`Failed to save legacy files: ${error.message}`);
      return false;
    }
  }
}

module.exports = IDRegistryEnhanced;
