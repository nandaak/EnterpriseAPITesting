/**
 * Enhanced Schema Adapter
 * Adapts Enhanced-ERP-Api-Schema-With-Payloads.json for test execution
 * Handles <createdId> replacement and payload management
 */

const fs = require('fs');
const path = require('path');

class EnhancedSchemaAdapter {
  constructor(schemaPath = 'test-data/Input/Enhanced-ERP-Api-Schema-Advanced-Fixed.json') {
    this.schemaPath = schemaPath;
    this.schema = this.loadSchema();
    this.idRegistry = new Map();
  }

  /**
   * Load the enhanced schema
   */
  loadSchema() {
    try {
      const schemaContent = fs.readFileSync(this.schemaPath, 'utf8');
      return JSON.parse(schemaContent);
    } catch (error) {
      console.error(`Error loading schema: ${error.message}`);
      return {};
    }
  }

  /**
   * Get all available modules
   */
  getModules() {
    return Object.keys(this.schema);
  }

  /**
   * Get module configuration
   */
  getModuleConfig(moduleName) {
    return this.schema[moduleName] || null;
  }

  /**
   * Get operation from module
   */
  getOperation(moduleName, operationName) {
    const module = this.getModuleConfig(moduleName);
    if (!module || !module[operationName]) {
      return null;
    }
    return module[operationName];
  }

  /**
   * Convert Enhanced schema operation to standard format
   * Enhanced format: { "POST": [url, payload], "summary": "...", "parameters": [...] }
   * Standard format: [url, payload]
   */
  convertToStandardFormat(operation, httpMethod) {
    if (!operation) return null;

    // If operation has the HTTP method directly
    if (operation[httpMethod]) {
      return operation[httpMethod];
    }

    // If operation is already in standard format [url, payload]
    if (Array.isArray(operation) && operation.length >= 2) {
      return operation;
    }

    return null;
  }

  /**
   * Get POST operation (Create)
   */
  getPostOperation(moduleName, operationName) {
    const operation = this.getOperation(moduleName, operationName);
    return this.convertToStandardFormat(operation, 'POST');
  }

  /**
   * Get PUT operation (Update)
   */
  getPutOperation(moduleName, operationName) {
    const operation = this.getOperation(moduleName, operationName);
    return this.convertToStandardFormat(operation, 'PUT');
  }

  /**
   * Get DELETE operation
   */
  getDeleteOperation(moduleName, operationName) {
    const operation = this.getOperation(moduleName, operationName);
    return this.convertToStandardFormat(operation, 'DELETE');
  }

  /**
   * Get GET operation (View)
   */
  getGetOperation(moduleName, operationName) {
    const operation = this.getOperation(moduleName, operationName);
    return this.convertToStandardFormat(operation, 'GET');
  }

  /**
   * Find CRUD operations for a module
   * Returns object with POST, PUT, DELETE, GET operations
   */
  findCrudOperations(moduleName) {
    const module = this.getModuleConfig(moduleName);
    if (!module) return null;

    const operations = {
      POST: null,
      PUT: null,
      DELETE: null,
      GET: null
    };

    // Search through all operations in the module
    Object.keys(module).forEach(operationName => {
      const operation = module[operationName];
      
      if (typeof operation === 'object' && !Array.isArray(operation)) {
        // Check for each HTTP method
        if (operation.POST && !operations.POST) {
          operations.POST = { name: operationName, data: operation.POST };
        }
        if (operation.PUT && !operations.PUT) {
          operations.PUT = { name: operationName, data: operation.PUT };
        }
        if (operation.DELETE && !operations.DELETE) {
          operations.DELETE = { name: operationName, data: operation.DELETE };
        }
        if (operation.GET && !operations.GET) {
          operations.GET = { name: operationName, data: operation.GET };
        }
      }
    });

    return operations;
  }

  /**
   * Replace <createdId> in URL
   */
  replaceIdInUrl(url, createdId) {
    if (!url || typeof url !== 'string') return url;
    return url.replace(/<createdId>/g, createdId);
  }

  /**
   * Replace <createdId> in payload
   */
  replaceIdInPayload(payload, createdId) {
    if (!payload || typeof payload !== 'object') return payload;
    
    const jsonString = JSON.stringify(payload);
    const replaced = jsonString.replace(/"<createdId>"/g, `"${createdId}"`);
    return JSON.parse(replaced);
  }

  /**
   * Store created ID for module
   */
  storeId(moduleName, id) {
    this.idRegistry.set(moduleName, id);
  }

  /**
   * Get stored ID for module
   */
  getId(moduleName) {
    return this.idRegistry.get(moduleName);
  }

  /**
   * Check if module has minimum CRUD operations
   */
  hasMinimumCrudOperations(moduleName) {
    const operations = this.findCrudOperations(moduleName);
    if (!operations) return false;

    // At minimum, need POST and GET
    return operations.POST !== null && operations.GET !== null;
  }

  /**
   * Get testable modules (modules with minimum CRUD operations)
   */
  getTestableModules() {
    return this.getModules().filter(moduleName => 
      this.hasMinimumCrudOperations(moduleName)
    );
  }

  /**
   * Get module statistics
   */
  getModuleStats(moduleName) {
    const module = this.getModuleConfig(moduleName);
    if (!module) return null;

    const operations = this.findCrudOperations(moduleName);
    
    return {
      moduleName,
      totalOperations: Object.keys(module).length,
      hasPOST: operations.POST !== null,
      hasPUT: operations.PUT !== null,
      hasDELETE: operations.DELETE !== null,
      hasGET: operations.GET !== null,
      isTestable: this.hasMinimumCrudOperations(moduleName)
    };
  }

  /**
   * Get all modules statistics
   */
  getAllModulesStats() {
    return this.getModules().map(moduleName => 
      this.getModuleStats(moduleName)
    );
  }

  /**
   * Prepare operation for execution
   * Replaces <createdId> if provided
   */
  prepareOperation(operation, createdId = null) {
    if (!operation || !Array.isArray(operation) || operation.length < 2) {
      return null;
    }

    let [url, payload] = operation;

    if (createdId) {
      url = this.replaceIdInUrl(url, createdId);
      payload = this.replaceIdInPayload(payload, createdId);
    }

    return [url, payload];
  }

  /**
   * Get operation summary
   */
  getOperationSummary(moduleName, operationName) {
    const operation = this.getOperation(moduleName, operationName);
    if (!operation || typeof operation !== 'object') return null;

    return {
      summary: operation.summary || '',
      parameters: operation.parameters || []
    };
  }
}

module.exports = EnhancedSchemaAdapter;
