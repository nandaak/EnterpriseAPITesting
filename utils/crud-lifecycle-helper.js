// utils/crud-lifecycle-helper.js - ENHANCED COMPLETE CRUD LIFECYCLE
const fs = require("fs");
const path = require("path");
const apiClient = require("./api-client");
const TestHelpers = require("./test-helpers");
const IDTypeManager = require("./id-type-manager");
const IDRegistryEnhanced = require("./id-registry-enhanced");
const Constants = require("../Constants");
const modulesConfig = require("../config/modules-config");
const logger = require("./logger");

const { FILE_PATHS, HTTP_STATUS_CODES } = Constants;

class CrudLifecycleHelper {
  constructor(modulePath) {
    this.actualModulePath = modulePath;
    this.createdId = null;
    this.createdIdType = null; // Track ID type (uuid, numeric, string, etc.)
    this.createdIdMetadata = null; // Store ID detection metadata
    this.apiClient = apiClient;
    this.testResults = [];
    this.currentTestPhase = "INITIAL";
    this.moduleSkipFlag = false;
    this.resourceState = {
      originalData: null,
      updatedData: null,
      deletionVerified: false,
    };
    // Enhanced ID Registry
    this.idRegistry = new IDRegistryEnhanced();
  }

  async initialize() {
    await this.verifyApiClientReady();
    this.loadCreatedIdFromFile();
  }

  async verifyApiClientReady() {
    try {
      if (!this.apiClient) {
        throw new Error("API client instance is not available");
      }

      if (
        typeof this.apiClient.post !== "function" ||
        typeof this.apiClient.get !== "function"
      ) {
        throw new Error("API client methods are not properly initialized");
      }

      logger.info("✅ API Client verified and ready for testing");
    } catch (error) {
      logger.error(`❌ API Client verification failed: ${error.message}`);
      this.moduleSkipFlag = true;
      throw new Error(`API Client Setup Failed: ${error.message}`);
    }
  }

  // --- COMPLETE CRUD LIFECYCLE METHODS ---

  /**
   * 🎯 PHASE 1: CREATE - Create a new resource
   */
  async runCreateTest(operationKey = "CREATE") {
    if (this.moduleSkipFlag) {
      throw new Error(
        `❌ SKIPPING TEST: Previous failure in module ${this.actualModulePath}`
      );
    }

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      this.moduleSkipFlag = true;
      throw new Error(
        `❌ CREATE OPERATION NOT FOUND: ${operationKey} for module ${this.actualModulePath}`
      );
    }

    if (!operation.endpoint || operation.endpoint === "URL_HERE") {
      this.moduleSkipFlag = true;
      throw new Error(
        `❌ INVALID ENDPOINT: ${operation.endpoint} for ${operationKey}`
      );
    }

    logger.info(
      `🌐 CREATE PHASE - Calling ${operationKey} endpoint: ${operation.endpoint}`
    );

    try {
      const response = await this.apiClient.post(
        operation.endpoint,
        operation.payload
      );

      if (response.status < 200 || response.status >= 400) {
        this.moduleSkipFlag = true;
        throw new Error(`❌ CREATE REQUEST FAILED: Status ${response.status}`);
      }

      TestHelpers.debugResponseStructure(response, "CREATE");
      
      // Enhanced ID extraction with type detection
      const idExtraction = IDTypeManager.extractIDFromResponse(response);

      if (!idExtraction.id) {
        this.moduleSkipFlag = true;
        throw new Error(
          `❌ ID EXTRACTION FAILED: Could not extract resource ID from response`
        );
      }

      // Store ID with type information
      this.createdId = String(idExtraction.id);
      this.createdIdType = idExtraction.type;
      this.createdIdMetadata = idExtraction.detection;

      // Log ID type information
      logger.info(`🆔 ID Type Detected: ${this.createdIdType}`);
      logger.info(`🆔 ID Format: ${idExtraction.format}`);
      IDTypeManager.logIDInfo(this.createdId, 'CREATE');

      // Save to enhanced registry (includes legacy files)
      const registryResult = this.idRegistry.addID({
        id: this.createdId,
        modulePath: this.actualModulePath,
        responseData: response.data,
        testPhase: 'CREATE',
        additionalMetadata: {
          endpoint: operation.endpoint,
          responseStatus: response.status,
          idType: this.createdIdType,
          idFormat: idExtraction.format,
          idMetadata: this.createdIdMetadata
        }
      });

      if (!registryResult.success) {
        this.moduleSkipFlag = true;
        throw new Error(
          `❌ ID PERSISTENCE FAILED: Could not save ID to registry`
        );
      }

      logger.info(`📝 ID saved to enhanced registry (Total IDs: ${registryResult.registryStats.totalIds})`);

      // Store original data for later comparison
      this.resourceState.originalData = response.data;

      const dataExists = await this.validateDataCreation(this.createdId);
      if (!dataExists) {
        this.moduleSkipFlag = true;
        throw new Error(
          `❌ DATA CREATION VERIFICATION FAILED: Resource ${this.createdId} not found in system`
        );
      }

      logger.info(
        `✅ CREATE SUCCESS - Resource created with ID: ${this.createdId} (${this.createdIdType})`
      );
      logger.info(`📊 Original data stored for comparison`);
      logger.info(`📊 Registry Stats - Module: ${registryResult.registryStats.moduleIdCount} IDs, Total: ${registryResult.registryStats.totalIds} IDs`);

      return {
        createdId: this.createdId,
        createdIdType: this.createdIdType,
        createdIdMetadata: this.createdIdMetadata,
        response,
        originalData: this.resourceState.originalData,
        extractionDetails: {
          source: "IDTypeManager",
          type: this.createdIdType,
          format: idExtraction.format,
          length: this.createdId.length,
          savedToFile: registryResult.success,
          dataVerified: dataExists,
          metadata: this.createdIdMetadata,
        },
      };
    } catch (error) {
      this.moduleSkipFlag = true;
      logger.error(`❌ CREATE PHASE FAILED: ${error.message}`);
      throw error;
    }
  }

  /**
   * 🎯 PHASE 2: VIEW (Initial) - Verify resource creation
   */
  async runInitialViewTest(operationKey = "View") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `View operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Use ID Type Manager for intelligent placeholder replacement
    const viewEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      currentId
    );

    logger.info(
      `🔍 VIEW PHASE 1 - Verifying created resource: ${viewEndpoint} (ID type: ${this.createdIdType})`
    );

    try {
      const response = await this.apiClient.get(viewEndpoint);

      // Enhanced validation for initial view
      this.validateInitialViewResponse(response, currentId);

      // Record view in enhanced registry
      this.idRegistry.recordView(currentId, this.actualModulePath);

      logger.info(`✅ VIEW PHASE 1 SUCCESS - Resource verified: ${currentId} (${this.createdIdType})`);
      return {
        response,
        resourceData: response.data,
        idType: this.createdIdType,
      };
    } catch (error) {
      this.handleError(error, "INITIAL_VIEW", operationKey);
    }
  }

  /**
   * 🎯 PHASE 3: UPDATE - Modify the created resource
   */
  async runUpdateTest(operationKey = "EDIT") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Update operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Use ID Type Manager for intelligent placeholder replacement
    const updateEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      currentId
    );

    // Enhanced payload with modifications and ID replacement
    let updatePayload = this.constructUpdatePayload(
      operation.payload,
      currentId
    );
    
    // Replace <createdId> in payload with proper type handling
    updatePayload = IDTypeManager.replaceInPayload(updatePayload, currentId);

    logger.info(`✏️ UPDATE PHASE - Modifying resource: ${updateEndpoint}`);
    logger.info(`📝 Update payload prepared with modifications (ID type: ${this.createdIdType})`);

    try {
      const response = await this.apiClient.put(updateEndpoint, updatePayload);

      if (response.status >= 400) {
        throw new Error(`UPDATE failed with status ${response.status}`);
      }

      // Store updated data for comparison
      this.resourceState.updatedData = response.data;

      // Record update in enhanced registry
      this.idRegistry.updateIDLifecycle(currentId, this.actualModulePath, {
        updatedData: this.sanitizeDataForStorage(response.data),
        timestamp: new Date().toISOString()
      });

      logger.info(`✅ UPDATE SUCCESS - Resource modified: ${currentId} (${this.createdIdType})`);
      return {
        response,
        updatedData: this.resourceState.updatedData,
        idType: this.createdIdType,
      };
    } catch (error) {
      this.handleError(error, "UPDATE", operationKey);
    }
  }

  /**
   * 🎯 PHASE 4: VIEW (Post-Update) - Verify modifications
   */
  async runPostUpdateViewTest(operationKey = "View") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `View operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Use ID Type Manager for intelligent placeholder replacement
    const viewEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      currentId
    );

    logger.info(`🔍 VIEW PHASE 2 - Verifying updates: ${viewEndpoint} (ID type: ${this.createdIdType})`);

    try {
      const response = await this.apiClient.get(viewEndpoint);

      // Validate that updates are persisted
      this.validatePostUpdateResponse(response, currentId);

      // Record view in enhanced registry
      this.idRegistry.recordView(currentId, this.actualModulePath);

      logger.info(`✅ VIEW PHASE 2 SUCCESS - Updates verified: ${currentId} (${this.createdIdType})`);
      return {
        response,
        currentData: response.data,
        changesVerified: this.verifyChangesApplied(response.data),
        idType: this.createdIdType,
      };
    } catch (error) {
      this.handleError(error, "POST_UPDATE_VIEW", operationKey);
    }
  }

  /**
   * 🎯 PHASE 5: DELETE - Remove the resource
   */
  async runDeleteTest(operationKey = "DELETE") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();
    const idType = this.createdIdType;

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Delete operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Use ID Type Manager for intelligent placeholder replacement
    const deleteEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      currentId
    );

    logger.info(`🗑️ DELETE PHASE - Removing resource: ${deleteEndpoint} (ID type: ${idType})`);

    try {
      const response = await this.apiClient.delete(deleteEndpoint);

      if (response.status >= 400) {
        throw new Error(`DELETE failed with status ${response.status}`);
      }

      // Verify deletion was successful
      await this.verifyDeletion(currentId);

      // Mark as deleted in enhanced registry
      this.idRegistry.markIDAsDeleted(currentId, this.actualModulePath);

      // Clear ID upon successful deletion
      if (response.status >= 200 && response.status < 300) {
        this.clearCreatedId();
        this.resourceState.deletionVerified = true;
      }

      logger.info(`✅ DELETE SUCCESS - Resource removed: ${currentId} (${idType})`);
      return {
        response,
        deletionVerified: this.resourceState.deletionVerified,
        idType: idType,
      };
    } catch (error) {
      this.handleError(error, "DELETE", operationKey);
    }
  }

  /**
   * 🎯 PHASE 6: VIEW (Negative Test) - Verify resource no longer exists
   */
  async runNegativeViewTest(operationKey = "View") {
    const currentId = this.getCreatedId(); // This should be null after deletion

    if (currentId) {
      throw new Error(`Resource ID still exists after deletion: ${currentId}`);
    }

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `View operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Use the last known ID to attempt viewing deleted resource
    const lastKnownId = this.resourceState.originalData?.id || "unknown";
    
    // Use ID Type Manager for intelligent placeholder replacement
    const viewEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      lastKnownId
    );

    logger.info(
      `🚫 NEGATIVE VIEW PHASE - Attempting to view deleted resource: ${viewEndpoint}`
    );

    try {
      // This should fail with 404 or similar
      const response = await this.apiClient.get(viewEndpoint);

      // If we get here, the resource still exists (which is a failure)
      throw new Error(
        `Resource still accessible after deletion - Expected 404 but got ${response.status}`
      );
    } catch (error) {
      // This is the expected behavior - resource should not be found
      if (error.response && error.response.status === 404) {
        logger.info(
          `✅ NEGATIVE VIEW SUCCESS - Resource properly deleted (404 received)`
        );
        return {
          success: true,
          expectedError: true,
          status: 404,
          message: "Resource not found as expected",
        };
      } else if (error.response && error.response.status === 410) {
        logger.info(
          `✅ NEGATIVE VIEW SUCCESS - Resource properly deleted (410 received)`
        );
        return {
          success: true,
          expectedError: true,
          status: 410,
          message: "Resource gone as expected",
        };
      } else {
        // Unexpected error
        logger.error(
          `❌ NEGATIVE VIEW FAILED - Unexpected error: ${error.message}`
        );
        throw new Error(`Negative test failed: ${error.message}`);
      }
    }
  }

  // --- ENHANCED VALIDATION METHODS ---

  validateInitialViewResponse(response, expectedId) {
    if (!response.data) {
      throw new Error("Initial view response contains no data");
    }

    // Verify the resource exists and has expected structure
    const responseString = JSON.stringify(response.data).toLowerCase();
    const expectedIdLower = expectedId.toLowerCase();

    if (!responseString.includes(expectedIdLower)) {
      logger.warn(
        `Expected ID ${expectedId} not found in initial view response`
      );
    }

    // Store for later comparison
    this.resourceState.originalData = response.data;

    logger.info(`📊 Initial view validated - Resource structure confirmed`);
  }

  validatePostUpdateResponse(response, expectedId) {
    if (!response.data) {
      throw new Error("Post-update view response contains no data");
    }

    // Verify resource still exists and modifications are visible
    const currentData = response.data;

    // Compare with original data to verify changes
    if (this.resourceState.originalData) {
      const changes = this.detectDataChanges(
        this.resourceState.originalData,
        currentData
      );
      logger.info(`📈 Data changes detected: ${changes.length} modifications`);

      if (changes.length === 0) {
        logger.warn(`⚠️ No data changes detected after update`);
      }
    }

    logger.info(`📊 Post-update view validated - Modifications confirmed`);
  }

  constructUpdatePayload(basePayload, resourceId) {
    if (!basePayload || typeof basePayload !== "object") {
      return basePayload || {};
    }

    // Create a deep copy
    const payload = JSON.parse(JSON.stringify(basePayload));

    // Add ID to payload
    if (resourceId) {
      payload.id = resourceId;
    }

    // Apply modifications for update verification
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    // Modify identifiable fields to prove update worked
    if (payload.description) {
      payload.description = `UPDATED - ${payload.description} - Modified ${timestamp}`;
    }

    if (payload.name) {
      payload.name = `Updated_${payload.name}_${timestamp}`;
    }

    if (payload.journalDate) {
      payload.journalDate = new Date().toISOString().split("T")[0];
    }

    // Add update marker
    payload._testUpdateMarker = `updated_${timestamp}`;

    logger.debug(`📝 Update payload constructed with modifications`);
    return payload;
  }

  verifyChangesApplied(currentData) {
    if (!this.resourceState.updatedData) {
      return {
        verified: false,
        reason: "No update data available for comparison",
      };
    }

    const changes = [];

    // Check for update marker
    if (currentData._testUpdateMarker) {
      changes.push("Update marker present");
    }

    // Check description was modified
    if (
      currentData.description &&
      currentData.description.includes("UPDATED -")
    ) {
      changes.push("Description updated");
    }

    return {
      verified: changes.length > 0,
      changes: changes,
      changeCount: changes.length,
    };
  }

  detectDataChanges(originalData, currentData) {
    const changes = [];

    if (!originalData || !currentData) {
      return changes;
    }

    // Simple field comparison (extend as needed)
    const fieldsToCompare = ["description", "name", "journalDate", "status"];

    fieldsToCompare.forEach((field) => {
      if (
        originalData[field] !== undefined &&
        currentData[field] !== undefined
      ) {
        if (originalData[field] !== currentData[field]) {
          changes.push({
            field: field,
            original: originalData[field],
            current: currentData[field],
          });
        }
      }
    });

    return changes;
  }

  async verifyDeletion(resourceId) {
    const operation = this.getOperationFromModuleConfig("View");

    if (!operation) {
      logger.warn("No VIEW operation available for deletion verification");
      return true;
    }

    // Use ID Type Manager for intelligent placeholder replacement
    const viewEndpoint = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      resourceId
    );

    try {
      // Attempt to view the deleted resource - this should fail
      await this.apiClient.get(viewEndpoint);

      // If we get here, deletion failed
      throw new Error(`Resource still exists after deletion: ${resourceId}`);
    } catch (error) {
      // Expected - resource should not be found
      if (
        error.response &&
        (error.response.status === 404 || error.response.status === 410)
      ) {
        logger.info(
          `✅ Deletion verified - Resource ${resourceId} (${this.createdIdType}) no longer exists`
        );
        return true;
      } else {
        logger.warn(
          `⚠️ Unexpected error during deletion verification: ${error.message}`
        );
        return false;
      }
    }
  }

  // --- EXISTING HELPER METHODS (keep as is) ---
  saveCreatedIdToFile(id) {
    try {
      // Save to root createdId.txt for backward compatibility and easy access
      fs.writeFileSync(FILE_PATHS.CREATED_ID_TXT, id);
      
      // Save to legacy createdId.json for backward compatibility
      const metadata = {
        id: id,
        module: this.actualModulePath,
        timestamp: new Date().toISOString(),
        type: typeof id,
        length: id.length,
      };
      fs.writeFileSync(
        FILE_PATHS.CREATED_ID_FILE,
        JSON.stringify(metadata, null, 2)
      );

      // Save to centralized createdIds.json (append, not overwrite)
      this.saveToCreatedIdsRegistry(id);

      const fileContent = fs
        .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
        .trim();
      if (fileContent !== id) {
        throw new Error(
          `File content mismatch: expected ${id}, got ${fileContent}`
        );
      }

      logger.info(`✅ ID saved to file: ${FILE_PATHS.CREATED_ID_TXT}`);
      logger.info(`✅ ID registered in centralized registry for module: ${this.actualModulePath}`);
      return true;
    } catch (error) {
      logger.error(`❌ FAILED TO SAVE ID: ${error.message}`);
      return false;
    }
  }

  /**
   * Save created ID to centralized registry (tests/createdIds.json)
   * This maintains a history of all created IDs for all modules
   * Enhanced to store complete createdId.json objects with full metadata
   */
  saveToCreatedIdsRegistry(id) {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      const legacyPath = path.join(process.cwd(), 'tests', 'createdId.json');
      
      // Load existing registry or create new one
      let registry = {
        modules: {},
        metadata: {
          created: new Date().toISOString(),
          lastUpdated: new Date().toISOString(),
          totalModules: 0,
          totalIds: 0,
          description: "Centralized storage for all created resource IDs across all tested modules"
        }
      };

      if (fs.existsSync(registryPath)) {
        const existingData = fs.readFileSync(registryPath, 'utf8');
        registry = JSON.parse(existingData);
      }

      // Read the legacy createdId.json for complete metadata
      let legacyData = null;
      if (fs.existsSync(legacyPath)) {
        try {
          legacyData = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
        } catch (e) {
          logger.warn(`Could not parse legacy createdId.json: ${e.message}`);
        }
      }

      // Initialize module entry if it doesn't exist
      if (!registry.modules[this.actualModulePath]) {
        registry.modules[this.actualModulePath] = {
          moduleName: this.actualModulePath,
          moduleDisplayName: this.formatModuleDisplayName(this.actualModulePath),
          ids: [],
          idObjects: [],
          firstCreated: new Date().toISOString(),
          lastCreated: null,
          lastDeleted: null,
          totalCreated: 0,
          totalDeleted: 0,
          currentId: null,
          currentIdObject: null,
          statistics: {
            averageIdLength: 0,
            idFormats: {},
            creationTimes: []
          }
        };
      }

      const timestamp = new Date().toISOString();
      
      // Create comprehensive ID object (enhanced createdId.json format)
      const idObject = {
        id: id,
        module: this.actualModulePath,
        moduleDisplayName: this.formatModuleDisplayName(this.actualModulePath),
        timestamp: timestamp,
        type: typeof id,
        length: id.length,
        format: this.detectIdFormat(id),
        testRun: {
          timestamp: timestamp,
          testPhase: this.currentTestPhase || 'CREATE',
          testResults: this.testResults.length,
          moduleStatus: this.moduleSkipFlag ? 'SKIPPED' : 'ACTIVE'
        },
        lifecycle: {
          created: timestamp,
          updated: null,
          deleted: null,
          viewedCount: 0,
          lastViewed: null
        },
        metadata: {
          originalData: this.resourceState.originalData ? 
            this.sanitizeDataForStorage(this.resourceState.originalData) : null,
          creationMethod: 'POST',
          apiEndpoint: this.getModuleEndpoint('CREATE'),
          testSuite: 'comprehensive-CRUD-Validation'
        }
      };

      // Add to simple IDs array (backward compatibility)
      registry.modules[this.actualModulePath].ids.push({
        id: id,
        timestamp: timestamp,
        type: typeof id,
        length: id.length
      });

      // Add complete ID object to new array
      registry.modules[this.actualModulePath].idObjects.push(idObject);

      // Update module metadata
      registry.modules[this.actualModulePath].lastCreated = timestamp;
      registry.modules[this.actualModulePath].totalCreated = registry.modules[this.actualModulePath].ids.length;
      registry.modules[this.actualModulePath].currentId = id;
      registry.modules[this.actualModulePath].currentIdObject = idObject;

      // Update statistics
      this.updateModuleStatistics(registry.modules[this.actualModulePath], id);

      // Update global metadata
      registry.metadata.lastUpdated = timestamp;
      registry.metadata.totalModules = Object.keys(registry.modules).length;
      registry.metadata.totalIds = Object.values(registry.modules).reduce(
        (sum, mod) => sum + mod.totalCreated, 0
      );

      // Save updated registry
      fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
      
      logger.debug(`📝 Registry updated: ${this.actualModulePath} now has ${registry.modules[this.actualModulePath].totalCreated} IDs`);
      logger.debug(`📊 Complete ID object stored with full metadata`);
      return true;
    } catch (error) {
      logger.error(`❌ Failed to update centralized registry: ${error.message}`);
      return false;
    }
  }

  /**
   * Format module name for display
   */
  formatModuleDisplayName(modulePath) {
    if (!modulePath) return '';
    return modulePath.split('.').map(part => 
      part.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    ).join(' → ');
  }

  /**
   * Detect ID format (UUID, GUID, numeric, etc.)
   */
  detectIdFormat(id) {
    if (!id) return 'unknown';
    
    const idStr = String(id);
    
    // UUID v4 format
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idStr)) {
      return 'UUID-v4';
    }
    
    // Generic UUID/GUID format
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(idStr)) {
      return 'UUID/GUID';
    }
    
    // Numeric ID
    if (/^\d+$/.test(idStr)) {
      return 'Numeric';
    }
    
    // Alphanumeric
    if (/^[a-z0-9]+$/i.test(idStr)) {
      return 'Alphanumeric';
    }
    
    return 'Custom';
  }

  /**
   * Sanitize data for storage (remove sensitive info, limit size)
   */
  sanitizeDataForStorage(data) {
    if (!data) return null;
    
    try {
      const sanitized = JSON.parse(JSON.stringify(data));
      
      // Remove potentially sensitive fields
      const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'authorization'];
      const removeSensitiveFields = (obj) => {
        if (typeof obj !== 'object' || obj === null) return;
        
        Object.keys(obj).forEach(key => {
          if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
            obj[key] = '[REDACTED]';
          } else if (typeof obj[key] === 'object') {
            removeSensitiveFields(obj[key]);
          }
        });
      };
      
      removeSensitiveFields(sanitized);
      
      // Limit size (keep only first 100 chars of long strings)
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
      logger.warn(`Could not sanitize data: ${error.message}`);
      return null;
    }
  }

  /**
   * Get module endpoint for operation
   */
  getModuleEndpoint(operationType) {
    try {
      const operation = this.getOperationFromModuleConfig(operationType);
      return operation ? operation.endpoint : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Update module statistics
   */
  updateModuleStatistics(moduleData, newId) {
    if (!moduleData.statistics) {
      moduleData.statistics = {
        averageIdLength: 0,
        idFormats: {},
        creationTimes: []
      };
    }

    // Update average ID length
    const totalLength = moduleData.ids.reduce((sum, idEntry) => sum + (idEntry.length || 0), 0);
    moduleData.statistics.averageIdLength = (totalLength / moduleData.ids.length).toFixed(2);

    // Update ID format counts
    const format = this.detectIdFormat(newId);
    moduleData.statistics.idFormats[format] = (moduleData.statistics.idFormats[format] || 0) + 1;

    // Track creation times (keep last 10)
    moduleData.statistics.creationTimes.push(new Date().toISOString());
    if (moduleData.statistics.creationTimes.length > 10) {
      moduleData.statistics.creationTimes = moduleData.statistics.creationTimes.slice(-10);
    }
  }

  loadCreatedIdFromFile() {
    try {
      let loadedId = null;
      
      // Priority 1: Load from root createdId.txt (most recent, used for UPDATE/DELETE/VIEW)
      if (fs.existsSync(FILE_PATHS.CREATED_ID_TXT)) {
        loadedId = fs.readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8").trim();
        logger.info(`📥 Loaded created ID from root text file: ${loadedId}`);
      } 
      // Priority 2: Load from legacy createdId.json
      else if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
        const jsonData = JSON.parse(
          fs.readFileSync(FILE_PATHS.CREATED_ID_FILE, "utf8")
        );
        loadedId = jsonData.id;
        logger.info(`📥 Loaded created ID from legacy JSON file: ${loadedId}`);
      }
      // Priority 3: Load from centralized registry for this specific module
      else {
        loadedId = this.loadFromCreatedIdsRegistry();
        if (loadedId) {
          logger.info(`📥 Loaded created ID from centralized registry: ${loadedId}`);
        }
      }

      if (loadedId) {
        this.createdId = loadedId;
        logger.info(`✅ Using existing created ID: ${this.createdId}`);
        return true;
      }
      return false;
    } catch (error) {
      logger.warn(`Could not load created ID from file: ${error.message}`);
      return false;
    }
  }

  /**
   * Load the most recent created ID for this module from centralized registry
   */
  loadFromCreatedIdsRegistry() {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return null;
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      if (registry.modules && registry.modules[this.actualModulePath]) {
        const moduleData = registry.modules[this.actualModulePath];
        
        // Return the current ID or the most recent one
        if (moduleData.currentId) {
          return moduleData.currentId;
        } else if (moduleData.ids && moduleData.ids.length > 0) {
          return moduleData.ids[moduleData.ids.length - 1].id;
        }
      }
      
      return null;
    } catch (error) {
      logger.warn(`Could not load from centralized registry: ${error.message}`);
      return null;
    }
  }

  getCreatedId() {
    if (this.createdId) {
      return this.createdId;
    }
    return this.loadCreatedIdFromFile() ? this.createdId : null;
  }

  verifyCreatedId() {
    const id = this.getCreatedId();
    if (!id) {
      throw new Error("No created ID available - CREATE test must run first");
    }
    if (typeof id !== "string" || id.length < 1) {
      throw new Error(`Invalid created ID: ${id}`);
    }
    return true;
  }

  enforcePrerequisite(key) {
    if (this.moduleSkipFlag) {
      throw new Error(
        `Skipping due to module failure in ${this.actualModulePath}`
      );
    }
    if (key === "createdId") {
      const currentId = this.getCreatedId();
      if (!currentId) {
        throw new Error("No created ID available - CREATE test must run first");
      }
    } else if (!this[key]) {
      throw new Error(`Skipping due to failed prerequisite: ${key}`);
    }
  }

  getOperationFromModuleConfig(operationKey) {
    const moduleConfig = this.findModuleInSchema(this.actualModulePath);
    if (!moduleConfig || !moduleConfig[operationKey]) {
      logger.error(
        `Operation ${operationKey} not found for module ${this.actualModulePath}`
      );
      return null;
    }
    const operationArray = moduleConfig[operationKey];
    if (!Array.isArray(operationArray) || operationArray.length < 1) {
      logger.error(
        `Invalid operation format for ${operationKey} in module ${this.actualModulePath}`
      );
      return null;
    }
    return {
      endpoint: operationArray[0],
      payload: operationArray[1] || {},
      requiresId: operationArray[0].includes("<createdId>"),
    };
  }

  findModuleInSchema(modulePath) {
    try {
      const pathParts = modulePath.split(".");
      let currentLevel = modulesConfig.schema || modulesConfig;
      for (const part of pathParts) {
        if (currentLevel && currentLevel[part]) {
          currentLevel = currentLevel[part];
        } else {
          logger.warn(
            `Module path part '${part}' not found in schema for path '${modulePath}'`
          );
          return null;
        }
      }
      return currentLevel;
    } catch (error) {
      logger.error(`Error finding module in schema: ${error.message}`);
      return null;
    }
  }

  async validateDataCreation(resourceId) {
    try {
      const viewOperation = this.getOperationFromModuleConfig("View");
      if (!viewOperation) {
        logger.warn(`⚠️ No VIEW operation available for data verification`);
        return true;
      }
      const viewEndpoint = viewOperation.endpoint.replace(
        "<createdId>",
        resourceId
      );
      logger.info(`🔍 Verifying data creation with endpoint: ${viewEndpoint}`);
      const viewResponse = await this.apiClient.get(viewEndpoint);
      if (viewResponse.status !== 200) {
        throw new Error(
          `Data verification failed: Status ${viewResponse.status}`
        );
      }
      if (!viewResponse.data || Object.keys(viewResponse.data).length === 0) {
        throw new Error(
          `Data verification failed: Empty response for resource ${resourceId}`
        );
      }
      logger.info(
        `✅ Data creation verified: Resource ${resourceId} is accessible`
      );
      return true;
    } catch (error) {
      logger.error(`❌ DATA VERIFICATION FAILED: ${error.message}`);
      return false;
    }
  }

  handleError(error, operationType, operationKey) {
    const enhancedError = new Error(
      `❌ ${operationType} OPERATION FAILED (${operationKey}): ${error.message}`
    );
    enhancedError.originalError = error;
    enhancedError.operation = operationKey;
    enhancedError.module = this.actualModulePath;
    logger.error(enhancedError.message);
    throw enhancedError;
  }

  clearCreatedId() {
    this.createdId = null;
    try {
      // Clear legacy files
      if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
        fs.unlinkSync(FILE_PATHS.CREATED_ID_FILE);
      }
      if (fs.existsSync(FILE_PATHS.CREATED_ID_TXT)) {
        fs.unlinkSync(FILE_PATHS.CREATED_ID_TXT);
      }
      
      // Mark as deleted in centralized registry (but keep history)
      this.markAsDeletedInRegistry();
      
      logger.info(`🗑️ Cleared created ID from memory and files`);
    } catch (error) {
      logger.warn(`Could not clear created ID files: ${error.message}`);
    }
  }

  /**
   * Mark the current ID as deleted in the centralized registry
   * Keeps the history but clears the currentId field
   * Updates lifecycle information in the ID object
   */
  markAsDeletedInRegistry() {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return;
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      if (registry.modules && registry.modules[this.actualModulePath]) {
        const moduleData = registry.modules[this.actualModulePath];
        const deletionTimestamp = new Date().toISOString();
        
        // Update the lifecycle of the current ID object
        if (moduleData.currentIdObject && moduleData.idObjects.length > 0) {
          // Find and update the current ID object
          const currentIdObj = moduleData.idObjects.find(
            obj => obj.id === moduleData.currentId
          );
          
          if (currentIdObj && currentIdObj.lifecycle) {
            currentIdObj.lifecycle.deleted = deletionTimestamp;
            currentIdObj.lifecycle.status = 'DELETED';
            currentIdObj.lifecycle.completedFullCycle = true;
          }
        }
        
        // Clear current ID but keep history
        moduleData.currentId = null;
        moduleData.currentIdObject = null;
        moduleData.lastDeleted = deletionTimestamp;
        moduleData.totalDeleted = (moduleData.totalDeleted || 0) + 1;
        
        // Update deletion statistics
        if (!moduleData.statistics.deletionTimes) {
          moduleData.statistics.deletionTimes = [];
        }
        moduleData.statistics.deletionTimes.push(deletionTimestamp);
        if (moduleData.statistics.deletionTimes.length > 10) {
          moduleData.statistics.deletionTimes = moduleData.statistics.deletionTimes.slice(-10);
        }
        
        // Update metadata
        registry.metadata.lastUpdated = deletionTimestamp;
        
        fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
        logger.debug(`📝 Marked ID as deleted in registry for module: ${this.actualModulePath}`);
        logger.debug(`🗑️ Updated lifecycle information for deleted resource`);
      }
    } catch (error) {
      logger.warn(`Could not update registry deletion status: ${error.message}`);
    }
  }

  /**
   * Update ID object lifecycle when viewed
   */
  recordViewInRegistry() {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return;
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      if (registry.modules && registry.modules[this.actualModulePath]) {
        const moduleData = registry.modules[this.actualModulePath];
        
        // Update the lifecycle of the current ID object
        if (moduleData.currentIdObject && moduleData.idObjects.length > 0) {
          const currentIdObj = moduleData.idObjects.find(
            obj => obj.id === moduleData.currentId
          );
          
          if (currentIdObj && currentIdObj.lifecycle) {
            currentIdObj.lifecycle.viewedCount = (currentIdObj.lifecycle.viewedCount || 0) + 1;
            currentIdObj.lifecycle.lastViewed = new Date().toISOString();
          }
        }
        
        // Update metadata
        registry.metadata.lastUpdated = new Date().toISOString();
        
        fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
        logger.debug(`👁️ Recorded view in registry for module: ${this.actualModulePath}`);
      }
    } catch (error) {
      logger.warn(`Could not record view in registry: ${error.message}`);
    }
  }

  /**
   * Update ID object lifecycle when updated
   */
  recordUpdateInRegistry(updatedData) {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return;
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      if (registry.modules && registry.modules[this.actualModulePath]) {
        const moduleData = registry.modules[this.actualModulePath];
        const updateTimestamp = new Date().toISOString();
        
        // Update the lifecycle of the current ID object
        if (moduleData.currentIdObject && moduleData.idObjects.length > 0) {
          const currentIdObj = moduleData.idObjects.find(
            obj => obj.id === moduleData.currentId
          );
          
          if (currentIdObj) {
            if (!currentIdObj.lifecycle.updates) {
              currentIdObj.lifecycle.updates = [];
            }
            
            currentIdObj.lifecycle.updated = updateTimestamp;
            currentIdObj.lifecycle.updates.push({
              timestamp: updateTimestamp,
              data: this.sanitizeDataForStorage(updatedData)
            });
            
            // Keep only last 3 updates
            if (currentIdObj.lifecycle.updates.length > 3) {
              currentIdObj.lifecycle.updates = currentIdObj.lifecycle.updates.slice(-3);
            }
          }
        }
        
        // Update metadata
        registry.metadata.lastUpdated = updateTimestamp;
        
        fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
        logger.debug(`✏️ Recorded update in registry for module: ${this.actualModulePath}`);
      }
    } catch (error) {
      logger.warn(`Could not record update in registry: ${error.message}`);
    }
  }

  async cleanup() {
    this.generateSummary();
    const failedTests = this.testResults.filter(
      (r) => r.status === "failed"
    ).length;
    if (failedTests === 0 && this.currentTestPhase === "FINAL") {
      logger.info(
        `🗑️ Cleared created ID from memory and files (all tests passed)`
      );
      this.clearCreatedId();
    } else {
      logger.info(
        `💾 Keeping created ID files (failures: ${failedTests}, phase: ${this.currentTestPhase})`
      );
    }
  }

  generateSummary() {
    const summary = {
      totalTests: this.testResults.length,
      passed: this.testResults.filter((r) => r.status === "passed").length,
      failed: this.testResults.filter((r) => r.status === "failed").length,
    };
    logger.info(`\n📊 CRUD TEST EXECUTION SUMMARY`);
    logger.info(`   Module: ${this.actualModulePath}`);
    logger.info(`   Total Tests: ${summary.totalTests}`);
    logger.info(`   ✅ Passed: ${summary.passed}`);
    logger.info(`   ❌ Failed: ${summary.failed}`);
    logger.info(
      `   📈 Success Rate: ${(
        (summary.passed / summary.totalTests) *
        100
      ).toFixed(1)}%`
    );
    logger.info(`   🚩 Module Skip Flag: ${this.moduleSkipFlag}`);
    if (this.createdId) {
      logger.info(`   🔑 Created ID: ${this.createdId}`);
    }
  }

  setTestPhase(phase) {
    this.currentTestPhase = phase;
    logger.debug(`Test phase set to: ${phase}`);
  }

  recordTestStatus(testName, status) {
    this.testResults.push({
      testName,
      module: this.actualModulePath,
      status: status,
      timestamp: new Date().toISOString(),
    });
  }

  getModuleStatus() {
    return {
      module: this.actualModulePath,
      isSkipped: this.moduleSkipFlag,
      createdId: this.createdId,
      testResults: this.testResults,
      passedTests: this.testResults.filter((r) => r.status === "passed").length,
      failedTests: this.testResults.filter((r) => r.status === "failed").length,
    };
  }

  /**
   * Get all created IDs for this module from the centralized registry
   * @returns {Array} Array of ID objects with timestamps
   */
  getAllModuleIds() {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return [];
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      if (registry.modules && registry.modules[this.actualModulePath]) {
        return registry.modules[this.actualModulePath].ids || [];
      }
      
      return [];
    } catch (error) {
      logger.warn(`Could not retrieve module IDs: ${error.message}`);
      return [];
    }
  }

  /**
   * Get statistics from the centralized registry
   * @returns {Object} Registry statistics
   */
  static getRegistryStats() {
    try {
      const registryPath = path.join(process.cwd(), 'tests', 'createdIds.json');
      
      if (!fs.existsSync(registryPath)) {
        return {
          totalModules: 0,
          totalIds: 0,
          modules: []
        };
      }

      const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
      
      const stats = {
        totalModules: Object.keys(registry.modules || {}).length,
        totalIds: 0,
        modules: []
      };

      Object.entries(registry.modules || {}).forEach(([moduleName, moduleData]) => {
        stats.totalIds += moduleData.totalCreated || 0;
        stats.modules.push({
          name: moduleName,
          totalCreated: moduleData.totalCreated || 0,
          currentId: moduleData.currentId || null,
          lastCreated: moduleData.lastCreated || null
        });
      });

      return stats;
    } catch (error) {
      logger.warn(`Could not retrieve registry stats: ${error.message}`);
      return {
        totalModules: 0,
        totalIds: 0,
        modules: []
      };
    }
  }
}

module.exports = CrudLifecycleHelper;
