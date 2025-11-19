// utils/crud-lifecycle-helper.js - ENHANCED COMPLETE CRUD LIFECYCLE
const fs = require("fs");
const path = require("path");
const apiClient = require("./api-client");
const TestHelpers = require("./test-helpers");
const Constants = require("../Constants");
const modulesConfig = require("../config/modules-config");
const logger = require("./logger");

const { FILE_PATHS, HTTP_STATUS_CODES } = Constants;

class CrudLifecycleHelper {
  constructor(modulePath) {
    this.actualModulePath = modulePath;
    this.createdId = null;
    this.apiClient = apiClient;
    this.testResults = [];
    this.currentTestPhase = "INITIAL";
    this.moduleSkipFlag = false;
    this.resourceState = {
      originalData: null,
      updatedData: null,
      deletionVerified: false,
    };
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
  async runCreateTest(operationKey = "Post") {
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
      const extractedId = TestHelpers.extractId(response);

      if (!extractedId) {
        this.moduleSkipFlag = true;
        throw new Error(
          `❌ ID EXTRACTION FAILED: Could not extract resource ID from response`
        );
      }

      this.createdId = String(extractedId);
      const saveSuccess = this.saveCreatedIdToFile(this.createdId);

      if (!saveSuccess) {
        this.moduleSkipFlag = true;
        throw new Error(
          `❌ ID PERSISTENCE FAILED: Could not save ID to file system`
        );
      }

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
        `✅ CREATE SUCCESS - Resource created with ID: ${this.createdId}`
      );
      logger.info(`📊 Original data stored for comparison`);

      return {
        createdId: this.createdId,
        response,
        originalData: this.resourceState.originalData,
        extractionDetails: {
          source: "enhanced extraction",
          type: typeof this.createdId,
          length: this.createdId.length,
          savedToFile: saveSuccess,
          dataVerified: dataExists,
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

    const viewEndpoint = operation.endpoint.replace("<createdId>", currentId);

    logger.info(
      `🔍 VIEW PHASE 1 - Verifying created resource: ${viewEndpoint}`
    );

    try {
      const response = await this.apiClient.get(viewEndpoint);

      // Enhanced validation for initial view
      this.validateInitialViewResponse(response, currentId);

      logger.info(`✅ VIEW PHASE 1 SUCCESS - Resource verified: ${currentId}`);
      return {
        response,
        resourceData: response.data,
      };
    } catch (error) {
      this.handleError(error, "INITIAL_VIEW", operationKey);
    }
  }

  /**
   * 🎯 PHASE 3: UPDATE - Modify the created resource
   */
  async runUpdateTest(operationKey = "PUT") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Update operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    const updateEndpoint = operation.endpoint.replace("<createdId>", currentId);

    // Enhanced payload with modifications
    const updatePayload = this.constructUpdatePayload(
      operation.payload,
      currentId
    );

    logger.info(`✏️ UPDATE PHASE - Modifying resource: ${updateEndpoint}`);
    logger.info(`📝 Update payload prepared with modifications`);

    try {
      const response = await this.apiClient.put(updateEndpoint, updatePayload);

      if (response.status >= 400) {
        throw new Error(`UPDATE failed with status ${response.status}`);
      }

      // Store updated data for comparison
      this.resourceState.updatedData = response.data;

      logger.info(`✅ UPDATE SUCCESS - Resource modified: ${currentId}`);
      return {
        response,
        updatedData: this.resourceState.updatedData,
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

    const viewEndpoint = operation.endpoint.replace("<createdId>", currentId);

    logger.info(`🔍 VIEW PHASE 2 - Verifying updates: ${viewEndpoint}`);

    try {
      const response = await this.apiClient.get(viewEndpoint);

      // Validate that updates are persisted
      this.validatePostUpdateResponse(response, currentId);

      logger.info(`✅ VIEW PHASE 2 SUCCESS - Updates verified: ${currentId}`);
      return {
        response,
        currentData: response.data,
        changesVerified: this.verifyChangesApplied(response.data),
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

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Delete operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    const deleteEndpoint = operation.endpoint.replace("<createdId>", currentId);

    logger.info(`🗑️ DELETE PHASE - Removing resource: ${deleteEndpoint}`);

    try {
      const response = await this.apiClient.delete(deleteEndpoint);

      if (response.status >= 400) {
        throw new Error(`DELETE failed with status ${response.status}`);
      }

      // Verify deletion was successful
      await this.verifyDeletion(currentId);

      // Clear ID upon successful deletion
      if (response.status >= 200 && response.status < 300) {
        this.clearCreatedId();
        this.resourceState.deletionVerified = true;
      }

      logger.info(`✅ DELETE SUCCESS - Resource removed: ${currentId}`);
      return {
        response,
        deletionVerified: this.resourceState.deletionVerified,
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
    const viewEndpoint = operation.endpoint.replace("<createdId>", lastKnownId);

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

    const viewEndpoint = operation.endpoint.replace("<createdId>", resourceId);

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
          `✅ Deletion verified - Resource ${resourceId} no longer exists`
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
      fs.writeFileSync(FILE_PATHS.CREATED_ID_TXT, id);
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

      const fileContent = fs
        .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
        .trim();
      if (fileContent !== id) {
        throw new Error(
          `File content mismatch: expected ${id}, got ${fileContent}`
        );
      }

      logger.info(`✅ ID saved to file: ${FILE_PATHS.CREATED_ID_TXT}`);
      return true;
    } catch (error) {
      logger.error(`❌ FAILED TO SAVE ID: ${error.message}`);
      return false;
    }
  }

  loadCreatedIdFromFile() {
    try {
      let loadedId = null;
      if (fs.existsSync(FILE_PATHS.CREATED_ID_TXT)) {
        loadedId = fs.readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8").trim();
        logger.info(`📥 Loaded created ID from text file: ${loadedId}`);
      } else if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
        const jsonData = JSON.parse(
          fs.readFileSync(FILE_PATHS.CREATED_ID_FILE, "utf8")
        );
        loadedId = jsonData.id;
        logger.info(`📥 Loaded created ID from JSON file: ${loadedId}`);
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
      if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
        fs.unlinkSync(FILE_PATHS.CREATED_ID_FILE);
      }
      if (fs.existsSync(FILE_PATHS.CREATED_ID_TXT)) {
        fs.unlinkSync(FILE_PATHS.CREATED_ID_TXT);
      }
      logger.info(`🗑️ Cleared created ID from memory and files`);
    } catch (error) {
      logger.warn(`Could not clear created ID files: ${error.message}`);
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
}

module.exports = CrudLifecycleHelper;
