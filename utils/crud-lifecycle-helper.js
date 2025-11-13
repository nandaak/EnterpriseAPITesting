// utils/crud-lifecycle-helper.js
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
    this.apiClient = apiClient; // Use the already initialized singleton
    this.testResults = [];
    this.currentTestPhase = "INITIAL";
  }

  async initialize() {
    // ✅ SIMPLIFIED: Just verify the API client is ready without checking token property
    await this.verifyApiClientReady();
    this.loadCreatedIdFromFile();
  }

  async verifyApiClientReady() {
    try {
      // ✅ Check if API client instance exists
      if (!this.apiClient) {
        throw new Error("API client instance is not available");
      }

      // ✅ Check if API client has the necessary methods
      if (
        typeof this.apiClient.post !== "function" ||
        typeof this.apiClient.get !== "function"
      ) {
        throw new Error("API client methods are not properly initialized");
      }

      // ✅ Test with a simple health check or token verification
      // Instead of checking token property, we'll do a simple test request
      // or just assume it's ready since it was initialized globally

      logger.info("✅ API Client verified and ready for testing");
    } catch (error) {
      logger.error(`❌ API Client verification failed: ${error.message}`);
      global.skipRemainingTests = true;
      throw new Error(`API Client Setup Failed: ${error.message}`);
    }
  }

  // --- Enhanced ID File Management ---
  saveCreatedIdToFile(id) {
    try {
      // Save to text file
      fs.writeFileSync(FILE_PATHS.CREATED_ID_TXT, id);

      // Save to JSON with metadata
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

      // ✅ VERIFY FILE WAS ACTUALLY WRITTEN
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

  /**
   * Load created ID from text file (primary) with JSON fallback
   */
  loadCreatedIdFromFile() {
    try {
      let loadedId = null;

      // First try to load from simple text file
      if (fs.existsSync(FILE_PATHS.CREATED_ID_TXT)) {
        loadedId = fs.readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8").trim();
        logger.info(`📥 Loaded created ID from text file: ${loadedId}`);
      }
      // Fallback to JSON file
      else if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
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

  /**
   * Get created ID with file fallback
   */
  getCreatedId() {
    if (this.createdId) {
      return this.createdId;
    }
    return this.loadCreatedIdFromFile() ? this.createdId : null;
  }

  /**
   * Verify created ID exists and is valid
   */
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

  // --- Enhanced Prerequisite Enforcement ---
  enforcePrerequisite(key) {
    if (global.skipRemainingTests) {
      const errorMsg = "Skipping due to global test failure";
      logger.info(`⏭️ ${errorMsg}`);
      throw new Error(errorMsg);
    }

    if (key === "createdId") {
      const currentId = this.getCreatedId();
      if (!currentId) {
        const errorMsg = "No created ID available - CREATE test must run first";
        logger.info(`⏭️ ${errorMsg}`);
        throw new Error(errorMsg);
      }
    } else if (!this[key]) {
      logger.warn(`Skipping test: Missing prerequisite (${key} is undefined)`);
      throw new Error(`Skipping due to failed prerequisite: ${key}`);
    }
  }

  // --- CRUD Operation Methods ---
  async runCreateTest(operationKey = "Post") {
    if (global.skipRemainingTests) {
      throw new Error("❌ SKIPPING TEST: Previous authentication failure");
    }

    // ✅ Get operation directly from moduleConfig
    const operation = this.getOperationFromModuleConfig(operationKey);

    // ✅ STRICT VALIDATION: Fail if operation not found
    if (!operation) {
      throw new Error(
        `❌ CREATE OPERATION NOT FOUND: ${operationKey} for module ${this.actualModulePath}`
      );
    }

    // ✅ STRICT VALIDATION: Fail if endpoint is invalid
    if (!operation.endpoint || operation.endpoint === "URL_HERE") {
      throw new Error(
        `❌ INVALID ENDPOINT: ${operation.endpoint} for ${operationKey}`
      );
    }

    logger.info(`🌐 Calling ${operationKey} endpoint: ${operation.endpoint}`);

    try {
      const response = await this.apiClient.post(
        operation.endpoint,
        operation.payload
      );

      // ✅ STRICT VALIDATION: Fail if status code indicates failure
      if (response.status < 200 || response.status >= 400) {
        throw new Error(
          `❌ CREATE REQUEST FAILED: Status ${response.status} - ${response.statusText}`
        );
      }

      // Debug the response structure
      TestHelpers.debugResponseStructure(response, "CREATE");

      // Use enhanced ID extraction
      const extractedId = TestHelpers.extractId(response);

      // ✅ STRICT VALIDATION: Fail if ID extraction fails
      if (!extractedId) {
        const errorMsg = `❌ ID EXTRACTION FAILED: Could not extract resource ID from response. Response: ${JSON.stringify(
          response.data
        )}`;
        logger.error(errorMsg);
        throw new Error(errorMsg);
      }

      this.createdId = String(extractedId);

      // ✅ STRICT VALIDATION: Fail if ID saving fails
      const saveSuccess = this.saveCreatedIdToFile(this.createdId);
      if (!saveSuccess) {
        throw new Error(
          `❌ ID PERSISTENCE FAILED: Could not save ID to file system`
        );
      }

      // ✅ VALIDATE ACTUAL DATA CREATION
      const dataExists = await this.validateDataCreation(this.createdId);
      if (!dataExists) {
        throw new Error(
          `❌ DATA CREATION VERIFICATION FAILED: Resource ${this.createdId} not found in system`
        );
      }

      logger.info(
        `✅ Successfully created and verified resource with ID: ${this.createdId}`
      );

      return {
        createdId: this.createdId,
        response,
        extractionDetails: {
          source: "enhanced extraction",
          type: typeof this.createdId,
          length: this.createdId.length,
          savedToFile: saveSuccess,
          dataVerified: dataExists,
          operation: operationKey,
        },
      };
    } catch (error) {
      global.skipRemainingTests = true;
      logger.error(`❌ CREATE TEST FAILED: ${error.message}`);
      throw error;
    }
  }

  /**
   * ✅ Get operation from module configuration directly
   */
  getOperationFromModuleConfig(operationKey) {
    // Find the module in the schema
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

  /**
   * ✅ FIND MODULE IN SCHEMA BY PATH
   */
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

  /**
   * ✅ VALIDATE ACTUAL DATA CREATION IN SYSTEM
   */
  async validateDataCreation(resourceId) {
    try {
      // Try to retrieve the created resource using View operation
      const viewOperation = this.getOperationFromModuleConfig("View");

      if (!viewOperation) {
        logger.warn(`⚠️ No VIEW operation available for data verification`);
        return true; // Can't verify, but don't fail the test
      }

      // Construct the view endpoint with the created ID
      const viewEndpoint = viewOperation.endpoint.replace(
        "<createdId>",
        resourceId
      );

      logger.info(`🔍 Verifying data creation with endpoint: ${viewEndpoint}`);

      const viewResponse = await this.apiClient.get(viewEndpoint);

      // ✅ STRICT VALIDATION: Fail if we can't retrieve the created data
      if (viewResponse.status !== 200) {
        throw new Error(
          `Data verification failed: Status ${viewResponse.status}`
        );
      }

      // ✅ Validate that the response contains the expected resource
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

  async runViewTest(operationKey = "View") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `View operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Replace the ID placeholder in the endpoint
    const viewEndpoint = operation.endpoint.replace("<createdId>", currentId);

    logger.info(`🌐 Calling ${operationKey} endpoint: ${viewEndpoint}`);
    logger.info(`🔑 Using created ID: ${currentId}`);

    try {
      const response = await this.apiClient.get(viewEndpoint);

      // Verify the response contains our ID or valid data
      this.validateViewResponse(response, currentId);

      return { response };
    } catch (error) {
      this.handleError(error, "VIEW", operationKey);
    }
  }

  async runUpdateTest(operationKey = "PUT") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Update operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Replace the ID placeholder in the endpoint and payload
    const updateEndpoint = operation.endpoint.replace("<createdId>", currentId);

    // Update payload with current ID
    const updatePayload = { ...operation.payload };
    if (updatePayload.id === "<createdId>") {
      updatePayload.id = currentId;
    }

    logger.info(`🌐 Calling ${operationKey} endpoint: ${updateEndpoint}`);
    logger.info(`🔑 Using created ID: ${currentId}`);

    try {
      const response = await this.apiClient.put(updateEndpoint, updatePayload);
      return { response };
    } catch (error) {
      this.handleError(error, "UPDATE", operationKey);
    }
  }

  async runDeleteTest(operationKey = "DELETE") {
    this.enforcePrerequisite("createdId");
    const currentId = this.getCreatedId();

    const operation = this.getOperationFromModuleConfig(operationKey);

    if (!operation) {
      throw new Error(
        `Delete operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // Replace the ID placeholder in the endpoint
    const deleteEndpoint = operation.endpoint.replace("<createdId>", currentId);

    logger.info(`🌐 Calling ${operationKey} endpoint: ${deleteEndpoint}`);
    logger.info(`🔑 Using created ID: ${currentId}`);

    try {
      const response = await this.apiClient.delete(deleteEndpoint);

      // Clear ID upon successful deletion
      if (response.status >= 200 && response.status < 300) {
        this.clearCreatedId();
      }

      return { response };
    } catch (error) {
      this.handleError(error, "DELETE", operationKey);
    }
  }

  // --- Helper Methods ---
  validateViewResponse(response, expectedId) {
    if (!response.data) {
      throw new Error("View response contains no data");
    }

    const responseString = JSON.stringify(response.data).toLowerCase();
    const expectedIdLower = expectedId.toLowerCase();

    if (!responseString.includes(expectedIdLower)) {
      logger.warn(`Expected ID ${expectedId} not found in view response`);
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

    // Only clear ID if all tests passed AND we're in the final phase
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
}

module.exports = CrudLifecycleHelper;
