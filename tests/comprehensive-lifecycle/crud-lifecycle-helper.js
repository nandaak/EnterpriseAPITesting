// tests/comprehensive-lifecycle/crud-lifecycle-helper.js - Enhanced with dynamic operations
const fs = require("fs");
const path = require("path");
const { ApiClient } = require("../../utils/api-client");
const TestHelpers = require("../../utils/test-helpers");
const Constants = require("../../Constants");
const TokenManager = require("../../utils/token-manager");
const modulesConfig = require("../../config/modules-config");

const { FILE_PATHS, HTTP_STATUS_CODES } = Constants;

class CrudLifecycleHelper {
  constructor(modulePath) {
    this.actualModulePath = modulePath;
    this.moduleConfig = modulesConfig.getModuleConfig(modulePath);
    this.createdId = null;
    this.schema = {};
    this.testResults = [];
    this.apiClient = null;

    if (!this.moduleConfig) {
      throw new Error(`Module configuration not found for: ${modulePath}`);
    }
  }

  // Add this method to CrudLifecycleHelper class for better error recovery
  setTestPhase(phase) {
    this.currentTestPhase = phase;
    if (this.safeConsole("debug")) {
      console.log(`[DEBUG] Test phase set to: ${phase}`);
    }
  }

  // Enhance the enforcePrerequisite method
  enforcePrerequisite(key) {
    if (global.skipRemainingTests) {
      const errorMsg = "Skipping due to global test failure";
      if (this.safeConsole("log")) {
        console.log(`[INFO] ⏭️ ${errorMsg}`);
      }
      throw new Error(errorMsg);
    }

    if (key === "createdId") {
      const currentId = this.getCreatedId();
      if (!currentId) {
        const errorMsg = "No created ID available - CREATE test must run first";
        if (this.safeConsole("log")) {
          console.log(`[INFO] ⏭️ ${errorMsg}`);
        }
        throw new Error(errorMsg);
      }
    } else if (!this[key]) {
      if (this.safeConsole("log")) {
        console.log(
          `[WARN] Skipping test: Missing prerequisite (${key} is undefined)`
        );
      }
      throw new Error(`Skipping due to failed prerequisite: ${key}`);
    }
  }

  // --- Initialization & Setup ---
  async initialize() {
    this.loadSchema(); // Added
    await this.setupEnvironmentAndToken();
    this.loadCreatedIdFromFile();
  }

  loadSchema() {
    try {
      if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
        this.schema = JSON.parse(
          fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8")
        );
        // FIXED: Use global console safely
        if (typeof console !== "undefined" && console.log) {
          console.log(
            `[INFO] ✅ Schema loaded successfully for ${this.actualModulePath}`
          );
        }
      } else {
        throw new Error(`Schema file not found at: ${FILE_PATHS.SCHEMA_PATH}`);
      }
    } catch (error) {
      // FIXED: Safe console usage
      if (typeof console !== "undefined" && console.error) {
        console.error(`[ERROR] ❌ Failed to load schema: ${error.message}`);
      }
      throw error;
    }
  }

  async setupEnvironmentAndToken() {
    // Ensure test directory exists
    const testDir = path.dirname(FILE_PATHS.CREATED_ID_FILE);
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    if (this.safeConsole("log")) {
      console.log("[INFO] 🔐 Loading and validating API token...");
    }

    try {
      const token = await TokenManager.getValidToken();
      if (!token) {
        throw new Error("Failed to obtain valid token");
      }

      if (this.safeConsole("log")) {
        console.log(`[INFO] 🔐 Token obtained (length: ${token.length})`);
      }

      this.apiClient = new ApiClient({
        headers: {
          Authorization: TokenManager.formatTokenForHeader(token),
        },
      });

      if (this.safeConsole("log")) {
        console.log(
          "[INFO] ✅ API Client successfully initialized with valid Bearer token"
        );
      }
    } catch (error) {
      if (this.safeConsole("error")) {
        console.error(
          `[ERROR] ❌ CRITICAL: Failed to setup API client: ${error.message}`
        );
      }
      global.skipRemainingTests = true;
      throw new Error(`Authentication Setup Failed: ${error.message}`);
    }
  }

  async verifyToken() {
    if (typeof console !== "undefined" && console.log) {
      console.log("[INFO] 🔐 Verifying token validity with actual API call...");
    }
    try {
      const isValid = await this.apiClient.testTokenValidity();
      if (!isValid) {
        throw new Error(
          "Token verification failed - check token validity and permissions"
        );
      }
      if (typeof console !== "undefined" && console.log) {
        console.log("[INFO] ✅ Token verification successful");
      }
    } catch (error) {
      if (typeof console !== "undefined" && console.error) {
        console.error(`[ERROR] ❌ Token verification failed: ${error.message}`);
      }
      global.skipRemainingTests = true;
      throw error;
    }
  }

  // --- Enhanced ID File Management ---
  /**
   * Enhanced ID file management with test phase awareness
   */
  saveCreatedIdToFile(createdId, testPhase = "CREATE") {
    try {
      const fileData = {
        createdId: createdId,
        timestamp: new Date().toISOString(),
        module: this.actualModulePath,
        operations: Object.keys(this.moduleConfig.operations),
        testPhase: testPhase,
        testRunId: this.getTestRunId(), // Unique identifier for this test run
      };

      // Save to JSON file (for structured data)
      fs.writeFileSync(
        FILE_PATHS.CREATED_ID_FILE,
        JSON.stringify(fileData, null, 2)
      );

      // Save to simple text file (for easy access by other tests)
      fs.writeFileSync(FILE_PATHS.CREATED_ID_TXT, createdId, "utf8");

      if (this.safeConsole("log")) {
        console.log(
          `[INFO] 💾 Saved created ID to files (Phase: ${testPhase}):`
        );
        console.log(`       📄 JSON: ${FILE_PATHS.CREATED_ID_FILE}`);
        console.log(`       📝 TXT: ${FILE_PATHS.CREATED_ID_TXT}`);
        console.log(`       🔑 ID: ${createdId}`);
        console.log(`       🎯 Module: ${this.actualModulePath}`);
      }

      return true;
    } catch (error) {
      if (this.safeConsole("error")) {
        console.error(
          `[ERROR] ❌ Failed to save created ID to file: ${error.message}`
        );
      }
      return false;
    }
  }

  /**
   * Enhanced file existence check for resilience test
   */
  verifyFilePersistence() {
    const fs = require("fs");
    const { FILE_PATHS } = Constants;

    const filesExist = {
      txtFile: fs.existsSync(FILE_PATHS.CREATED_ID_TXT),
      jsonFile: fs.existsSync(FILE_PATHS.CREATED_ID_FILE),
    };

    if (this.safeConsole("debug")) {
      console.log(`[DEBUG] File persistence check:`);
      console.log(`  - TXT File exists: ${filesExist.txtFile}`);
      console.log(`  - JSON File exists: ${filesExist.jsonFile}`);
    }

    return filesExist;
  }

  // Add this method to generate unique test run ID
  getTestRunId() {
    if (!this.testRunId) {
      this.testRunId = `testrun_${Date.now()}_${Math.random()
        .toString(36)
        .substr(2, 9)}`;
    }
    return this.testRunId;
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
        if (this.safeConsole("log")) {
          console.log(
            `[INFO] 📥 Loaded created ID from text file: ${loadedId}`
          );
        }
      }
      // Fallback to JSON file
      else if (fs.existsSync(FILE_PATHS.CREATED_ID_FILE)) {
        const jsonData = JSON.parse(
          fs.readFileSync(FILE_PATHS.CREATED_ID_FILE, "utf8")
        );
        loadedId = jsonData.createdId;
        if (this.safeConsole("log")) {
          console.log(
            `[INFO] 📥 Loaded created ID from JSON file: ${loadedId}`
          );
        }
      }

      if (loadedId) {
        this.createdId = loadedId;
        if (this.safeConsole("log")) {
          console.log(`[INFO] ✅ Using existing created ID: ${this.createdId}`);
        }
        return true;
      }

      return false;
    } catch (error) {
      if (this.safeConsole("warn")) {
        console.warn(
          `[WARN] Could not load created ID from file: ${error.message}`
        );
      }
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

    if (typeof id !== "string" || id.length < 5) {
      throw new Error(`Invalid created ID: ${id}`);
    }

    return true;
  }

  // --- Enhanced Prerequisite Enforcement ---
  // --- Payload Generation ---

  getTestPayload(operation = "Post") {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    const payloadPath = this.actualModulePath.split(".");
    let current = this.schema;
    for (const part of payloadPath) {
      if (current && current[part]) {
        current = current[part];
      } else {
        if (typeof console !== "undefined" && console.log) {
          console.log(
            `[WARN] Path segment "${part}" not found in schema. Using generic payload.`
          );
        }
        break;
      }
    }

    let payload = {
      name: `Test-${timestamp}`,
      description: `API Testing ${timestamp}`,
      status: "Active",
    };

    if (
      current &&
      current[operation] &&
      Array.isArray(current[operation]) &&
      current[operation].length > 1
    ) {
      payload = JSON.parse(JSON.stringify(current[operation][1]));
    }

    if (payload.description) {
      payload.description = `${payload.description} - ${timestamp}`;
    }
    if (payload.journalDate) {
      payload.journalDate = new Date().toISOString().split("T")[0];
    }

    // Remove ID fields for CREATE operations
    if (operation === "Post") {
      delete payload.id;
      delete payload.journalCode;
      delete payload.referenceNumber;
    }

    if (typeof console !== "undefined" && console.log) {
      console.log(
        `[DEBUG] Generated ${operation} payload with ${
          Object.keys(payload).length
        } fields`
      );
    }
    return payload;
  }

  // --- Test Lifecycle Management ---

  // --- CRUD Operation Methods ---
  async runCreateTest(operationKey = "Post") {
    if (global.skipRemainingTests) {
      throw new Error("Skipping due to authentication failure prerequisite.");
    }

    const operation = modulesConfig.getOperationWithId(
      this.actualModulePath,
      operationKey
    );

    if (!operation) {
      throw new Error(
        `Create operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    if (this.safeConsole("log")) {
      console.log(
        `[INFO] 🌐 Calling ${operationKey} endpoint: ${operation.endpoint}`
      );
      console.log(`[DEBUG] Operation requires ID: ${operation.requiresId}`);
    }

    try {
      const response = await this.apiClient.post(
        operation.endpoint,
        operation.payload
      );

      // --- Success Path ---
      if (response.status >= 200 && response.status < 400) {
        // Debug the response structure first
        TestHelpers.debugResponseStructure(response, "CREATE");

        // Use enhanced ID extraction
        const extractedId = TestHelpers.extractIdEnhanced(response);

        if (!extractedId) {
          if (this.safeConsole("error")) {
            console.error(
              `[ERROR] ❌ Could not extract ID from successful response`
            );
          }
          throw new Error(
            "ID extraction failed - cannot continue CRUD lifecycle"
          );
        }

        this.createdId = String(extractedId);

        // Save to files
        const saveSuccess = this.saveCreatedIdToFile(this.createdId);
        if (!saveSuccess && this.safeConsole("warn")) {
          console.warn(
            `[WARN] Could not save ID to file, but continuing with in-memory ID`
          );
        }

        if (this.safeConsole("log")) {
          console.log(
            `[INFO] ✅ Successfully created resource with ID: ${this.createdId}`
          );
        }

        return {
          createdId: this.createdId,
          response,
          extractionDetails: {
            source: "enhanced extraction",
            type: typeof this.createdId,
            length: this.createdId.length,
            savedToFile: saveSuccess,
            operation: operationKey,
          },
        };
      } else {
        global.skipRemainingTests = true;
        throw new Error(`POST failed with status ${response.status}`);
      }
    } catch (error) {
      global.skipRemainingTests = true;
      this.handleError(error, "CREATE", operationKey);
    }
  }

  async runViewTest(operationKey = "View") {
    const currentId = this.getCreatedId();

    if (!currentId) {
      throw new Error("Cannot view: Resource ID is missing.");
    }

    const operation = modulesConfig.getOperationWithId(
      this.actualModulePath,
      operationKey,
      currentId
    );

    if (!operation) {
      throw new Error(
        `View operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    if (this.safeConsole("log")) {
      console.log(
        `[INFO] 🌐 Calling ${operationKey} endpoint: ${operation.endpoint}`
      );
      console.log(`[INFO] 🔑 Using created ID: ${currentId}`);
    }

    try {
      const response = await this.apiClient.get(operation.endpoint);

      // Verify the response contains our ID or valid data
      this.validateViewResponse(response, currentId);

      return { response };
    } catch (error) {
      this.handleError(error, "VIEW", operationKey);
    }
  }

  async runUpdateTest(operationKey = "PUT") {
    const currentId = this.getCreatedId();

    if (!currentId) {
      throw new Error("Cannot update: Resource ID is missing.");
    }

    const operation = modulesConfig.getOperationWithId(
      this.actualModulePath,
      operationKey,
      currentId
    );

    if (!operation) {
      throw new Error(
        `Update operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    // FIXED: Use the properly constructed endpoint from modules-config
    // The endpoint should already have the ID properly integrated
    const updateEndpoint = operation.endpoint;

    if (this.safeConsole("log")) {
      console.log(
        `[INFO] 🌐 Calling ${operationKey} endpoint: ${updateEndpoint}`
      );
      console.log(`[INFO] 🔑 Using created ID: ${currentId}`);
      console.log(
        `[DEBUG] Update payload keys: ${Object.keys(operation.payload).join(
          ", "
        )}`
      );
    }

    try {
      const response = await this.apiClient.put(
        updateEndpoint,
        operation.payload
      );
      return { response };
    } catch (error) {
      this.handleError(error, "UPDATE", operationKey);
    }
  }

  async runDeleteTest(operationKey = "DELETE") {
    const currentId = this.getCreatedId();

    if (!currentId) {
      throw new Error("Cannot delete: Resource ID is missing.");
    }

    const operation = modulesConfig.getOperationWithId(
      this.actualModulePath,
      operationKey,
      currentId
    );

    if (!operation) {
      throw new Error(
        `Delete operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    if (this.safeConsole("log")) {
      console.log(
        `[INFO] 🌐 Calling ${operationKey} endpoint: ${operation.endpoint}`
      );
      console.log(`[INFO] 🔑 Using created ID: ${currentId}`);
    }

    try {
      const response = await this.apiClient.delete(operation.endpoint);

      // Clear ID upon successful deletion
      if (response.status >= 200 && response.status < 300) {
        this.clearCreatedId();
      }

      return { response };
    } catch (error) {
      this.handleError(error, "DELETE", operationKey);
    }
  }

  async runNegativeViewTest(operationKey = "View") {
    const currentId = this.getCreatedId();
    const deletedId = currentId || "00000000-0000-0000-0000-000000000000";

    const operation = modulesConfig.getOperationWithId(
      this.actualModulePath,
      operationKey,
      deletedId
    );

    if (!operation) {
      throw new Error(
        `Negative view operation ${operationKey} not found for module ${this.actualModulePath}`
      );
    }

    if (this.safeConsole("log")) {
      console.log(
        `[INFO] 🌐 Calling Negative ${operationKey} endpoint: ${operation.endpoint}`
      );
      console.log(`[INFO] 🔑 Testing with ID: ${deletedId}`);
    }

    try {
      const response = await this.apiClient.get(operation.endpoint);
      return { response, error: null };
    } catch (error) {
      const response = error.response || { status: 500 };
      return { response, error: error.message };
    }
  }

  /**
   * Create minimal update payload to avoid server errors
   */
  getMinimalUpdatePayload(operation = "PUT", currentId) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    // Start with basic required fields based on the schema
    let payload = {
      id: currentId,
      description: `Updated via API Testing ${timestamp}`,
    };

    // Add minimal required fields for JournalEntry update
    if (this.actualModulePath.includes("Journal_Entry")) {
      payload = {
        ...payload,
        journalCode: `JENT_${timestamp.substring(0, 8)}`,
        journalDate: new Date().toISOString().split("T")[0],
        status: "Unbalanced",
        totalDebitAmount: 0,
        totalCreditAmount: 0,
        journalEntryLines: [],
        journalEntryAttachments: [],
      };
    }

    if (typeof console !== "undefined" && console.log) {
      console.log(
        `[DEBUG] Using minimal update payload with ${
          Object.keys(payload).length
        } fields`
      );
    }
    return payload;
  }

  // --- Enhanced Helper Methods ---
  validateViewResponse(response, expectedId) {
    if (!response.data) {
      throw new Error("View response contains no data");
    }

    const responseString = JSON.stringify(response.data).toLowerCase();
    const expectedIdLower = expectedId.toLowerCase();

    if (!responseString.includes(expectedIdLower)) {
      if (this.safeConsole("warn")) {
        console.warn(
          `[WARN] Expected ID ${expectedId} not found in view response`
        );
        console.log(
          `[DEBUG] Response data:`,
          JSON.stringify(response.data, null, 2)
        );
      }
    }
  }

  handleError(error, operation, operationKey) {
    let errorMessage = error.message;

    if (error.response) {
      const status = error.response.status;
      const serverData = error.response.data;

      if (status === HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR) {
        errorMessage = `${operation} Server Error (500): ${
          serverData?.message || "Check payload and server logs"
        }`;
      } else if (status === HTTP_STATUS_CODES.BAD_REQUEST) {
        errorMessage = `${operation} Bad Request (400): ${
          serverData?.message || "Invalid payload data"
        }`;
      } else if (status === HTTP_STATUS_CODES.UNAUTHORIZED) {
        errorMessage = `${operation} Unauthorized (401): Check token validity`;
      } else if (status === HTTP_STATUS_CODES.NOT_FOUND) {
        errorMessage = `${operation} Not Found (404): Resource may not exist`;
      }

      if (this.safeConsole("error")) {
        console.error(`[DEBUG] ${operation} error details:`, serverData);
      }
    }

    if (this.safeConsole("error")) {
      console.error(`[ERROR] ❌ ${operation} failed: ${errorMessage}`);
    }

    if (operation === "CREATE") {
      global.skipRemainingTests = true;
    }

    throw new Error(errorMessage);
  }

  safeConsole(method) {
    return typeof console !== "undefined" && console[method];
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
      if (this.safeConsole("log")) {
        console.log(`[INFO] 🗑️ Cleared created ID from memory and files`);
      }
    } catch (error) {
      if (this.safeConsole("warn")) {
        console.warn(
          `[WARN] Could not clear created ID files: ${error.message}`
        );
      }
    }
  }

  recordTestStatus(testName, state) {
    const status = state.currentTestResults?.some((r) => r.status === "failed")
      ? "failed"
      : "passed";

    this.testResults.push({
      testName,
      module: this.actualModulePath,
      status: status,
      duration: state.currentTestDuration,
    });
  }

  // Modify cleanup to be phase-aware
  async cleanup() {
    this.generateSummary();

    // Only clear ID if all tests passed AND we're in the final phase
    const failedTests = this.testResults.filter(
      (r) => r.status === "failed"
    ).length;

    if (failedTests === 0 && this.currentTestPhase === "FINAL") {
      if (this.safeConsole("log")) {
        console.log(
          `[INFO] 🗑️ Cleared created ID from memory and files (all tests passed)`
        );
      }
      this.clearCreatedId();
    } else {
      if (this.safeConsole("log")) {
        console.log(
          `[INFO] 💾 Keeping created ID files (failures: ${failedTests}, phase: ${this.currentTestPhase})`
        );
      }
    }
  }
  // async cleanup() {
  //   this.generateSummary();

  //   // Only clear ID if all tests passed
  //   const failedTests = this.testResults.filter(
  //     (r) => r.status === "failed"
  //   ).length;

  //   if (failedTests === 0) {
  //     if (this.safeConsole("log")) {
  //       console.log(
  //         `[INFO] 🗑️ Cleared created ID from memory and files (all tests passed)`
  //       );
  //     }
  //   } else {
  //     if (this.safeConsole("log")) {
  //       console.log(
  //         `[INFO] 💾 Keeping created ID files due to test failures: ${failedTests} failed`
  //       );
  //     }
  //   }

  //   if (this.safeConsole("log")) {
  //     console.log(
  //       `[INFO] 🏁 Completed CRUD lifecycle tests for ${this.actualModulePath}`
  //     );
  //   }
  // }

  generateSummary() {
    const summary = {
      totalTests: this.testResults.length,
      passed: this.testResults.filter((r) => r.status === "passed").length,
      failed: this.testResults.filter((r) => r.status === "failed").length,
    };

    if (this.safeConsole("log")) {
      console.log(`\n📊 CRUD TEST EXECUTION SUMMARY`);
      console.log(`   Module: ${this.actualModulePath}`);
      console.log(`   Total Tests: ${summary.totalTests}`);
      console.log(`   ✅ Passed: ${summary.passed}`);
      console.log(`   ❌ Failed: ${summary.failed}`);
      console.log(
        `   📈 Success Rate: ${(
          (summary.passed / summary.totalTests) *
          100
        ).toFixed(1)}%`
      );

      if (this.createdId) {
        console.log(`   🔑 Created ID: ${this.createdId}`);
      }

      console.log(
        `   🎯 Available Operations: ${Object.keys(
          this.moduleConfig.operations
        ).join(", ")}`
      );
    }
  }
}

module.exports = CrudLifecycleHelper;
