// tests/comprehensive-lifecycle/crud.test.js - Enhanced comprehensive test suite
const CrudLifecycleHelper = require("./crud-lifecycle-helper");
const logger = require("../../utils/logger");
const Constants = require("../../Constants");
const modulesConfig = require("../../config/modules-config");

const { TEST_CONFIG, HTTP_STATUS_CODES } = Constants;

// Initialize the helper instance
let crudHelper;

describe("Enterprise CRUD Lifecycle Validation Suite", () => {
  // Use the configuration to find the target module dynamically
  const availableModules = modulesConfig.getAvailableModules();

  // Default to Journal Entry if available, otherwise use first module
  const targetModule =
    availableModules.find((m) => m.includes("Journal_Entry")) ||
    availableModules[0] ||
    "Accounting.Transaction.Journal_Entry";

  const moduleConfig = modulesConfig.getModuleConfig(targetModule);
  const actualModulePath = moduleConfig?.fullPath || targetModule;

  beforeAll(() => {
    logger.info(`🎯 Target testing module: ${actualModulePath}`);
    logger.info(
      `📋 Available operations: ${Object.keys(
        moduleConfig?.operations || {}
      ).join(", ")}`
    );
  });

  // 1. Setup Phase: Initialize helper and set up authentication
  beforeAll(async () => {
    crudHelper = new CrudLifecycleHelper(actualModulePath);
    await crudHelper.initialize();
  }, TEST_CONFIG.TIMEOUT.LONG);

  // 2. Teardown Phase: Generate final report and cleanup resources
  afterAll(async () => {
    await crudHelper.cleanup();
  });

  // 3. Record test status after each complete run
  afterEach(() => {
    crudHelper.recordTestStatus(
      expect.getState().currentTestName,
      expect.getState()
    );
  });

  // =========================================================================
  // 🎯 COMPREHENSIVE CRUD TESTS - Dynamic and Robust
  // =========================================================================

  test(
    "**** 🎯 [TC-1] CREATE - Successfully create a new resource",
    async () => {
      const { createdId, response, extractionDetails } =
        await crudHelper.runCreateTest("Post");

      // Enhanced status validation
      expect([HTTP_STATUS_CODES.CREATED, HTTP_STATUS_CODES.OK]).toContain(
        response.status
      );

      // Enhanced ID validation
      expect(createdId).toBeDefined();

      const createdIdString = String(createdId);
      expect(createdIdString).toBeTruthy();
      expect(createdIdString.length).toBeGreaterThan(5);

      // Log extraction details
      console.log(`[INFO] Extracted ID: ${createdIdString}`);
      console.log(`[INFO] Operation: ${extractionDetails.operation}`);
      console.log(
        `[INFO] Saved to file: ${
          extractionDetails.savedToFile ? "✅ YES" : "❌ NO"
        }`
      );

      // Validate ID format
      if (createdIdString.includes("-") && createdIdString.length === 36) {
        console.log(`[INFO] ✅ ID is UUID format: ${createdIdString}`);
      }

      // Verify file was created
      const fs = require("fs");
      const { FILE_PATHS } = Constants;
      expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(true);

      // Verify file content matches
      const fileContent = fs
        .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
        .trim();
      expect(fileContent).toBe(createdIdString);

      console.log(
        `[SUCCESS] ✅ CREATE test completed - Resource ID: ${createdIdString}`
      );
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-2] VIEW - Retrieve the newly created resource",
    async () => {
      // This will load ID from file if not in memory
      crudHelper.enforcePrerequisite("createdId");

      const { response } = await crudHelper.runViewTest("View");

      // Expect 200 for successful VIEW
      expect(response.status).toBe(HTTP_STATUS_CODES.OK);

      const createdId = crudHelper.getCreatedId();
      console.log(
        `[INFO] ✅ VIEW test completed - Retrieved resource with ID: ${createdId}`
      );
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-3] UPDATE - Modify and verify the created resource",
    async () => {
      crudHelper.enforcePrerequisite("createdId");

      const { response } = await crudHelper.runUpdateTest("PUT");

      // Enhanced status validation for UPDATE
      const validStatuses = [
        HTTP_STATUS_CODES.OK, // 200 - Standard success
        HTTP_STATUS_CODES.ACCEPTED, // 202 - Update accepted
        HTTP_STATUS_CODES.NO_CONTENT, // 204 - Update successful, no content
      ];

      expect(validStatuses).toContain(response.status);

      const createdId = crudHelper.getCreatedId();
      console.log(
        `[INFO] ✅ UPDATE test completed - Modified resource with ID: ${createdId}`
      );
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-4] DELETE - Remove the resource",
    async () => {
      crudHelper.enforcePrerequisite("createdId");

      const { response } = await crudHelper.runDeleteTest("DELETE");

      // Enhanced status validation for DELETE
      const validStatuses = [
        HTTP_STATUS_CODES.OK, // 200 - Standard success
        HTTP_STATUS_CODES.NO_CONTENT, // 204 - Delete successful, no content
        HTTP_STATUS_CODES.ACCEPTED, // 202 - Delete accepted
      ];

      expect(validStatuses).toContain(response.status);

      console.log(
        `[INFO] ✅ DELETE test completed - Resource successfully removed`
      );
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-5] VIEW (Negative) - Attempt to retrieve the deleted resource",
    async () => {
      const { response, error } = await crudHelper.runNegativeViewTest("View");

      // Enhanced negative test logic
      if (error) {
        // If there's an error, check that it's a "not found" type error
        const notFoundStatuses = [
          HTTP_STATUS_CODES.NOT_FOUND, // 404 - Resource not found
          HTTP_STATUS_CODES.BAD_REQUEST, // 400 - Invalid ID
          HTTP_STATUS_CODES.GONE, // 410 - Resource permanently deleted
        ];

        expect(notFoundStatuses).toContain(response.status);
        console.log(
          `[INFO] ✅ Negative test passed - Resource correctly not found (${response.status})`
        );
      } else {
        // If no error but we get a response, it should not be 200 (OK)
        const unexpectedSuccessStatuses = [
          HTTP_STATUS_CODES.OK, // 200 - Resource still exists (unexpected)
          HTTP_STATUS_CODES.CREATED, // 201 - Resource created (definitely unexpected)
        ];

        // The response status should NOT be in the success codes
        expect(unexpectedSuccessStatuses).not.toContain(response.status);
        console.log(
          `[INFO] ⚠️ Negative test - Resource returned ${response.status} (expected non-200)`
        );
      }
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  // =========================================================================
  // 🎯 ADDITIONAL ROBUSTNESS TESTS
  // =========================================================================

  test(
    "🎯 [TC-6] RESILIENCE - Verify created ID persistence across tests",
    async () => {
      const fs = require("fs");
      const { FILE_PATHS } = Constants;

      // Verify files exist
      expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(true);
      expect(fs.existsSync(FILE_PATHS.CREATED_ID_FILE)).toBe(true);

      // Verify content consistency
      const txtContent = fs
        .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
        .trim();
      const jsonContent = JSON.parse(
        fs.readFileSync(FILE_PATHS.CREATED_ID_FILE, "utf8")
      );

      expect(txtContent).toBe(jsonContent.createdId);
      expect(jsonContent.module).toBe(actualModulePath);

      console.log(`[INFO] ✅ Resilience test passed - ID persistence verified`);
    },
    TEST_CONFIG.TIMEOUT.SHORT
  );

  test(
    "🎯 [TC-7] CONFIGURATION - Verify module configuration integrity",
    async () => {
      const moduleConfig = modulesConfig.getModuleConfig(actualModulePath);

      expect(moduleConfig).toBeDefined();
      expect(moduleConfig.operations).toBeDefined();
      expect(Object.keys(moduleConfig.operations).length).toBeGreaterThan(0);

      // Verify each operation has required properties
      Object.values(moduleConfig.operations).forEach((operation) => {
        expect(operation.endpoint).toBeDefined();
        expect(typeof operation.endpoint).toBe("string");
        expect(operation.endpoint.length).toBeGreaterThan(0);
        expect(operation.operationType).toBeDefined();
      });

      console.log(
        `[INFO] ✅ Configuration test passed - Module configuration is valid`
      );
      console.log(
        `[INFO] Available operations: ${Object.keys(
          moduleConfig.operations
        ).join(", ")}`
      );
    },
    TEST_CONFIG.TIMEOUT.SHORT
  );
});
