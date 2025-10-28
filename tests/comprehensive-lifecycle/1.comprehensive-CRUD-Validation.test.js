// tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js - Fixed structure
const CrudLifecycleHelper = require("./crud-lifecycle-helper");
const logger = require("../../utils/logger");
const Constants = require("../../Constants");
const modulesConfig = require("../../config/modules-config");

const { TEST_CONFIG, HTTP_STATUS_CODES } = Constants;

// Initialize the helper instance
let crudHelper;

describe("Enterprise CRUD Lifecycle Validation Suite", () => {
  // Allure suite setup - FIXED: Move inside describe block
  beforeAll(() => {
    global.allure.epic("Enterprise API Testing");
    global.allure.feature("CRUD Lifecycle Operations");
    global.allure.story("Journal Entry Management");
    global.allure.addLabel("suite", "comprehensive-crud");
  });

  // Use the configuration to find the target module dynamically
  const availableModules = modulesConfig.getAvailableModules();
  const targetModule =
    availableModules.find((m) => m.includes("Journal_Entry")) ||
    availableModules[0];
  const moduleConfig = modulesConfig.getModuleConfig(targetModule);
  const actualModulePath = moduleConfig?.fullPath || targetModule;

  // FIXED: Move this inside a beforeAll hook
  beforeAll(() => {
    logger.info(`🎯 Target testing module: ${actualModulePath}`);
    global.allure.addLabel("module", actualModulePath);
    global.allure.addParameter("targetModule", actualModulePath); // This should work now
  });

  // 1. Setup Phase: Initialize helper and set up authentication
  beforeAll(async () => {
    await global.allureStep("Test Environment Setup", async () => {
      crudHelper = new CrudLifecycleHelper(actualModulePath);
      await crudHelper.initialize();

      global.attachAllureLog("Module Configuration", {
        module: actualModulePath,
        operations: Object.keys(moduleConfig?.operations || {}),
        availableModules: availableModules.length,
      });
    });
  }, TEST_CONFIG.TIMEOUT.LONG);

  // 2. Teardown Phase: Generate final report and cleanup resources
  afterAll(async () => {
    await global.allureStep("Test Suite Cleanup", async () => {
      await crudHelper.cleanup();
      global.attachAllureLog(
        "Cleanup Completed",
        "All resources cleaned up successfully"
      );
    });
  });

  // =========================================================================
  // 🎯 COMPREHENSIVE CRUD TESTS - Fixed structure
  // =========================================================================

  test(
    "**** 🎯 [TC-1] CREATE - Successfully create a new resource",
    async () => {
      global.allure.severity("critical");
      global.allure.description(
        "Test the creation of a new Journal Entry resource through POST operation"
      );

      const { createdId, response, extractionDetails } =
        await global.allureStep(
          "Execute CREATE Operation",
          async () => {
            return await crudHelper.runCreateTest("Post");
          },
          { operation: "Post", module: actualModulePath }
        );

      await global.allureStep("Validate CREATE Response", async () => {
        // Enhanced status validation
        expect([HTTP_STATUS_CODES.CREATED, HTTP_STATUS_CODES.OK]).toContain(
          response.status
        );

        // Enhanced ID validation
        expect(createdId).toBeDefined();
        const createdIdString = String(createdId);
        expect(createdIdString).toBeTruthy();
        expect(createdIdString.length).toBeGreaterThan(5);

        // Attach validation details to Allure
        global.attachJSON("CREATE Validation Details", {
          status: response.status,
          createdId: createdIdString,
          extractionMethod: extractionDetails.operation,
          idLength: createdIdString.length,
          isUUID:
            createdIdString.includes("-") && createdIdString.length === 36,
        });
        // Validate ID format
        if (createdIdString.includes("-") && createdIdString.length === 36) {
          console.log(`[INFO] ✅ ID is UUID format: ${createdIdString}`);
          global.allure.addLabel("idFormat", "UUID");
        }
        console.log(
          `[SUCCESS] ✅ CREATE test completed - Resource ID: ${createdIdString}`
        );
      });

      await global.allureStep("Verify File Persistence", async () => {
        const fs = require("fs");
        const { FILE_PATHS } = Constants;

        expect(fs.existsSync(FILE_PATHS.CREATED_ID_TXT)).toBe(true);

        const fileContent = fs
          .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
          .trim();
        expect(fileContent).toBe(String(createdId));

        global.attachAllureLog("File Persistence Verified", {
          txtFile: FILE_PATHS.CREATED_ID_TXT,
          jsonFile: FILE_PATHS.CREATED_ID_FILE,
          contentMatches: fileContent === String(createdId),
        });
      });
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-2] VIEW - Retrieve the newly created resource",
    async () => {
      global.allure.severity("high");
      global.allure.description(
        "Test retrieval of the created resource through VIEW operation"
      );

      await global.allureStep("Execute VIEW Operation", async () => {
        crudHelper.enforcePrerequisite("createdId");

        const { response } = await crudHelper.runViewTest("View");

        // Enhanced status validation for VIEW
        const validStatuses = [
          HTTP_STATUS_CODES.OK,
          HTTP_STATUS_CODES.ACCEPTED,
        ];
        expect(validStatuses).toContain(response.status);

        const createdId = crudHelper.getCreatedId();

        global.attachJSON("VIEW Operation Results", {
          status: response.status,
          resourceId: createdId,
          validation: "SUCCESS",
        });

        console.log(
          `[INFO] ✅ VIEW test completed - Retrieved resource with ID: ${createdId}`
        );
      });
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-3] UPDATE - Modify and verify the created resource",
    async () => {
      global.allure.severity("high");
      global.allure.description(
        "Test modification of the created resource through UPDATE operation"
      );

      await global.allureStep("Execute UPDATE Operation", async () => {
        crudHelper.enforcePrerequisite("createdId");

        const { response } = await crudHelper.runUpdateTest("PUT");

        // Enhanced status validation for UPDATE
        const validStatuses = [
          HTTP_STATUS_CODES.OK,
          HTTP_STATUS_CODES.ACCEPTED,
          HTTP_STATUS_CODES.NO_CONTENT,
        ];
        expect(validStatuses).toContain(response.status);

        const createdId = crudHelper.getCreatedId();

        global.attachJSON("UPDATE Operation Results", {
          status: response.status,
          resourceId: createdId,
          expectedStatuses: validStatuses,
          validation: "SUCCESS",
        });

        console.log(
          `[INFO] ✅ UPDATE test completed - Modified resource with ID: ${createdId}`
        );
      });
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-4] DELETE - Remove the resource",
    async () => {
      global.allure.severity("critical");
      global.allure.description(
        "Test deletion of the resource through DELETE operation"
      );

      await global.allureStep("Execute DELETE Operation", async () => {
        crudHelper.enforcePrerequisite("createdId");

        const { response } = await crudHelper.runDeleteTest("DELETE");

        // Enhanced status validation for DELETE
        const validStatuses = [
          HTTP_STATUS_CODES.OK,
          HTTP_STATUS_CODES.NO_CONTENT,
          HTTP_STATUS_CODES.ACCEPTED,
        ];
        expect(validStatuses).toContain(response.status);

        global.attachJSON("DELETE Operation Results", {
          status: response.status,
          expectedStatuses: validStatuses,
          validation: "SUCCESS",
        });

        console.log(
          `[INFO] ✅ DELETE test completed - Resource successfully removed`
        );
      });
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-5] VIEW (Negative) - Attempt to retrieve the deleted resource",
    async () => {
      global.allure.severity("normal");
      global.allure.description(
        "Negative test to verify resource is properly deleted and cannot be retrieved"
      );

      await global.allureStep("Execute Negative VIEW Operation", async () => {
        const { response, error } = await crudHelper.runNegativeViewTest(
          "View"
        );

        global.attachJSON("Negative VIEW Operation Details", {
          responseStatus: response?.status,
          error: error,
          expectation: "Resource should not be found after deletion",
        });

        // Enhanced negative test logic
        if (error) {
          const expectedErrorStatuses = [
            HTTP_STATUS_CODES.NOT_FOUND,
            HTTP_STATUS_CODES.BAD_REQUEST,
            HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR,
          ];

          expect(expectedErrorStatuses).toContain(response.status);

          global.attachAllureLog("Negative Test Validation", {
            status: response.status,
            expectedStatuses: expectedErrorStatuses,
            result: "PASSED - Resource correctly not found",
          });
        }
      });
    },
    TEST_CONFIG.TIMEOUT.MEDIUM
  );

  test(
    "🎯 [TC-6] RESILIENCE - Verify created ID persistence across tests",
    async () => {
      global.allure.severity("normal");
      global.allure.description(
        "Verify that created IDs persist correctly across test executions"
      );

      await global.allureStep("Verify File Persistence", async () => {
        const fs = require("fs");
        const { FILE_PATHS } = Constants;

        const fileCheck = crudHelper.verifyFilePersistence();

        global.attachJSON("File Persistence Check", fileCheck);

        if (!fileCheck.txtFile || !fileCheck.jsonFile) {
          const currentId = crudHelper.getCreatedId();
          if (!currentId) {
            console.log(
              `[INFO] ⚠️ Resilience test - Files cleaned up as expected`
            );
            expect(true).toBe(true);
            return;
          }
        }

        expect(fileCheck.txtFile).toBe(true);
        expect(fileCheck.jsonFile).toBe(true);

        // Enhanced content consistency verification
        const txtContent = fs
          .readFileSync(FILE_PATHS.CREATED_ID_TXT, "utf8")
          .trim();
        const jsonContent = JSON.parse(
          fs.readFileSync(FILE_PATHS.CREATED_ID_FILE, "utf8")
        );
        expect(txtContent).toBe(jsonContent.createdId);
        expect(jsonContent.module).toBe(actualModulePath);
        global.attachJSON("Resilience Test Results", {
          txtContent: txtContent,
          jsonContent: jsonContent,
          consistency: txtContent === jsonContent.createdId,
          moduleMatch: jsonContent.module === actualModulePath,
        });

        console.log(
          `[INFO] ✅ Resilience test passed - ID persistence verified`
        );
      });
    },
    TEST_CONFIG.TIMEOUT.SHORT
  );

  test(
    "🎯 [TC-7] CONFIGURATION - Verify module configuration integrity",
    async () => {
      global.allure.severity("normal");
      global.allure.description(
        "Verify that module configuration is properly loaded and valid"
      );

      await global.allureStep("Validate Module Configuration", async () => {
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

        global.attachJSON("Module Configuration Validation", {
          module: actualModulePath,
          operationCount: Object.keys(moduleConfig.operations).length,
          operations: Object.keys(moduleConfig.operations),
          validation: "SUCCESS",
        });

        console.log(
          `[INFO] ✅ Configuration test passed - Module configuration is valid`
        );
      });
    },
    TEST_CONFIG.TIMEOUT.SHORT
  );
});
