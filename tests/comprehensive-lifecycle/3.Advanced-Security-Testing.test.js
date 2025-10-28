const TestHelpers = require("../../utils/test-helpers");
const logger = require("../../utils/logger");
const { schema, TEST_TAGS } = require("../../Constants/Constants");

// Enhanced specialized test suites to run on all ERP backend APIs
describe("Advanced Security Testing", () => {
  beforeAll(() => {
    if (global.allure) {
      global.allure.epic("Security Testing");
      global.allure.feature("Advanced Security Scenarios");
    }
    logger.info("🔒 Starting Advanced Security Testing");
  });

  // Run advanced security tests on all modules with endpoints
  const runAdvancedSecurityOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const hasEndpoints =
        moduleConfig.Post ||
        moduleConfig.PUT ||
        moduleConfig.DELETE ||
        moduleConfig.View ||
        moduleConfig.EDIT ||
        moduleConfig.LookUP ||
        moduleConfig.Commit;

      if (hasEndpoints) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        test(`[AdvancedSecurity] should test advanced security scenarios for ${fullModuleName}`, async () => {
          if (global.allure) {
            global.allure.severity("critical");
            global.allure.story("Advanced Security Patterns");
            global.allure.description(
              `Testing advanced security scenarios for ${fullModuleName}`
            );
            global.allure.addLabel("tag", TEST_TAGS.AdvancedSecurity);
            global.allure.addLabel("module", fullModuleName);
          }

          await global.allureStep(
            `Advanced Security Testing for ${fullModuleName}`,
            async () => {
              logger.info(
                `Running advanced security scenarios for ${fullModuleName}...`
              );

              // Advanced security tests specific to each module
              const advancedSecurityResults =
                await TestHelpers.testAdvancedSecurityScenarios(
                  moduleConfig,
                  fullModuleName
                );

              global.attachJSON(
                `Advanced Security Results - ${fullModuleName}`,
                advancedSecurityResults
              );

              // If any advanced security test fails, the whole test fails
              if (
                advancedSecurityResults.failed &&
                advancedSecurityResults.failed.length > 0
              ) {
                throw new Error(
                  `Advanced security tests failed for ${fullModuleName}`
                );
              }

              logger.info(
                `✅ Advanced security scenarios completed for ${fullModuleName}`
              );
            }
          );
        }, 30000);
      }

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && !hasEndpoints) {
        runAdvancedSecurityOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run advanced security on all modules
  runAdvancedSecurityOnAllModules(schema);
});
