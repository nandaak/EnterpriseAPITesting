const TestHelpers = require("../../utils/test-helpers");
const logger = require("../../utils/logger");
const { schema, TEST_TAGS } = require("../../Constants/Constants");

describe("Performance Under Malicious Load", () => {
  beforeAll(() => {
    if (global.allure) {
      global.allure.epic("Performance Testing");
      global.allure.feature("Malicious Load Performance");
    }
    logger.info("⚡ Starting Performance Under Malicious Load Testing");
  });

  // Run performance tests on all modules with POST endpoints
  const runPerformanceTestsOnAllModules = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      const hasPostEndpoint =
        moduleConfig.Post && moduleConfig.Post[0] !== "URL_HERE";

      if (hasPostEndpoint) {
        const fullModuleName = parentPath
          ? `${parentPath}.${moduleName}`
          : moduleName;

        test(`[Performance] should maintain performance under malicious load for ${fullModuleName}`, async () => {
          if (global.allure) {
            global.allure.severity("normal");
            global.allure.story("Performance Under Attack");
            global.allure.description(
              `Testing performance under malicious load for ${fullModuleName}`
            );
            global.allure.addLabel("tag", TEST_TAGS.Performance);
            global.allure.addLabel("module", fullModuleName);
          }

          await global.allureStep(
            `Performance Testing for ${fullModuleName}`,
            async () => {
              logger.info(
                `Testing performance under malicious load for ${fullModuleName}...`
              );

              const performanceResults =
                await TestHelpers.testPerformanceUnderMaliciousLoad(
                  moduleConfig,
                  fullModuleName
                );

              global.attachJSON(
                `Performance Results - ${fullModuleName}`,
                performanceResults
              );

              // If performance tests fail, the whole test fails
              if (!performanceResults.success) {
                throw new Error(
                  `Performance under malicious load failed for ${fullModuleName}`
                );
              }

              logger.info(
                `✅ Performance under malicious load validated for ${fullModuleName}`
              );
            }
          );
        }, 45000);
      }

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && !hasPostEndpoint) {
        runPerformanceTestsOnAllModules(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run performance tests on all modules
  runPerformanceTestsOnAllModules(schema);
});
