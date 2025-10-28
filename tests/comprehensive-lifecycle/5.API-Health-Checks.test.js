const TestHelpers = require("../../utils/test-helpers");
const logger = require("../../utils/logger");
const {
  schema,
  TEST_TAGS,
  endpointTypes,
} = require("../../Constants/Constants");

// Enhanced API Endpoint Health Checks to run on all endpoints
describe("API Endpoint Health Checks", () => {
  beforeAll(() => {
    if (global.allure) {
      global.allure.epic("Health Monitoring");
      global.allure.feature("Endpoint Health Checks");
    }
    logger.info("🏥 Starting API Endpoint Health Checks");
  });

  // Run health checks on all endpoints
  const runHealthChecksOnAllEndpoints = (modules, parentPath = "") => {
    Object.entries(modules).forEach(([moduleName, moduleConfig]) => {
      if (typeof moduleConfig !== "object" || moduleConfig === null) return;

      // Check all endpoint types

      let hasEndpoints = false;

      endpointTypes.forEach((endpointType) => {
        if (
          moduleConfig[endpointType] &&
          moduleConfig[endpointType][0] !== "URL_HERE"
        ) {
          hasEndpoints = true;
          const fullModuleName = parentPath
            ? `${parentPath}.${moduleName}`
            : moduleName;
          const endpointName = `${fullModuleName}.${endpointType}`;

          test(`[HealthCheck] should verify ${endpointType} endpoint health for ${fullModuleName}`, async () => {
            if (global.allure) {
              global.allure.severity("normal");
              global.allure.story("Endpoint Accessibility");
              global.allure.description(
                `Health check for ${endpointType} endpoint in ${fullModuleName}`
              );
              global.allure.addLabel("tag", TEST_TAGS.HealthChecks);
              global.allure.addLabel("module", fullModuleName);
              global.allure.addLabel("endpoint-type", endpointType);
            }

            await global.allureStep(
              `Health Check for ${endpointName}`,
              async () => {
                logger.info(`Checking health of ${endpointName}...`);

                const healthResult =
                  await TestHelpers.performIndividualHealthCheck(
                    moduleConfig[endpointType][0],
                    endpointType,
                    fullModuleName
                  );

                global.attachJSON(
                  `Health Check Result - ${endpointName}`,
                  healthResult
                );

                if (!healthResult.healthy) {
                  throw new Error(
                    `Health check failed for ${endpointName}: ${healthResult.error}`
                  );
                }

                logger.info(`✅ ${endpointName} is healthy and accessible`);
              }
            );
          }, 15000);
        }
      });

      // Recursively test nested modules
      if (typeof moduleConfig === "object" && !hasEndpoints) {
        runHealthChecksOnAllEndpoints(
          moduleConfig,
          parentPath ? `${parentPath}.${moduleName}` : moduleName
        );
      }
    });
  };

  // Run health checks on all endpoints
  runHealthChecksOnAllEndpoints(schema);
});
