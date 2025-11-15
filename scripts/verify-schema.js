// scripts/verify-schema.js
const SchemaLoader = require("../utils/schema-loader");
const logger = require("../utils/logger");

logger.info("🔍 Verifying backend API schema loading...");

const schema = SchemaLoader.loadBackendApiSchema();

if (schema) {
  const endpoints = SchemaLoader.extractAllEndpoints(schema);
  logger.info(`✅ Schema verification successful!`);
  logger.info(`📊 Found ${endpoints.length} endpoints across all modules`);

  // Show some examples
  endpoints.slice(0, 3).forEach((endpoint, index) => {
    logger.info(
      `   Example ${index + 1}: ${endpoint.module}.${endpoint.type} -> ${
        endpoint.url
      }`
    );
  });
} else {
  logger.error("❌ Schema verification failed!");
  logger.info("💡 Check the file path and JSON format of your schema file");
}
