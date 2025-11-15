// utils/schema-debugger.js
const logger = require("./logger");

function debugSchemaStructure(schema, depth = 0, path = "") {
  if (!schema || typeof schema !== "object") {
    logger.warn(`📁 ${"  ".repeat(depth)}${path}: [NOT AN OBJECT]`);
    return;
  }

  Object.entries(schema).forEach(([key, value]) => {
    const currentPath = path ? `${path}.${key}` : key;

    if (typeof value === "object" && value !== null) {
      // Check if this level has endpoints
      const hasEndpoints = [
        "Post",
        "PUT",
        "DELETE",
        "View",
        "EDIT",
        "GET",
        "POST",
      ].some(
        (type) =>
          value[type] && Array.isArray(value[type]) && value[type].length > 0
      );

      if (hasEndpoints) {
        logger.info(`🔍 ${"  ".repeat(depth)}${currentPath}: [HAS ENDPOINTS]`);
        // Log the endpoints
        ["Post", "PUT", "DELETE", "View", "EDIT", "GET", "POST"].forEach(
          (type) => {
            if (
              value[type] &&
              Array.isArray(value[type]) &&
              value[type].length > 0
            ) {
              logger.info(`   ${"  ".repeat(depth)}${type}: ${value[type][0]}`);
            }
          }
        );
      } else {
        logger.debug(`📁 ${"  ".repeat(depth)}${currentPath}`);
      }

      // Recursively debug nested structure (limit depth to avoid too much output)
      if (depth < 3) {
        debugSchemaStructure(value, depth + 1, currentPath);
      }
    } else {
      logger.debug(`📄 ${"  ".repeat(depth)}${currentPath}: ${value}`);
    }
  });
}

module.exports = { debugSchemaStructure };
