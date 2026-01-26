const logger = require("./logger");
const fs = require("fs");
const path = require("path");
const API_Schema = "test-data/Input/Enhanced-ERP-Api-Schema-With-Payloads.json";

// Enhanced URL validation - handles both full URLs and relative paths
const isValidUrl = (string) => {
  if (!string || typeof string !== "string") return false;
  if (string === "URL_HERE" || string.trim() === "") return false;
  
  // Handle placeholder replacement
  if (string.includes("<createdId>")) {
    string = string.replace("<createdId>", "test-health-check-id");
  }

  // Check if it's a relative path (starts with /)
  if (string.startsWith("/")) {
    // Valid relative path - should start with / and contain valid characters
    return /^\/[a-zA-Z0-9\-_\/{}]*$/.test(string);
  }

  // Check if it's a full URL
  try {
    const url = new URL(string);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (_) {
    return false;
  }
};

// Load schema from file
const loadSchema = () => {
  try {
    const schemaPath = path.resolve(process.cwd(), API_Schema);

    if (!fs.existsSync(schemaPath)) {
      throw new Error(`Schema file not found at: ${schemaPath}`);
    }

    logger.info(`📁 Loading schema from: ${schemaPath}`);
    const schemaData = fs.readFileSync(schemaPath, "utf8");
    const schema = JSON.parse(schemaData);

    logger.info("✅ Schema loaded successfully");
    return schema;
  } catch (error) {
    logger.error(`❌ Failed to load schema: ${error.message}`);
    throw error;
  }
};

// Map operation to HTTP method
const getHttpMethod = (operation) => {
  const methodMap = {
    Post: "POST",
    PUT: "EDIT",
    DELETE: "DELETE",
    View: "GET",
    GET: "GET",
    EDIT: "EDIT",
    LookUP: "GET",
    Commit: "POST",
  };
  return methodMap[operation] || "GET";
};

// FIXED: Professional schema processing for Enhanced schema structure
const extractEndpointsFromSchema = (schema) => {
  const endpoints = [];
  let endpointCount = 0;

  logger.info("🔄 Starting professional schema traversal...");

  // HTTP methods to look for in the Enhanced schema
  const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

  // Traverse the schema structure
  Object.entries(schema).forEach(([moduleName, moduleData]) => {
    if (!moduleData || typeof moduleData !== "object") return;

    // Each module contains operation objects
    Object.entries(moduleData).forEach(([operationKey, operationData]) => {
      if (!operationData || typeof operationData !== "object") return;

      // Check for HTTP method arrays in the operation
      httpMethods.forEach((method) => {
        if (
          operationData[method] &&
          Array.isArray(operationData[method]) &&
          operationData[method][0]
        ) {
          const endpointUrl = operationData[method][0];
          const payload = operationData[method][1] || null;

          // Process URL (replace placeholders if needed)
          const processedUrl = endpointUrl.includes("<createdId>")
            ? endpointUrl.replace("<createdId>", "test-health-check-id")
            : endpointUrl;

          if (isValidUrl(processedUrl)) {
            endpointCount++;

            endpoints.push({
              id: endpointCount,
              url: processedUrl,
              method: method,
              operation: operationKey,
              module: moduleName,
              fullPath: `${moduleName}.${operationKey}`,
              payload: payload,
              requiresAuth: true,
              testNumber: endpointCount,
              originalUrl: endpointUrl,
              summary: operationData.summary || "",
              parameters: operationData.parameters || [],
            });

            if (endpointCount <= 5 || endpointCount % 100 === 0) {
              logger.debug(
                `📍 [${String(endpointCount).padStart(
                  3,
                  "0"
                )}] Found: ${method} ${moduleName}.${operationKey}`
              );
            }
          }
        }
      });
    });
  });

  logger.info(
    `✅ Schema traversal complete. Found ${endpoints.length} valid endpoints`
  );

  // Log endpoint distribution for verification
  if (endpoints.length > 0) {
    const methodDistribution = endpoints.reduce((acc, ep) => {
      acc[ep.method] = (acc[ep.method] || 0) + 1;
      return acc;
    }, {});

    logger.info("🌐 Method Distribution:");
    Object.entries(methodDistribution).forEach(([method, count]) => {
      logger.info(`   - ${method}: ${count} endpoints`);
    });

    // Log module distribution
    const moduleDistribution = {};
    endpoints.forEach((ep) => {
      moduleDistribution[ep.module] = (moduleDistribution[ep.module] || 0) + 1;
    });

    const topModules = Object.entries(moduleDistribution)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);

    logger.info("📦 Top 5 Modules:");
    topModules.forEach(([module, count]) => {
      logger.info(`   - ${module}: ${count} endpoints`);
    });
  }

  return endpoints;
};

module.exports = {
  isValidUrl,
  loadSchema,
  getHttpMethod,
  extractEndpointsFromSchema,
};
