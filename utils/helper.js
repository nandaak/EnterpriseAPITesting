const logger = require("./logger");
const fs = require("fs");
const path = require("path");
const API_Schema = "test-data/Input/Main-Backend-Api-Schema.json";

// Enhanced URL validation
const isValidUrl = (string) => {
  if (!string || typeof string !== "string") return false;
  if (string === "URL_HERE" || string.trim() === "") return false;
  if (string.includes("<createdId>")) {
    // Replace placeholder with test ID for valid testing
    return string.replace("<createdId>", "test-health-check-id");
  }

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

// FIXED: Professional schema processing with better traversal
const extractEndpointsFromSchema = (schema) => {
  const endpoints = [];
  let endpointCount = 0;

  logger.info("🔄 Starting professional schema traversal...");

  const traverse = (obj, currentPath = []) => {
    if (!obj || typeof obj !== "object") return;

    // Check if current level has HTTP operations directly
    const httpOperations = [
      "CREATE",
      "EDIT",
      "DELETE",
      "View",
      "GET",
      "EDIT",
      "LookUP",
      "Commit",
    ];

    // Look for operations at current level
    httpOperations.forEach((operation) => {
      if (
        obj[operation] &&
        Array.isArray(obj[operation]) &&
        obj[operation][0]
      ) {
        const endpointUrl = obj[operation][0];
        const processedUrl = endpointUrl.includes("<createdId>")
          ? endpointUrl.replace("<createdId>", "test-health-check-id")
          : endpointUrl;

        if (isValidUrl(processedUrl)) {
          endpointCount++;
          const modulePath =
            currentPath.length > 0 ? currentPath.join(".") : "Root";

          endpoints.push({
            id: endpointCount,
            url: processedUrl,
            method: getHttpMethod(operation),
            operation: operation,
            module: modulePath,
            fullPath: `${modulePath}.${operation}`,
            payload: obj[operation][1] || null,
            requiresAuth: true,
            testNumber: endpointCount,
            originalUrl: endpointUrl, // Keep original for reference
          });

          logger.debug(
            `📍 [${String(endpointCount).padStart(
              3,
              "0"
            )}] Found: ${operation} ${modulePath}`
          );
        }
      }
    });

    // Recursively traverse nested objects
    Object.entries(obj).forEach(([key, value]) => {
      if (
        value &&
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value)
      ) {
        // Only traverse if it's not an operation array and looks like a module container
        const isLikelyModule =
          !httpOperations.includes(key) &&
          typeof value === "object" &&
          Object.keys(value).some(
            (k) => httpOperations.includes(k) || typeof value[k] === "object"
          );

        if (isLikelyModule) {
          traverse(value, [...currentPath, key]);
        }
      }
    });
  };

  traverse(schema);
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
  }

  return endpoints;
};

module.exports = {
  isValidUrl,
  loadSchema,
  getHttpMethod,
  extractEndpointsFromSchema,
};
