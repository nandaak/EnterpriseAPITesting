// config/modules-config.js - Enhanced with proper logging
const fs = require("fs");
const path = require("path");
const { FILE_PATHS } = require("../Constants");

class ModulesConfig {
  constructor() {
    this.schema = this.loadSchema();
    this.modules = this.extractModules();
  }

  // Add safe console method to ModulesConfig
  safeConsole(method) {
    return typeof console !== "undefined" && console[method];
  }

  loadSchema() {
    try {
      if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
        const schemaData = fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8");
        this.schema = JSON.parse(schemaData);

        if (this.safeConsole("log")) {
          console.log(
            "✅ Schema loaded successfully from:",
            FILE_PATHS.SCHEMA_PATH
          );
        }

        return this.schema;
      } else {
        throw new Error(`Schema file not found at: ${FILE_PATHS.SCHEMA_PATH}`);
      }
    } catch (error) {
      if (this.safeConsole("error")) {
        console.error(`[ERROR] ❌ Failed to load schema: ${error.message}`);
      }
      throw error;
    }
  }

  extractModules() {
    const modules = {};

    const extractFromObject = (obj, path = []) => {
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = [...path, key];

        if (value && typeof value === "object") {
          // Check if this is a module (has CRUD operations)
          const hasOperations =
            value.Post ||
            value.PUT ||
            value.DELETE ||
            value.View ||
            value.Get ||
            value.EDIT ||
            value.Lookup;

          if (hasOperations) {
            const modulePath = currentPath.join(".");
            modules[modulePath] = this.processModuleConfig(modulePath, value);

            if (this.safeConsole("debug")) {
              console.log(
                `[DEBUG] Found module: ${modulePath} with operations:`,
                Object.keys(value).filter((k) =>
                  [
                    "Post",
                    "PUT",
                    "DELETE",
                    "View",
                    "Get",
                    "EDIT",
                    "Lookup",
                  ].includes(k)
                )
              );
            }
          }

          // Recursively search deeper
          extractFromObject(value, currentPath);
        }
      }
    };

    extractFromObject(this.schema);
    return modules;
  }

  processModuleConfig(modulePath, moduleData) {
    const operations = {};
    const pathParts = modulePath.split(".");

    // Extract available operations
    const operationTypes = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "Get",
      "EDIT",
      "Lookup",
    ];

    operationTypes.forEach((opType) => {
      if (
        moduleData[opType] &&
        Array.isArray(moduleData[opType]) &&
        moduleData[opType].length > 0
      ) {
        const [endpoint, payload] = moduleData[opType];

        operations[opType] = {
          endpoint: endpoint,
          payload: payload || {},
          operationType: opType,
          requiresId: this.determineIfRequiresId(opType, endpoint),
          fullPath: modulePath,
        };
      }
    });

    if (this.safeConsole("log") && Object.keys(operations).length > 0) {
      console.log(
        `✅ Found module: ${modulePath} with endpoints: [ ${Object.keys(
          operations
        ).join(", ")} ]`
      );
    }

    return {
      fullPath: modulePath,
      operations: operations,
      pathParts: pathParts,
    };
  }

  determineIfRequiresId(operationType, endpoint) {
    const idRequiredOperations = ["PUT", "DELETE", "View", "EDIT", "Get"];
    const hasIdInEndpoint = endpoint && endpoint.includes("<createdId>");

    return idRequiredOperations.includes(operationType) || hasIdInEndpoint;
  }

  getModuleConfig(modulePath) {
    return this.modules[modulePath];
  }

  getAvailableModules() {
    return Object.keys(this.modules);
  }

  getOperationConfig(modulePath, operationType) {
    const moduleConfig = this.getModuleConfig(modulePath);
    return moduleConfig ? moduleConfig.operations[operationType] : null;
  }

  // Enhanced method to get complete operation details with ID
  getOperationWithId(modulePath, operationType, createdId) {
    const operationConfig = this.getOperationConfig(modulePath, operationType);
    if (!operationConfig) {
      throw new Error(
        `Operation ${operationType} not found for module ${modulePath}`
      );
    }

    // Use enhanced endpoint construction
    const endpoint = this.constructEndpointWithId(
      operationConfig.endpoint,
      createdId,
      operationType
    );

    // Use enhanced payload construction
    const payload = this.constructPayloadWithId(
      operationConfig.payload,
      createdId,
      operationType
    );

    return {
      endpoint: endpoint,
      payload: payload,
      operationType: operationType,
      requiresId: operationConfig.requiresId,
      originalEndpoint: operationConfig.endpoint,
    };
  }

  // Professional endpoint construction method
  constructEndpointWithId(baseEndpoint, createdId, operationType) {
    if (!baseEndpoint) {
      return baseEndpoint;
    }

    let finalEndpoint = baseEndpoint;

    // Replace <createdId> placeholder with actual ID
    if (createdId && baseEndpoint.includes("<createdId>")) {
      finalEndpoint = baseEndpoint.replace(/<createdId>/g, createdId);
    }
    // Handle ID appending for specific operations
    else if (
      createdId &&
      this.requiresIdAppending(operationType, baseEndpoint)
    ) {
      finalEndpoint = `${baseEndpoint}/${createdId}`;
    }
    // Handle query parameters for View operations
    else if (
      operationType === "View" &&
      createdId &&
      baseEndpoint.includes("?")
    ) {
      if (baseEndpoint.includes("Id=")) {
        finalEndpoint = baseEndpoint.replace(/Id=[^&]*/, `Id=${createdId}`);
      } else {
        finalEndpoint = `${baseEndpoint}&Id=${createdId}`;
      }
    }

    // Enhanced debugging
    if (this.safeConsole("debug")) {
      console.log(`[DEBUG] Endpoint construction for ${operationType}:`);
      console.log(`  - Base: ${baseEndpoint}`);
      console.log(`  - ID: ${createdId || "N/A"}`);
      console.log(`  - Final: ${finalEndpoint}`);
      console.log(
        `  - Requires ID: ${this.determineIfRequiresId(
          operationType,
          baseEndpoint
        )}`
      );
    }

    return finalEndpoint;
  }

  // Enhanced payload construction method
  constructPayloadWithId(basePayload, createdId, operationType) {
    if (!basePayload || typeof basePayload !== "object") {
      return basePayload || {};
    }

    // Create a deep copy to avoid modifying the original
    const payload = JSON.parse(JSON.stringify(basePayload));

    // Add ID to payload for UPDATE operations
    if (operationType === "PUT" && createdId) {
      payload.id = createdId;
    }

    // Enhance payload with timestamps for uniqueness
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (payload.description) {
      payload.description = `${payload.description} - Updated ${timestamp}`;
    }
    if (payload.journalDate && operationType === "PUT") {
      payload.journalDate = new Date().toISOString();
    }

    if (this.safeConsole("debug")) {
      console.log(`[DEBUG] Payload construction for ${operationType}:`);
      console.log(`  - Base keys: ${Object.keys(basePayload).join(", ")}`);
      console.log(`  - Final keys: ${Object.keys(payload).join(", ")}`);
      console.log(`  - Has ID: ${!!payload.id}`);
    }

    return payload;
  }

  requiresIdAppending(operationType, endpoint) {
    // Operations that typically need ID appended to URL
    const appendIdOperations = ["DELETE", "GET"];
    const hasIdPlaceholder = endpoint.includes("<createdId>");
    const hasIdInUrl = endpoint.match(/\/[a-f0-9-]{36}/i); // UUID pattern

    return (
      appendIdOperations.includes(operationType) &&
      !hasIdPlaceholder &&
      !hasIdInUrl &&
      !endpoint.includes("?")
    );
  }

  // Validate module configuration
  validateModuleConfig(modulePath) {
    const config = this.getModuleConfig(modulePath);
    if (!config) {
      throw new Error(`Module configuration not found: ${modulePath}`);
    }

    const { operations } = config;
    if (!operations || Object.keys(operations).length === 0) {
      throw new Error(`No operations defined for module: ${modulePath}`);
    }

    // Validate each operation
    Object.entries(operations).forEach(([opType, opConfig]) => {
      if (!opConfig.endpoint) {
        throw new Error(`Missing endpoint for ${opType} in ${modulePath}`);
      }
      if (typeof opConfig.endpoint !== "string") {
        throw new Error(`Invalid endpoint type for ${opType} in ${modulePath}`);
      }
    });

    return true;
  }
}

// Create and export singleton instance
const modulesConfigInstance = new ModulesConfig();

// Export both the class and instance
module.exports = modulesConfigInstance;
module.exports.ModulesConfig = ModulesConfig;