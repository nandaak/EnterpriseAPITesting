// config/modules-config.js - Enhanced with dynamic ID replacement
const fs = require("fs");
const path = require("path");
const { FILE_PATHS } = require("../Constants");

class ModulesConfig {
  constructor() {
    this.schema = this.loadSchema();
    this.modules = this.extractModules();
  }

  loadSchema() {
    try {
      if (fs.existsSync(FILE_PATHS.SCHEMA_PATH)) {
        const schema = JSON.parse(
          fs.readFileSync(FILE_PATHS.SCHEMA_PATH, "utf8")
        );
        console.log(
          "✅ Schema loaded successfully from:",
          FILE_PATHS.SCHEMA_PATH
        );
        return schema;
      } else {
        throw new Error(`Schema file not found at: ${FILE_PATHS.SCHEMA_PATH}`);
      }
    } catch (error) {
      console.error("❌ Failed to load schema:", error.message);
      throw error;
    }
  }

  extractModules() {
    const modules = {};

    const extractFromObject = (obj, path = []) => {
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = [...path, key];

        if (value && typeof value === "object" && !Array.isArray(value)) {
          // Check if this object has CRUD operations
          const hasCrudOperations =
            value.Post ||
            value.PUT ||
            value.DELETE ||
            value.View ||
            value.Post ||
            value.Put ||
            value.Delete ||
            value.View;

          if (hasCrudOperations) {
            const modulePath = currentPath.join(".");
            modules[modulePath] = this.processModuleConfig(value, modulePath);
          } else {
            // Continue digging deeper
            extractFromObject(value, currentPath);
          }
        }
      }
    };

    extractFromObject(this.schema);
    return modules;
  }

  processModuleConfig(moduleData, modulePath) {
    const config = {
      fullPath: modulePath,
      operations: {},
    };

    // Process each operation type
    const operationTypes = ["Post", "PUT", "DELETE", "View", "Get"];

    operationTypes.forEach((opType) => {
      if (
        moduleData[opType] &&
        Array.isArray(moduleData[opType]) &&
        moduleData[opType].length >= 1
      ) {
        const [endpoint, payload] = moduleData[opType];

        config.operations[opType] = {
          endpoint: endpoint,
          payload: payload || {},
          requiresId: this.detectIdRequirement(endpoint, opType),
          idPlaceholder: this.detectIdPlaceholder(endpoint),
          operationType: opType,
        };
      }
    });

    console.log(
      `✅ Found module: ${modulePath} with endpoints:`,
      Object.keys(config.operations)
    );
    return config;
  }

  detectIdRequirement(endpoint, operationType) {
    const idIndicators = ["<createdId>", "{id}", "/Id=", "/id=", "/ID="];
    return (
      idIndicators.some((indicator) => endpoint.includes(indicator)) ||
      operationType === "DELETE" ||
      operationType === "PUT" ||
      operationType === "View"
    );
  }

  detectIdPlaceholder(endpoint) {
    if (endpoint.includes("<createdId>")) return "<createdId>";
    if (endpoint.includes("{id}")) return "{id}";
    if (endpoint.includes("{Id}")) return "{Id}";
    if (endpoint.includes("{ID}")) return "{ID}";
    return null;
  }

  getEndpointWithId(operationConfig, createdId) {
    if (!operationConfig || !createdId) {
      return operationConfig.endpoint;
    }

    let endpoint = operationConfig.endpoint;

    // Replace placeholder if exists
    if (operationConfig.idPlaceholder) {
      endpoint = endpoint.replace(
        new RegExp(operationConfig.idPlaceholder, "g"),
        createdId
      );
    }

    // Replace ID in query parameters
    if (endpoint.includes("Id=") && !endpoint.includes(createdId)) {
      endpoint = endpoint.replace(/Id=.*?(?=&|$)/, `Id=${createdId}`);
    }

    // Replace ID in path parameters
    if (endpoint.includes("/JournalEntry/") && !endpoint.includes(createdId)) {
      const parts = endpoint.split("/JournalEntry/");
      if (parts.length === 2) {
        const existingId = parts[1].split("/")[0];
        if (existingId && existingId !== createdId) {
          endpoint = endpoint.replace(existingId, createdId);
        } else if (!existingId || existingId === "<createdId>") {
          endpoint = `${parts[0]}/JournalEntry/${createdId}`;
        }
      }
    }

    return endpoint;
  }

  getPayloadWithId(operationConfig, createdId, originalPayload = {}) {
    let payload = { ...originalPayload };

    if (createdId && operationConfig.operationType === "PUT") {
      payload.id = createdId;
    }

    // Ensure required fields are present
    if (
      operationConfig.operationType === "Post" ||
      operationConfig.operationType === "PUT"
    ) {
      payload = this.enhancePayloadWithTimestamps(
        payload,
        operationConfig.operationType
      );
    }

    return payload;
  }

  enhancePayloadWithTimestamps(payload, operationType) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const enhancedPayload = { ...payload };

    // Add timestamp to ensure uniqueness
    if (enhancedPayload.description) {
      enhancedPayload.description = `${enhancedPayload.description} - ${timestamp}`;
    }

    if (enhancedPayload.name) {
      enhancedPayload.name = `${enhancedPayload.name}-${timestamp}`;
    }

    // Update dates to current
    if (enhancedPayload.journalDate) {
      enhancedPayload.journalDate = new Date().toISOString().split("T")[0];
    }

    if (enhancedPayload.createdOn && operationType === "Post") {
      enhancedPayload.createdOn = new Date().toISOString();
    }

    return enhancedPayload;
  }

  getAvailableModules() {
    return Object.keys(this.modules);
  }

  getModuleConfig(modulePath) {
    return this.modules[modulePath];
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

    return {
      endpoint: this.getEndpointWithId(operationConfig, createdId),
      payload: this.getPayloadWithId(
        operationConfig,
        createdId,
        operationConfig.payload
      ),
      operationType: operationType,
      requiresId: operationConfig.requiresId,
      originalEndpoint: operationConfig.endpoint,
    };
  }
}

// Create and export singleton instance
const modulesConfig = new ModulesConfig();
module.exports = modulesConfig;
