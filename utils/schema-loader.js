// utils/schema-loader.js
const fs = require("fs");
const path = require("path");
const logger = require("./logger");

class SchemaLoader {
  /**
   * Load the main backend API schema from JSON file
   */
  static loadBackendApiSchema() {
    try {
      const schemaPath = path.join(
        __dirname,
        "../test-data/Input/Main-Backend-Api-Schema.json"
      );

      logger.debug(`🔍 Looking for schema file at: ${schemaPath}`);

      if (!fs.existsSync(schemaPath)) {
        logger.error(`❌ Schema file not found: ${schemaPath}`);
        // Try to find the file in common locations
        const alternativePaths = [
          path.join(
            process.cwd(),
            "test-data/Input/Main-Backend-Api-Schema.json"
          ),
          path.join(process.cwd(), "Main-Backend-Api-Schema.json"),
          path.join(
            __dirname,
            "../../test-data/Input/Main-Backend-Api-Schema.json"
          ),
        ];

        for (const altPath of alternativePaths) {
          if (fs.existsSync(altPath)) {
            logger.info(`✅ Found schema at alternative location: ${altPath}`);
            return this.loadSchemaFromPath(altPath);
          }
        }

        return null;
      }

      return this.loadSchemaFromPath(schemaPath);
    } catch (error) {
      logger.error(`❌ Failed to load backend API schema: ${error.message}`);
      return null;
    }
  }

  /**
   * Load schema from specific path
   */
  static loadSchemaFromPath(schemaPath) {
    try {
      const schemaData = fs.readFileSync(schemaPath, "utf8");
      const schema = JSON.parse(schemaData);

      logger.info(
        `✅ Loaded backend API schema with ${
          Object.keys(schema).length
        } main modules`
      );
      this.logSchemaStats(schema);

      return schema;
    } catch (error) {
      logger.error(`❌ Failed to parse schema file: ${error.message}`);
      return null;
    }
  }

  /**
   * Log statistics about the loaded schema
   */
  static logSchemaStats(schema) {
    if (!schema || typeof schema !== "object") {
      logger.warn("⚠️ No schema data to analyze");
      return;
    }

    let totalEndpoints = 0;
    const moduleStats = {};
    const endpointTypes = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "EDIT",
      "GET",
      "POST",
    ];

    const countEndpoints = (obj, path = "") => {
      if (!obj || typeof obj !== "object") return;

      Object.entries(obj).forEach(([key, value]) => {
        const currentPath = path ? `${path}.${key}` : key;

        if (typeof value === "object" && value !== null) {
          // Check if this object has endpoint definitions
          const hasEndpoints = endpointTypes.some(
            (type) =>
              value[type] &&
              Array.isArray(value[type]) &&
              value[type].length > 0
          );

          if (hasEndpoints) {
            moduleStats[currentPath] = {};
            endpointTypes.forEach((type) => {
              if (
                value[type] &&
                Array.isArray(value[type]) &&
                value[type].length > 0
              ) {
                const endpointUrl = value[type][0];
                if (
                  typeof endpointUrl === "string" &&
                  endpointUrl.includes("/")
                ) {
                  moduleStats[currentPath][type] = endpointUrl;
                  totalEndpoints++;
                }
              }
            });
          }

          // Recursively check nested objects
          countEndpoints(value, currentPath);
        }
      });
    };

    countEndpoints(schema);

    logger.info(`📊 Schema Analysis Report:`);
    logger.info(
      `   Total Modules with Endpoints: ${Object.keys(moduleStats).length}`
    );
    logger.info(`   Total Endpoints: ${totalEndpoints}`);

    // Log module distribution
    const mainModules = {};
    Object.keys(moduleStats).forEach((modulePath) => {
      const mainModule = modulePath.split(".")[0];
      mainModules[mainModule] =
        (mainModules[mainModule] || 0) +
        Object.keys(moduleStats[modulePath]).length;
    });

    logger.info(`\n📦 Main Module Distribution:`);
    Object.entries(mainModules).forEach(([module, count]) => {
      logger.info(`   ${module}: ${count} endpoints`);
    });

    // Log first few endpoints for verification
    const sampleEndpoints = Object.entries(moduleStats).slice(0, 3);
    if (sampleEndpoints.length > 0) {
      logger.info(`\n🔍 Sample Endpoints Found:`);
      sampleEndpoints.forEach(([modulePath, endpoints]) => {
        Object.entries(endpoints).forEach(([type, url]) => {
          logger.info(`   📍 ${modulePath}.${type}: ${url}`);
        });
      });
    }

    if (Object.keys(moduleStats).length > 3) {
      logger.info(
        `   ... and ${Object.keys(moduleStats).length - 3} more modules`
      );
    }
  }

  /**
   * Extract all endpoints from schema for health checks
   */
  static extractAllEndpoints(schema) {
    const endpoints = [];

    if (!schema || typeof schema !== "object") {
      logger.warn("⚠️ No schema provided for endpoint extraction");
      return endpoints;
    }

    const endpointTypes = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "EDIT",
      "GET",
      "POST",
    ];

    const extractEndpoints = (obj, modulePath = "") => {
      if (!obj || typeof obj !== "object") return;

      Object.entries(obj).forEach(([key, value]) => {
        const currentPath = modulePath ? `${modulePath}.${key}` : key;

        if (typeof value === "object" && value !== null) {
          // Check for endpoint definitions
          endpointTypes.forEach((type) => {
            if (
              value[type] &&
              Array.isArray(value[type]) &&
              value[type].length > 0
            ) {
              const endpointUrl = value[type][0];
              if (
                typeof endpointUrl === "string" &&
                endpointUrl.includes("/")
              ) {
                endpoints.push({
                  module: currentPath,
                  type: type,
                  url: endpointUrl,
                  data: value[type][1] || {}, // Include test data if available
                });
              }
            }
          });

          // Recursively extract from nested objects
          extractEndpoints(value, currentPath);
        }
      });
    };

    extractEndpoints(schema);

    logger.debug(`✅ Extracted ${endpoints.length} endpoints from schema`);
    return endpoints;
  }

  /**
   * Validate endpoint URLs and fix common issues
   */
  static normalizeEndpointUrl(url) {
    if (!url || typeof url !== "string") {
      logger.warn(`⚠️ Invalid endpoint URL: ${url}`);
      return url;
    }

    const baseUrl = "https://api.microtecstage.com";

    // Fix double base URL issues
    if (url.startsWith(baseUrl + baseUrl)) {
      const normalized = url.replace(baseUrl, "");
      logger.debug(`🔧 Fixed double base URL: ${url} -> ${normalized}`);
      return normalized;
    }

    // Ensure relative paths are properly formatted
    if (!url.startsWith("http") && !url.startsWith("/")) {
      return `/${url}`;
    }

    return url;
  }
}

module.exports = SchemaLoader;
