// utils/schema-processor.js
const fs = require("fs");
const path = require("path");
const logger = require("./logger");

class SchemaProcessor {
  constructor() {
    this.processedEndpoints = [];
  }

  /**
   * Enhanced schema processing with better traversal
   */
  processSchema(schema) {
    if (!schema || typeof schema !== "object") {
      throw new Error("Invalid schema provided");
    }

    this.processedEndpoints = [];
    this._traverseSchema(schema);

    logger.info(
      `✅ Processed ${this.processedEndpoints.length} endpoints from schema`
    );
    return this.processedEndpoints;
  }

  /**
   * Recursive schema traversal
   */
  _traverseSchema(node, currentPath = []) {
    if (!node || typeof node !== "object") return;

    // Check if this node contains API operations
    if (this._hasApiOperations(node)) {
      this._extractOperations(node, currentPath);
    }

    // Recursively traverse child nodes
    Object.entries(node).forEach(([key, value]) => {
      if (value && typeof value === "object") {
        this._traverseSchema(value, [...currentPath, key]);
      }
    });
  }

  /**
   * Check if node contains API operations
   */
  _hasApiOperations(node) {
    const apiOperations = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "GET",
      "EDIT",
      "LookUP",
    ];
    return apiOperations.some(
      (op) =>
        node[op] &&
        Array.isArray(node[op]) &&
        node[op][0] &&
        typeof node[op][0] === "string"
    );
  }

  /**
   * Extract operations from a module node
   */
  _extractOperations(moduleNode, pathArray) {
    const apiOperations = [
      "Post",
      "PUT",
      "DELETE",
      "View",
      "GET",
      "EDIT",
      "LookUP",
    ];
    const modulePath = pathArray.join(".") || "Root";

    apiOperations.forEach((operation) => {
      if (moduleNode[operation] && Array.isArray(moduleNode[operation])) {
        const [endpoint, payload] = moduleNode[operation];

        if (this._isValidEndpoint(endpoint)) {
          this.processedEndpoints.push({
            url: endpoint,
            method: this._getHttpMethod(operation),
            operation: operation,
            module: modulePath,
            fullPath: `${modulePath}.${operation}`,
            payload: payload || {},
            requiresAuth: true,
            category: this._getCategory(pathArray),
          });
        }
      }
    });
  }

  /**
   * Validate endpoint URL
   */
  _isValidEndpoint(url) {
    if (!url || typeof url !== "string") return false;
    if (url === "URL_HERE" || url.trim() === "") return false;

    try {
      const urlObj = new URL(url);
      return urlObj.protocol === "http:" || urlObj.protocol === "https:";
    } catch (error) {
      return false;
    }
  }

  /**
   * Map operation to HTTP method
   */
  _getHttpMethod(operation) {
    const methodMap = {
      Post: "POST",
      PUT: "PUT",
      DELETE: "DELETE",
      View: "GET",
      GET: "GET",
      EDIT: "PUT",
      LookUP: "GET",
    };
    return methodMap[operation] || "GET";
  }

  /**
   * Categorize endpoints by module path
   */
  _getCategory(pathArray) {
    if (pathArray.length === 0) return "Unknown";

    const firstSegment = pathArray[0];
    const categoryMap = {
      Accounting: "Financial",
      Finance: "Financial",
      Sales: "Business",
      Purchase: "Business",
      Inventory: "Operations",
      General_Settings: "System",
      Distribution: "Operations",
      Human_Resources: "HR",
      Fixed_Assets: "Financial",
    };

    return categoryMap[firstSegment] || "Other";
  }

  /**
   * Get endpoints by category
   */
  getEndpointsByCategory(endpoints) {
    return endpoints.reduce((acc, endpoint) => {
      const category = endpoint.category;
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(endpoint);
      return acc;
    }, {});
  }

  /**
   * Generate endpoint statistics
   */
  generateEndpointStats(endpoints) {
    const stats = {
      total: endpoints.length,
      byMethod: {},
      byCategory: {},
      byModule: {},
      averageUrlLength: 0,
    };

    endpoints.forEach((endpoint) => {
      // Count by method
      stats.byMethod[endpoint.method] =
        (stats.byMethod[endpoint.method] || 0) + 1;

      // Count by category
      stats.byCategory[endpoint.category] =
        (stats.byCategory[endpoint.category] || 0) + 1;

      // Count by module
      stats.byModule[endpoint.module] =
        (stats.byModule[endpoint.module] || 0) + 1;
    });

    // Calculate average URL length
    const totalUrlLength = endpoints.reduce(
      (sum, ep) => sum + ep.url.length,
      0
    );
    stats.averageUrlLength = Math.round(totalUrlLength / endpoints.length);

    return stats;
  }
}

module.exports = SchemaProcessor;
