// test/helpers/moduleIsolationHelper.js
const apiClient = require("../../utils/api-client");
const logger = require("../../utils/logger");
const TokenManager = require("../../utils/token-manager");

class ModuleIsolationHelper {
  constructor(moduleName, modulePath) {
    this.moduleName = moduleName;
    this.modulePath = modulePath;
    this.authToken = null;
    this.createdResources = [];
    this.errors = [];
    this.moduleSkipFlag = false;
    this.testResults = {
      create: { success: false, error: null },
      view: { success: false, error: null },
      update: { success: false, error: null },
      delete: { success: false, error: null },
      config: { success: false, error: null },
    };
  }

  async initialize() {
    try {
      await this.authenticate();
      logger.info(`✅ ${this.moduleName} - Module initialized successfully`);
      return true;
    } catch (error) {
      this.errors.push({ step: "initialize", error: error.message });
      logger.error(
        `❌ ${this.moduleName} - Initialization failed: ${error.message}`
      );
      this.moduleSkipFlag = true;
      return false;
    }
  }

  async authenticate() {
    try {
      // Fresh authentication for this specific module
      this.authToken = await TokenManager.getValidToken();

      if (!this.authToken) {
        throw new Error("Failed to obtain authentication token");
      }

      logger.info(`🔐 ${this.moduleName} - Authentication successful`);
      return true;
    } catch (error) {
      throw new Error(`Authentication failed: ${error.message}`);
    }
  }

  async createResource(endpoint, payload) {
    if (this.moduleSkipFlag) {
      throw new Error(
        `Module ${this.moduleName} is skipped due to previous failure`
      );
    }

    try {
      const response = await apiClient.post(endpoint, payload);

      if (response.status >= 400) {
        throw new Error(`CREATE failed with status ${response.status}`);
      }

      const resourceId = this.extractResourceId(response);
      if (resourceId) {
        this.createdResources.push({
          id: resourceId,
          endpoint: endpoint,
          timestamp: new Date().toISOString(),
        });
      }

      this.testResults.create = { success: true, error: null };
      logger.info(
        `✅ ${this.moduleName} - Resource created successfully: ${resourceId}`
      );
      return response;
    } catch (error) {
      this.testResults.create = { success: false, error: error.message };
      this.errors.push({ step: "create", error: error.message });
      this.moduleSkipFlag = true;
      throw error;
    }
  }

  async viewResource(endpoint) {
    if (this.moduleSkipFlag) {
      throw new Error(
        `Module ${this.moduleName} is skipped due to previous failure`
      );
    }

    try {
      const response = await apiClient.get(endpoint);

      if (response.status >= 400) {
        throw new Error(`VIEW failed with status ${response.status}`);
      }

      this.testResults.view = { success: true, error: null };
      logger.info(`✅ ${this.moduleName} - Resource viewed successfully`);
      return response;
    } catch (error) {
      this.testResults.view = { success: false, error: error.message };
      this.errors.push({ step: "view", error: error.message });
      throw error;
    }
  }

  async updateResource(endpoint, payload) {
    if (this.moduleSkipFlag) {
      throw new Error(
        `Module ${this.moduleName} is skipped due to previous failure`
      );
    }

    try {
      const response = await apiClient.put(endpoint, payload);

      if (response.status >= 400) {
        throw new Error(`UPDATE failed with status ${response.status}`);
      }

      this.testResults.update = { success: true, error: null };
      logger.info(`✅ ${this.moduleName} - Resource updated successfully`);
      return response;
    } catch (error) {
      this.testResults.update = { success: false, error: error.message };
      this.errors.push({ step: "update", error: error.message });
      throw error;
    }
  }

  async deleteResource(endpoint) {
    if (this.moduleSkipFlag) {
      throw new Error(
        `Module ${this.moduleName} is skipped due to previous failure`
      );
    }

    try {
      const response = await apiClient.delete(endpoint);

      if (response.status >= 400) {
        throw new Error(`DELETE failed with status ${response.status}`);
      }

      this.testResults.delete = { success: true, error: null };
      logger.info(`✅ ${this.moduleName} - Resource deleted successfully`);
      return response;
    } catch (error) {
      this.testResults.delete = { success: false, error: error.message };
      this.errors.push({ step: "delete", error: error.message });
      throw error;
    }
  }

  extractResourceId(response) {
    try {
      if (response.data && response.data.id) {
        return response.data.id;
      }
      if (response.data && response.data.data && response.data.data.id) {
        return response.data.data.id;
      }

      // Try to extract ID from response headers or URL
      const responseString = JSON.stringify(response.data);
      const idMatch = responseString.match(/"id":\s*"([^"]+)"/);
      if (idMatch) {
        return idMatch[1];
      }

      return null;
    } catch (error) {
      logger.warn(`Could not extract resource ID: ${error.message}`);
      return null;
    }
  }

  async cleanup() {
    const cleanupResults = {
      attempted: 0,
      successful: 0,
      failed: 0,
      errors: [],
    };

    for (const resource of this.createdResources.reverse()) {
      cleanupResults.attempted++;
      try {
        // Construct delete endpoint if needed
        let deleteEndpoint = resource.endpoint;
        if (resource.id && !deleteEndpoint.includes(resource.id)) {
          deleteEndpoint = `${deleteEndpoint}/${resource.id}`;
        }

        await apiClient.delete(deleteEndpoint);
        cleanupResults.successful++;
        logger.info(
          `🗑️ ${this.moduleName} - Cleaned up resource: ${resource.id}`
        );
      } catch (error) {
        cleanupResults.failed++;
        cleanupResults.errors.push({
          resourceId: resource.id,
          error: error.message,
        });
        logger.warn(
          `⚠️ ${this.moduleName} - Cleanup failed for resource ${resource.id}: ${error.message}`
        );
      }
    }

    this.createdResources = [];
    logger.info(
      `🧹 ${this.moduleName} - Cleanup completed: ${cleanupResults.successful}/${cleanupResults.attempted} successful`
    );

    return cleanupResults;
  }

  getTestResults() {
    return {
      module: this.moduleName,
      path: this.modulePath,
      results: this.testResults,
      errors: this.errors,
      resourcesCreated: this.createdResources.length,
      isSkipped: this.moduleSkipFlag,
    };
  }

  reportModuleStatus() {
    const results = this.getTestResults();
    const passedOperations = Object.values(this.testResults).filter(
      (r) => r.success
    ).length;
    const totalOperations = Object.keys(this.testResults).length;

    logger.info(`📊 ${this.moduleName} - Module Test Summary:`);
    logger.info(`   Operations: ${passedOperations}/${totalOperations} passed`);
    logger.info(`   Resources Created: ${this.createdResources.length}`);
    logger.info(`   Errors: ${this.errors.length}`);
    logger.info(
      `   Status: ${this.moduleSkipFlag ? "❌ SKIPPED" : "✅ ACTIVE"}`
    );

    return results;
  }

  isOperationSkipped(operation) {
    return (
      this.moduleSkipFlag || this.testResults[operation]?.success === false
    );
  }
}

module.exports = ModuleIsolationHelper;
