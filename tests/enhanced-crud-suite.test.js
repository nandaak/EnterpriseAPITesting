/**
 * Enhanced CRUD Test Suite
 * Tests all 96 modules using Enhanced-ERP-Api-Schema-With-Payloads.json
 * 
 * Features:
 * - Real payloads from Swagger
 * - <createdId> correlation
 * - Complete CRUD lifecycle
 * - ID Registry integration
 * - Comprehensive reporting
 */

const EnhancedSchemaAdapter = require('../utils/enhanced-schema-adapter');
const apiClient = require('../utils/api-client');
const TokenManager = require('../utils/token-manager');
const logger = require('../utils/logger');
const { validateAndEnhancePayload } = require('../utils/payload-validator');
const { handleTestError } = require('../utils/error-handler');
const { getFailureLogger } = require('../utils/failure-response-logger');
const fs = require('fs');
const path = require('path');

// Initialize failure logger
const failureLogger = getFailureLogger();

// Initialize adapter
const adapter = new EnhancedSchemaAdapter();

// Test configuration
const TEST_CONFIG = {
  timeout: 30000,
  retries: 2,
  idRegistryPath: 'test-data/id-registry.json',
  createdIdsPath: 'test-data/created-ids.json'
};

// ID Registry for tracking created IDs
class IDRegistry {
  constructor() {
    this.registry = this.loadRegistry();
  }

  loadRegistry() {
    try {
      if (fs.existsSync(TEST_CONFIG.idRegistryPath)) {
        return JSON.parse(fs.readFileSync(TEST_CONFIG.idRegistryPath, 'utf8'));
      }
    } catch (error) {
      logger.warn(`Could not load ID registry: ${error.message}`);
    }
    return {};
  }

  saveRegistry() {
    try {
      const dir = path.dirname(TEST_CONFIG.idRegistryPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(
        TEST_CONFIG.idRegistryPath,
        JSON.stringify(this.registry, null, 2)
      );
    } catch (error) {
      logger.error(`Could not save ID registry: ${error.message}`);
    }
  }

  store(moduleName, id, metadata = {}) {
    if (!this.registry[moduleName]) {
      this.registry[moduleName] = [];
    }

    this.registry[moduleName].push({
      id,
      createdAt: new Date().toISOString(),
      ...metadata
    });

    this.saveRegistry();
  }

  getLatest(moduleName) {
    const entries = this.registry[moduleName];
    if (!entries || entries.length === 0) return null;
    return entries[entries.length - 1].id;
  }

  getAll(moduleName) {
    return this.registry[moduleName] || [];
  }
}

const idRegistry = new IDRegistry();

// Test results tracking
const testResults = {
  total: 0,
  passed: 0,
  failed: 0,
  skipped: 0,
  modules: {}
};

describe('Enhanced CRUD Test Suite - All 96 Modules', () => {

  beforeAll(async () => {
    logger.info('🚀 Starting Enhanced CRUD Test Suite');
    logger.info('='.repeat(70));

    // Ensure valid authentication token
    logger.info('🔐 Validating authentication...');
    try {
      const tokenStatus = await TokenManager.validateAndRefreshTokenWithStatus();

      if (!tokenStatus.success) {
        throw new Error(`Authentication failed: ${tokenStatus.message}`);
      }

      logger.info(`✅ Authentication successful: ${tokenStatus.message}`);

      // Verify token is loaded in API client
      const token = await TokenManager.getValidToken();
      if (!token) {
        throw new Error('No valid token available for API client');
      }

      logger.info(`✅ Token loaded (length: ${token.length} characters)`);

    } catch (error) {
      logger.error(`❌ Authentication setup failed: ${error.message}`);
      throw error;
    }

    logger.info('📊 Test Suite Information:');
    logger.info(`   Total modules available: ${adapter.getModules().length}`);
    logger.info(`   Testable modules: ${adapter.getTestableModules().length}`);
    logger.info('='.repeat(70));
  });

  afterAll(() => {
    logger.info('Enhanced CRUD Test Suite completed');
    logger.info(`Results: ${testResults.passed} passed, ${testResults.failed} failed, ${testResults.skipped} skipped`);

    // Save final results
    const resultsPath = 'test-results/enhanced-crud-results.json';
    const dir = path.dirname(resultsPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(resultsPath, JSON.stringify(testResults, null, 2));

    // Generate failure response report
    const failureReport = failureLogger.generateReport();
    const failureStats = failureLogger.getStats();

    logger.info('📊 Failure Response Summary:');
    logger.info(`   Total failures logged: ${failureStats.total}`);
    logger.info(`   400 Bad Request: ${failureStats.status400}`);
    logger.info(`   404 Not Found: ${failureStats.status404}`);
    logger.info(`   500 Server Error: ${failureStats.status500}`);
    logger.info(`   Unique URLs: ${failureStats.uniqueUrls}`);
    logger.info(`   Report saved: failure_response.json`);
    logger.info(`   Detailed report: ${failureReport.reportPath}`);
  });

  // Get testable modules
  const testableModules = adapter.getTestableModules();

  // Generate tests for each module
  testableModules.forEach(moduleName => {
    describe(`Module: ${moduleName}`, () => {
      let createdId = null;
      let moduleStats = {
        create: null,
        read: null,
        update: null,
        delete: null
      };

      // Find CRUD operations
      const crudOps = adapter.findCrudOperations(moduleName);

      // Test CREATE (POST)
      if (crudOps.POST) {
        test(`CREATE - ${moduleName}`, async () => {
          testResults.total++;

          try {
            const [url, payload] = crudOps.POST.data;

            // Validate and enhance payload
            const enhancedPayload = validateAndEnhancePayload(moduleName, payload, 'POST');

            logger.info(`Testing CREATE for ${moduleName}`);
            logger.debug(`URL: ${url}`);
            logger.debug(`Payload: ${JSON.stringify(enhancedPayload, null, 2)}`);

            const response = await apiClient.post(url, enhancedPayload);

            expect(response.status).toBe(200);
            expect(response.data).toBeDefined();

            // Extract ID from response
            createdId = response.data.id || response.data.Id || response.data.ID;

            if (createdId) {
              logger.success(`Created ${moduleName} with ID: ${createdId}`);

              // Store in registry
              idRegistry.store(moduleName, createdId, {
                operation: 'CREATE',
                url,
                status: 'success'
              });

              // Store in adapter
              adapter.storeId(moduleName, createdId);

              moduleStats.create = 'PASSED';
              testResults.passed++;
            } else {
              logger.warn(`No ID returned for ${moduleName}`);
              moduleStats.create = 'PASSED_NO_ID';
              testResults.passed++;
            }

          } catch (error) {
            const [url, payload] = crudOps.POST.data;
            const errorInfo = handleTestError(error, {
              moduleName,
              operation: 'CREATE',
              url,
              payload
            });

            // Log failure response if 400, 404, or 500
            if (error.response && (error.response.status === 400 || error.response.status === 404 || error.response.status === 500)) {
              failureLogger.logFailure(
                'POST',
                url,
                error.response.status,
                error.response.data,
                payload
              );
              logger.warn(`Failure logged: POST ${url} - Status ${error.response.status}`);
            }

            logger.error(`CREATE failed for ${moduleName}: ${errorInfo.message}`);
            logger.debug(`Error category: ${errorInfo.category} - ${errorInfo.suggestion}`);

            moduleStats.create = 'FAILED';
            testResults.failed++;
            throw error;
          }
        }, TEST_CONFIG.timeout);
      }

      // Test READ (GET)
      if (crudOps.GET) {
        test(`READ - ${moduleName}`, async () => {
          testResults.total++;

          // Skip if no ID from CREATE
          if (!createdId) {
            logger.warn(`Skipping READ for ${moduleName} - no created ID`);
            testResults.skipped++;
            moduleStats.read = 'SKIPPED';
            return;
          }

          try {
            const prepared = adapter.prepareOperation(crudOps.GET.data, createdId);
            if (!prepared) {
              throw new Error('Could not prepare GET operation');
            }

            const [url] = prepared;

            logger.info(`Testing READ for ${moduleName} with ID: ${createdId}`);
            logger.debug(`URL: ${url}`);

            const response = await apiClient.get(url);

            expect(response.status).toBe(200);
            expect(response.data).toBeDefined();

            logger.success(`Successfully read ${moduleName}`);
            moduleStats.read = 'PASSED';
            testResults.passed++;

          } catch (error) {
            // Log failure response if 400, 404, or 500
            if (error.response && (error.response.status === 400 || error.response.status === 404 || error.response.status === 500)) {
              const url = adapter.prepareOperation(crudOps.GET.data, createdId)?.[0];
              if (url) {
                failureLogger.logFailure(
                  'GET',
                  url,
                  error.response.status,
                  error.response.data,
                  null
                );
                logger.warn(`Failure logged: GET ${url} - Status ${error.response.status}`);
              }
            }

            logger.error(`READ failed for ${moduleName}: ${error.message}`);
            moduleStats.read = 'FAILED';
            testResults.failed++;
            throw error;
          }
        }, TEST_CONFIG.timeout);
      }

      // Test UPDATE (PUT)
      if (crudOps.PUT) {
        test(`UPDATE - ${moduleName}`, async () => {
          testResults.total++;

          // Skip if no ID from CREATE
          if (!createdId) {
            logger.warn(`Skipping UPDATE for ${moduleName} - no created ID`);
            testResults.skipped++;
            moduleStats.update = 'SKIPPED';
            return;
          }

          try {
            const prepared = adapter.prepareOperation(crudOps.PUT.data, createdId);
            if (!prepared) {
              throw new Error('Could not prepare PUT operation');
            }

            const [url, payload] = prepared;

            // Validate and enhance payload
            const enhancedPayload = validateAndEnhancePayload(moduleName, payload, 'PUT');

            logger.info(`Testing UPDATE for ${moduleName} with ID: ${createdId}`);
            logger.debug(`URL: ${url}`);
            logger.debug(`Payload: ${JSON.stringify(enhancedPayload, null, 2)}`);

            const response = await apiClient.put(url, enhancedPayload);

            expect(response.status).toBe(200);

            logger.success(`Successfully updated ${moduleName}`);
            moduleStats.update = 'PASSED';
            testResults.passed++;

          } catch (error) {
            // Log failure response if 400, 404, or 500
            if (error.response && (error.response.status === 400 || error.response.status === 404 || error.response.status === 500)) {
              const prepared = adapter.prepareOperation(crudOps.PUT.data, createdId);
              if (prepared) {
                const [url, payload] = prepared;
                failureLogger.logFailure(
                  'PUT',
                  url,
                  error.response.status,
                  error.response.data,
                  payload
                );
                logger.warn(`Failure logged: PUT ${url} - Status ${error.response.status}`);
              }
            }

            logger.error(`UPDATE failed for ${moduleName}: ${error.message}`);
            moduleStats.update = 'FAILED';
            testResults.failed++;
            throw error;
          }
        }, TEST_CONFIG.timeout);
      }

      // Test DELETE
      if (crudOps.DELETE) {
        test(`DELETE - ${moduleName}`, async () => {
          testResults.total++;

          // Skip if no ID from CREATE
          if (!createdId) {
            logger.warn(`Skipping DELETE for ${moduleName} - no created ID`);
            testResults.skipped++;
            moduleStats.delete = 'SKIPPED';
            return;
          }

          try {
            const prepared = adapter.prepareOperation(crudOps.DELETE.data, createdId);
            if (!prepared) {
              throw new Error('Could not prepare DELETE operation');
            }

            const [url] = prepared;

            logger.info(`Testing DELETE for ${moduleName} with ID: ${createdId}`);
            logger.debug(`URL: ${url}`);

            const response = await apiClient.delete(url);

            expect(response.status).toBe(200);

            logger.success(`Successfully deleted ${moduleName}`);
            moduleStats.delete = 'PASSED';
            testResults.passed++;

          } catch (error) {
            // Log failure response if 400, 404, or 500
            if (error.response && (error.response.status === 400 || error.response.status === 404 || error.response.status === 500)) {
              const url = adapter.prepareOperation(crudOps.DELETE.data, createdId)?.[0];
              if (url) {
                failureLogger.logFailure(
                  'DELETE',
                  url,
                  error.response.status,
                  error.response.data,
                  null
                );
                logger.warn(`Failure logged: DELETE ${url} - Status ${error.response.status}`);
              }
            }

            logger.error(`DELETE failed for ${moduleName}: ${error.message}`);
            moduleStats.delete = 'FAILED';
            testResults.failed++;
            throw error;
          }
        }, TEST_CONFIG.timeout);
      }

      // Store module results
      afterAll(() => {
        testResults.modules[moduleName] = {
          ...moduleStats,
          createdId,
          timestamp: new Date().toISOString()
        };
      });
    });
  });
});

// Export for use in other tests
module.exports = {
  adapter,
  idRegistry,
  testResults
};
