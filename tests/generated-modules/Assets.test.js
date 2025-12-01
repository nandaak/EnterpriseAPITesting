/**
 * Auto-generated test for module: Assets
 * Generated: 2025-12-01T15:06:00.405Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: Yes
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'Assets';

describe('Module: Assets', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Assets', async () => {
    const [url, payload] = ["/erp-apis/Assets",{"name":"string","fixedAssetsGroupId":1}];
    
    logger.info('Testing CREATE for Assets');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Assets with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Assets by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Assets",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Assets with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Assets');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Assets', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Assets",{"id":"<createdId>","name":"string","assetGroupId":"<createdId>","barcode":"string","isDepreciate":true,"depreciationMethod":"StraightLine","depreciationRate":1,"usefulLife":1,"salvageValue":1,"assetAccountId":"<createdId>","accumulatedDepreciationAccountId":"<createdId>","assetExpenseAccountId":"<createdId>","plAccountId":"<createdId>"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Assets with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Assets');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Assets', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Assets/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Assets with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Assets');
  }, TEST_TIMEOUT);
});
