/**
 * Auto-generated test for module: FixedAssetsGroup
 * Generated: 2025-12-01T13:40:51.234Z
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
const moduleName = 'FixedAssetsGroup';

describe('Module: FixedAssetsGroup', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new FixedAssetsGroup', async () => {
    const [url, payload] = ["/erp-apis/FixedAssetsGroup",{"name":"string","isDepreciate":true,"depreciationMethod":"StraightLine","depreciationRate":1,"usefulLife":1,"salvageValue":1,"assetAccountId":1,"accumulatedDepreciationAccountId":1,"assetExpenseAccountId":1,"plAccountId":1}];
    
    logger.info('Testing CREATE for FixedAssetsGroup');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created FixedAssetsGroup with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get FixedAssetsGroup by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FixedAssetsGroup",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for FixedAssetsGroup with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read FixedAssetsGroup');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update FixedAssetsGroup', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FixedAssetsGroup",{"id":"<createdId>","name":"string","isDepreciate":true,"depreciationMethod":"StraightLine","depreciationRate":1,"usefulLife":1,"salvageValue":1,"assetAccountId":"<createdId>","accumulatedDepreciationAccountId":"<createdId>","assetExpenseAccountId":"<createdId>","plAccountId":"<createdId>"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for FixedAssetsGroup with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated FixedAssetsGroup');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete FixedAssetsGroup', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FixedAssetsGroup/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for FixedAssetsGroup with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted FixedAssetsGroup');
  }, TEST_TIMEOUT);
});
