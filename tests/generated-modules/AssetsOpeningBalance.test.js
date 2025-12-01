/**
 * Auto-generated test for module: AssetsOpeningBalance
 * Generated: 2025-12-01T13:40:51.228Z
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
const moduleName = 'AssetsOpeningBalance';

describe('Module: AssetsOpeningBalance', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AssetsOpeningBalance', async () => {
    const [url, payload] = ["/erp-apis/AssetsOpeningBalance",{"assetOpeningBalanceJournalEntryLineId":"00000000-0000-0000-0000-000000000000","accumulatedDepOpeningBalanceJournalEntryLineId":"00000000-0000-0000-0000-000000000000","details":[{"assetId":1,"purchaseValue":1,"accumulatedDepreciation":1,"purchaseDate":"2025-11-26T16:29:05.635Z","depreciationStartDate":"2025-11-26T16:29:05.635Z","lastDepreciationDate":"2025-11-26T16:29:05.635Z","locationId":1}]}];
    
    logger.info('Testing CREATE for AssetsOpeningBalance');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AssetsOpeningBalance with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AssetsOpeningBalance by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsOpeningBalance",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AssetsOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AssetsOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update AssetsOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsOpeningBalance",{"id":"<createdId>","assetOpeningBalanceJournalEntryLineId":"<createdId>","accumulatedDepOpeningBalanceJournalEntryLineId":"<createdId>","details":[{"id":"<createdId>","assetId":"<createdId>","purchaseValue":1,"accumulatedDepreciation":1,"purchaseDate":"2025-11-26T16:29:05.635Z","depreciationStartDate":"2025-11-26T16:29:05.635Z","lastDepreciationDate":"2025-11-26T16:29:05.635Z","locationId":"<createdId>"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for AssetsOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated AssetsOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete AssetsOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsOpeningBalance/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for AssetsOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted AssetsOpeningBalance');
  }, TEST_TIMEOUT);
});
