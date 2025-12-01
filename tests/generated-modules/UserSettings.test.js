/**
 * Auto-generated test for module: UserSettings
 * Generated: 2025-12-01T15:06:00.428Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'UserSettings';

describe('Module: UserSettings', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new UserSettings', async () => {
    const [url, payload] = ["/erp-apis/UserSettings/Copy",{"sourceUserId":"00000000-0000-0000-0000-000000000000","targetUserIds":["00000000-0000-0000-0000-000000000000"]}];
    
    logger.info('Testing CREATE for UserSettings');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created UserSettings with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get UserSettings by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/UserSettings/GetAll",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for UserSettings with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read UserSettings');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update UserSettings', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/UserSettings",{"userId":"<createdId>","branchIds":["00000000-0000-0000-0000-000000000000"],"treasuryId":"<createdId>","warehouseId":"<createdId>","bankId":"<createdId>","language":"Arabic","canEditSalesPrice":true,"minimumPricePercentage":1,"allowSellingBelowPriceLimit":true,"enableMaximumSalesPriceLimit":true,"maximumPricePercentage":1}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for UserSettings with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated UserSettings');
  }, TEST_TIMEOUT);
  
  
});
