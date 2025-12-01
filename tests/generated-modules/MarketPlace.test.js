/**
 * Auto-generated test for module: MarketPlace
 * Generated: 2025-12-01T15:06:00.422Z
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
const moduleName = 'MarketPlace';

describe('Module: MarketPlace', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new MarketPlace', async () => {
    const [url, payload] = ["/erp-apis/MarketPlace",{"name":"string","nameAr":"string","status":"Active","latitude":1,"longitude":1,"errorRadius":1}];
    
    logger.info('Testing CREATE for MarketPlace');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created MarketPlace with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get MarketPlace by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/MarketPlace",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for MarketPlace with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read MarketPlace');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update MarketPlace', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/MarketPlace",{"id":"<createdId>","name":"string","nameAr":"string","status":"Active","latitude":1,"longitude":1,"errorRadius":1}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for MarketPlace with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated MarketPlace');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete MarketPlace', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/MarketPlace/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for MarketPlace with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted MarketPlace');
  }, TEST_TIMEOUT);
});
