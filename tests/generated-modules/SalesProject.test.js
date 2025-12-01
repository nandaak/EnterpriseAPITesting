/**
 * Auto-generated test for module: SalesProject
 * Generated: 2025-12-01T15:06:00.426Z
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
const moduleName = 'SalesProject';

describe('Module: SalesProject', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesProject', async () => {
    const [url, payload] = ["/erp-apis/SalesProject",{"name":"string","nameAr":"string","description":"string","customerId":1,"startDate":"2025-11-26T16:29:05.638Z","endDate":"2025-11-26T16:29:05.638Z","contractValue":1}];
    
    logger.info('Testing CREATE for SalesProject');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesProject with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesProject by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProject",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesProject with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesProject');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesProject', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProject",{"id":"<createdId>","name":"string","nameAr":"string","description":"string","customerId":"<createdId>","startDate":"2025-11-26T16:29:05.638Z","endDate":"2025-11-26T16:29:05.638Z","contractValue":1}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesProject with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesProject');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesProject', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProject/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesProject with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesProject');
  }, TEST_TIMEOUT);
});
