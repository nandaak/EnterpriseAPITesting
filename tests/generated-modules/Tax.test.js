/**
 * Auto-generated test for module: Tax
 * Generated: 2025-12-01T15:06:00.427Z
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
const moduleName = 'Tax';

describe('Module: Tax', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Tax', async () => {
    const [url, payload] = ["/erp-apis/Tax",{"name":"string","nameAr":"string","code":"string","ratio":1,"accountId":1,"taxGroupId":1}];
    
    logger.info('Testing CREATE for Tax');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Tax with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Tax by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tax",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Tax with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Tax');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Tax', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tax",{"id":"<createdId>","accountId":"<createdId>"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Tax with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Tax');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Tax', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tax",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Tax with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Tax');
  }, TEST_TIMEOUT);
});
