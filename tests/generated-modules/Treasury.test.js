/**
 * Auto-generated test for module: Treasury
 * Generated: 2025-12-01T13:40:51.244Z
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
const moduleName = 'Treasury';

describe('Module: Treasury', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Treasury', async () => {
    const [url, payload] = ["/erp-apis/Treasury",{"name":"string","nameAr":"string","currencyId":1,"branches":["00000000-0000-0000-0000-000000000000"],"accountId":1,"journalEntryLineId":"00000000-0000-0000-0000-000000000000","accountOpeningBalance":1,"openingBalance":1}];
    
    logger.info('Testing CREATE for Treasury');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Treasury with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Treasury by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Treasury",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Treasury with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Treasury');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Treasury', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Treasury",{"id":"<createdId>","name":"string","nameAr":"string","currencyId":"<createdId>","branches":["00000000-0000-0000-0000-000000000000"],"accountId":"<createdId>","journalEntryLineId":"<createdId>","accountOpeningBalance":1,"openingBalance":1}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Treasury with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Treasury');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Treasury', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Treasury/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Treasury with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Treasury');
  }, TEST_TIMEOUT);
});
