/**
 * Auto-generated test for module: Currency
 * Generated: 2025-12-01T15:06:00.411Z
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
const moduleName = 'Currency';

describe('Module: Currency', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Currency', async () => {
    const [url, payload] = ["/erp-apis/Currency",{"name":"string","nameAr":"string","symbol":"string","subUnit":"string","countryCode":"string","differenceAccount":1}];
    
    logger.info('Testing CREATE for Currency');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Currency with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Currency by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Currency",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Currency with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Currency');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Currency', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Currency",{"id":"<createdId>","code":"string","name":"string","nameAr":"string","symbol":"string","subUnit":"string","countryCode":"string","differenceAccount":1}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Currency with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Currency');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Currency', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Currency/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Currency with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Currency');
  }, TEST_TIMEOUT);
});
