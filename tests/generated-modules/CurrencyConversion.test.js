/**
 * Auto-generated test for module: CurrencyConversion
 * Generated: 2025-12-01T15:06:00.417Z
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
const moduleName = 'CurrencyConversion';

describe('Module: CurrencyConversion', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CurrencyConversion', async () => {
    const [url, payload] = ["/erp-apis/CurrencyConversion",{"fromCurrencyId":1,"fromCurrencyRate":1,"toCurrencyId":1,"note":"string"}];
    
    logger.info('Testing CREATE for CurrencyConversion');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CurrencyConversion with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CurrencyConversion by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CurrencyConversion",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CurrencyConversion with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CurrencyConversion');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update CurrencyConversion', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CurrencyConversion",{"id":"<createdId>","fromCurrencyId":"<createdId>","fromCurrencyRate":1,"toCurrencyId":"<createdId>","note":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for CurrencyConversion with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated CurrencyConversion');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete CurrencyConversion', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CurrencyConversion/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for CurrencyConversion with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted CurrencyConversion');
  }, TEST_TIMEOUT);
});
