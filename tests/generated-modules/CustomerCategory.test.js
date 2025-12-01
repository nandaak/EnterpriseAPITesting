/**
 * Auto-generated test for module: CustomerCategory
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
const moduleName = 'CustomerCategory';

describe('Module: CustomerCategory', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CustomerCategory', async () => {
    const [url, payload] = ["/erp-apis/CustomerCategory",{"name":"string","nameAr":"string","receivableAccountId":1,"salesAccountId":1,"salesReturnAccountId":1,"discountAccountId":1,"pricePolicyId":1,"paymentTermId":1,"marketType":"B2B"}];
    
    logger.info('Testing CREATE for CustomerCategory');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CustomerCategory with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CustomerCategory by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerCategory",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CustomerCategory with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CustomerCategory');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update CustomerCategory', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerCategory",{"id":"<createdId>","name":"string","nameAr":"string","code":"string","receivableAccountId":"<createdId>","salesAccountId":"<createdId>","salesReturnAccountId":"<createdId>","discountAccountId":"<createdId>","pricePolicyId":"<createdId>","paymentTermId":"<createdId>","marketType":"B2B"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for CustomerCategory with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated CustomerCategory');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete CustomerCategory', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerCategory/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for CustomerCategory with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted CustomerCategory');
  }, TEST_TIMEOUT);
});
