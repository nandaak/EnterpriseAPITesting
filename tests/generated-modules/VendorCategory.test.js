/**
 * Auto-generated test for module: VendorCategory
 * Generated: 2025-12-01T15:06:00.429Z
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
const moduleName = 'VendorCategory';

describe('Module: VendorCategory', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new VendorCategory', async () => {
    const [url, payload] = ["/erp-apis/VendorCategory",{"name":"string","nameAr":"string","payableAccountId":1,"purchaseAccountId":1,"purchaseReturnAccountId":1,"discountAccountId":1,"pricePolicyId":1,"paymentTermId":1,"marketType":"B2B"}];
    
    logger.info('Testing CREATE for VendorCategory');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created VendorCategory with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get VendorCategory by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorCategory",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for VendorCategory with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read VendorCategory');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update VendorCategory', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorCategory",{"id":"<createdId>","name":"string","nameAr":"string","payableAccountId":"<createdId>","purchaseAccountId":"<createdId>","purchaseReturnAccountId":"<createdId>","discountAccountId":"<createdId>","pricePolicyId":"<createdId>","paymentTermId":"<createdId>","marketType":"B2B"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for VendorCategory with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated VendorCategory');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete VendorCategory', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorCategory/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for VendorCategory with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted VendorCategory');
  }, TEST_TIMEOUT);
});
