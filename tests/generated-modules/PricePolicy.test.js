/**
 * Auto-generated test for module: PricePolicy
 * Generated: 2025-12-01T13:40:51.239Z
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
const moduleName = 'PricePolicy';

describe('Module: PricePolicy', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new PricePolicy', async () => {
    const [url, payload] = ["/erp-apis/PricePolicy",{"name":"string","nameAr":"string","policySource":"Manual","policyItemsList":[{"itemId":1,"uomId":"00000000-0000-0000-0000-000000000000","itemVariantId":1,"price":1,"isVatApplied":true,"isSellingPriceIncludeVat":true,"taxId":1,"taxRatio":1,"priceWithVat":1}]}];
    
    logger.info('Testing CREATE for PricePolicy');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created PricePolicy with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get PricePolicy by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PricePolicy",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for PricePolicy with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read PricePolicy');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update PricePolicy', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PricePolicy",{"id":"<createdId>","name":"string","nameAr":"string","policySource":"Manual","policyItemsList":[{"id":"<createdId>","itemId":"<createdId>","itemVariantId":"<createdId>","uomId":"<createdId>","isVatApplied":true,"isSellingPriceIncludeVat":true,"taxRatio":1,"taxId":"<createdId>","price":1,"priceWithVat":1}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for PricePolicy with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated PricePolicy');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete PricePolicy', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PricePolicy/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for PricePolicy with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted PricePolicy');
  }, TEST_TIMEOUT);
});
