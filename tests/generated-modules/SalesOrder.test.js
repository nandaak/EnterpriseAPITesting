/**
 * Auto-generated test for module: SalesOrder
 * Generated: 2025-12-01T13:40:51.241Z
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
const moduleName = 'SalesOrder';

describe('Module: SalesOrder', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesOrder', async () => {
    const [url, payload] = ["/erp-apis/SalesOrder",{"orderDate":"2025-11-26T16:29:05.637Z","externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","expiryDate":"2025-11-26T16:29:05.637Z","description":"string","termsAndConditions":"string","customerId":1,"currencyId":1,"currencyRate":1,"salesmanId":"00000000-0000-0000-0000-000000000000","paymentTermId":1,"pricePolicyId":1,"items":[{"barCode":"string","barCodeId":1,"itemId":1,"itemCode":"string","itemName":"string","itemVariantId":1,"itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":1,"itemCategoryNameAr":"string","itemCategoryNameEn":"string","categoryType":{},"description":"string","quantity":1,"price":1,"vatPercentage":1,"isVatIncluded":true,"uomId":"00000000-0000-0000-0000-000000000000","uomCode":"string","uomNameAr":"string","uomNameEn":"string","taxId":1,"trackingType":{},"hasExpiryDate":true,"salesDetailDiscounts":[{}]}],"salesOrderAttachments":[{"attachmentId":"string","name":"string"}],"salesDiscounts":[{"discountPolicyId":1,"discountPolicyName":"string","discountPercentage":1,"isActive":true}],"enableWorkflow":true}];
    
    logger.info('Testing CREATE for SalesOrder');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesOrder with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesOrder by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesOrder",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesOrder with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesOrder');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesOrder', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesOrder",{"id":"<createdId>","orderDate":"2025-11-26T16:29:05.638Z","expiryDate":"2025-11-26T16:29:05.638Z","description":"string","termsAndConditions":"string","customerId":"<createdId>","currencyId":"<createdId>","currencyRate":1,"salesmanId":"<createdId>","paymentTermId":"<createdId>","pricePolicyId":"<createdId>","items":[{"id":"<createdId>","barCode":"string","barCodeId":"<createdId>","itemId":"<createdId>","itemCode":"string","itemName":"string","itemVariantId":"<createdId>","itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":"<createdId>","itemCategoryNameAr":"string","itemCategoryNameEn":"string","uomId":"<createdId>","uomCode":"string","uomNameAr":"string","uomNameEn":"string","taxId":"<createdId>","categoryType":{},"description":"string","quantity":1,"price":1,"isVatIncluded":true,"vatPercentage":1,"trackingType":{},"hasExpiryDate":true,"salesDetailDiscounts":[{}]}],"salesOrderAttachments":[{"id":"<createdId>","attachmentId":"<createdId>","name":"string"}],"salesDiscounts":[{"id":"<createdId>","discountPolicyId":"<createdId>","discountPolicyName":"string","discountPercentage":1,"isActive":true}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesOrder with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesOrder');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesOrder', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesOrder/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesOrder with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesOrder');
  }, TEST_TIMEOUT);
});
