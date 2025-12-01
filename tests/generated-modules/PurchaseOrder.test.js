/**
 * Auto-generated test for module: PurchaseOrder
 * Generated: 2025-12-01T15:06:00.424Z
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
const moduleName = 'PurchaseOrder';

describe('Module: PurchaseOrder', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new PurchaseOrder', async () => {
    const [url, payload] = ["/erp-apis/PurchaseOrder",{"orderDate":"2025-11-26T16:29:05.637Z","description":"string","termsAndCondition":"string","vendorId":1,"vendorName":"string","currencyId":1,"currencyName":"string","currencyRate":1,"paymentTermId":1,"purchaseOrderDetails":[{"barCode":"string","barCodeId":1,"itemId":1,"itemCode":"string","itemName":"string","itemVariantId":1,"itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":1,"itemCategoryNameAr":"string","itemCategoryNameEn":"string","categoryType":{},"description":"string","uomId":"00000000-0000-0000-0000-000000000000","uomCode":"string","uomNameAr":"string","uomNameEn":"string","quantity":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":1,"notes":"string","trackingType":{},"hasExpiryDate":true}],"purchaseOrderAttachments":[{"attachmentId":"string","name":"string"}],"enableWorkflow":true}];
    
    logger.info('Testing CREATE for PurchaseOrder');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created PurchaseOrder with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get PurchaseOrder by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PurchaseOrder",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for PurchaseOrder with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read PurchaseOrder');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update PurchaseOrder', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PurchaseOrder",{"id":"<createdId>","orderDate":"2025-11-26T16:29:05.637Z","description":"string","termsAndCondition":"string","vendorId":"<createdId>","vendorName":"string","currencyId":"<createdId>","currencyName":"string","currencyRate":1,"paymentTermId":"<createdId>","purchaseOrderDetails":[{"id":"<createdId>","barCode":"string","barCodeId":"<createdId>","itemId":"<createdId>","itemCode":"string","itemName":"string","itemVariantId":"<createdId>","itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":"<createdId>","itemCategoryNameAr":"string","itemCategoryNameEn":"string","categoryType":{},"description":"string","uomId":"<createdId>","uomCode":"string","uomNameAr":"string","uomNameEn":"string","quantity":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":"<createdId>","notes":"string","trackingType":{},"hasExpiryDate":true}],"purchaseOrderAttachments":[{"id":"<createdId>","attachmentId":"<createdId>","name":"string"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for PurchaseOrder with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated PurchaseOrder');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete PurchaseOrder', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PurchaseOrder/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for PurchaseOrder with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted PurchaseOrder');
  }, TEST_TIMEOUT);
});
