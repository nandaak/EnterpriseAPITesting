/**
 * Auto-generated test for module: AssetsReturnPurchaseInvoice
 * Generated: 2025-12-01T13:40:51.229Z
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
const moduleName = 'AssetsReturnPurchaseInvoice';

describe('Module: AssetsReturnPurchaseInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AssetsReturnPurchaseInvoice', async () => {
    const [url, payload] = ["/erp-apis/AssetsReturnPurchaseInvoice",{"date":"2025-11-26T16:29:05.635Z","description":"string","vendorId":1,"vendorCode":"string","vendorName":"string","vendorNameAr":"string","currencyId":1,"currencyName":"string","currencyNameAr":"string","currencyRate":1,"reference":"string","paymentTermId":1,"paymentTermName":"string","paymentTermNameAr":"string","assetsReturnPurchaseInvoiceDetails":[{"assetId":1,"assetName":"string","remainingQuantity":1,"quantityToReturn":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":1,"taxName":"string","taxNameAr":"string","assetsPurchaseInvoiceDetailId":"00000000-0000-0000-0000-000000000000"}]}];
    
    logger.info('Testing CREATE for AssetsReturnPurchaseInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AssetsReturnPurchaseInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AssetsReturnPurchaseInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnPurchaseInvoice/<createdId>/GetById",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AssetsReturnPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AssetsReturnPurchaseInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update AssetsReturnPurchaseInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnPurchaseInvoice",{"id":"<createdId>","date":"2025-11-26T16:29:05.635Z","description":"string","vendorId":"<createdId>","vendorCode":"string","vendorName":"string","vendorNameAr":"string","currencyId":"<createdId>","currencyName":"string","currencyNameAr":"string","currencyRate":1,"reference":"string","paymentTermId":"<createdId>","paymentTermName":"string","paymentTermNameAr":"string","assetsReturnPurchaseInvoiceDetails":[{"id":"<createdId>","assetId":"<createdId>","assetName":"string","remainingQuantity":1,"quantityToReturn":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":"<createdId>","taxName":"string","taxNameAr":"string","assetsPurchaseInvoiceDetailId":"<createdId>","assetsReturnPurchaseInvoiceHeaderId":"<createdId>"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for AssetsReturnPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated AssetsReturnPurchaseInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete AssetsReturnPurchaseInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnPurchaseInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for AssetsReturnPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted AssetsReturnPurchaseInvoice');
  }, TEST_TIMEOUT);
});
