/**
 * Auto-generated test for module: AssetsPurchaseInvoice
 * Generated: 2025-12-01T15:06:00.406Z
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
const moduleName = 'AssetsPurchaseInvoice';

describe('Module: AssetsPurchaseInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AssetsPurchaseInvoice', async () => {
    const [url, payload] = ["/erp-apis/AssetsPurchaseInvoice",{"date":"2025-11-26T16:29:05.635Z","description":"string","vendorId":1,"vendorCode":"string","vendorName":"string","vendorNameAr":"string","currencyId":1,"currencyName":"string","currencyNameAr":"string","currencyRate":1,"reference":"string","paymentTermId":1,"paymentTermName":"string","paymentTermNameAr":"string","assetsPurchaseInvoiceDetails":[{"assetId":1,"assetName":"string","quantity":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":1,"taxName":"string","taxNameAr":"string","assetLocationId":1,"assetLocationName":"string","activationDate":"2025-11-26T16:29:05.635Z"}]}];
    
    logger.info('Testing CREATE for AssetsPurchaseInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AssetsPurchaseInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AssetsPurchaseInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsPurchaseInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AssetsPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AssetsPurchaseInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update AssetsPurchaseInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsPurchaseInvoice",{"id":"<createdId>","date":"2025-11-26T16:29:05.635Z","description":"string","vendorId":"<createdId>","vendorCode":"string","vendorName":"string","vendorNameAr":"string","currencyId":"<createdId>","currencyName":"string","currencyNameAr":"string","currencyRate":1,"reference":"string","paymentTermId":"<createdId>","paymentTermName":"string","paymentTermNameAr":"string","assetsPurchaseInvoiceDetails":[{"id":"<createdId>","assetId":"<createdId>","assetName":"string","quantity":1,"cost":1,"discountPercentage":1,"discountAmount":1,"vatPercentage":1,"taxId":"<createdId>","taxName":"string","taxNameAr":"string","assetLocationId":"<createdId>","assetLocationName":"string","activationDate":"2025-11-26T16:29:05.635Z"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for AssetsPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated AssetsPurchaseInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete AssetsPurchaseInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsPurchaseInvoice/DeleteLine/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for AssetsPurchaseInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted AssetsPurchaseInvoice');
  }, TEST_TIMEOUT);
});
