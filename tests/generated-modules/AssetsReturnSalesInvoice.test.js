/**
 * Auto-generated test for module: AssetsReturnSalesInvoice
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
const moduleName = 'AssetsReturnSalesInvoice';

describe('Module: AssetsReturnSalesInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AssetsReturnSalesInvoice', async () => {
    const [url, payload] = ["/erp-apis/AssetsReturnSalesInvoice",{"date":"2025-11-26T16:29:05.635Z","reference":"string","description":"string","customerId":1,"customerCode":"string","customerName":"string","customerNameAr":"string","applicationSource":"ERP","assetsSalesInvoiceHeaderIds":["00000000-0000-0000-0000-000000000000"],"assetsReturnSalesInvoiceDetails":[{"assetId":1,"assetName":"string","assetCode":"string","remainingQuantity":1,"quantityToReturn":1,"price":1,"taxId":1,"taxName":"string","taxNameAr":"string","vatPercentage":1,"assetsSalesInvoiceDetailId":"00000000-0000-0000-0000-000000000000"}]}];
    
    logger.info('Testing CREATE for AssetsReturnSalesInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AssetsReturnSalesInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AssetsReturnSalesInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnSalesInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AssetsReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AssetsReturnSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update AssetsReturnSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnSalesInvoice/<createdId>",{"id":"<createdId>","date":"2025-11-26T16:29:05.635Z","reference":"string","description":"string","customerId":"<createdId>","customerCode":"string","customerName":"string","customerNameAr":"string","applicationSource":"ERP","assetsSalesInvoiceHeaderIds":["00000000-0000-0000-0000-000000000000"],"assetsReturnSalesInvoiceDetails":[{"id":"<createdId>","assetId":"<createdId>","assetName":"string","assetCode":"string","remainingQuantity":1,"quantityToReturn":1,"price":1,"taxId":"<createdId>","taxName":"string","taxNameAr":"string","vatPercentage":1,"assetsSalesInvoiceDetailId":"<createdId>"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for AssetsReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated AssetsReturnSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete AssetsReturnSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsReturnSalesInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for AssetsReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted AssetsReturnSalesInvoice');
  }, TEST_TIMEOUT);
});
