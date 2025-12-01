/**
 * Auto-generated test for module: AssetsSalesInvoice
 * Generated: 2025-12-01T15:06:00.409Z
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
const moduleName = 'AssetsSalesInvoice';

describe('Module: AssetsSalesInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AssetsSalesInvoice', async () => {
    const [url, payload] = ["/erp-apis/AssetsSalesInvoice",{"date":"2025-11-26T16:29:05.635Z","reference":"string","description":"string","customerId":1,"customerCode":"string","customerName":"string","customerNameAr":"string","paymentTermId":1,"paymentTermCode":"string","paymentTermName":"string","paymentTermNameAr":"string","applicationSource":"ERP","assetsSalesInvoiceDetails":[{"id":"00000000-0000-0000-0000-000000000000","assetId":1,"assetName":"string","assetCode":"string","quantity":1,"price":1,"taxId":1,"taxName":"string","taxNameAr":"string","vatPercentage":1}]}];
    
    logger.info('Testing CREATE for AssetsSalesInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AssetsSalesInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AssetsSalesInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsSalesInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AssetsSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AssetsSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update AssetsSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsSalesInvoice",{"id":"<createdId>","date":"2025-11-26T16:29:05.635Z","reference":"string","description":"string","customerId":"<createdId>","customerCode":"string","customerName":"string","customerNameAr":"string","paymentTermId":"<createdId>","paymentTermCode":"string","paymentTermName":"string","paymentTermNameAr":"string","applicationSource":"ERP","assetsSalesInvoiceDetails":[{"id":"<createdId>","assetId":"<createdId>","assetName":"string","assetCode":"string","quantity":1,"price":1,"taxId":"<createdId>","taxName":"string","taxNameAr":"string","vatPercentage":1}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for AssetsSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated AssetsSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete AssetsSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AssetsSalesInvoice/<createdId>/DeleteLine",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for AssetsSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted AssetsSalesInvoice');
  }, TEST_TIMEOUT);
});
