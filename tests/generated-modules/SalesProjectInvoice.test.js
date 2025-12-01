/**
 * Auto-generated test for module: SalesProjectInvoice
 * Generated: 2025-12-01T13:40:51.242Z
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
const moduleName = 'SalesProjectInvoice';

describe('Module: SalesProjectInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesProjectInvoice', async () => {
    const [url, payload] = ["/erp-apis/SalesProjectInvoice",{"invoiceDate":"2025-11-26T16:29:05.638Z","code":"string","description":"string","taxId":1,"vatPercentage":1,"salesProjectId":"00000000-0000-0000-0000-000000000000","actualExecutionValue":1,"taxableTotal":1,"items":[{"itemName":"string","itemValue":1,"itemType":{},"taxId":1,"taxPercentage":1,"taxAmount":1,"total":1}]}];
    
    logger.info('Testing CREATE for SalesProjectInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesProjectInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesProjectInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProjectInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesProjectInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesProjectInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesProjectInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProjectInvoice",{"id":"<createdId>","invoiceDate":"2025-11-26T16:29:05.638Z","code":"string","description":"string","taxId":"<createdId>","vatPercentage":1,"salesProjectId":"<createdId>","actualExecutionValue":1,"taxableTotal":1,"items":[{"id":"<createdId>","itemName":"string","itemValue":1,"itemType":{},"taxId":"<createdId>","taxPercentage":1,"taxAmount":1,"total":1}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesProjectInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesProjectInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesProjectInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesProjectInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesProjectInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesProjectInvoice');
  }, TEST_TIMEOUT);
});
