/**
 * Auto-generated test for module: ReturnInvoice
 * Generated: 2025-12-01T15:06:00.425Z
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
const moduleName = 'ReturnInvoice';

describe('Module: ReturnInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new ReturnInvoice', async () => {
    const [url, payload] = ["/erp-apis/ReturnInvoice",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","returnInvoiceDate":"2025-11-26T16:29:05.637Z","invoiceHeaderId":"00000000-0000-0000-0000-000000000000","description":"string","returnInvoiceDetails":[{"toReturnQuantity":1,"invoiceDetailId":"00000000-0000-0000-0000-000000000000"}]}];
    
    logger.info('Testing CREATE for ReturnInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created ReturnInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get ReturnInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for ReturnInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read ReturnInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update ReturnInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnInvoice",{"id":"<createdId>","returnInvoiceDate":"2025-11-26T16:29:05.637Z","description":"string","returnInvoiceDetails":[{"id":"<createdId>","toReturnQuantity":1}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for ReturnInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated ReturnInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete ReturnInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for ReturnInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted ReturnInvoice');
  }, TEST_TIMEOUT);
});
