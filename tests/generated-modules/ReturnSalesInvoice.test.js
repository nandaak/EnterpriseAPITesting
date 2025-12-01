/**
 * Auto-generated test for module: ReturnSalesInvoice
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
const moduleName = 'ReturnSalesInvoice';

describe('Module: ReturnSalesInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new ReturnSalesInvoice', async () => {
    const [url, payload] = ["/erp-apis/ReturnSalesInvoice",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","returnInvoiceDate":"2025-11-26T16:29:05.637Z","salesInvoiceHeaderId":"00000000-0000-0000-0000-000000000000","description":"string","warehouseId":1,"warehouseName":"string","posSessionId":"00000000-0000-0000-0000-000000000000","returnSalesInvoiceDetails":[{"toReturnQuantity":1,"salesInvoiceDetailId":"00000000-0000-0000-0000-000000000000","returnSalesInvoiceDetailIngredients":[{}]}],"posReturnInvoicePayments":[{"amount":1,"paymentMethodType":{},"paymentMethodCode":"string","paymentMethodId":1}]}];
    
    logger.info('Testing CREATE for ReturnSalesInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created ReturnSalesInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get ReturnSalesInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnSalesInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for ReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read ReturnSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update ReturnSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnSalesInvoice",{"id":"<createdId>","returnInvoiceDate":"2025-11-26T16:29:05.637Z","description":"string","warehouseId":"<createdId>","warehouseName":"string","returnSalesInvoiceDetails":[{"id":"<createdId>","toReturnQuantity":1}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for ReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated ReturnSalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete ReturnSalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ReturnSalesInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for ReturnSalesInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted ReturnSalesInvoice');
  }, TEST_TIMEOUT);
});
