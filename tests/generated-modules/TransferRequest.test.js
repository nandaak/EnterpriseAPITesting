/**
 * Auto-generated test for module: TransferRequest
 * Generated: 2025-12-01T15:06:00.428Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'TransferRequest';

describe('Module: TransferRequest', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new TransferRequest', async () => {
    const [url, payload] = ["/erp-apis/TransferRequest",{"receiptDate":"2025-11-26T16:29:05.638Z","notes":"string","externalCode":"string","transferRequestDetails":[{"barCode":"string","itemBarcodeId":1,"itemId":1,"itemVariantId":1,"uomId":"00000000-0000-0000-0000-000000000000","description":"string","quantity":1,"remainingQuantity":1,"notes":"string"}]}];
    
    logger.info('Testing CREATE for TransferRequest');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created TransferRequest with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get TransferRequest by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TransferRequest",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for TransferRequest with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read TransferRequest');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update TransferRequest', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TransferRequest/DeclineTransfer/<createdId>",{}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for TransferRequest with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated TransferRequest');
  }, TEST_TIMEOUT);
  
  
});
