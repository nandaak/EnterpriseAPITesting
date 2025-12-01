/**
 * Auto-generated test for module: FundTransfer
 * Generated: 2025-12-01T15:06:00.419Z
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
const moduleName = 'FundTransfer';

describe('Module: FundTransfer', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new FundTransfer', async () => {
    const [url, payload] = ["/erp-apis/FundTransfer",{"date":"2025-11-26T16:29:05.636Z","description":"string","reference":"string","amount":1,"fromPaymentHubDetails":"string","fromBankAccount":"string","toPaymentHubDetails":"string","toBankAccount":"string","fundTransferToDetail":{"paymentHubId":"Treasury","paymentHubDetailsId":1,"bankAccountId":1,"currencyId":1,"paymentMethodId":1,"rate":1,"currentBalance":1,"amount":1,"glAccountId":1,"fundTransferStatus":"From","commissionValue":1,"bankReference":"string"},"fundTransferFromDetail":{}}];
    
    logger.info('Testing CREATE for FundTransfer');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created FundTransfer with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get FundTransfer by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FundTransfer",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for FundTransfer with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read FundTransfer');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update FundTransfer', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FundTransfer",{"id":"<createdId>","date":"2025-11-26T16:29:05.636Z","description":"string","reference":"string","amount":1,"fromPaymentHubDetails":"string","fromBankAccount":"string","toPaymentHubDetails":"string","toBankAccount":"string","fundTransferToDetail":{"paymentHubId":"Treasury","paymentHubDetailsId":"<createdId>","bankAccountId":"<createdId>","currencyId":"<createdId>","paymentMethodId":"<createdId>","rate":1,"currentBalance":1,"amount":1,"fundTransferStatus":"From","commissionAmount":1,"bankReference":"string"},"fundTransferFromDetail":{}}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for FundTransfer with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated FundTransfer');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete FundTransfer', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FundTransfer/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for FundTransfer with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted FundTransfer');
  }, TEST_TIMEOUT);
});
