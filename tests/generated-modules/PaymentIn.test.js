/**
 * Auto-generated test for module: PaymentIn
 * Generated: 2025-12-01T15:06:00.422Z
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
const moduleName = 'PaymentIn';

describe('Module: PaymentIn', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new PaymentIn', async () => {
    const [url, payload] = ["/erp-apis/PaymentIn",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","paymentInDate":"2025-11-26T16:29:05.637Z","description":"string","paymentHub":"Treasury","paymentHubDetailId":"string","bankAccountId":1,"currencyId":1,"rate":1,"glAccountId":1,"taxId":1,"isCustomerAdvancedPayment":true,"isAmountIncludesVat":true,"sourceDocumentId":"string","sourceDocumentType":"FundTransfer","paymentInDetails":[{"externalIdentifier":"00000000-0000-0000-0000-000000000000","amount":1,"rate":1,"currencyId":1,"paymentMethodId":1,"paymentMethodType":{},"paidBy":{},"paidByDetailsId":"string","paymentInMethodDetails":{},"glAccountId":1,"notes":"string","paymentInDate":"2025-11-26T16:29:05.637Z","paymentInDetailCostCenters":[{}]}],"isFromFundTransfer":true,"saveToContext":true,"enableWorkflow":true}];
    
    logger.info('Testing CREATE for PaymentIn');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created PaymentIn with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get PaymentIn by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentIn",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for PaymentIn with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read PaymentIn');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update PaymentIn', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentIn",{"id":"<createdId>","paymentInDate":"2025-11-26T16:29:05.637Z","description":"string","paymentHubDetailId":"<createdId>","bankAccountId":"<createdId>","currencyId":"<createdId>","rate":1,"glAccountId":"<createdId>","taxId":"<createdId>","isCustomerAdvancedPayment":true,"isAmountIncludesVat":true,"paymentInDetails":[{"id":"<createdId>","amount":1,"rate":1,"currencyId":"<createdId>","paymentMethodId":"<createdId>","paymentMethodType":{},"paidBy":{},"paidByDetailsId":"<createdId>","paymentInMethodDetail":{},"glAccountId":"<createdId>","notes":"string","paymentInDetailCostCenters":[{}]}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for PaymentIn with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated PaymentIn');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete PaymentIn', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentIn/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for PaymentIn with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted PaymentIn');
  }, TEST_TIMEOUT);
});
