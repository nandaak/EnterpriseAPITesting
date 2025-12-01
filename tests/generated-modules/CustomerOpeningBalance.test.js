/**
 * Auto-generated test for module: CustomerOpeningBalance
 * Generated: 2025-12-01T15:06:00.418Z
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
const moduleName = 'CustomerOpeningBalance';

describe('Module: CustomerOpeningBalance', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CustomerOpeningBalance', async () => {
    const [url, payload] = ["/erp-apis/CustomerOpeningBalance",{"openingBalanceJournalEntryLineId":"00000000-0000-0000-0000-000000000000","amountNature":"Debit","customerOpeningBalanceDetails":[{"id":"00000000-0000-0000-0000-000000000000","customerId":1,"balance":1,"balanceType":{},"dueDates":[{}]}]}];
    
    logger.info('Testing CREATE for CustomerOpeningBalance');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CustomerOpeningBalance with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CustomerOpeningBalance by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerOpeningBalance",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CustomerOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CustomerOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update CustomerOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerOpeningBalance",{"id":"<createdId>","openingBalanceJournalEntryLineId":"<createdId>","amountNature":"Debit","customerOpeningBalanceDetails":[{"id":"<createdId>","customerId":"<createdId>","balance":1,"balanceType":{},"dueDates":[{}]}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for CustomerOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated CustomerOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete CustomerOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerOpeningBalance/DeleteOpeningBalanceHeader/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for CustomerOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted CustomerOpeningBalance');
  }, TEST_TIMEOUT);
});
