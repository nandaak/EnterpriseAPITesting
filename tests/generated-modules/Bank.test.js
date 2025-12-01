/**
 * Auto-generated test for module: Bank
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
const moduleName = 'Bank';

describe('Module: Bank', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Bank', async () => {
    const [url, payload] = ["/erp-apis/Bank",{"code":"string","shortName":"string","contactName":"string","phone":"string","name":"string","nameAr":"string","bankAddress":"string","bankEmail":"string","fax":"string","bankAccounts":[{"accountNumber":"string","glAccountId":1,"iban":"string","currencyId":1,"accountOpeningBalance":1,"openingBalance":1,"userPermission":[{}],"branches":[{}]}]}];
    
    logger.info('Testing CREATE for Bank');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Bank with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Bank by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Bank",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Bank with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Bank');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Bank', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Bank/Edit",{"id":"<createdId>","code":"string","shortName":"string","contactName":"string","phone":"string","name":"string","nameAr":"string","bankAddress":"string","bankEmail":"string","fax":"string","bankAccounts":[{"id":"<createdId>","accountNumber":"string","glAccountId":"<createdId>","iban":"string","currencyId":"<createdId>","accountOpeningBalance":1,"openingBalance":1,"userPermission":[{}],"branches":[{}]}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Bank with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Bank');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Bank', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Bank/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Bank with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Bank');
  }, TEST_TIMEOUT);
});
