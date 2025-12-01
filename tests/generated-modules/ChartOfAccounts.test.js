/**
 * Auto-generated test for module: ChartOfAccounts
 * Generated: 2025-12-01T13:40:51.231Z
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
const moduleName = 'ChartOfAccounts';

describe('Module: ChartOfAccounts', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new ChartOfAccounts', async () => {
    const [url, payload] = ["/erp-apis/ChartOfAccounts/AddAccount",{"name":"string","nameAr":"string","parentId":1,"natureId":"Debit","costCenterConfig":"Mandatory","hasNoChild":true,"accountTypeId":1,"accountSectionId":1,"currencyId":1,"tags":[1],"companies":["00000000-0000-0000-0000-000000000000"],"accountActivation":"Active","periodicActiveFrom":"2025-11-26T16:29:05.635Z","periodicActiveTo":"2025-11-26T16:29:05.635Z","costCenters":[{"percentage":1,"costCenterId":1}]}];
    
    logger.info('Testing CREATE for ChartOfAccounts');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created ChartOfAccounts with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get ChartOfAccounts by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ChartOfAccounts",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for ChartOfAccounts with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read ChartOfAccounts');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update ChartOfAccounts', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ChartOfAccounts/EditAccount",{"id":"<createdId>","name":"string","nameAr":"string","parentId":"<createdId>","natureId":"Debit","costCenterConfig":"Mandatory","hasNoChild":true,"accountTypeId":"<createdId>","accountSectionId":"<createdId>","currencyId":"<createdId>","tags":[1],"companies":["00000000-0000-0000-0000-000000000000"],"accountActivation":"Active","periodicActiveFrom":"2025-11-26T16:29:05.635Z","periodicActiveTo":"2025-11-26T16:29:05.635Z","costCenters":[{"id":"<createdId>","percentage":1,"costCenterId":"<createdId>"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for ChartOfAccounts with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated ChartOfAccounts');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete ChartOfAccounts', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ChartOfAccounts/Delete",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for ChartOfAccounts with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted ChartOfAccounts');
  }, TEST_TIMEOUT);
});
