/**
 * Auto-generated test for module: SalesMan
 * Generated: 2025-12-01T13:40:51.241Z
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
const moduleName = 'SalesMan';

describe('Module: SalesMan', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesMan', async () => {
    const [url, payload] = ["/erp-apis/SalesMan",{"salesTeamId":"00000000-0000-0000-0000-000000000000","userId":"00000000-0000-0000-0000-000000000000","name":"string","nameAr":"string","salesPhone":"string","paymentTermId":1,"treasuryId":1,"paymentMethods":[1]}];
    
    logger.info('Testing CREATE for SalesMan');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesMan with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesMan by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesMan",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesMan with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesMan');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesMan', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesMan",{"id":"<createdId>","salesTeamId":"<createdId>","salesPhone":"string","name":"string","nameAr":"string","isActive":true,"userId":"<createdId>","branchesIds":["00000000-0000-0000-0000-000000000000"],"paymentTermId":"<createdId>","treasuryId":"<createdId>","paymentMethods":[1]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesMan with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesMan');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesMan', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesMan/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesMan with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesMan');
  }, TEST_TIMEOUT);
});
