/**
 * Auto-generated test for module: SalesTeam
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
const moduleName = 'SalesTeam';

describe('Module: SalesTeam', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesTeam', async () => {
    const [url, payload] = ["/erp-apis/SalesTeam",{"name":"string","nameAr":"string"}];
    
    logger.info('Testing CREATE for SalesTeam');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesTeam with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesTeam by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesTeam",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesTeam with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesTeam');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesTeam', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesTeam/EditSalesTeamGeneral",{"id":"<createdId>","name":"string","nameAr":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesTeam with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesTeam');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesTeam', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesTeam/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesTeam with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesTeam');
  }, TEST_TIMEOUT);
});
