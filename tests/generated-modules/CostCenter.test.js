/**
 * Auto-generated test for module: CostCenter
 * Generated: 2025-12-01T15:06:00.410Z
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
const moduleName = 'CostCenter';

describe('Module: CostCenter', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CostCenter', async () => {
    const [url, payload] = ["/erp-apis/CostCenter/AddCostCenter",{"name":"string","nameAr":"string","parentId":1,"isDetail":true,"isActive":true}];
    
    logger.info('Testing CREATE for CostCenter');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CostCenter with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CostCenter by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CostCenter/GetCostCenters",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CostCenter with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CostCenter');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update CostCenter', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CostCenter/EditCostCenter",{"id":"<createdId>","name":"string","nameAr":"string","parentId":"<createdId>","isDetail":true,"isActive":true}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for CostCenter with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated CostCenter');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete CostCenter', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CostCenter/Delete",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for CostCenter with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted CostCenter');
  }, TEST_TIMEOUT);
});
