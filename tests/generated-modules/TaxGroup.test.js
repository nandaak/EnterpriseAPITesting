/**
 * Auto-generated test for module: TaxGroup
 * Generated: 2025-12-01T13:40:51.243Z
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
const moduleName = 'TaxGroup';

describe('Module: TaxGroup', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new TaxGroup', async () => {
    const [url, payload] = ["/erp-apis/TaxGroup",{"name":"string","nameAr":"string","code":"string","companyId":"string","branchId":"string"}];
    
    logger.info('Testing CREATE for TaxGroup');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created TaxGroup with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get TaxGroup by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TaxGroup",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for TaxGroup with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read TaxGroup');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update TaxGroup', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TaxGroup",{"id":"<createdId>","name":"string","nameAr":"string","code":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for TaxGroup with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated TaxGroup');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete TaxGroup', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TaxGroup",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for TaxGroup with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted TaxGroup');
  }, TEST_TIMEOUT);
});
