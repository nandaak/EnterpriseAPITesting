/**
 * Auto-generated test for module: Device
 * Generated: 2025-12-01T13:40:51.233Z
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
const moduleName = 'Device';

describe('Module: Device', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Device', async () => {
    const [url, payload] = ["/erp-apis/Device",{"name":"string","nameAr":"string","prefix":"string","salesManId":"00000000-0000-0000-0000-000000000000","deviceLicenseId":"00000000-0000-0000-0000-000000000000"}];
    
    logger.info('Testing CREATE for Device');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Device with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Device by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Device",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Device with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Device');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Device', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Device/EditDevice",{"id":"<createdId>","name":"string","nameAr":"string","prefix":"string","salesManId":"<createdId>"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Device with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Device');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Device', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Device/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Device with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Device');
  }, TEST_TIMEOUT);
});
