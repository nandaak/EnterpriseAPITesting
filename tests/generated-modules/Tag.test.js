/**
 * Auto-generated test for module: Tag
 * Generated: 2025-12-01T15:06:00.427Z
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
const moduleName = 'Tag';

describe('Module: Tag', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Tag', async () => {
    const [url, payload] = ["/erp-apis/Tag",{"name":"string","nameAr":"string","moduleIds":[1]}];
    
    logger.info('Testing CREATE for Tag');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Tag with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Tag by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tag/Tagdropdown",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Tag with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Tag');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Tag', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tag",{"id":"<createdId>","name":"string","nameAr":"string","code":"string","modulesId":["<createdId>"],"isActive":true}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Tag with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Tag');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Tag', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Tag",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Tag with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Tag');
  }, TEST_TIMEOUT);
});
