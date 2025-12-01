/**
 * Auto-generated test for module: CurrentUserInfo
 * Generated: 2025-12-01T13:40:51.232Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: No
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'CurrentUserInfo';

describe('Module: CurrentUserInfo', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CurrentUserInfo', async () => {
    const [url, payload] = ["/erp-apis/CurrentUserInfo/GenerateAppToken",{}];
    
    logger.info('Testing CREATE for CurrentUserInfo');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CurrentUserInfo with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CurrentUserInfo by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CurrentUserInfo",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CurrentUserInfo with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CurrentUserInfo');
  }, TEST_TIMEOUT);
  
  
  
  
});
