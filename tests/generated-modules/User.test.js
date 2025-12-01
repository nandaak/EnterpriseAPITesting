/**
 * Auto-generated test for module: User
 * Generated: 2025-12-01T13:40:51.244Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'User';

describe('Module: User', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new User', async () => {
    const [url, payload] = ["/erp-apis/User",{"id":"00000000-0000-0000-0000-000000000000","name":"string","email":"string","subdomain":"string","tenantId":"00000000-0000-0000-0000-000000000000","identityId":"string","phone":"string","countryCode":"string"}];
    
    logger.info('Testing CREATE for User');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created User with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get User by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/User/UsersDropdownQuery",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for User with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read User');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update User', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/User/UpdateUserProfile",{"userId":"<createdId>","name":"string","email":"string","phone":"string","countryCode":"string","phoneCode":"string","photo":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for User with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated User');
  }, TEST_TIMEOUT);
  
  
});
