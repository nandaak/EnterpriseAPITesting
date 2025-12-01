/**
 * Auto-generated test for module: Levels
 * Generated: 2025-12-01T13:40:51.237Z
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
const moduleName = 'Levels';

describe('Module: Levels', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Levels', async () => {
    const [url, payload] = ["/erp-apis/Levels",{"levels":[{"id":1,"name":"string","levelNumber":1,"numberOfDigits":1}]}];
    
    logger.info('Testing CREATE for Levels');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Levels with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Levels by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Levels",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Levels with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Levels');
  }, TEST_TIMEOUT);
  
  
  
  
});
