/**
 * Auto-generated test for module: Workflows
 * Generated: 2025-12-01T15:06:00.430Z
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
const moduleName = 'Workflows';

describe('Module: Workflows', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Workflows', async () => {
    const [url, payload] = ["/erp-apis/api/workflows/ExecuteAction",{"requestTracking":"string","actionId":1,"controlValues":[{"actionControlId":1,"value":"string"}]}];
    
    logger.info('Testing CREATE for Workflows');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Workflows with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Workflows by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/api/workflows/GetRequestHistory/{RequestTracking}",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Workflows with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Workflows');
  }, TEST_TIMEOUT);
  
  
  
  
});
