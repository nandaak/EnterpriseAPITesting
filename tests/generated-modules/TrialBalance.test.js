/**
 * Auto-generated test for module: TrialBalance
 * Generated: 2025-12-01T15:06:00.428Z
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
const moduleName = 'TrialBalance';

describe('Module: TrialBalance', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new TrialBalance', async () => {
    const [url, payload] = ["/erp-apis/TrialBalance",{"dateFrom":"2025-11-26T16:29:05.638Z","dateTo":"2025-11-26T16:29:05.638Z","posted":true,"unposted":true,"allowZero":true,"accounts":[1],"branches":["00000000-0000-0000-0000-000000000000"]}];
    
    logger.info('Testing CREATE for TrialBalance');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created TrialBalance with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get TrialBalance by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/TrialBalance",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for TrialBalance with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read TrialBalance');
  }, TEST_TIMEOUT);
  
  
  
  
});
