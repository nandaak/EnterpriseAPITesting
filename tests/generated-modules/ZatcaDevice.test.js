/**
 * Auto-generated test for module: ZatcaDevice
 * Generated: 2025-12-01T13:40:51.247Z
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
const moduleName = 'ZatcaDevice';

describe('Module: ZatcaDevice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new ZatcaDevice', async () => {
    const [url, payload] = ["/erp-apis/ZatcaDevice/Activate",{"environment":"Production","activationCode":"string"}];
    
    logger.info('Testing CREATE for ZatcaDevice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created ZatcaDevice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get ZatcaDevice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/ZatcaDevice/CurrentInfo",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for ZatcaDevice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read ZatcaDevice');
  }, TEST_TIMEOUT);
  
  
  
  
});
