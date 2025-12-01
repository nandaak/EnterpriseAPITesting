/**
 * Auto-generated test for module: CustomerReports
 * Generated: 2025-12-01T15:06:00.418Z
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
const moduleName = 'CustomerReports';

describe('Module: CustomerReports', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new CustomerReports', async () => {
    const [url, payload] = ["/erp-apis/CustomerReports/CustomerBalanceReport",{"customerIds":[1],"fromDate":"2025-11-26T16:29:05.636Z","toDate":"2025-11-26T16:29:05.636Z"}];
    
    logger.info('Testing CREATE for CustomerReports');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created CustomerReports with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get CustomerReports by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/CustomerReports/CustomerStatmentReport",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for CustomerReports with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read CustomerReports');
  }, TEST_TIMEOUT);
  
  
  
  
});
