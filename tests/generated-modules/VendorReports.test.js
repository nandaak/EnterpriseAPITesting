/**
 * Auto-generated test for module: VendorReports
 * Generated: 2025-12-01T13:40:51.246Z
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
const moduleName = 'VendorReports';

describe('Module: VendorReports', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new VendorReports', async () => {
    const [url, payload] = ["/erp-apis/VendorReports/VendorBalanceReport",{"vendorIds":[1],"fromDate":"2025-11-26T16:29:05.638Z","toDate":"2025-11-26T16:29:05.638Z"}];
    
    logger.info('Testing CREATE for VendorReports');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created VendorReports with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get VendorReports by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorReports/VendorStatmentReport",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for VendorReports with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read VendorReports');
  }, TEST_TIMEOUT);
  
  
  
  
});
