/**
 * Auto-generated test for module: AccountingReports
 * Generated: 2025-12-01T15:06:00.404Z
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
const moduleName = 'AccountingReports';

describe('Module: AccountingReports', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new AccountingReports', async () => {
    const [url, payload] = ["/erp-apis/AccountingReports/AccountStatmentReport",{"dateFrom":"2025-11-26T16:29:05.634Z","dateTo":"2025-11-26T16:29:05.634Z","posted":true,"unPosted":true,"accounts":[1],"costCenters":[1],"branches":["00000000-0000-0000-0000-000000000000"]}];
    
    logger.info('Testing CREATE for AccountingReports');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created AccountingReports with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get AccountingReports by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/AccountingReports/PrintOutAccountStatement",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for AccountingReports with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read AccountingReports');
  }, TEST_TIMEOUT);
  
  
  
  
});
