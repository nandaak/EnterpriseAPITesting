/**
 * Auto-generated test for module: FinanceReports
 * Generated: 2025-12-01T15:06:00.419Z
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
const moduleName = 'FinanceReports';

describe('Module: FinanceReports', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new FinanceReports', async () => {
    const [url, payload] = ["/erp-apis/FinanceReports/TreasuryStatement",{"dateFrom":"2025-11-26T16:29:05.636Z","dateTo":"2025-11-26T16:29:05.636Z","treasuryId":1}];
    
    logger.info('Testing CREATE for FinanceReports');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created FinanceReports with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get FinanceReports by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FinanceReports/PrintOutBankAccountStatement",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for FinanceReports with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read FinanceReports');
  }, TEST_TIMEOUT);
  
  
  
  
});
