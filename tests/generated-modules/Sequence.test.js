/**
 * Auto-generated test for module: Sequence
 * Generated: 2025-12-01T13:40:51.242Z
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
const moduleName = 'Sequence';

describe('Module: Sequence', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Sequence', async () => {
    const [url, payload] = ["/erp-apis/Sequence",{"status":true,"companyId":"00000000-0000-0000-0000-000000000000","branchesIds":["00000000-0000-0000-0000-000000000000"],"module":"Accounting","screen":"PaymentIn","type":"Continuous","sequenceDetails":[{"order":1,"segment":{},"detailValue":"string","valueOption":"string"}]}];
    
    logger.info('Testing CREATE for Sequence');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Sequence with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Sequence by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Sequence/{Screen}",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Sequence with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Sequence');
  }, TEST_TIMEOUT);
  
  
  
  
});
