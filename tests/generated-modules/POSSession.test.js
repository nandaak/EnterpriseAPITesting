/**
 * Auto-generated test for module: POSSession
 * Generated: 2025-12-01T15:06:00.423Z
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
const moduleName = 'POSSession';

describe('Module: POSSession', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new POSSession', async () => {
    const [url, payload] = ["/erp-apis/POSSession",{"uid":"00000000-0000-0000-0000-000000000000","externalCode":"string","shiftName":"string","openingBalance":1,"endingCashBalance":1,"endingCreditBalance":1,"endingVisaBalance":1,"branchCode":"string","branchName":"string","cashierName":"string","cashierCode":"string","deviceCode":"string","deviceName":"string","totalCount":1,"closedAt":"2025-11-26T16:29:05.637Z","openedAt":"2025-11-26T16:29:05.637Z","businessDate":"2025-11-26"}];
    
    logger.info('Testing CREATE for POSSession');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created POSSession with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get POSSession by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/POSSession",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for POSSession with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read POSSession');
  }, TEST_TIMEOUT);
  
  
  
  
});
