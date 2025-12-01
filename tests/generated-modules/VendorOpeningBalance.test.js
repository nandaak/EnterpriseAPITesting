/**
 * Auto-generated test for module: VendorOpeningBalance
 * Generated: 2025-12-01T15:06:00.430Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: Yes
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'VendorOpeningBalance';

describe('Module: VendorOpeningBalance', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new VendorOpeningBalance', async () => {
    const [url, payload] = ["/erp-apis/VendorOpeningBalance",{"openingBalanceJournalEntryLineId":"00000000-0000-0000-0000-000000000000","amountNature":"Debit","vendorOpeningBalanceDetails":[{"id":"00000000-0000-0000-0000-000000000000","vendorId":1,"balance":1,"balanceType":{},"dueDates":[{}]}]}];
    
    logger.info('Testing CREATE for VendorOpeningBalance');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created VendorOpeningBalance with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get VendorOpeningBalance by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorOpeningBalance",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for VendorOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read VendorOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update VendorOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorOpeningBalance",{"id":"<createdId>","openingBalanceJournalEntryLineId":"<createdId>","amountNature":"Debit","vendorOpeningBalanceDetails":[{"id":"<createdId>","vendorId":"<createdId>","balance":1,"balanceType":{},"dueDates":[{}]}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for VendorOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated VendorOpeningBalance');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete VendorOpeningBalance', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VendorOpeningBalance/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for VendorOpeningBalance with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted VendorOpeningBalance');
  }, TEST_TIMEOUT);
});
