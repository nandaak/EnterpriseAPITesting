/**
 * Auto-generated test for module: OpeningBalanceJournalEntry
 * Generated: 2025-12-01T13:40:51.238Z
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
const moduleName = 'OpeningBalanceJournalEntry';

describe('Module: OpeningBalanceJournalEntry', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new OpeningBalanceJournalEntry', async () => {
    const [url, payload] = ["/erp-apis/OpeningBalanceJournalEntry",{"refrenceNumber":"string","journalDate":"2025-11-26T16:29:05.636Z","type":"Manual","description":"string","openingBalanceJournalEntryLines":[{"lineDescription":"string","debitAmount":1,"creditAmount":1,"currencyRate":1,"currencyId":1,"accountId":1,"costCenters":[{}]}],"openingBalanceJournalEntryAttachments":[{"attachmentId":"string","name":"string"}]}];
    
    logger.info('Testing CREATE for OpeningBalanceJournalEntry');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created OpeningBalanceJournalEntry with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get OpeningBalanceJournalEntry by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/OpeningBalanceJournalEntry",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for OpeningBalanceJournalEntry with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read OpeningBalanceJournalEntry');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update OpeningBalanceJournalEntry', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/OpeningBalanceJournalEntry/Edit",{"id":"<createdId>","referenceNumber":"string","journalDate":"2025-11-26T16:29:05.637Z","description":"string","journalEntryLines":[{"id":"<createdId>","accountId":"<createdId>","lineDescription":"string","debitAmount":1,"creditAmount":1,"debitAmountLocal":1,"creditAmountLocal":1,"currencyRate":1,"currencyId":"<createdId>","costCenters":[{}]}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for OpeningBalanceJournalEntry with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated OpeningBalanceJournalEntry');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete OpeningBalanceJournalEntry', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/OpeningBalanceJournalEntry/DeleteLine",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for OpeningBalanceJournalEntry with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted OpeningBalanceJournalEntry');
  }, TEST_TIMEOUT);
});
