/**
 * Auto-generated test for module: JournalEntry
 * Generated: 2025-12-01T13:40:51.236Z
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
const moduleName = 'JournalEntry';

describe('Module: JournalEntry', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new JournalEntry', async () => {
    const [url, payload] = ["/erp-apis/JournalEntry",{"refrenceNumber":"string","journalDate":"2025-11-26T16:29:05.636Z","type":"Manual","description":"string","periodId":"string","isHeaderDescriptionCopied":true,"journalEntryLines":[{"lineDescription":"string","debitAmount":1,"creditAmount":1,"currencyRate":1,"currencyId":1,"accountId":1,"isVatLine":true,"hasVat":true,"createdOn":"2025-11-26T16:29:05.636Z","costCenters":[{}]}],"journalEntryAttachments":[{"attachmentId":"string","name":"string"}],"enableWorkflow":true}];
    
    logger.info('Testing CREATE for JournalEntry');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created JournalEntry with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get JournalEntry by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/JournalEntry",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for JournalEntry with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read JournalEntry');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update JournalEntry', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/JournalEntry/Edit",{"id":"<createdId>","referenceNumber":"string","journalDate":"2025-11-26T16:29:05.636Z","description":"string","isHeaderDescriptionCopied":true,"journalEntryLines":[{"id":"<createdId>","accountId":"<createdId>","lineDescription":"string","debitAmount":1,"creditAmount":1,"debitAmountLocal":1,"creditAmountLocal":1,"currencyRate":1,"isVatLine":true,"hasVat":true,"currencyId":"<createdId>","createdOn":"2025-11-26T16:29:05.636Z","costCenters":[{}]}],"journalEntryAttachments":[{"id":"<createdId>","attachmentId":"<createdId>","name":"string"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for JournalEntry with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated JournalEntry');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete JournalEntry', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/JournalEntry/DeleteLine",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for JournalEntry with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted JournalEntry');
  }, TEST_TIMEOUT);
});
