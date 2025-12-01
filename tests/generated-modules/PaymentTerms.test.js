/**
 * Auto-generated test for module: PaymentTerms
 * Generated: 2025-12-01T15:06:00.423Z
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
const moduleName = 'PaymentTerms';

describe('Module: PaymentTerms', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new PaymentTerms', async () => {
    const [url, payload] = ["/erp-apis/PaymentTerms",{"name":"string","nameAr":"string","paymentTermLines":[{"dueTermValue":1,"afterValue":1,"afterPeriod":{},"note":"string"}]}];
    
    logger.info('Testing CREATE for PaymentTerms');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created PaymentTerms with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get PaymentTerms by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentTerms",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for PaymentTerms with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read PaymentTerms');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update PaymentTerms', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentTerms",{"id":"<createdId>","name":"string","nameAr":"string","paymentTermLines":[{"id":"<createdId>","dueTermValue":1,"afterValue":1,"afterPeriod":{},"note":"string"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for PaymentTerms with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated PaymentTerms');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete PaymentTerms', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/PaymentTerms/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for PaymentTerms with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted PaymentTerms');
  }, TEST_TIMEOUT);
});
