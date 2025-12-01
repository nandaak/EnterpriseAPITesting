/**
 * Auto-generated test for module: FinancialYear
 * Generated: 2025-12-01T15:06:00.419Z
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
const moduleName = 'FinancialYear';

describe('Module: FinancialYear', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new FinancialYear', async () => {
    const [url, payload] = ["/erp-apis/FinancialYear",{"name":"string","code":"string","fromDate":"2025-11-26","toDate":"2025-11-26","noOfExtraPeriods":1,"financialYearPeriods":[{"status":true,"periodStart":"2025-11-26","periodEnd":"2025-11-26"}]}];
    
    logger.info('Testing CREATE for FinancialYear');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created FinancialYear with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get FinancialYear by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FinancialYear",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for FinancialYear with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read FinancialYear');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update FinancialYear', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FinancialYear",{"id":"<createdId>","name":"string","code":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for FinancialYear with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated FinancialYear');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete FinancialYear', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/FinancialYear/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for FinancialYear with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted FinancialYear');
  }, TEST_TIMEOUT);
});
