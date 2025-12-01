/**
 * Auto-generated test for module: SalesManVisit
 * Generated: 2025-12-01T15:06:00.426Z
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
const moduleName = 'SalesManVisit';

describe('Module: SalesManVisit', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesManVisit', async () => {
    const [url, payload] = ["/erp-apis/SalesManVisit",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","journeyDate":"2025-11-26T16:29:05.637Z","salesManId":"00000000-0000-0000-0000-000000000000","marketPlaceId":"00000000-0000-0000-0000-000000000000","customerId":1,"permission":{"canCollectPayments":true,"canUpdateCustomerInfo":true,"canCreateSalesInvoice":true,"canProcessReturnSalesInvoice":true,"canShowCustomerStatement":true,"canProcessSalesOrder":true,"canProcessCreditNote":true}}];
    
    logger.info('Testing CREATE for SalesManVisit');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesManVisit with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesManVisit by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesManVisit/GetVisitList",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesManVisit with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesManVisit');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesManVisit', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesManVisit",{"id":"<createdId>","journeyDate":"2025-11-26T16:29:05.637Z","permission":{"canCollectPayments":true,"canUpdateCustomerInfo":true,"canCreateSalesInvoice":true,"canProcessReturnSalesInvoice":true,"canShowCustomerStatement":true,"canProcessSalesOrder":true,"canProcessCreditNote":true},"salesManId":"<createdId>","marketPlaceId":"<createdId>","customerId":"<createdId>"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesManVisit with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesManVisit');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesManVisit', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesManVisit/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesManVisit with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesManVisit');
  }, TEST_TIMEOUT);
});
