/**
 * Auto-generated test for module: Branch
 * Generated: 2025-12-01T13:40:51.230Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'Branch';

describe('Module: Branch', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Branch', async () => {
    const [url, payload] = ["/erp-apis/Branch",{"nameEn":"string","nameAr":"string","branchRegion":"string","branchCity":1,"branchAddress":"string","mobileNumberCode":"string","mobileNumber":"string","branchEmail":"string","countryCode":"string"}];
    
    logger.info('Testing CREATE for Branch');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Branch with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Branch by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Branch/<createdId>/GetAll",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Branch with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Branch');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Branch', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Branch",{"id":"<createdId>","nameEn":"string","nameAr":"string","branchRegion":"string","branchCity":1,"branchAddress":"string","mobileNumberCode":"string","mobileNumber":"string","branchEmail":"string","countryCode":"string"}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Branch with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Branch');
  }, TEST_TIMEOUT);
  
  
});
