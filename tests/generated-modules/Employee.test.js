/**
 * Auto-generated test for module: Employee
 * Generated: 2025-12-01T13:40:51.234Z
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
const moduleName = 'Employee';

describe('Module: Employee', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Employee', async () => {
    const [url, payload] = ["/erp-apis/Employee/AddPersonal",{"attendanceCode":1,"employeeName":"string","employeePhoto":"string","birthDate":"2025-11-26T16:29:05.636Z","countryOfBirth":"string","birthCity":1,"nationality":"string","gender":"Male","maritalStatus":"Single","religion":"Muslim","militaryStatus":"Finished","militaryNumber":"string","bloodType":"APositive","withSpecialNeeds":true}];
    
    logger.info('Testing CREATE for Employee');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Employee with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Employee by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Employee",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Employee with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Employee');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Employee', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Employee/EditPersonal",{"id":"<createdId>","attendanceCode":1,"employeeName":"string","employeePhoto":"string","birthDate":"2025-11-26T16:29:05.636Z","countryOfBirth":"string","birthCity":1,"nationality":"string","gender":"Male","maritalStatus":"Single","religion":"Muslim","militaryStatus":"Finished","militaryNumber":"string","bloodType":"APositive","withSpecialNeeds":true}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Employee with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Employee');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Employee', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Employee/SoftDelete",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Employee with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Employee');
  }, TEST_TIMEOUT);
});
