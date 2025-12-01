/**
 * Auto-generated test for module: WorkflowConfiguration
 * Generated: 2025-12-01T13:40:51.246Z
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
const moduleName = 'WorkflowConfiguration';

describe('Module: WorkflowConfiguration', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new WorkflowConfiguration', async () => {
    const [url, payload] = ["/erp-apis/WorkflowConfiguration",{"moduleId":1,"serviceId":1,"actions":[{"actionId":1,"actionNameAr":"string","actionNameEn":"string"}],"workflowTemplateId":1,"workflowTemplateNameAr":"string","workflowTemplateNameEn":"string","isActive":true}];
    
    logger.info('Testing CREATE for WorkflowConfiguration');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created WorkflowConfiguration with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get WorkflowConfiguration by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/WorkflowConfiguration",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for WorkflowConfiguration with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read WorkflowConfiguration');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update WorkflowConfiguration', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/WorkflowConfiguration",{"id":"<createdId>","moduleId":"<createdId>","serviceId":"<createdId>","actions":[{"actionId":"<createdId>","actionNameAr":"string","actionNameEn":"string"}],"workflowTemplateId":"<createdId>","workflowTemplateNameAr":"string","workflowTemplateNameEn":"string","isActive":true}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for WorkflowConfiguration with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated WorkflowConfiguration');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete WorkflowConfiguration', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/WorkflowConfiguration/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for WorkflowConfiguration with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted WorkflowConfiguration');
  }, TEST_TIMEOUT);
});
