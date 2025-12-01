#!/usr/bin/env node
/**
 * Module Test Generator
 * Generates individual test files for each module
 * Uses Enhanced-ERP-Api-Schema-With-Payloads.json
 */

const fs = require('fs');
const path = require('path');
const EnhancedSchemaAdapter = require('../utils/enhanced-schema-adapter');

const CONFIG = {
  outputDir: 'tests/generated-modules',
  templateFile: 'tests/templates/module-test.template.js'
};

console.log('🔧 Module Test Generator\n');
console.log('='.repeat(70));

// Initialize adapter
const adapter = new EnhancedSchemaAdapter();

// Get testable modules
const testableModules = adapter.getTestableModules();

console.log(`\n📦 Found ${testableModules.length} testable modules\n`);

// Create output directory
if (!fs.existsSync(CONFIG.outputDir)) {
  fs.mkdirSync(CONFIG.outputDir, { recursive: true });
}

// Generate test for each module
let generated = 0;
testableModules.forEach(moduleName => {
  const testContent = generateModuleTest(moduleName);
  const fileName = `${moduleName}.test.js`;
  const filePath = path.join(CONFIG.outputDir, fileName);
  
  fs.writeFileSync(filePath, testContent);
  generated++;
});

console.log(`\n✅ Generated ${generated} module test files`);
console.log(`   Output: ${CONFIG.outputDir}\n`);
console.log('='.repeat(70));

/**
 * Generate test content for a module
 */
function generateModuleTest(moduleName) {
  const crudOps = adapter.findCrudOperations(moduleName);
  const stats = adapter.getModuleStats(moduleName);

  return `/**
 * Auto-generated test for module: ${moduleName}
 * Generated: ${new Date().toISOString()}
 * 
 * Operations available:
 * - POST: ${stats.hasPOST ? 'Yes' : 'No'}
 * - GET: ${stats.hasGET ? 'Yes' : 'No'}
 * - PUT: ${stats.hasPUT ? 'Yes' : 'No'}
 * - DELETE: ${stats.hasDELETE ? 'Yes' : 'No'}
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = '${moduleName}';

describe('Module: ${moduleName}', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  ${crudOps.POST ? generateCreateTest(moduleName, crudOps.POST) : ''}
  
  ${crudOps.GET ? generateReadTest(moduleName, crudOps.GET) : ''}
  
  ${crudOps.PUT ? generateUpdateTest(moduleName, crudOps.PUT) : ''}
  
  ${crudOps.DELETE ? generateDeleteTest(moduleName, crudOps.DELETE) : ''}
});
`;
}

function generateCreateTest(moduleName, postOp) {
  return `
  test('CREATE - should create new ${moduleName}', async () => {
    const [url, payload] = ${JSON.stringify(postOp.data)};
    
    logger.info('Testing CREATE for ${moduleName}');
    logger.debug(\`URL: \${url}\`);
    logger.debug(\`Payload: \${JSON.stringify(payload, null, 2)}\`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(\`Created ${moduleName} with ID: \${createdId}\`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);`;
}

function generateReadTest(moduleName, getOp) {
  return `
  test('READ - should get ${moduleName} by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(${JSON.stringify(getOp.data)}, createdId);
    const [url] = prepared;
    
    logger.info(\`Testing READ for ${moduleName} with ID: \${createdId}\`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read ${moduleName}');
  }, TEST_TIMEOUT);`;
}

function generateUpdateTest(moduleName, putOp) {
  return `
  test('UPDATE - should update ${moduleName}', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(${JSON.stringify(putOp.data)}, createdId);
    const [url, payload] = prepared;
    
    logger.info(\`Testing UPDATE for ${moduleName} with ID: \${createdId}\`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated ${moduleName}');
  }, TEST_TIMEOUT);`;
}

function generateDeleteTest(moduleName, deleteOp) {
  return `
  test('DELETE - should delete ${moduleName}', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(${JSON.stringify(deleteOp.data)}, createdId);
    const [url] = prepared;
    
    logger.info(\`Testing DELETE for ${moduleName} with ID: \${createdId}\`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted ${moduleName}');
  }, TEST_TIMEOUT);`;
}
