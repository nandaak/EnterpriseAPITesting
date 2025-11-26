#!/usr/bin/env node
// scripts/swagger-integration-tool.js
/**
 * Swagger API Integration Tool
 * 
 * Fetches Swagger API documentation and generates/updates JSON schemas
 * for comprehensive ERP module testing
 * 
 * Features:
 * - Fetch Swagger API documentation
 * - Parse API endpoints and schemas
 * - Generate test data schemas
 * - Update existing schemas with new endpoints
 * - Validate schema structure
 * - Generate test templates
 * 
 * Usage:
 *   node scripts/swagger-integration-tool.js [command] [options]
 * 
 * Commands:
 *   fetch              Fetch Swagger documentation
 *   parse              Parse Swagger and generate schemas
 *   update             Update existing schemas
 *   validate           Validate schema structure
 *   generate           Generate complete test schemas
 *   help               Show help
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  swaggerUrl: 'https://microtecsaudi.com:2032/gateway/swagger/docs/v1/erp-apis',
  swaggerFile: 'swagger-api-docs.json',
  outputDir: 'test-data/Input',
  schemasDir: 'test-data/Input',
  backupDir: 'backups/schemas',
  mainSchemaFile: 'Main-Backend-Api-Schema.json',
  standardizedSchemaFile: 'Main-Standarized-Backend-Api-Schema.json',
  generatedSchemaFile: 'Generated-Backend-Api-Schema.json'
};

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0] || 'help';
const options = parseOptions(args.slice(1));

console.log('🔧 Swagger API Integration Tool\n');
console.log('='.repeat(60));

// Execute command
switch (command) {
  case 'fetch':
    fetchSwaggerDocs();
    break;
  
  case 'parse':
    parseSwaggerDocs();
    break;
  
  case 'update':
    updateSchemas();
    break;
  
  case 'validate':
    validateSchemas();
    break;
  
  case 'generate':
    generateCompleteSchemas();
    break;
  
  case 'help':
    showHelp();
    break;
  
  default:
    console.log(`❌ Unknown command: ${command}`);
    console.log('Run "node scripts/swagger-integration-tool.js help" for usage');
}

console.log('='.repeat(60));

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

/**
 * Fetch Swagger documentation from API
 */
function fetchSwaggerDocs() {
  console.log('\n📥 Fetching Swagger API documentation...\n');
  console.log(`URL: ${CONFIG.swaggerUrl}`);

  const file = fs.createWriteStream(CONFIG.swaggerFile);
  
  const request = https.get(CONFIG.swaggerUrl, {
    rejectUnauthorized: false // Skip SSL verification
  }, (response) => {
    if (response.statusCode !== 200) {
      console.log(`❌ Failed to fetch: HTTP ${response.statusCode}`);
      return;
    }

    response.pipe(file);

    file.on('finish', () => {
      file.close();
      const stats = fs.statSync(CONFIG.swaggerFile);
      console.log(`✅ Swagger docs downloaded successfully`);
      console.log(`   File: ${CONFIG.swaggerFile}`);
      console.log(`   Size: ${(stats.size / 1024).toFixed(2)} KB`);
      
      // Validate JSON
      try {
        const content = fs.readFileSync(CONFIG.swaggerFile, 'utf8');
        const swagger = JSON.parse(content);
        console.log(`   Version: ${swagger.openapi || swagger.swagger || 'Unknown'}`);
        console.log(`   Title: ${swagger.info?.title || 'Unknown'}`);
        console.log(`   Paths: ${Object.keys(swagger.paths || {}).length}`);
      } catch (error) {
        console.log(`⚠️  Warning: Could not parse JSON: ${error.message}`);
      }
    });
  });

  request.on('error', (error) => {
    console.log(`❌ Error fetching Swagger docs: ${error.message}`);
    console.log('\n💡 Tip: Check your network connection and API availability');
  });

  request.end();
}

/**
 * Parse Swagger documentation and extract API information
 */
function parseSwaggerDocs() {
  console.log('\n📖 Parsing Swagger documentation...\n');

  if (!fs.existsSync(CONFIG.swaggerFile)) {
    console.log(`❌ Swagger file not found: ${CONFIG.swaggerFile}`);
    console.log('💡 Run: node scripts/swagger-integration-tool.js fetch');
    return;
  }

  try {
    const content = fs.readFileSync(CONFIG.swaggerFile, 'utf8');
    const swagger = JSON.parse(content);

    console.log('API Information:');
    console.log(`  Title: ${swagger.info?.title || 'N/A'}`);
    console.log(`  Version: ${swagger.info?.version || 'N/A'}`);
    console.log(`  Description: ${swagger.info?.description || 'N/A'}`);

    const paths = swagger.paths || {};
    const pathCount = Object.keys(paths).length;
    console.log(`\nTotal Endpoints: ${pathCount}`);

    // Group by module/tag
    const modules = {};
    Object.keys(paths).forEach(pathKey => {
      const pathObj = paths[pathKey];
      Object.keys(pathObj).forEach(method => {
        if (typeof pathObj[method] === 'object') {
          const operation = pathObj[method];
          const tags = operation.tags || ['Untagged'];
          tags.forEach(tag => {
            if (!modules[tag]) {
              modules[tag] = [];
            }
            modules[tag].push({
              path: pathKey,
              method: method.toUpperCase(),
              summary: operation.summary || '',
              operationId: operation.operationId || ''
            });
          });
        }
      });
    });

    console.log(`\nModules/Tags: ${Object.keys(modules).length}`);
    Object.keys(modules).sort().forEach(module => {
      console.log(`  ${module}: ${modules[module].length} endpoints`);
    });

    // Save parsed data
    const parsedFile = 'swagger-parsed.json';
    fs.writeFileSync(parsedFile, JSON.stringify({
      info: swagger.info,
      modules: modules,
      totalEndpoints: pathCount
    }, null, 2));

    console.log(`\n✅ Parsed data saved to: ${parsedFile}`);

  } catch (error) {
    console.log(`❌ Error parsing Swagger docs: ${error.message}`);
  }
}

/**
 * Update existing schemas with new endpoints from Swagger
 */
function updateSchemas() {
  console.log('\n🔄 Updating existing schemas...\n');

  if (!fs.existsSync(CONFIG.swaggerFile)) {
    console.log(`❌ Swagger file not found: ${CONFIG.swaggerFile}`);
    console.log('💡 Run: node scripts/swagger-integration-tool.js fetch');
    return;
  }

  // Backup existing schemas
  backupSchemas();

  // Load Swagger docs
  const swagger = JSON.parse(fs.readFileSync(CONFIG.swaggerFile, 'utf8'));
  
  // Load existing schemas
  const mainSchemaPath = path.join(CONFIG.schemasDir, CONFIG.mainSchemaFile);
  const standardizedSchemaPath = path.join(CONFIG.schemasDir, CONFIG.standardizedSchemaFile);

  if (fs.existsSync(mainSchemaPath)) {
    console.log(`Updating: ${CONFIG.mainSchemaFile}`);
    updateSchemaFile(mainSchemaPath, swagger);
  }

  if (fs.existsSync(standardizedSchemaPath)) {
    console.log(`Updating: ${CONFIG.standardizedSchemaFile}`);
    updateSchemaFile(standardizedSchemaPath, swagger);
  }

  console.log('\n✅ Schema update complete');
}

/**
 * Validate schema structure
 */
function validateSchemas() {
  console.log('\n✔️  Validating schemas...\n');

  const schemas = [
    CONFIG.mainSchemaFile,
    CONFIG.standardizedSchemaFile
  ];

  let allValid = true;

  schemas.forEach(schemaFile => {
    const schemaPath = path.join(CONFIG.schemasDir, schemaFile);
    
    if (!fs.existsSync(schemaPath)) {
      console.log(`⚠️  Not found: ${schemaFile}`);
      return;
    }

    console.log(`Validating: ${schemaFile}`);

    try {
      const content = fs.readFileSync(schemaPath, 'utf8');
      const schema = JSON.parse(content);

      // Validate structure
      const issues = validateSchemaStructure(schema);

      if (issues.length === 0) {
        console.log(`  ✅ Valid`);
      } else {
        console.log(`  ❌ Issues found:`);
        issues.forEach(issue => console.log(`     - ${issue}`));
        allValid = false;
      }

    } catch (error) {
      console.log(`  ❌ Error: ${error.message}`);
      allValid = false;
    }
  });

  console.log(`\n${allValid ? '✅' : '❌'} Validation ${allValid ? 'passed' : 'failed'}`);
}

/**
 * Generate complete test schemas from Swagger
 */
function generateCompleteSchemas() {
  console.log('\n🏗️  Generating complete test schemas...\n');

  if (!fs.existsSync(CONFIG.swaggerFile)) {
    console.log(`❌ Swagger file not found: ${CONFIG.swaggerFile}`);
    console.log('💡 Run: node scripts/swagger-integration-tool.js fetch');
    return;
  }

  try {
    const swagger = JSON.parse(fs.readFileSync(CONFIG.swaggerFile, 'utf8'));
    const generatedSchema = generateSchemaFromSwagger(swagger);

    const outputPath = path.join(CONFIG.outputDir, CONFIG.generatedSchemaFile);
    fs.writeFileSync(outputPath, JSON.stringify(generatedSchema, null, 2));

    console.log(`✅ Generated schema saved to: ${outputPath}`);
    console.log(`   Modules: ${Object.keys(generatedSchema).length}`);

  } catch (error) {
    console.log(`❌ Error generating schemas: ${error.message}`);
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function parseOptions(args) {
  const options = {};
  args.forEach(arg => {
    if (arg.startsWith('--')) {
      const [key, value] = arg.substring(2).split('=');
      options[key] = value || true;
    }
  });
  return options;
}

function backupSchemas() {
  console.log('Creating backups...');
  
  if (!fs.existsSync(CONFIG.backupDir)) {
    fs.mkdirSync(CONFIG.backupDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const schemas = [CONFIG.mainSchemaFile, CONFIG.standardizedSchemaFile];

  schemas.forEach(schemaFile => {
    const sourcePath = path.join(CONFIG.schemasDir, schemaFile);
    if (fs.existsSync(sourcePath)) {
      const backupPath = path.join(CONFIG.backupDir, `${schemaFile}.${timestamp}.backup`);
      fs.copyFileSync(sourcePath, backupPath);
      console.log(`  ✓ Backed up: ${schemaFile}`);
    }
  });
}

function updateSchemaFile(schemaPath, swagger) {
  // Implementation for updating schema with Swagger data
  console.log(`  Processing: ${path.basename(schemaPath)}`);
  // TODO: Implement schema update logic
}

function validateSchemaStructure(schema) {
  const issues = [];

  // Check if schema is an object
  if (typeof schema !== 'object' || schema === null) {
    issues.push('Schema must be an object');
    return issues;
  }

  // Validate each module
  Object.keys(schema).forEach(moduleKey => {
    const module = schema[moduleKey];
    
    if (typeof module !== 'object') {
      issues.push(`Module ${moduleKey} must be an object`);
      return;
    }

    // Check for operations
    Object.keys(module).forEach(subKey => {
      const subModule = module[subKey];
      
      if (typeof subModule === 'object' && subModule !== null) {
        // Check for CRUD operations
        Object.keys(subModule).forEach(operationKey => {
          const operation = subModule[operationKey];
          
          if (Array.isArray(operation)) {
            if (operation.length < 2) {
              issues.push(`${moduleKey}.${subKey}.${operationKey} should have [url, payload]`);
            }
          }
        });
      }
    });
  });

  return issues;
}

function generateSchemaFromSwagger(swagger) {
  const schema = {};
  const paths = swagger.paths || {};

  // Group endpoints by tags/modules
  Object.keys(paths).forEach(pathKey => {
    const pathObj = paths[pathKey];
    
    Object.keys(pathObj).forEach(method => {
      if (typeof pathObj[method] === 'object') {
        const operation = pathObj[method];
        const tags = operation.tags || ['General'];
        const operationId = operation.operationId || '';

        tags.forEach(tag => {
          if (!schema[tag]) {
            schema[tag] = {};
          }

          const operationName = operationId || `${method}_${pathKey.replace(/\//g, '_')}`;
          
          schema[tag][operationName] = {
            [method.toUpperCase()]: [
              pathKey,
              {} // Placeholder for payload
            ]
          };
        });
      }
    });
  });

  return schema;
}

function showHelp() {
  console.log('\n📖 Swagger API Integration Tool - Help\n');
  console.log('Usage: node scripts/swagger-integration-tool.js [command] [options]\n');
  console.log('Commands:');
  console.log('  fetch              Fetch Swagger API documentation from server');
  console.log('  parse              Parse Swagger docs and show API structure');
  console.log('  update             Update existing schemas with new endpoints');
  console.log('  validate           Validate schema structure and format');
  console.log('  generate           Generate complete test schemas from Swagger');
  console.log('  help               Show this help message');
  console.log('\nExamples:');
  console.log('  node scripts/swagger-integration-tool.js fetch');
  console.log('  node scripts/swagger-integration-tool.js parse');
  console.log('  node scripts/swagger-integration-tool.js generate');
  console.log('  node scripts/swagger-integration-tool.js validate');
  console.log('\nWorkflow:');
  console.log('  1. Fetch Swagger documentation');
  console.log('  2. Parse to see API structure');
  console.log('  3. Generate or update schemas');
  console.log('  4. Validate schemas');
  console.log('\nConfiguration:');
  console.log(`  Swagger URL: ${CONFIG.swaggerUrl}`);
  console.log(`  Output Dir: ${CONFIG.outputDir}`);
  console.log(`  Backup Dir: ${CONFIG.backupDir}`);
}
