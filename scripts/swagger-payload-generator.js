#!/usr/bin/env node
/**
 * Swagger Payload Generator
 * Extracts real request body schemas from Swagger documentation
 * and generates valid payloads for POST/PUT operations
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  swaggerFile: 'swagger-api-docs.json',
  enhancedSchemaFile: 'test-data/Input/Enhanced-ERP-Api-Schema.json',
  outputFile: 'test-data/Input/Enhanced-ERP-Api-Schema-With-Payloads.json',
  backupDir: 'backups/schemas'
};

console.log('🔧 Swagger Payload Generator\n');
console.log('='.repeat(70));

// Main execution
generatePayloads();

function generatePayloads() {
  console.log('\n📦 Generating Real Payloads from Swagger...\n');

  // Load Swagger documentation
  if (!fs.existsSync(CONFIG.swaggerFile)) {
    console.log(`❌ Swagger file not found: ${CONFIG.swaggerFile}`);
    console.log('💡 Run: npm run swagger:advanced:fetch');
    return;
  }

  // Load enhanced schema
  if (!fs.existsSync(CONFIG.enhancedSchemaFile)) {
    console.log(`❌ Enhanced schema not found: ${CONFIG.enhancedSchemaFile}`);
    console.log('💡 Run: npm run swagger:advanced:generate');
    return;
  }

  try {
    console.log('Loading Swagger documentation...');
    const swagger = JSON.parse(fs.readFileSync(CONFIG.swaggerFile, 'utf8'));
    
    console.log('Loading enhanced schema...');
    const enhancedSchema = JSON.parse(fs.readFileSync(CONFIG.enhancedSchemaFile, 'utf8'));

    console.log('Extracting request body schemas...');
    const enhancedWithPayloads = enhanceSchemaWithPayloads(enhancedSchema, swagger);

    // Backup original
    backupFile(CONFIG.enhancedSchemaFile);

    // Save enhanced version
    console.log('\nSaving enhanced schema with payloads...');
    fs.writeFileSync(CONFIG.outputFile, JSON.stringify(enhancedWithPayloads, null, 2));

    // Statistics
    const stats = calculateStats(enhancedWithPayloads);
    console.log('\n✅ Payload Generation Complete!\n');
    console.log('Statistics:');
    console.log(`  Modules: ${stats.modules}`);
    console.log(`  Operations: ${stats.operations}`);
    console.log(`  POST operations: ${stats.postOps}`);
    console.log(`  PUT operations: ${stats.putOps}`);
    console.log(`  Payloads generated: ${stats.payloadsGenerated}`);
    console.log(`  Empty payloads: ${stats.emptyPayloads}`);
    console.log(`\n  Output: ${CONFIG.outputFile}`);

  } catch (error) {
    console.log(`❌ Error: ${error.message}`);
    console.log(error.stack);
  }
}

function enhanceSchemaWithPayloads(schema, swagger) {
  const enhanced = {};
  const paths = swagger.paths || {};
  const components = swagger.components || {};
  const schemas = components.schemas || {};

  Object.keys(schema).forEach(moduleName => {
    enhanced[moduleName] = {};
    const module = schema[moduleName];

    Object.keys(module).forEach(operationName => {
      const operation = module[operationName];
      
      if (typeof operation === 'object' && !Array.isArray(operation)) {
        enhanced[moduleName][operationName] = {};

        Object.keys(operation).forEach(method => {
          const methodData = operation[method];
          
          if (Array.isArray(methodData) && methodData.length >= 2) {
            const [url, currentPayload] = methodData;
            
            // For POST and PUT, try to get real payload from Swagger
            if (method === 'POST' || method === 'PUT') {
              const realPayload = extractPayloadFromSwagger(url, method, paths, schemas);
              enhanced[moduleName][operationName][method] = [
                url,
                realPayload || currentPayload || {}
              ];
            } else {
              enhanced[moduleName][operationName][method] = methodData;
            }
          } else {
            enhanced[moduleName][operationName][method] = methodData;
          }
        });

        // Copy other properties
        if (operation.summary) {
          enhanced[moduleName][operationName].summary = operation.summary;
        }
        if (operation.parameters) {
          enhanced[moduleName][operationName].parameters = operation.parameters;
        }
      } else {
        enhanced[moduleName][operationName] = operation;
      }
    });
  });

  return enhanced;
}

function extractPayloadFromSwagger(url, method, paths, schemas) {
  // Find matching path in Swagger
  const pathKey = findMatchingPath(url, paths);
  if (!pathKey) {
    return null;
  }

  const pathObj = paths[pathKey];
  const methodLower = method.toLowerCase();
  
  if (!pathObj[methodLower]) {
    return null;
  }

  const operation = pathObj[methodLower];
  const requestBody = operation.requestBody;

  if (!requestBody || !requestBody.content) {
    return null;
  }

  // Get JSON content
  const jsonContent = requestBody.content['application/json'];
  if (!jsonContent || !jsonContent.schema) {
    return null;
  }

  // Generate example from schema
  return generateExampleFromSchema(jsonContent.schema, schemas);
}

function findMatchingPath(url, paths) {
  // Try exact match first
  if (paths[url]) {
    return url;
  }

  // Try to match with path parameters
  const urlParts = url.split('/').filter(p => p);
  
  for (const pathKey of Object.keys(paths)) {
    const pathParts = pathKey.split('/').filter(p => p);
    
    if (urlParts.length !== pathParts.length) {
      continue;
    }

    let matches = true;
    for (let i = 0; i < urlParts.length; i++) {
      const urlPart = urlParts[i];
      const pathPart = pathParts[i];
      
      // Check if path part is a parameter
      if (pathPart.startsWith('{') && pathPart.endsWith('}')) {
        continue; // Parameter matches anything
      }
      
      if (urlPart !== pathPart) {
        matches = false;
        break;
      }
    }

    if (matches) {
      return pathKey;
    }
  }

  return null;
}

function generateExampleFromSchema(schema, allSchemas, depth = 0, visited = new Set()) {
  if (depth > 5) {
    return {}; // Prevent infinite recursion
  }

  // Handle $ref
  if (schema.$ref) {
    const refPath = schema.$ref.replace('#/components/schemas/', '');
    
    if (visited.has(refPath)) {
      return {}; // Circular reference
    }
    
    visited.add(refPath);
    
    if (allSchemas[refPath]) {
      return generateExampleFromSchema(allSchemas[refPath], allSchemas, depth + 1, visited);
    }
    return {};
  }

  // Handle allOf
  if (schema.allOf) {
    let combined = {};
    schema.allOf.forEach(subSchema => {
      const example = generateExampleFromSchema(subSchema, allSchemas, depth + 1, visited);
      combined = { ...combined, ...example };
    });
    return combined;
  }

  // Handle oneOf / anyOf - use first option
  if (schema.oneOf || schema.anyOf) {
    const options = schema.oneOf || schema.anyOf;
    if (options.length > 0) {
      return generateExampleFromSchema(options[0], allSchemas, depth + 1, visited);
    }
    return {};
  }

  const type = schema.type;

  // Handle object
  if (type === 'object' || schema.properties) {
    const example = {};
    const properties = schema.properties || {};
    const required = schema.required || [];

    Object.keys(properties).forEach(propName => {
      const propSchema = properties[propName];
      
      // Generate value based on property schema
      example[propName] = generateValueFromSchema(propSchema, allSchemas, depth + 1, visited);
    });

    return example;
  }

  // Handle array
  if (type === 'array') {
    if (schema.items) {
      const itemExample = generateExampleFromSchema(schema.items, allSchemas, depth + 1, visited);
      return [itemExample];
    }
    return [];
  }

  // Handle primitive types
  return generateValueFromSchema(schema, allSchemas, depth, visited);
}

function generateValueFromSchema(schema, allSchemas, depth = 0, visited = new Set()) {
  // Handle $ref
  if (schema.$ref) {
    return generateExampleFromSchema(schema, allSchemas, depth, visited);
  }

  const type = schema.type;
  const format = schema.format;
  const example = schema.example;

  // Use example if provided
  if (example !== undefined) {
    return example;
  }

  // Use default if provided
  if (schema.default !== undefined) {
    return schema.default;
  }

  // Use enum if provided
  if (schema.enum && schema.enum.length > 0) {
    return schema.enum[0];
  }

  // Generate based on type and format
  switch (type) {
    case 'string':
      if (format === 'date-time') {
        return new Date().toISOString();
      }
      if (format === 'date') {
        return new Date().toISOString().split('T')[0];
      }
      if (format === 'email') {
        return 'test@example.com';
      }
      if (format === 'uuid') {
        return '00000000-0000-0000-0000-000000000000';
      }
      // Check property name for hints
      if (schema.description) {
        const desc = schema.description.toLowerCase();
        if (desc.includes('email')) return 'test@example.com';
        if (desc.includes('phone')) return '1234567890';
        if (desc.includes('url')) return 'https://example.com';
      }
      return 'string';

    case 'integer':
    case 'number':
      if (schema.minimum !== undefined) {
        return schema.minimum;
      }
      if (schema.maximum !== undefined) {
        return schema.maximum;
      }
      return type === 'integer' ? 1 : 1.0;

    case 'boolean':
      return true;

    case 'array':
      if (schema.items) {
        const itemExample = generateExampleFromSchema(schema.items, allSchemas, depth + 1, visited);
        return [itemExample];
      }
      return [];

    case 'object':
      return generateExampleFromSchema(schema, allSchemas, depth, visited);

    default:
      return null;
  }
}

function calculateStats(schema) {
  const stats = {
    modules: 0,
    operations: 0,
    postOps: 0,
    putOps: 0,
    payloadsGenerated: 0,
    emptyPayloads: 0
  };

  Object.keys(schema).forEach(moduleName => {
    stats.modules++;
    const module = schema[moduleName];

    Object.keys(module).forEach(operationName => {
      stats.operations++;
      const operation = module[operationName];

      if (typeof operation === 'object') {
        if (operation.POST) {
          stats.postOps++;
          const payload = Array.isArray(operation.POST) ? operation.POST[1] : {};
          if (Object.keys(payload).length > 0) {
            stats.payloadsGenerated++;
          } else {
            stats.emptyPayloads++;
          }
        }
        if (operation.PUT) {
          stats.putOps++;
          const payload = Array.isArray(operation.PUT) ? operation.PUT[1] : {};
          if (Object.keys(payload).length > 0) {
            stats.payloadsGenerated++;
          } else {
            stats.emptyPayloads++;
          }
        }
      }
    });
  });

  return stats;
}

function backupFile(filePath) {
  if (!fs.existsSync(CONFIG.backupDir)) {
    fs.mkdirSync(CONFIG.backupDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = path.basename(filePath);
  const backupPath = path.join(CONFIG.backupDir, `${fileName}.${timestamp}.backup`);
  
  if (fs.existsSync(filePath)) {
    fs.copyFileSync(filePath, backupPath);
    console.log(`  ✓ Backed up: ${fileName}`);
  }
}
