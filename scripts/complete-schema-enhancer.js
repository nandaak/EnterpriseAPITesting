#!/usr/bin/env node
/**
 * Complete Schema Enhancer
 * Updates ALL schema files with real payloads from Swagger
 * Handles Main, Standardized, Enhanced, and Module schemas
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  swaggerFile: 'swagger-api-docs.json',
  inputDir: 'test-data/Input',
  modulesDir: 'test-data/modules',
  backupDir: 'backups/schemas',
  schemas: [
    'Main-Backend-Api-Schema.json',
    'Main-Standarized-Backend-Api-Schema.json',
    'Enhanced-ERP-Api-Schema.json'
  ]
};

console.log('🚀 Complete Schema Enhancer\n');
console.log('='.repeat(70));

// Main execution
enhanceAllSchemas();

function enhanceAllSchemas() {
  console.log('\n📦 Enhancing ALL Schemas with Real Payloads...\n');

  // Load Swagger
  if (!fs.existsSync(CONFIG.swaggerFile)) {
    console.log(`❌ Swagger file not found: ${CONFIG.swaggerFile}`);
    console.log('💡 Run: npm run swagger:advanced:fetch');
    return;
  }

  try {
    console.log('Loading Swagger documentation...');
    const swagger = JSON.parse(fs.readFileSync(CONFIG.swaggerFile, 'utf8'));
    const paths = swagger.paths || {};
    const schemas = swagger.components?.schemas || {};

    let totalUpdated = 0;

    // Enhance main schemas
    console.log('\n📄 Enhancing Main Schemas:');
    CONFIG.schemas.forEach(schemaFile => {
      const schemaPath = path.join(CONFIG.inputDir, schemaFile);
      
      if (fs.existsSync(schemaPath)) {
        console.log(`\n  Processing: ${schemaFile}`);
        const updated = enhanceSchemaFile(schemaPath, paths, schemas);
        console.log(`    ✅ Updated ${updated} payloads`);
        totalUpdated += updated;
      } else {
        console.log(`  ⚠️  Not found: ${schemaFile}`);
      }
    });

    // Enhance module schemas
    if (fs.existsSync(CONFIG.modulesDir)) {
      console.log('\n📦 Enhancing Module Schemas:');
      const moduleFiles = fs.readdirSync(CONFIG.modulesDir)
        .filter(f => f.startsWith('Module-') && f.endsWith('.json'));

      let moduleCount = 0;
      moduleFiles.forEach(moduleFile => {
        const modulePath = path.join(CONFIG.modulesDir, moduleFile);
        const updated = enhanceSchemaFile(modulePath, paths, schemas);
        if (updated > 0) {
          moduleCount++;
        }
      });

      console.log(`\n  ✅ Enhanced ${moduleCount} module schemas`);
    }

    console.log('\n' + '='.repeat(70));
    console.log(`\n✅ Complete! Total payloads updated: ${totalUpdated}\n`);

  } catch (error) {
    console.log(`❌ Error: ${error.message}`);
    console.log(error.stack);
  }
}

function enhanceSchemaFile(filePath, paths, schemas) {
  // Backup
  backupFile(filePath);

  // Load schema
  const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  // Enhance
  let updatedCount = 0;
  const enhanced = enhanceSchemaRecursive(schema, paths, schemas, (updated) => {
    if (updated) updatedCount++;
  });

  // Save
  fs.writeFileSync(filePath, JSON.stringify(enhanced, null, 2));

  return updatedCount;
}

function enhanceSchemaRecursive(obj, paths, schemas, onUpdate) {
  if (Array.isArray(obj)) {
    return obj.map(item => enhanceSchemaRecursive(item, paths, schemas, onUpdate));
  }

  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const enhanced = {};

  for (const key of Object.keys(obj)) {
    const value = obj[key];

    // Check if this is an operation with method and array
    if (Array.isArray(value) && value.length >= 2) {
      const [url, payload] = value;
      
      // Check if this is a POST or PUT operation
      const isPostOrPut = key === 'Post' || key === 'POST' || key === 'PUT' || key === 'PUT' || key === 'save';
      
      if (isPostOrPut && typeof url === 'string' && url.startsWith('/')) {
        // Try to get real payload
        const realPayload = extractPayloadFromSwagger(url, key, paths, schemas);
        
        if (realPayload && Object.keys(realPayload).length > 0) {
          enhanced[key] = [url, realPayload];
          onUpdate(true);
        } else {
          enhanced[key] = value;
        }
      } else {
        enhanced[key] = value;
      }
    } else if (typeof value === 'object') {
      enhanced[key] = enhanceSchemaRecursive(value, paths, schemas, onUpdate);
    } else {
      enhanced[key] = value;
    }
  }

  return enhanced;
}

function extractPayloadFromSwagger(url, method, paths, schemas) {
  const pathKey = findMatchingPath(url, paths);
  if (!pathKey) {
    return null;
  }

  const pathObj = paths[pathKey];
  
  // Normalize method name
  let methodLower = method.toLowerCase();
  if (methodLower === 'save') methodLower = 'post';
  
  if (!pathObj[methodLower]) {
    return null;
  }

  const operation = pathObj[methodLower];
  const requestBody = operation.requestBody;

  if (!requestBody || !requestBody.content) {
    return null;
  }

  const jsonContent = requestBody.content['application/json'];
  if (!jsonContent || !jsonContent.schema) {
    return null;
  }

  return generateExampleFromSchema(jsonContent.schema, schemas);
}

function findMatchingPath(url, paths) {
  // Try exact match
  if (paths[url]) {
    return url;
  }

  // Try with path parameters
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
      
      if (pathPart.startsWith('{') && pathPart.endsWith('}')) {
        continue;
      }
      
      // Handle <createdId> placeholder
      if (urlPart === '<createdId>' || urlPart.match(/^\d+$/)) {
        if (pathPart.startsWith('{') && pathPart.endsWith('}')) {
          continue;
        }
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
  if (depth > 5) return {};

  // Handle $ref
  if (schema.$ref) {
    const refPath = schema.$ref.replace('#/components/schemas/', '');
    if (visited.has(refPath)) return {};
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

  // Handle oneOf / anyOf
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

    Object.keys(properties).forEach(propName => {
      const propSchema = properties[propName];
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

  return generateValueFromSchema(schema, allSchemas, depth, visited);
}

function generateValueFromSchema(schema, allSchemas, depth = 0, visited = new Set()) {
  if (schema.$ref) {
    return generateExampleFromSchema(schema, allSchemas, depth, visited);
  }

  const type = schema.type;
  const format = schema.format;

  // Use example if provided
  if (schema.example !== undefined) {
    return schema.example;
  }

  // Use default if provided
  if (schema.default !== undefined) {
    return schema.default;
  }

  // Use enum if provided
  if (schema.enum && schema.enum.length > 0) {
    return schema.enum[0];
  }

  // Generate based on type
  switch (type) {
    case 'string':
      if (format === 'date-time') return new Date().toISOString();
      if (format === 'date') return new Date().toISOString().split('T')[0];
      if (format === 'email') return 'test@example.com';
      if (format === 'uuid') return '00000000-0000-0000-0000-000000000000';
      return 'string';

    case 'integer':
      return schema.minimum !== undefined ? schema.minimum : 1;

    case 'number':
      return schema.minimum !== undefined ? schema.minimum : 1.0;

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

function backupFile(filePath) {
  if (!fs.existsSync(CONFIG.backupDir)) {
    fs.mkdirSync(CONFIG.backupDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = path.basename(filePath);
  const backupPath = path.join(CONFIG.backupDir, `${fileName}.${timestamp}.backup`);
  
  if (fs.existsSync(filePath)) {
    fs.copyFileSync(filePath, backupPath);
  }
}
