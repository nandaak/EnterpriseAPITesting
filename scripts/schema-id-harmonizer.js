#!/usr/bin/env node
/**
 * Schema ID Harmonizer
 * Standardizes all schemas to use <createdId> placeholders
 * Ensures CRUD operations are properly correlated
 * Integrates with ID Registry System
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  inputDir: 'test-data/Input',
  modulesDir: 'test-data/modules',
  backupDir: 'backups/schemas',
  schemas: [
    'Main-Backend-Api-Schema.json',
    'Main-Standarized-Backend-Api-Schema.json',
    'Enhanced-ERP-Api-Schema.json',
    'Enhanced-ERP-Api-Schema-With-Payloads.json'
  ]
};

console.log('🔗 Schema ID Harmonizer\n');
console.log('='.repeat(70));

// Main execution
harmonizeAllSchemas();

function harmonizeAllSchemas() {
  console.log('\n🔄 Harmonizing All Schemas with <createdId>...\n');

  let totalUpdates = 0;
  const stats = {
    urlsUpdated: 0,
    payloadsUpdated: 0,
    modulesProcessed: 0
  };

  // Process main schemas
  console.log('📄 Processing Main Schemas:\n');
  CONFIG.schemas.forEach(schemaFile => {
    const schemaPath = path.join(CONFIG.inputDir, schemaFile);
    
    if (fs.existsSync(schemaPath)) {
      console.log(`  Processing: ${schemaFile}`);
      const result = harmonizeSchemaFile(schemaPath);
      console.log(`    ✅ URLs: ${result.urlsUpdated}, Payloads: ${result.payloadsUpdated}`);
      stats.urlsUpdated += result.urlsUpdated;
      stats.payloadsUpdated += result.payloadsUpdated;
      stats.modulesProcessed++;
    }
  });

  // Process module schemas
  if (fs.existsSync(CONFIG.modulesDir)) {
    console.log('\n📦 Processing Module Schemas:\n');
    const moduleFiles = fs.readdirSync(CONFIG.modulesDir)
      .filter(f => f.startsWith('Module-') && f.endsWith('.json'));

    let moduleCount = 0;
    moduleFiles.forEach(moduleFile => {
      const modulePath = path.join(CONFIG.modulesDir, moduleFile);
      const result = harmonizeSchemaFile(modulePath);
      if (result.urlsUpdated > 0 || result.payloadsUpdated > 0) {
        moduleCount++;
      }
      stats.urlsUpdated += result.urlsUpdated;
      stats.payloadsUpdated += result.payloadsUpdated;
    });

    console.log(`  ✅ Updated ${moduleCount} module schemas`);
    stats.modulesProcessed += moduleCount;
  }

  console.log('\n' + '='.repeat(70));
  console.log('\n✅ Harmonization Complete!\n');
  console.log('Statistics:');
  console.log(`  Modules Processed: ${stats.modulesProcessed}`);
  console.log(`  URLs Updated: ${stats.urlsUpdated}`);
  console.log(`  Payloads Updated: ${stats.payloadsUpdated}`);
  console.log(`  Total Updates: ${stats.urlsUpdated + stats.payloadsUpdated}\n`);
}

function harmonizeSchemaFile(filePath) {
  // Backup
  backupFile(filePath);

  // Load schema
  const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  
  // Harmonize
  const stats = { urlsUpdated: 0, payloadsUpdated: 0 };
  const harmonized = harmonizeSchemaRecursive(schema, stats);

  // Save
  fs.writeFileSync(filePath, JSON.stringify(harmonized, null, 2));

  return stats;
}

function harmonizeSchemaRecursive(obj, stats) {
  if (Array.isArray(obj)) {
    return obj.map(item => harmonizeSchemaRecursive(item, stats));
  }

  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const harmonized = {};

  for (const key of Object.keys(obj)) {
    const value = obj[key];

    // Check if this is an operation array [url, payload]
    if (Array.isArray(value) && value.length >= 2) {
      const [url, payload] = value;
      
      if (typeof url === 'string' && url.startsWith('/')) {
        // Harmonize URL
        const harmonizedUrl = harmonizeUrl(url, key);
        if (harmonizedUrl !== url) {
          stats.urlsUpdated++;
        }

        // Harmonize payload
        const harmonizedPayload = harmonizePayload(payload, key);
        if (JSON.stringify(harmonizedPayload) !== JSON.stringify(payload)) {
          stats.payloadsUpdated++;
        }

        harmonized[key] = [harmonizedUrl, harmonizedPayload];
      } else {
        harmonized[key] = value;
      }
    } else if (typeof value === 'object') {
      harmonized[key] = harmonizeSchemaRecursive(value, stats);
    } else {
      harmonized[key] = value;
    }
  }

  return harmonized;
}

function harmonizeUrl(url, operationType) {
  // Replace numeric IDs in URL with <createdId>
  let harmonized = url;

  // Pattern 1: /endpoint/{Id} or /endpoint/{id}
  harmonized = harmonized.replace(/\/\{[Ii]d\}/g, '/<createdId>');

  // Pattern 2: /endpoint/123 (numeric ID)
  harmonized = harmonized.replace(/\/\d+(?=\/|$)/g, '/<createdId>');

  // Pattern 3: /endpoint/{SomeId}
  harmonized = harmonized.replace(/\/\{[A-Za-z]+[Ii]d\}/g, '/<createdId>');

  // Pattern 4: Already has <createdId> - keep it
  // No change needed

  return harmonized;
}

function harmonizePayload(payload, operationType) {
  if (typeof payload !== 'object' || payload === null) {
    return payload;
  }

  // For PUT/Edit operations, replace ID values with <createdId>
  const isPutOrEdit = operationType === 'PUT' || 
                      operationType === 'Put' || 
                      operationType === 'EDIT' || 
                      operationType === 'Edit' ||
                      operationType.toLowerCase().includes('put') ||
                      operationType.toLowerCase().includes('edit');

  if (isPutOrEdit) {
    return harmonizePayloadIds(payload);
  }

  return payload;
}

function harmonizePayloadIds(obj, depth = 0) {
  if (depth > 10) return obj; // Prevent infinite recursion

  if (Array.isArray(obj)) {
    return obj.map(item => harmonizePayloadIds(item, depth + 1));
  }

  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const harmonized = {};

  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const keyLower = key.toLowerCase();

    // Check if this is an ID field
    const isIdField = keyLower === 'id' || 
                      keyLower.endsWith('id') ||
                      keyLower.includes('_id');

    if (isIdField) {
      // Replace with <createdId> placeholder
      if (typeof value === 'string') {
        // UUID format
        if (value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
          harmonized[key] = '<createdId>';
        } else if (value === 'string' || value === '') {
          harmonized[key] = '<createdId>';
        } else {
          harmonized[key] = value;
        }
      } else if (typeof value === 'number') {
        // Numeric ID
        harmonized[key] = '<createdId>';
      } else if (Array.isArray(value)) {
        // Array of IDs
        harmonized[key] = value.map(v => {
          if (typeof v === 'string' && v.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
            return '<createdId>';
          } else if (typeof v === 'number') {
            return '<createdId>';
          }
          return v;
        });
      } else {
        harmonized[key] = value;
      }
    } else if (typeof value === 'object') {
      // Recursively process nested objects
      harmonized[key] = harmonizePayloadIds(value, depth + 1);
    } else {
      harmonized[key] = value;
    }
  }

  return harmonized;
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
