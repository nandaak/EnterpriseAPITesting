#!/usr/bin/env node
/**
 * Schema Enhancement Utility
 * Professional tool for enhancing, validating, and managing API schemas
 * 
 * Features:
 * - Deep schema validation
 * - Automatic ID placeholder replacement
 * - Schema comparison and diff
 * - Missing endpoint detection
 * - Schema optimization
 */

const fs = require('fs');
const path = require('path');

const CONFIG = {
  inputDir: 'test-data/Input',
  modulesDir: 'test-data/modules',
  outputDir: 'test-data/Output',
  backupDir: 'backups/schemas',
  swaggerFile: 'swagger-api-docs.json',
  parsedFile: 'swagger-parsed.json'
};

// Main execution
const command = process.argv[2] || 'help';
const options = parseArgs(process.argv.slice(3));

console.log('🔧 Schema Enhancement Utility\n');
console.log('='.repeat(70));

executeCommand(command, options);

console.log('='.repeat(70));

// Command router
function executeCommand(cmd, opts) {
  const commands = {
    'validate': validateSchemas,
    'compare': compareSchemas,
    'optimize': optimizeSchemas,
    'standardize': standardizeSchemas,
    'detect': detectMissingEndpoints,
    'convert': convertToStandardized,
    'analyze': analyzeSchemas,
    'help': showHelp
  };

  const handler = commands[cmd];
  if (handler) {
    handler(opts);
  } else {
    console.log(`❌ Unknown command: ${cmd}`);
    showHelp();
  }
}

function parseArgs(args) {
  const opts = {};
  args.forEach(arg => {
    if (arg.startsWith('--')) {
      const [key, value] = arg.substring(2).split('=');
      opts[key] = value || true;
    }
  });
  return opts;
}

// ============================================================================
// COMMAND IMPLEMENTATIONS
// ============================================================================

/**
 * Validate schemas with deep inspection
 */
function validateSchemas(opts) {
  console.log('\n✔️  Deep Schema Validation\n');

  const schemaFiles = getSchemaFiles();
  let totalIssues = 0;

  schemaFiles.forEach(file => {
    console.log(`\nValidating: ${file}`);
    const filePath = path.join(CONFIG.inputDir, file);
    
    try {
      const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const validation = performDeepValidation(schema, file);

      if (validation.issues.length === 0) {
        console.log(`  ✅ Valid - ${validation.stats.modules} modules, ${validation.stats.operations} operations`);
      } else {
        console.log(`  ❌ Issues found: ${validation.issues.length}`);
        totalIssues += validation.issues.length;
        
        if (opts.verbose) {
          validation.issues.forEach(issue => {
            console.log(`     - ${issue}`);
          });
        }
      }

      if (opts.stats) {
        console.log(`     Modules: ${validation.stats.modules}`);
        console.log(`     Operations: ${validation.stats.operations}`);
        console.log(`     Endpoints: ${validation.stats.endpoints}`);
      }

    } catch (error) {
      console.log(`  ❌ Error: ${error.message}`);
      totalIssues++;
    }
  });

  console.log(`\n${totalIssues === 0 ? '✅' : '❌'} Total issues: ${totalIssues}`);
}

/**
 * Compare two schemas
 */
function compareSchemas(opts) {
  console.log('\n🔍 Schema Comparison\n');

  const file1 = opts.file1 || 'Main-Backend-Api-Schema.json';
  const file2 = opts.file2 || 'Main-Standarized-Backend-Api-Schema.json';

  const path1 = path.join(CONFIG.inputDir, file1);
  const path2 = path.join(CONFIG.inputDir, file2);

  if (!fs.existsSync(path1) || !fs.existsSync(path2)) {
    console.log('❌ One or both files not found');
    return;
  }

  try {
    const schema1 = JSON.parse(fs.readFileSync(path1, 'utf8'));
    const schema2 = JSON.parse(fs.readFileSync(path2, 'utf8'));

    const comparison = compareSchemaStructures(schema1, schema2);

    console.log(`Comparing: ${file1} vs ${file2}\n`);
    console.log(`Modules in ${file1}: ${comparison.modules1.length}`);
    console.log(`Modules in ${file2}: ${comparison.modules2.length}`);
    console.log(`Common modules: ${comparison.common.length}`);
    console.log(`Only in ${file1}: ${comparison.only1.length}`);
    console.log(`Only in ${file2}: ${comparison.only2.length}`);

    if (opts.verbose && comparison.only1.length > 0) {
      console.log(`\nModules only in ${file1}:`);
      comparison.only1.forEach(m => console.log(`  - ${m}`));
    }

    if (opts.verbose && comparison.only2.length > 0) {
      console.log(`\nModules only in ${file2}:`);
      comparison.only2.forEach(m => console.log(`  - ${m}`));
    }

  } catch (error) {
    console.log(`❌ Comparison error: ${error.message}`);
  }
}

/**
 * Optimize schemas
 */
function optimizeSchemas(opts) {
  console.log('\n⚡ Schema Optimization\n');

  const schemaFiles = getSchemaFiles();

  schemaFiles.forEach(file => {
    console.log(`Optimizing: ${file}`);
    const filePath = path.join(CONFIG.inputDir, file);
    
    try {
      const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const optimized = optimizeSchema(schema);

      // Backup original
      backupFile(filePath);

      // Save optimized
      fs.writeFileSync(filePath, JSON.stringify(optimized, null, 2));
      console.log(`  ✅ Optimized`);

    } catch (error) {
      console.log(`  ❌ Error: ${error.message}`);
    }
  });
}

/**
 * Standardize schemas
 */
function standardizeSchemas(opts) {
  console.log('\n📐 Schema Standardization\n');

  const mainFile = 'Main-Backend-Api-Schema.json';
  const mainPath = path.join(CONFIG.inputDir, mainFile);

  if (!fs.existsSync(mainPath)) {
    console.log(`❌ Main schema not found: ${mainFile}`);
    return;
  }

  try {
    const mainSchema = JSON.parse(fs.readFileSync(mainPath, 'utf8'));
    const standardized = standardizeSchema(mainSchema);

    const outputPath = path.join(CONFIG.inputDir, 'Main-Standarized-Backend-Api-Schema.json');
    fs.writeFileSync(outputPath, JSON.stringify(standardized, null, 2));

    console.log(`✅ Standardized schema created`);
    console.log(`   Output: ${outputPath}`);

  } catch (error) {
    console.log(`❌ Standardization error: ${error.message}`);
  }
}

/**
 * Detect missing endpoints
 */
function detectMissingEndpoints(opts) {
  console.log('\n🔎 Detecting Missing Endpoints\n');

  if (!fs.existsSync(CONFIG.parsedFile)) {
    console.log(`❌ Parsed Swagger file not found`);
    console.log('💡 Run: node scripts/advanced-swagger-integration.js parse');
    return;
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(CONFIG.parsedFile, 'utf8'));
    const mainPath = path.join(CONFIG.inputDir, 'Main-Backend-Api-Schema.json');
    
    if (!fs.existsSync(mainPath)) {
      console.log(`❌ Main schema not found`);
      return;
    }

    const mainSchema = JSON.parse(fs.readFileSync(mainPath, 'utf8'));
    const missing = findMissingEndpoints(parsed.modules, mainSchema);

    console.log(`Total Swagger modules: ${Object.keys(parsed.modules).length}`);
    console.log(`Total Schema modules: ${Object.keys(mainSchema).length}`);
    console.log(`Missing modules: ${missing.modules.length}`);
    console.log(`Missing endpoints: ${missing.endpoints.length}`);

    if (opts.verbose && missing.modules.length > 0) {
      console.log('\nMissing Modules:');
      missing.modules.forEach(m => console.log(`  - ${m}`));
    }

    if (opts.save) {
      const reportPath = 'missing-endpoints-report.json';
      fs.writeFileSync(reportPath, JSON.stringify(missing, null, 2));
      console.log(`\n✅ Report saved: ${reportPath}`);
    }

  } catch (error) {
    console.log(`❌ Detection error: ${error.message}`);
  }
}

/**
 * Convert to standardized format
 */
function convertToStandardized(opts) {
  console.log('\n🔄 Converting to Standardized Format\n');

  const inputFile = opts.input || 'Main-Backend-Api-Schema.json';
  const outputFile = opts.output || 'Converted-Standardized-Schema.json';

  const inputPath = path.join(CONFIG.inputDir, inputFile);
  const outputPath = path.join(CONFIG.inputDir, outputFile);

  if (!fs.existsSync(inputPath)) {
    console.log(`❌ Input file not found: ${inputFile}`);
    return;
  }

  try {
    const schema = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
    const converted = convertToStandardizedFormat(schema);

    fs.writeFileSync(outputPath, JSON.stringify(converted, null, 2));

    console.log(`✅ Conversion complete`);
    console.log(`   Input: ${inputFile}`);
    console.log(`   Output: ${outputFile}`);

  } catch (error) {
    console.log(`❌ Conversion error: ${error.message}`);
  }
}

/**
 * Analyze schemas
 */
function analyzeSchemas(opts) {
  console.log('\n📊 Schema Analysis\n');

  const schemaFiles = getSchemaFiles();
  const analysis = {};

  schemaFiles.forEach(file => {
    const filePath = path.join(CONFIG.inputDir, file);
    
    try {
      const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      analysis[file] = analyzeSchemaStructure(schema);
    } catch (error) {
      console.log(`⚠️  Error analyzing ${file}: ${error.message}`);
    }
  });

  // Display analysis
  Object.keys(analysis).forEach(file => {
    const stats = analysis[file];
    console.log(`\n${file}:`);
    console.log(`  Modules: ${stats.modules}`);
    console.log(`  Operations: ${stats.operations}`);
    console.log(`  Endpoints: ${stats.endpoints}`);
    console.log(`  HTTP Methods: ${Object.keys(stats.methods).join(', ')}`);
    console.log(`  Has Placeholders: ${stats.hasPlaceholders ? 'Yes' : 'No'}`);
    console.log(`  Completeness: ${stats.completeness.toFixed(1)}%`);
  });

  if (opts.save) {
    const reportPath = 'schema-analysis-report.json';
    fs.writeFileSync(reportPath, JSON.stringify(analysis, null, 2));
    console.log(`\n✅ Analysis saved: ${reportPath}`);
  }
}

/**
 * Show help
 */
function showHelp() {
  console.log('\n📖 Schema Enhancement Utility - Help\n');
  console.log('Usage: node scripts/schema-enhancement-utility.js [command] [options]\n');
  console.log('Commands:');
  console.log('  validate      Deep validation of all schemas');
  console.log('  compare       Compare two schema files');
  console.log('  optimize      Optimize schema structure');
  console.log('  standardize   Convert to standardized format');
  console.log('  detect        Detect missing endpoints from Swagger');
  console.log('  convert       Convert schema to standardized format');
  console.log('  analyze       Analyze schema structure and statistics');
  console.log('  help          Show this help message');
  console.log('\nOptions:');
  console.log('  --verbose     Show detailed output');
  console.log('  --stats       Show statistics');
  console.log('  --save        Save report to file');
  console.log('  --file1=FILE  First file for comparison');
  console.log('  --file2=FILE  Second file for comparison');
  console.log('  --input=FILE  Input file for conversion');
  console.log('  --output=FILE Output file for conversion');
  console.log('\nExamples:');
  console.log('  node scripts/schema-enhancement-utility.js validate --verbose');
  console.log('  node scripts/schema-enhancement-utility.js compare --file1=Main-Backend-Api-Schema.json');
  console.log('  node scripts/schema-enhancement-utility.js detect --save');
  console.log('  node scripts/schema-enhancement-utility.js analyze --save');
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getSchemaFiles() {
  if (!fs.existsSync(CONFIG.inputDir)) {
    return [];
  }
  
  return fs.readdirSync(CONFIG.inputDir)
    .filter(f => f.endsWith('.json') && f.includes('Schema'));
}

function performDeepValidation(schema, fileName) {
  const issues = [];
  const stats = {
    modules: 0,
    operations: 0,
    endpoints: 0
  };

  if (typeof schema !== 'object' || schema === null) {
    issues.push('Schema must be an object');
    return { issues, stats };
  }

  Object.keys(schema).forEach(moduleKey => {
    stats.modules++;
    const module = schema[moduleKey];
    
    if (typeof module !== 'object') {
      issues.push(`Module ${moduleKey} must be an object`);
      return;
    }

    Object.keys(module).forEach(subKey => {
      const subModule = module[subKey];
      
      if (typeof subModule === 'object' && subModule !== null) {
        Object.keys(subModule).forEach(operationKey => {
          stats.operations++;
          const operation = subModule[operationKey];
          
          if (Array.isArray(operation)) {
            stats.endpoints++;
            
            if (operation.length < 2) {
              issues.push(`${moduleKey}.${subKey}.${operationKey}: Missing [url, payload]`);
            }
            
            if (typeof operation[0] !== 'string') {
              issues.push(`${moduleKey}.${subKey}.${operationKey}: URL must be string`);
            }
            
            if (operation[0] === 'URL_HERE') {
              issues.push(`${moduleKey}.${subKey}.${operationKey}: Placeholder URL not replaced`);
            }
            
            if (typeof operation[1] !== 'object') {
              issues.push(`${moduleKey}.${subKey}.${operationKey}: Payload must be object`);
            }
          }
        });
      }
    });
  });

  return { issues, stats };
}

function compareSchemaStructures(schema1, schema2) {
  const modules1 = Object.keys(schema1);
  const modules2 = Object.keys(schema2);
  
  const common = modules1.filter(m => modules2.includes(m));
  const only1 = modules1.filter(m => !modules2.includes(m));
  const only2 = modules2.filter(m => !modules1.includes(m));

  return {
    modules1,
    modules2,
    common,
    only1,
    only2
  };
}

function optimizeSchema(schema) {
  // Remove empty objects, sort keys, clean up structure
  const optimized = {};
  
  Object.keys(schema).sort().forEach(moduleKey => {
    const module = schema[moduleKey];
    
    if (typeof module === 'object' && Object.keys(module).length > 0) {
      optimized[moduleKey] = {};
      
      Object.keys(module).sort().forEach(subKey => {
        const subModule = module[subKey];
        
        if (typeof subModule === 'object' && Object.keys(subModule).length > 0) {
          optimized[moduleKey][subKey] = subModule;
        }
      });
    }
  });

  return optimized;
}

function standardizeSchema(schema) {
  const standardized = {};
  
  Object.keys(schema).forEach(moduleKey => {
    standardized[moduleKey] = {};
    const module = schema[moduleKey];
    
    Object.keys(module).forEach(subKey => {
      standardized[moduleKey][subKey] = {};
      const subModule = module[subKey];
      
      Object.keys(subModule).forEach(operationKey => {
        const operation = subModule[operationKey];
        
        if (Array.isArray(operation) && operation.length >= 2) {
          // Replace hardcoded IDs with <createdId> placeholder
          const url = operation[0].replace(/\/\d+/g, '/<createdId>');
          const payload = replaceIdsInPayload(operation[1]);
          
          standardized[moduleKey][subKey][operationKey] = [url, payload];
        } else {
          standardized[moduleKey][subKey][operationKey] = operation;
        }
      });
    });
  });

  return standardized;
}

function replaceIdsInPayload(payload) {
  if (typeof payload !== 'object' || payload === null) {
    return payload;
  }

  const replaced = Array.isArray(payload) ? [] : {};
  
  Object.keys(payload).forEach(key => {
    const value = payload[key];
    
    if (key.toLowerCase().includes('id') && typeof value === 'number') {
      replaced[key] = '<createdId>';
    } else if (typeof value === 'object') {
      replaced[key] = replaceIdsInPayload(value);
    } else {
      replaced[key] = value;
    }
  });

  return replaced;
}

function findMissingEndpoints(swaggerModules, schema) {
  const missing = {
    modules: [],
    endpoints: []
  };

  Object.keys(swaggerModules).forEach(moduleName => {
    if (!schema[moduleName]) {
      missing.modules.push(moduleName);
    } else {
      // Check for missing endpoints within module
      swaggerModules[moduleName].forEach(endpoint => {
        const found = findEndpointInSchema(schema[moduleName], endpoint.path, endpoint.method);
        if (!found) {
          missing.endpoints.push({
            module: moduleName,
            path: endpoint.path,
            method: endpoint.method
          });
        }
      });
    }
  });

  return missing;
}

function findEndpointInSchema(module, path, method) {
  for (const subKey of Object.keys(module)) {
    const subModule = module[subKey];
    
    for (const operationKey of Object.keys(subModule)) {
      const operation = subModule[operationKey];
      
      if (Array.isArray(operation) && operation[0] === path) {
        return true;
      }
      
      if (typeof operation === 'object' && operation[method]) {
        const methodOp = operation[method];
        if (Array.isArray(methodOp) && methodOp[0] === path) {
          return true;
        }
      }
    }
  }
  
  return false;
}

function convertToStandardizedFormat(schema) {
  return standardizeSchema(schema);
}

function analyzeSchemaStructure(schema) {
  const stats = {
    modules: 0,
    operations: 0,
    endpoints: 0,
    methods: {},
    hasPlaceholders: false,
    completeness: 0
  };

  let totalEndpoints = 0;
  let completeEndpoints = 0;

  Object.keys(schema).forEach(moduleKey => {
    stats.modules++;
    const module = schema[moduleKey];
    
    Object.keys(module).forEach(subKey => {
      const subModule = module[subKey];
      
      Object.keys(subModule).forEach(operationKey => {
        stats.operations++;
        const operation = subModule[operationKey];
        
        if (Array.isArray(operation)) {
          stats.endpoints++;
          totalEndpoints++;
          
          if (operation[0] && operation[0] !== 'URL_HERE') {
            completeEndpoints++;
          }
          
          if (operation[0] && operation[0].includes('<createdId>')) {
            stats.hasPlaceholders = true;
          }
        } else if (typeof operation === 'object') {
          Object.keys(operation).forEach(method => {
            if (!stats.methods[method]) {
              stats.methods[method] = 0;
            }
            stats.methods[method]++;
          });
        }
      });
    });
  });

  stats.completeness = totalEndpoints > 0 ? (completeEndpoints / totalEndpoints) * 100 : 0;

  return stats;
}

function backupFile(filePath) {
  if (!fs.existsSync(CONFIG.backupDir)) {
    fs.mkdirSync(CONFIG.backupDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = path.basename(filePath);
  const backupPath = path.join(CONFIG.backupDir, `${fileName}.${timestamp}.backup`);
  
  fs.copyFileSync(filePath, backupPath);
}
