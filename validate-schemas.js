const fs = require('fs');
const path = require('path');

// Valid keys according to the requirements
const VALID_KEYS = ['CREATE', 'EDIT', 'DELETE', 'View', 'LookUP', 'EXPORT', 'PRINT'];

function validateSchemaFile(filePath) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Validating: ${path.basename(filePath)}`);
  console.log('='.repeat(80));
  
  try {
    const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    
    let totalEndpoints = 0;
    let validEndpoints = 0;
    let invalidEndpoints = [];
    let keyDistribution = {
      CREATE: 0,
      EDIT: 0,
      DELETE: 0,
      View: 0,
      LookUP: 0,
      EXPORT: 0,
      PRINT: 0,
      OTHER: 0
    };
    
    for (const [moduleName, endpoints] of Object.entries(schema)) {
      if (!endpoints || typeof endpoints !== 'object') continue;
      
      for (const [endpointKey, endpointData] of Object.entries(endpoints)) {
        if (!endpointData || typeof endpointData !== 'object') continue;
        
        totalEndpoints++;
        
        // Find the operation key
        const operationKeys = Object.keys(endpointData).filter(k => 
          !['summary', 'parameters', 'description', 'tags', 'responses'].includes(k)
        );
        
        for (const key of operationKeys) {
          if (Array.isArray(endpointData[key])) {
            if (VALID_KEYS.includes(key)) {
              validEndpoints++;
              keyDistribution[key]++;
            } else {
              keyDistribution.OTHER++;
              invalidEndpoints.push({
                module: moduleName,
                endpoint: endpointKey,
                invalidKey: key,
                apiPath: endpointData[key][0]
              });
            }
          }
        }
      }
    }
    
    const validationRate = totalEndpoints > 0 ? ((validEndpoints / totalEndpoints) * 100).toFixed(2) : 0;
    
    console.log(`\n📊 Validation Results:`);
    console.log(`   Total Endpoints: ${totalEndpoints}`);
    console.log(`   Valid Endpoints: ${validEndpoints}`);
    console.log(`   Invalid Endpoints: ${invalidEndpoints.length}`);
    console.log(`   Validation Rate: ${validationRate}%`);
    
    console.log(`\n📈 Key Distribution:`);
    Object.entries(keyDistribution).forEach(([key, count]) => {
      if (count > 0) {
        const percentage = ((count / totalEndpoints) * 100).toFixed(1);
        console.log(`   ${key}: ${count} (${percentage}%)`);
      }
    });
    
    if (invalidEndpoints.length > 0) {
      console.log(`\n⚠️  Invalid Endpoints Found:`);
      invalidEndpoints.slice(0, 10).forEach(item => {
        console.log(`   - ${item.module}.${item.endpoint}: ${item.invalidKey}`);
      });
      if (invalidEndpoints.length > 10) {
        console.log(`   ... and ${invalidEndpoints.length - 10} more`);
      }
    } else {
      console.log(`\n✅ All endpoints are valid!`);
    }
    
    return {
      fileName: path.basename(filePath),
      totalEndpoints,
      validEndpoints,
      invalidEndpoints: invalidEndpoints.length,
      validationRate: parseFloat(validationRate),
      keyDistribution,
      isValid: invalidEndpoints.length === 0,
      invalidDetails: invalidEndpoints
    };
    
  } catch (error) {
    console.error(`\n❌ Error validating ${path.basename(filePath)}: ${error.message}`);
    return {
      fileName: path.basename(filePath),
      totalEndpoints: 0,
      validEndpoints: 0,
      invalidEndpoints: 0,
      validationRate: 0,
      keyDistribution: {},
      isValid: false,
      error: error.message
    };
  }
}

function main() {
  const inputDir = path.join(__dirname, 'test-data', 'Input');
  const files = fs.readdirSync(inputDir).filter(f => f.endsWith('.json'));
  
  console.log('\n' + '█'.repeat(80));
  console.log('  SCHEMA VALIDATION TOOL');
  console.log('  Verifying Semantic Key Compliance');
  console.log('█'.repeat(80));
  console.log(`\nValidating ${files.length} schema files...\n`);
  
  const results = [];
  
  for (const file of files) {
    const filePath = path.join(inputDir, file);
    const result = validateSchemaFile(filePath);
    results.push(result);
  }
  
  // Generate summary
  console.log('\n' + '█'.repeat(80));
  console.log('  VALIDATION SUMMARY');
  console.log('█'.repeat(80));
  
  const totalEndpoints = results.reduce((sum, r) => sum + r.totalEndpoints, 0);
  const totalValid = results.reduce((sum, r) => sum + r.validEndpoints, 0);
  const totalInvalid = results.reduce((sum, r) => sum + r.invalidEndpoints, 0);
  const overallRate = totalEndpoints > 0 ? ((totalValid / totalEndpoints) * 100).toFixed(2) : 0;
  
  console.log(`\n📊 Overall Statistics:`);
  console.log(`   Total Files: ${files.length}`);
  console.log(`   Total Endpoints: ${totalEndpoints}`);
  console.log(`   Valid Endpoints: ${totalValid}`);
  console.log(`   Invalid Endpoints: ${totalInvalid}`);
  console.log(`   Overall Validation Rate: ${overallRate}%`);
  
  console.log(`\n📋 File-by-File Results:`);
  results.forEach(result => {
    const status = result.isValid ? '✅' : '⚠️';
    console.log(`   ${status} ${result.fileName}: ${result.validationRate}% valid (${result.validEndpoints}/${result.totalEndpoints})`);
  });
  
  // Aggregate key distribution
  const aggregateDistribution = {
    CREATE: 0,
    EDIT: 0,
    DELETE: 0,
    View: 0,
    LookUP: 0,
    EXPORT: 0,
    PRINT: 0,
    OTHER: 0
  };
  
  results.forEach(result => {
    Object.entries(result.keyDistribution).forEach(([key, count]) => {
      aggregateDistribution[key] += count;
    });
  });
  
  console.log(`\n📈 Aggregate Key Distribution:`);
  Object.entries(aggregateDistribution).forEach(([key, count]) => {
    if (count > 0) {
      const percentage = ((count / totalEndpoints) * 100).toFixed(1);
      console.log(`   ${key}: ${count} (${percentage}%)`);
    }
  });
  
  // Save validation report
  const reportPath = path.join(__dirname, 'schema-validation-report.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    summary: {
      totalFiles: files.length,
      totalEndpoints,
      totalValid,
      totalInvalid,
      overallValidationRate: parseFloat(overallRate),
      aggregateDistribution
    },
    results,
    validKeys: VALID_KEYS
  }, null, 2), 'utf8');
  
  console.log(`\n📄 Validation report saved to: schema-validation-report.json`);
  
  if (totalInvalid === 0) {
    console.log('\n' + '█'.repeat(80));
    console.log('  ✨ ALL SCHEMAS ARE VALID! ✨');
    console.log('█'.repeat(80) + '\n');
  } else {
    console.log('\n' + '█'.repeat(80));
    console.log(`  ⚠️  ${totalInvalid} INVALID ENDPOINTS FOUND`);
    console.log('█'.repeat(80) + '\n');
  }
}

main();
