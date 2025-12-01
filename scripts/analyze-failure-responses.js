#!/usr/bin/env node
/**
 * Analyze Failure Responses
 * Analyzes failure_response.json to identify patterns and solutions
 */

const fs = require('fs');

console.log('🔍 Failure Response Analyzer\n');
console.log('='.repeat(70));

// Load failure responses
let failures = {};
try {
  if (fs.existsSync('failure_response.json')) {
    failures = JSON.parse(fs.readFileSync('failure_response.json', 'utf8'));
    console.log(`\n✅ Loaded ${Object.keys(failures).length} failure responses\n`);
  } else {
    console.log('\n⚠️  No failure_response.json found. Run tests first.\n');
    process.exit(0);
  }
} catch (error) {
  console.error(`❌ Error loading failures: ${error.message}`);
  process.exit(1);
}

// Analyze failures
const analysis = {
  total: 0,
  byStatus: {
    400: [],
    404: [],
    500: []
  },
  byMethod: {
    GET: [],
    POST: [],
    PUT: [],
    DELETE: []
  },
  commonErrors: {},
  missingFields: {},
  validationErrors: []
};

// Process each failure
Object.entries(failures).forEach(([key, failure]) => {
  analysis.total++;
  
  // By status
  if (failure.statusCode === 400) {
    analysis.byStatus[400].push(key);
  } else if (failure.statusCode === 404) {
    analysis.byStatus[404].push(key);
  } else if (failure.statusCode === 500) {
    analysis.byStatus[500].push(key);
  }
  
  // By method
  if (analysis.byMethod[failure.method]) {
    analysis.byMethod[failure.method].push(key);
  }
  
  // Extract error messages
  const response = failure.response;
  let errorMessage = '';
  
  if (typeof response === 'string') {
    errorMessage = response;
  } else if (response && response.message) {
    errorMessage = response.message;
  } else if (response && response.error) {
    errorMessage = response.error;
  } else if (response && response.errors) {
    errorMessage = JSON.stringify(response.errors);
  }
  
  // Track common errors
  if (errorMessage) {
    if (!analysis.commonErrors[errorMessage]) {
      analysis.commonErrors[errorMessage] = [];
    }
    analysis.commonErrors[errorMessage].push(key);
  }
  
  // Detect missing field errors
  if (errorMessage.toLowerCase().includes('required') || 
      errorMessage.toLowerCase().includes('missing')) {
    analysis.validationErrors.push({
      key,
      message: errorMessage,
      payload: failure.requestPayload
    });
  }
});

// Display results
console.log('📊 Analysis Results:\n');
console.log(`Total Failures: ${analysis.total}`);
console.log(`   400 Bad Request: ${analysis.byStatus[400].length}`);
console.log(`   404 Not Found: ${analysis.byStatus[404].length}`);
console.log(`   500 Server Error: ${analysis.byStatus[500].length}`);

console.log('\n📋 By HTTP Method:');
Object.entries(analysis.byMethod).forEach(([method, failures]) => {
  if (failures.length > 0) {
    console.log(`   ${method}: ${failures.length} failures`);
  }
});

// Top error messages
console.log('\n🔝 Top Error Messages:');
const sortedErrors = Object.entries(analysis.commonErrors)
  .sort((a, b) => b[1].length - a[1].length)
  .slice(0, 10);

sortedErrors.forEach(([message, occurrences], index) => {
  console.log(`\n${index + 1}. "${message.substring(0, 80)}${message.length > 80 ? '...' : ''}"`);
  console.log(`   Occurrences: ${occurrences.length}`);
  console.log(`   Examples: ${occurrences.slice(0, 3).join(', ')}`);
});

// Validation errors
if (analysis.validationErrors.length > 0) {
  console.log('\n⚠️  Validation Errors (Missing/Required Fields):');
  analysis.validationErrors.slice(0, 5).forEach((error, index) => {
    console.log(`\n${index + 1}. ${error.key}`);
    console.log(`   Message: ${error.message}`);
    if (error.payload) {
      console.log(`   Payload fields: ${Object.keys(error.payload).join(', ')}`);
    }
  });
}

// 400 errors breakdown
console.log('\n\n📋 400 Bad Request Breakdown:');
analysis.byStatus[400].slice(0, 10).forEach((key, index) => {
  const failure = failures[key];
  console.log(`\n${index + 1}. ${key}`);
  
  let errorMsg = 'Unknown error';
  if (typeof failure.response === 'string') {
    errorMsg = failure.response.substring(0, 100);
  } else if (failure.response && failure.response.message) {
    errorMsg = failure.response.message.substring(0, 100);
  }
  
  console.log(`   Error: ${errorMsg}`);
  if (failure.requestPayload) {
    console.log(`   Payload: ${JSON.stringify(failure.requestPayload).substring(0, 100)}...`);
  }
});

// 500 errors breakdown
// 404 errors breakdown
console.log('\n\n📋 404 Not Found Breakdown:');
analysis.byStatus[404].slice(0, 10).forEach((key, index) => {
  const failure = failures[key];
  console.log(`\n${index + 1}. ${key}`);
  
  let errorMsg = 'Not found';
  if (typeof failure.response === 'string') {
    errorMsg = failure.response.substring(0, 100);
  } else if (failure.response && failure.response.message) {
    errorMsg = failure.response.message.substring(0, 100);
  }
  
  console.log(`   Error: ${errorMsg}`);
});

console.log('\n\n📋 500 Server Error Breakdown:');
analysis.byStatus[500].slice(0, 10).forEach((key, index) => {
  const failure = failures[key];
  console.log(`\n${index + 1}. ${key}`);
  
  let errorMsg = 'Internal server error';
  if (typeof failure.response === 'string') {
    errorMsg = failure.response.substring(0, 100);
  } else if (failure.response && failure.response.message) {
    errorMsg = failure.response.message.substring(0, 100);
  }
  
  console.log(`   Error: ${errorMsg}`);
});

// Generate recommendations
console.log('\n\n💡 Recommendations:\n');

if (analysis.byStatus[400].length > 0) {
  console.log('1. 400 Bad Request Fixes:');
  console.log('   → Review validation error messages');
  console.log('   → Add missing required fields to payloads');
  console.log('   → Check field types and formats');
  console.log('   → Validate against API documentation');
}

if (analysis.byStatus[404].length > 0) {
  console.log('\n2. 404 Not Found Fixes:');
  console.log('   → Verify endpoint URLs are correct');
  console.log('   → Check API version in URLs');
  console.log('   → Cross-reference with Swagger documentation');
  console.log('   → Ensure resource IDs exist before accessing');
}

if (analysis.byStatus[500].length > 0) {
  console.log('\n3. 500 Server Error Fixes:');
  console.log('   → Check backend logs for details');
  console.log('   → Verify prerequisite data exists');
  console.log('   → Test endpoints manually');
  console.log('   → Contact backend team if needed');
}

if (analysis.validationErrors.length > 0) {
  console.log('\n4. Validation Error Fixes:');
  console.log('   → Add missing required fields');
  console.log('   → Use correct field types');
  console.log('   → Follow API schema requirements');
}

// Save detailed analysis
const detailedAnalysis = {
  timestamp: new Date().toISOString(),
  summary: {
    total: analysis.total,
    status400: analysis.byStatus[400].length,
    status404: analysis.byStatus[404].length,
    status500: analysis.byStatus[500].length
  },
  byMethod: Object.entries(analysis.byMethod).reduce((acc, [method, failures]) => {
    acc[method] = failures.length;
    return acc;
  }, {}),
  topErrors: sortedErrors.map(([message, occurrences]) => ({
    message,
    count: occurrences.length,
    examples: occurrences.slice(0, 3)
  })),
  validationErrors: analysis.validationErrors.length,
  recommendations: [
    'Review and fix 400 errors by adding required fields',
    'Verify 404 errors - check URLs and resource IDs',
    'Investigate 500 errors with backend team',
    'Update payload templates based on error messages',
    'Add field validation before sending requests'
  ]
};

fs.writeFileSync('failure_analysis.json', JSON.stringify(detailedAnalysis, null, 2));
console.log('\n📁 Detailed analysis saved: failure_analysis.json');

console.log('\n' + '='.repeat(70));
console.log('✅ Analysis complete!\n');
