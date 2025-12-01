#!/usr/bin/env node
/**
 * Test Error Analyzer
 * Analyzes test failures and categorizes them for systematic fixing
 */

const fs = require('fs');

console.log('🔍 Test Error Analyzer\n');
console.log('='.repeat(70));

// Read test output
const testOutput = fs.readFileSync('test-run-output.log', 'utf8');

// Error categories
const errors = {
  loggerSuccess: [],
  status400: [],
  status404: [],
  status500: [],
  other: []
};

// Parse errors
const lines = testOutput.split('\n');
let currentModule = null;

lines.forEach((line, index) => {
  // Extract module name
  if (line.includes('Module:')) {
    const match = line.match(/Module: (\w+)/);
    if (match) currentModule = match[1];
  }
  
  // Categorize errors
  if (line.includes('logger.success is not a function')) {
    errors.loggerSuccess.push(currentModule);
  } else if (line.includes('Received: 400')) {
    errors.status400.push(currentModule);
  } else if (line.includes('Received: 404')) {
    errors.status404.push(currentModule);
  } else if (line.includes('status code 500')) {
    errors.status500.push(currentModule);
  }
});

// Remove duplicates
Object.keys(errors).forEach(key => {
  errors[key] = [...new Set(errors[key])];
});

// Generate report
console.log('\n📊 Error Analysis Report:\n');
console.log(`❌ logger.success errors: ${errors.loggerSuccess.length}`);
console.log(`❌ 400 Bad Request: ${errors.status400.length}`);
console.log(`❌ 404 Not Found: ${errors.status404.length}`);
console.log(`❌ 500 Server Error: ${errors.status500.length}`);

console.log('\n📋 Detailed Breakdown:\n');

if (errors.loggerSuccess.length > 0) {
  console.log('🔧 Logger.success Issues:');
  console.log('   Fix: Add success() method to Logger class');
  console.log(`   Affected: ${errors.loggerSuccess.slice(0, 5).join(', ')}...`);
}

if (errors.status400.length > 0) {
  console.log('\n🔧 400 Bad Request (Invalid Payloads):');
  console.log('   Fix: Improve payload generation with required fields');
  console.log(`   Count: ${errors.status400.length} modules`);
  console.log(`   Sample: ${errors.status400.slice(0, 5).join(', ')}`);
}

if (errors.status404.length > 0) {
  console.log('\n🔧 404 Not Found (Wrong URLs):');
  console.log('   Fix: Verify endpoint URLs in schema');
  console.log(`   Affected: ${errors.status404.join(', ')}`);
}

if (errors.status500.length > 0) {
  console.log('\n🔧 500 Server Error (Backend Issues):');
  console.log('   Fix: Check payload structure and required dependencies');
  console.log(`   Count: ${errors.status500.length} modules`);
  console.log(`   Sample: ${errors.status500.slice(0, 5).join(', ')}`);
}

// Save detailed report
const report = {
  timestamp: new Date().toISOString(),
  summary: {
    loggerSuccess: errors.loggerSuccess.length,
    status400: errors.status400.length,
    status404: errors.status404.length,
    status500: errors.status500.length,
    total: errors.loggerSuccess.length + errors.status400.length + 
           errors.status404.length + errors.status500.length
  },
  details: errors
};

fs.writeFileSync('test-error-analysis.json', JSON.stringify(report, null, 2));
console.log('\n✅ Detailed report saved: test-error-analysis.json');

// Generate fix priority
console.log('\n🎯 Fix Priority:\n');
console.log('1. ✅ Fix logger.success() - Quick win (affects all tests)');
console.log('2. 🔧 Fix 400 errors - Payload improvements');
console.log('3. 🔧 Fix 500 errors - Backend compatibility');
console.log('4. 🔧 Fix 404 errors - URL corrections');
