const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const testFiles = [
  'tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js',
  'tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js',
  'tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js',
  'tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js',
  'tests/comprehensive-lifecycle/5.API-Health-Checks.test.js'
];

// Create results directory
const resultsDir = './test-results';
if (!fs.existsSync(resultsDir)) {
  fs.mkdirSync(resultsDir, { recursive: true });
}

console.log('Starting sequential test execution with comprehensive reporting...\n');

let allPassed = true;
const results = [];
const jsonResults = [];

testFiles.forEach((testFile, index) => {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Running Test ${index + 1}/${testFiles.length}: ${testFile}`);
  console.log('='.repeat(80) + '\n');
  
  const jsonOutput = path.join(resultsDir, `test-result-${index + 1}.json`);
  
  try {
    execSync(`npx jest ${testFile} --config=jest.config.js --json --outputFile=${jsonOutput}`, {
      stdio: 'inherit',
      encoding: 'utf-8'
    });
    results.push({ file: testFile, status: 'PASSED', index: index + 1 });
    console.log(`\n✅ Test ${index + 1} PASSED\n`);
  } catch (error) {
    results.push({ file: testFile, status: 'FAILED', index: index + 1 });
    allPassed = false;
    console.log(`\n❌ Test ${index + 1} FAILED\n`);
  }
  
  // Read and store JSON result
  if (fs.existsSync(jsonOutput)) {
    try {
      const jsonData = JSON.parse(fs.readFileSync(jsonOutput, 'utf-8'));
      jsonResults.push({
        testFile,
        index: index + 1,
        ...jsonData
      });
    } catch (e) {
      console.log(`Warning: Could not parse JSON result for ${testFile}`);
    }
  }
});

// Generate comprehensive HTML report
console.log('\nGenerating comprehensive HTML report...');
generateHTMLReport(results, jsonResults);

console.log('\n' + '='.repeat(80));
console.log('TEST EXECUTION SUMMARY');
console.log('='.repeat(80));
results.forEach((result, index) => {
  const icon = result.status === 'PASSED' ? '✅' : '❌';
  console.log(`${icon} Test ${index + 1}: ${result.status} - ${result.file}`);
});
console.log('='.repeat(80));
console.log(`\n📊 Comprehensive HTML Report: ${path.resolve('./html-report/comprehensive-report.html')}\n`);

process.exit(allPassed ? 0 : 1);

function generateHTMLReport(results, jsonResults) {
  const reportDir = './html-report';
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true });
  }

  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;
  let totalSkipped = 0;
  let totalDuration = 0;

  jsonResults.forEach(result => {
    totalTests += result.numTotalTests || 0;
    totalPassed += result.numPassedTests || 0;
    totalFailed += result.numFailedTests || 0;
    totalSkipped += result.numPendingTests || 0;
    
    if (result.testResults && result.testResults[0]) {
      totalDuration += result.testResults[0].endTime - result.testResults[0].startTime;
    }
  });

  const passRate = totalTests > 0 ? ((totalPassed / totalTests) * 100).toFixed(2) : 0;
  const timestamp = new Date().toLocaleString();

  let testSuitesHTML = '';
  
  jsonResults.forEach((result, idx) => {
    const suiteStatus = result.success ? 'passed' : 'failed';
    const suiteIcon = result.success ? '✅' : '❌';
    
    testSuitesHTML += `
      <div class="test-suite ${suiteStatus}">
        <div class="suite-header">
          <h3>${suiteIcon} Test Suite ${result.index}: ${path.basename(result.testFile)}</h3>
          <div class="suite-stats">
            <span class="stat passed">✓ ${result.numPassedTests || 0} Passed</span>
            <span class="stat failed">✗ ${result.numFailedTests || 0} Failed</span>
            <span class="stat skipped">⊘ ${result.numPendingTests || 0} Skipped</span>
            <span class="stat total">Total: ${result.numTotalTests || 0}</span>
          </div>
        </div>
        <div class="suite-details">
          <p><strong>File:</strong> ${result.testFile}</p>
          ${generateTestCasesHTML(result)}
        </div>
      </div>
    `;
  });

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Comprehensive API Test Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 20px;
      min-height: 100vh;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      overflow: hidden;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      text-align: center;
    }
    .header h1 {
      font-size: 2.5em;
      margin-bottom: 10px;
      text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
    }
    .header .timestamp {
      opacity: 0.9;
      font-size: 1.1em;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      padding: 40px;
      background: #f8f9fa;
    }
    .summary-card {
      background: white;
      padding: 25px;
      border-radius: 10px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      text-align: center;
      transition: transform 0.2s;
    }
    .summary-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    .summary-card .number {
      font-size: 3em;
      font-weight: bold;
      margin: 10px 0;
    }
    .summary-card .label {
      color: #666;
      font-size: 1.1em;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .summary-card.total .number { color: #667eea; }
    .summary-card.passed .number { color: #10b981; }
    .summary-card.failed .number { color: #ef4444; }
    .summary-card.skipped .number { color: #f59e0b; }
    .summary-card.rate .number { color: #8b5cf6; }
    .summary-card.duration .number { font-size: 2em; }
    .test-suites {
      padding: 40px;
    }
    .test-suite {
      margin-bottom: 30px;
      border: 2px solid #e5e7eb;
      border-radius: 10px;
      overflow: hidden;
      transition: all 0.3s;
    }
    .test-suite:hover {
      box-shadow: 0 8px 16px rgba(0,0,0,0.1);
    }
    .test-suite.passed {
      border-color: #10b981;
    }
    .test-suite.failed {
      border-color: #ef4444;
    }
    .suite-header {
      background: #f8f9fa;
      padding: 20px;
      border-bottom: 2px solid #e5e7eb;
    }
    .suite-header h3 {
      font-size: 1.4em;
      margin-bottom: 15px;
      color: #1f2937;
    }
    .suite-stats {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
    }
    .stat {
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: 600;
      font-size: 0.95em;
    }
    .stat.passed {
      background: #d1fae5;
      color: #065f46;
    }
    .stat.failed {
      background: #fee2e2;
      color: #991b1b;
    }
    .stat.skipped {
      background: #fef3c7;
      color: #92400e;
    }
    .stat.total {
      background: #e0e7ff;
      color: #3730a3;
    }
    .suite-details {
      padding: 20px;
      background: white;
    }
    .suite-details p {
      margin: 10px 0;
      color: #4b5563;
    }
    .test-cases {
      margin-top: 20px;
    }
    .test-case {
      padding: 15px;
      margin: 10px 0;
      border-left: 4px solid #e5e7eb;
      background: #f9fafb;
      border-radius: 4px;
    }
    .test-case.passed {
      border-left-color: #10b981;
      background: #f0fdf4;
    }
    .test-case.failed {
      border-left-color: #ef4444;
      background: #fef2f2;
    }
    .test-case-title {
      font-weight: 600;
      margin-bottom: 8px;
      color: #1f2937;
    }
    .test-case-duration {
      color: #6b7280;
      font-size: 0.9em;
    }
    .failure-message {
      margin-top: 10px;
      padding: 15px;
      background: #fee;
      border-left: 4px solid #ef4444;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
      color: #991b1b;
      white-space: pre-wrap;
      overflow-x: auto;
    }
    .footer {
      background: #1f2937;
      color: white;
      padding: 30px;
      text-align: center;
    }
    @media print {
      body { background: white; padding: 0; }
      .container { box-shadow: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚀 Comprehensive API Test Report</h1>
      <p class="timestamp">Generated: ${timestamp}</p>
    </div>
    
    <div class="summary">
      <div class="summary-card total">
        <div class="label">Total Tests</div>
        <div class="number">${totalTests}</div>
      </div>
      <div class="summary-card passed">
        <div class="label">Passed</div>
        <div class="number">${totalPassed}</div>
      </div>
      <div class="summary-card failed">
        <div class="label">Failed</div>
        <div class="number">${totalFailed}</div>
      </div>
      <div class="summary-card skipped">
        <div class="label">Skipped</div>
        <div class="number">${totalSkipped}</div>
      </div>
      <div class="summary-card rate">
        <div class="label">Pass Rate</div>
        <div class="number">${passRate}%</div>
      </div>
      <div class="summary-card duration">
        <div class="label">Duration</div>
        <div class="number">${(totalDuration / 1000).toFixed(2)}s</div>
      </div>
    </div>
    
    <div class="test-suites">
      <h2 style="margin-bottom: 30px; color: #1f2937; font-size: 2em;">📋 Test Suites</h2>
      ${testSuitesHTML}
    </div>
    
    <div class="footer">
      <p>ERP API Testing Suite | Powered by Jest</p>
    </div>
  </div>
</body>
</html>
  `;

  fs.writeFileSync(path.join(reportDir, 'comprehensive-report.html'), html);
}

function generateTestCasesHTML(result) {
  if (!result.testResults || !result.testResults[0] || !result.testResults[0].assertionResults) {
    return '<p>No detailed test results available.</p>';
  }

  const assertions = result.testResults[0].assertionResults;
  
  let html = '<div class="test-cases">';
  
  assertions.forEach(assertion => {
    const status = assertion.status === 'passed' ? 'passed' : 'failed';
    const icon = assertion.status === 'passed' ? '✓' : '✗';
    const duration = assertion.duration ? `${assertion.duration}ms` : 'N/A';
    
    html += `
      <div class="test-case ${status}">
        <div class="test-case-title">${icon} ${assertion.title}</div>
        <div class="test-case-duration">Duration: ${duration}</div>
        ${assertion.failureMessages && assertion.failureMessages.length > 0 ? 
          `<div class="failure-message">${assertion.failureMessages.join('\n\n')}</div>` : ''}
      </div>
    `;
  });
  
  html += '</div>';
  return html;
}
