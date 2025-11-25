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
      <div class="test-suite ${suiteStatus}" data-suite-id="suite-${idx}" data-suite-status="${suiteStatus}">
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
      transition: all 0.3s;
      cursor: pointer;
      position: relative;
    }
    .summary-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    .summary-card.active {
      transform: scale(1.05);
      box-shadow: 0 8px 20px rgba(0,0,0,0.25);
      border: 3px solid;
    }
    .summary-card.active.total { border-color: #667eea; }
    .summary-card.active.passed { border-color: #10b981; }
    .summary-card.active.failed { border-color: #ef4444; }
    .summary-card.active.skipped { border-color: #f59e0b; }
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
    .filter-badge {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(0,0,0,0.1);
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 0.7em;
      font-weight: bold;
      opacity: 0;
      transition: opacity 0.3s;
    }
    .summary-card.active .filter-badge {
      opacity: 1;
    }
    .controls {
      padding: 30px 40px;
      background: #f8f9fa;
      border-top: 2px solid #e5e7eb;
      border-bottom: 2px solid #e5e7eb;
    }
    .controls-row {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      align-items: center;
    }
    .search-box {
      flex: 1;
      min-width: 300px;
      position: relative;
    }
    .search-box input {
      width: 100%;
      padding: 12px 45px 12px 15px;
      border: 2px solid #e5e7eb;
      border-radius: 8px;
      font-size: 1em;
      transition: all 0.3s;
    }
    .search-box input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    .search-icon {
      position: absolute;
      right: 15px;
      top: 50%;
      transform: translateY(-50%);
      color: #9ca3af;
      font-size: 1.2em;
    }
    .suite-filter {
      min-width: 250px;
    }
    .suite-filter select {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e5e7eb;
      border-radius: 8px;
      font-size: 1em;
      background: white;
      cursor: pointer;
      transition: all 0.3s;
    }
    .suite-filter select:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    .clear-filters {
      padding: 12px 24px;
      background: #ef4444;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 1em;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }
    .clear-filters:hover {
      background: #dc2626;
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(239, 68, 68, 0.3);
    }
    .clear-filters:active {
      transform: translateY(0);
    }
    .active-filters {
      padding: 15px 40px;
      background: #fef3c7;
      border-bottom: 2px solid #fbbf24;
      display: none;
    }
    .active-filters.show {
      display: block;
    }
    .filter-tag {
      display: inline-block;
      padding: 6px 12px;
      background: #667eea;
      color: white;
      border-radius: 20px;
      margin-right: 10px;
      font-size: 0.9em;
      font-weight: 600;
    }
    .results-count {
      padding: 15px 40px;
      background: #e0e7ff;
      border-bottom: 2px solid #c7d2fe;
      font-weight: 600;
      color: #3730a3;
    }
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
    .test-suite.hidden {
      display: none;
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
    .module-group {
      margin: 20px 0;
      border: 2px solid #e5e7eb;
      border-radius: 8px;
      overflow: hidden;
      background: white;
      transition: all 0.3s;
    }
    .module-group:hover {
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .module-group.passed {
      border-color: #10b981;
    }
    .module-group.failed {
      border-color: #ef4444;
    }
    .module-group.skipped {
      border-color: #f59e0b;
    }
    .module-header {
      background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
      padding: 15px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #e5e7eb;
    }
    .module-title {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 600;
      font-size: 1.1em;
      color: #1f2937;
    }
    .module-icon {
      font-size: 1.5em;
    }
    .module-name {
      font-weight: 700;
      color: #374151;
    }
    .module-stats {
      display: flex;
      gap: 12px;
    }
    .module-stat {
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.85em;
      font-weight: 600;
    }
    .module-stat.passed {
      background: #d1fae5;
      color: #065f46;
    }
    .module-stat.failed {
      background: #fee2e2;
      color: #991b1b;
    }
    .module-stat.skipped {
      background: #fef3c7;
      color: #92400e;
    }
    .module-tests {
      padding: 10px;
    }
    .test-case {
      padding: 15px;
      margin: 10px 0;
      border-left: 4px solid #e5e7eb;
      background: #f9fafb;
      border-radius: 4px;
      transition: all 0.3s;
    }
    .test-case.passed {
      border-left-color: #10b981;
      background: #f0fdf4;
    }
    .test-case.failed {
      border-left-color: #ef4444;
      background: #fef2f2;
    }
    .test-case.skipped {
      border-left-color: #f59e0b;
      background: #fffbeb;
    }
    .test-case.hidden {
      display: none;
    }
    .test-case.highlight {
      background: #fef3c7;
      border-left-color: #f59e0b;
      box-shadow: 0 4px 8px rgba(245, 158, 11, 0.2);
    }
    .phase-badge {
      display: inline-block;
      padding: 3px 8px;
      background: #e0e7ff;
      color: #3730a3;
      border-radius: 12px;
      font-size: 0.75em;
      font-weight: 600;
      margin-left: 8px;
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
      <div class="summary-card total" onclick="filterByStatus('all')" data-filter="all">
        <div class="filter-badge">FILTER</div>
        <div class="label">Total Tests</div>
        <div class="number">${totalTests}</div>
      </div>
      <div class="summary-card passed" onclick="filterByStatus('passed')" data-filter="passed">
        <div class="filter-badge">FILTER</div>
        <div class="label">Passed</div>
        <div class="number">${totalPassed}</div>
      </div>
      <div class="summary-card failed" onclick="filterByStatus('failed')" data-filter="failed">
        <div class="filter-badge">FILTER</div>
        <div class="label">Failed</div>
        <div class="number">${totalFailed}</div>
      </div>
      <div class="summary-card skipped" onclick="filterByStatus('skipped')" data-filter="skipped">
        <div class="filter-badge">FILTER</div>
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
    
    <div class="controls">
      <div class="controls-row">
        <div class="search-box">
          <input type="text" id="searchInput" placeholder="🔍 Search by test title or error message..." oninput="performSearch()">
          <span class="search-icon">🔍</span>
        </div>
        <div class="suite-filter">
          <select id="suiteFilter" onchange="filterBySuite()">
            <option value="all">📋 All Test Suites</option>
            ${jsonResults.map((result, idx) => 
              `<option value="suite-${idx}">Suite ${result.index}: ${path.basename(result.testFile)}</option>`
            ).join('')}
          </select>
        </div>
        <div class="suite-filter">
          <select id="moduleFilter" onchange="filterByModule()">
            <option value="all">📦 All Modules</option>
          </select>
        </div>
        <button class="clear-filters" onclick="clearAllFilters()">🔄 Clear Filters</button>
      </div>
    </div>
    
    <div class="active-filters" id="activeFilters">
      <strong>Active Filters:</strong> <span id="filterTags"></span>
    </div>
    
    <div class="results-count" id="resultsCount">
      Showing all ${totalTests} tests
    </div>
    
    <div class="test-suites">
      <h2 style="margin-bottom: 30px; color: #1f2937; font-size: 2em;">📋 Test Suites</h2>
      ${testSuitesHTML}
    </div>
    
    <div class="footer">
      <p>ERP API Testing Suite | Powered by Jest</p>
    </div>
  </div>
  
  <script>
    // State management
    let currentFilters = {
      status: 'all',
      suite: 'all',
      module: 'all',
      search: ''
    };
    
    // Filter by status (from summary cards)
    function filterByStatus(status) {
      currentFilters.status = status;
      
      // Update active card styling
      document.querySelectorAll('.summary-card[data-filter]').forEach(card => {
        card.classList.remove('active');
      });
      
      if (status !== 'all') {
        const activeCard = document.querySelector(\`.summary-card[data-filter="\${status}"]\`);
        if (activeCard) activeCard.classList.add('active');
      } else {
        const totalCard = document.querySelector('.summary-card[data-filter="all"]');
        if (totalCard) totalCard.classList.add('active');
      }
      
      applyFilters();
    }
    
    // Filter by suite (from dropdown)
    function filterBySuite() {
      const suiteSelect = document.getElementById('suiteFilter');
      currentFilters.suite = suiteSelect.value;
      applyFilters();
    }
    
    // Filter by module (from dropdown)
    function filterByModule() {
      const moduleSelect = document.getElementById('moduleFilter');
      currentFilters.module = moduleSelect.value;
      applyFilters();
    }
    
    // Search functionality
    function performSearch() {
      const searchInput = document.getElementById('searchInput');
      currentFilters.search = searchInput.value.toLowerCase().trim();
      applyFilters();
    }
    
    // Clear all filters
    function clearAllFilters() {
      currentFilters = {
        status: 'all',
        suite: 'all',
        module: 'all',
        search: ''
      };
      
      // Reset UI
      document.getElementById('searchInput').value = '';
      document.getElementById('suiteFilter').value = 'all';
      document.getElementById('moduleFilter').value = 'all';
      document.querySelectorAll('.summary-card').forEach(card => {
        card.classList.remove('active');
      });
      
      applyFilters();
    }
    
    // Apply all active filters
    function applyFilters() {
      const allSuites = document.querySelectorAll('.test-suite');
      const allTestCases = document.querySelectorAll('.test-case');
      const allModuleGroups = document.querySelectorAll('.module-group');
      
      let visibleTests = 0;
      let visibleSuites = 0;
      let visibleModules = 0;
      
      // First, handle suite-level filtering
      allSuites.forEach(suite => {
        const suiteId = suite.getAttribute('data-suite-id');
        let suiteVisible = true;
        
        // Suite filter
        if (currentFilters.suite !== 'all' && suiteId !== currentFilters.suite) {
          suiteVisible = false;
        }
        
        if (suiteVisible) {
          suite.classList.remove('hidden');
          
          // Filter module groups within visible suites
          const moduleGroups = suite.querySelectorAll('.module-group');
          let suiteHasVisibleTests = false;
          
          moduleGroups.forEach(moduleGroup => {
            const moduleName = moduleGroup.getAttribute('data-module');
            let moduleVisible = true;
            
            // Module filter
            if (currentFilters.module !== 'all' && moduleName !== currentFilters.module) {
              moduleVisible = false;
            }
            
            if (moduleVisible) {
              // Now filter test cases within visible modules
              const testCases = moduleGroup.querySelectorAll('.test-case');
              let moduleHasVisibleTests = false;
              
              testCases.forEach(testCase => {
                let testVisible = true;
                
                // Status filter
                if (currentFilters.status !== 'all') {
                  const testStatus = testCase.getAttribute('data-status');
                  if (testStatus !== currentFilters.status) {
                    testVisible = false;
                  }
                }
                
                // Search filter
                if (currentFilters.search) {
                  const searchText = testCase.getAttribute('data-search-text');
                  if (!searchText.includes(currentFilters.search)) {
                    testVisible = false;
                  } else {
                    // Highlight matching test
                    testCase.classList.add('highlight');
                  }
                } else {
                  testCase.classList.remove('highlight');
                }
                
                // Apply visibility
                if (testVisible) {
                  testCase.classList.remove('hidden');
                  visibleTests++;
                  moduleHasVisibleTests = true;
                  suiteHasVisibleTests = true;
                } else {
                  testCase.classList.add('hidden');
                }
              });
              
              // Hide module if no tests are visible
              if (!moduleHasVisibleTests && (currentFilters.status !== 'all' || currentFilters.search)) {
                moduleGroup.classList.add('hidden');
              } else {
                moduleGroup.classList.remove('hidden');
                if (moduleHasVisibleTests) visibleModules++;
              }
            } else {
              moduleGroup.classList.add('hidden');
            }
          });
          
          // Hide suite if no tests are visible
          if (!suiteHasVisibleTests && (currentFilters.status !== 'all' || currentFilters.search || currentFilters.module !== 'all')) {
            suite.classList.add('hidden');
          } else {
            visibleSuites++;
          }
        } else {
          suite.classList.add('hidden');
        }
      });
      
      // Update results count
      updateResultsCount(visibleTests, visibleSuites, visibleModules);
      
      // Update active filters display
      updateActiveFilters();
    }
    
    // Update results count display
    function updateResultsCount(visibleTests, visibleSuites, visibleModules) {
      const resultsCount = document.getElementById('resultsCount');
      const totalTests = ${totalTests};
      const totalSuites = ${jsonResults.length};
      
      if (visibleTests === totalTests) {
        resultsCount.textContent = \`Showing all \${totalTests} tests from \${visibleSuites} suites and \${visibleModules} modules\`;
      } else {
        resultsCount.textContent = \`Showing \${visibleTests} of \${totalTests} tests from \${visibleSuites} suites and \${visibleModules} modules\`;
      }
    }
    
    // Update active filters display
    function updateActiveFilters() {
      const activeFiltersDiv = document.getElementById('activeFilters');
      const filterTags = document.getElementById('filterTags');
      const filters = [];
      
      if (currentFilters.status !== 'all') {
        filters.push(\`<span class="filter-tag">Status: \${currentFilters.status.toUpperCase()}</span>\`);
      }
      
      if (currentFilters.suite !== 'all') {
        const suiteSelect = document.getElementById('suiteFilter');
        const selectedOption = suiteSelect.options[suiteSelect.selectedIndex].text;
        filters.push(\`<span class="filter-tag">\${selectedOption}</span>\`);
      }
      
      if (currentFilters.module !== 'all') {
        const moduleSelect = document.getElementById('moduleFilter');
        const selectedOption = moduleSelect.options[moduleSelect.selectedIndex].text;
        filters.push(\`<span class="filter-tag">\${selectedOption}</span>\`);
      }
      
      if (currentFilters.search) {
        filters.push(\`<span class="filter-tag">Search: "\${currentFilters.search}"</span>\`);
      }
      
      if (filters.length > 0) {
        filterTags.innerHTML = filters.join('');
        activeFiltersDiv.classList.add('show');
      } else {
        activeFiltersDiv.classList.remove('show');
      }
    }
    
    // Populate module dropdown
    function populateModuleDropdown() {
      const moduleSelect = document.getElementById('moduleFilter');
      const allModules = new Set();
      
      // Collect all unique modules
      document.querySelectorAll('.module-group[data-module]').forEach(moduleGroup => {
        const moduleName = moduleGroup.getAttribute('data-module');
        if (moduleName && moduleName !== 'ungrouped') {
          allModules.add(moduleName);
        }
      });
      
      // Sort and add to dropdown
      const sortedModules = Array.from(allModules).sort();
      sortedModules.forEach(moduleName => {
        const option = document.createElement('option');
        option.value = moduleName;
        
        // Format module name for display
        const parts = moduleName.split('.');
        const formattedName = parts.map(part => 
          part.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase())
        ).join(' → ');
        
        // Get icon
        const lowerPath = moduleName.toLowerCase();
        let icon = '📋';
        if (lowerPath.includes('inventory')) icon = '📦';
        else if (lowerPath.includes('finance') || lowerPath.includes('accounting')) icon = '💰';
        else if (lowerPath.includes('sales')) icon = '🛒';
        else if (lowerPath.includes('purchase')) icon = '🛍️';
        else if (lowerPath.includes('hr') || lowerPath.includes('employee')) icon = '👥';
        else if (lowerPath.includes('general') || lowerPath.includes('settings')) icon = '⚙️';
        else if (lowerPath.includes('warehouse')) icon = '🏭';
        
        option.textContent = \`\${icon} \${formattedName}\`;
        moduleSelect.appendChild(option);
      });
    }
    
    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
      console.log('Interactive Test Report Loaded');
      console.log('Total Tests: ${totalTests}');
      console.log('Total Suites: ${jsonResults.length}');
      
      // Populate module dropdown
      populateModuleDropdown();
      
      // Count modules
      const totalModules = document.querySelectorAll('.module-group[data-module]').length;
      console.log('Total Modules: ' + totalModules);
      
      // Add keyboard shortcut for search (Ctrl+F or Cmd+F)
      document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
          e.preventDefault();
          document.getElementById('searchInput').focus();
        }
      });
    });
  </script>
</body>
</html>
  `;

  fs.writeFileSync(path.join(reportDir, 'comprehensive-report.html'), html);
}

function extractModuleName(testTitle) {
  // Extract module name from test title like "COMPLETE CRUD LIFECYCLE: General_Settings.Master_Data.Discount_Policy"
  const match = testTitle.match(/COMPLETE CRUD LIFECYCLE:\s*(.+?)(?:\s|$)/);
  if (match && match[1]) {
    return match[1].trim();
  }
  return null;
}

function formatModuleName(modulePath) {
  if (!modulePath) return '';
  
  // Split by dots and format each part
  const parts = modulePath.split('.');
  return parts.map(part => {
    // Replace underscores with spaces and capitalize
    return part.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }).join(' → ');
}

function getModuleIcon(modulePath) {
  if (!modulePath) return '📦';
  
  const lowerPath = modulePath.toLowerCase();
  
  if (lowerPath.includes('inventory')) return '📦';
  if (lowerPath.includes('finance') || lowerPath.includes('accounting')) return '💰';
  if (lowerPath.includes('sales')) return '🛒';
  if (lowerPath.includes('purchase')) return '🛍️';
  if (lowerPath.includes('hr') || lowerPath.includes('employee')) return '👥';
  if (lowerPath.includes('general') || lowerPath.includes('settings')) return '⚙️';
  if (lowerPath.includes('warehouse')) return '🏭';
  if (lowerPath.includes('customer')) return '👤';
  if (lowerPath.includes('supplier') || lowerPath.includes('vendor')) return '🏢';
  if (lowerPath.includes('product') || lowerPath.includes('item')) return '📦';
  if (lowerPath.includes('report')) return '📊';
  if (lowerPath.includes('security')) return '🔒';
  
  return '📋';
}

function generateTestCasesHTML(result) {
  if (!result.testResults || !result.testResults[0] || !result.testResults[0].assertionResults) {
    return '<p>No detailed test results available.</p>';
  }

  const assertions = result.testResults[0].assertionResults;
  
  // Group tests by module
  const moduleGroups = {};
  const ungroupedTests = [];
  
  assertions.forEach(assertion => {
    const moduleName = extractModuleName(assertion.fullName || assertion.title);
    
    if (moduleName) {
      if (!moduleGroups[moduleName]) {
        moduleGroups[moduleName] = [];
      }
      moduleGroups[moduleName].push(assertion);
    } else {
      ungroupedTests.push(assertion);
    }
  });
  
  let html = '<div class="test-cases">';
  
  // Render grouped tests by module
  Object.keys(moduleGroups).sort().forEach(moduleName => {
    const moduleTests = moduleGroups[moduleName];
    const moduleIcon = getModuleIcon(moduleName);
    const formattedModuleName = formatModuleName(moduleName);
    
    // Count statuses for this module
    const modulePassed = moduleTests.filter(t => t.status === 'passed').length;
    const moduleFailed = moduleTests.filter(t => t.status === 'failed').length;
    const moduleSkipped = moduleTests.filter(t => t.status === 'pending').length;
    const moduleStatus = moduleFailed > 0 ? 'failed' : (moduleSkipped === moduleTests.length ? 'skipped' : 'passed');
    
    html += `
      <div class="module-group ${moduleStatus}" data-module="${moduleName}">
        <div class="module-header">
          <div class="module-title">
            <span class="module-icon">${moduleIcon}</span>
            <span class="module-name">${formattedModuleName}</span>
          </div>
          <div class="module-stats">
            <span class="module-stat passed">✓ ${modulePassed}</span>
            <span class="module-stat failed">✗ ${moduleFailed}</span>
            <span class="module-stat skipped">⊘ ${moduleSkipped}</span>
          </div>
        </div>
        <div class="module-tests">
    `;
    
    moduleTests.forEach(assertion => {
      const status = assertion.status === 'passed' ? 'passed' : (assertion.status === 'pending' ? 'skipped' : 'failed');
      const icon = assertion.status === 'passed' ? '✓' : (assertion.status === 'pending' ? '⊘' : '✗');
      const duration = assertion.duration ? `${assertion.duration}ms` : 'N/A';
      const failureText = assertion.failureMessages && assertion.failureMessages.length > 0 ? 
        assertion.failureMessages.join(' ') : '';
      const searchText = `${assertion.title} ${failureText}`.toLowerCase();
      
      // Extract phase from title (e.g., "[PHASE 1/6] CREATE")
      const phaseMatch = assertion.title.match(/\[PHASE (\d+)\/\d+\]\s*(\w+)/);
      const phaseLabel = phaseMatch ? `<span class="phase-badge">Phase ${phaseMatch[1]}: ${phaseMatch[2]}</span>` : '';
      
      html += `
        <div class="test-case ${status}" 
             data-status="${status}" 
             data-search-text="${searchText.replace(/"/g, '&quot;')}"
             data-title="${assertion.title.replace(/"/g, '&quot;')}"
             data-module="${moduleName}">
          <div class="test-case-title">${icon} ${assertion.title} ${phaseLabel}</div>
          <div class="test-case-duration">Duration: ${duration}</div>
          ${assertion.failureMessages && assertion.failureMessages.length > 0 ? 
            `<div class="failure-message">${assertion.failureMessages.join('\n\n')}</div>` : ''}
        </div>
      `;
    });
    
    html += `
        </div>
      </div>
    `;
  });
  
  // Render ungrouped tests
  if (ungroupedTests.length > 0) {
    html += '<div class="module-group" data-module="ungrouped"><div class="module-tests">';
    
    ungroupedTests.forEach(assertion => {
      const status = assertion.status === 'passed' ? 'passed' : (assertion.status === 'pending' ? 'skipped' : 'failed');
      const icon = assertion.status === 'passed' ? '✓' : (assertion.status === 'pending' ? '⊘' : '✗');
      const duration = assertion.duration ? `${assertion.duration}ms` : 'N/A';
      const failureText = assertion.failureMessages && assertion.failureMessages.length > 0 ? 
        assertion.failureMessages.join(' ') : '';
      const searchText = `${assertion.title} ${failureText}`.toLowerCase();
      
      html += `
        <div class="test-case ${status}" 
             data-status="${status}" 
             data-search-text="${searchText.replace(/"/g, '&quot;')}"
             data-title="${assertion.title.replace(/"/g, '&quot;')}">
          <div class="test-case-title">${icon} ${assertion.title}</div>
          <div class="test-case-duration">Duration: ${duration}</div>
          ${assertion.failureMessages && assertion.failureMessages.length > 0 ? 
            `<div class="failure-message">${assertion.failureMessages.join('\n\n')}</div>` : ''}
        </div>
      `;
    });
    
    html += '</div></div>';
  }
  
  html += '</div>';
  return html;
}
