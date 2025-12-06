const fs = require('fs');
const path = require('path');

/**
 * REFACTORING VERIFICATION SCRIPT
 * 
 * Verifies that all old schema keys have been replaced with new semantic keys
 */

console.log('\n' + '█'.repeat(80));
console.log('  REFACTORING VERIFICATION TOOL');
console.log('  Checking for Old Schema Key References');
console.log('█'.repeat(80) + '\n');

// Patterns to check for (old keys that should not exist)
const OLD_PATTERNS = [
  { pattern: /moduleConfig\.Post(?![a-zA-Z])/g, name: 'moduleConfig.Post' },
  { pattern: /moduleConfig\["Post"\]/g, name: 'moduleConfig["Post"]' },
  { pattern: /moduleConfig\['Post'\]/g, name: "moduleConfig['Post']" },
  { pattern: /operationKey = ["']Post["']/g, name: 'operationKey = "Post"' },
  { pattern: /operationType === ["']Post["']/g, name: 'operationType === "Post"' },
];

// Files to check
const filesToCheck = [
  'tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js',
  'tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js',
  'tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js',
  'tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js',
  'tests/comprehensive-lifecycle/5.API-Health-Checks.test.js',
  'utils/crud-lifecycle-helper.js',
  'utils/helper.js',
  'utils/test-helpers.js',
  'utils/security-helpers.js',
  'utils/performance-helpers.js',
];

let totalIssues = 0;
const issuesByFile = {};

console.log('Checking files for old schema key references...\n');

filesToCheck.forEach(filePath => {
  const fullPath = path.join(__dirname, filePath);
  
  if (!fs.existsSync(fullPath)) {
    console.log(`⚠️  File not found: ${filePath}`);
    return;
  }
  
  const content = fs.readFileSync(fullPath, 'utf8');
  const fileIssues = [];
  
  OLD_PATTERNS.forEach(({ pattern, name }) => {
    const matches = content.match(pattern);
    if (matches) {
      fileIssues.push({
        pattern: name,
        count: matches.length,
        matches: matches
      });
      totalIssues += matches.length;
    }
  });
  
  if (fileIssues.length > 0) {
    issuesByFile[filePath] = fileIssues;
    console.log(`❌ ${path.basename(filePath)}: ${fileIssues.length} issue(s) found`);
    fileIssues.forEach(issue => {
      console.log(`   - ${issue.pattern}: ${issue.count} occurrence(s)`);
    });
  } else {
    console.log(`✅ ${path.basename(filePath)}: Clean`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('VERIFICATION SUMMARY');
console.log('='.repeat(80) + '\n');

if (totalIssues === 0) {
  console.log('✅ SUCCESS: All files have been properly refactored!');
  console.log('   No old schema key references found.');
  console.log('\n🎉 All test files are ready to use with new semantic keys!\n');
} else {
  console.log(`❌ ISSUES FOUND: ${totalIssues} old key reference(s) detected`);
  console.log(`   Files with issues: ${Object.keys(issuesByFile).length}`);
  console.log('\n📋 Detailed Issues:\n');
  
  Object.entries(issuesByFile).forEach(([file, issues]) => {
    console.log(`File: ${file}`);
    issues.forEach(issue => {
      console.log(`  - ${issue.pattern}: ${issue.count} occurrence(s)`);
      issue.matches.forEach((match, idx) => {
        console.log(`    ${idx + 1}. "${match}"`);
      });
    });
    console.log('');
  });
  
  console.log('⚠️  Please review and fix the issues above.\n');
}

// Save verification report
const report = {
  timestamp: new Date().toISOString(),
  totalFilesChecked: filesToCheck.length,
  totalIssues,
  filesWithIssues: Object.keys(issuesByFile).length,
  issuesByFile,
  status: totalIssues === 0 ? 'PASS' : 'FAIL'
};

fs.writeFileSync(
  path.join(__dirname, 'refactoring-verification-report.json'),
  JSON.stringify(report, null, 2),
  'utf8'
);

console.log('📄 Verification report saved to: refactoring-verification-report.json\n');

process.exit(totalIssues === 0 ? 0 : 1);
