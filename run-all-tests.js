const { execSync } = require('child_process');

const testFiles = [
  'tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js',
  'tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js',
  'tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js',
  'tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js',
  'tests/comprehensive-lifecycle/5.API-Health-Checks.test.js'
];

console.log('Starting sequential test execution...\n');

let allPassed = true;
const results = [];

testFiles.forEach((testFile, index) => {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Running Test ${index + 1}/${testFiles.length}: ${testFile}`);
  console.log('='.repeat(80) + '\n');
  
  try {
    execSync(`npx jest ${testFile} --config=jest.config.js`, {
      stdio: 'inherit',
      encoding: 'utf-8'
    });
    results.push({ file: testFile, status: 'PASSED' });
    console.log(`\n✅ Test ${index + 1} PASSED\n`);
  } catch (error) {
    results.push({ file: testFile, status: 'FAILED' });
    allPassed = false;
    console.log(`\n❌ Test ${index + 1} FAILED\n`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('TEST EXECUTION SUMMARY');
console.log('='.repeat(80));
results.forEach((result, index) => {
  const icon = result.status === 'PASSED' ? '✅' : '❌';
  console.log(`${icon} Test ${index + 1}: ${result.status} - ${result.file}`);
});
console.log('='.repeat(80) + '\n');

process.exit(allPassed ? 0 : 1);
