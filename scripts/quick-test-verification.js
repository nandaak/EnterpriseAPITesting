/**
 * Quick Test Verification
 * Tests a few enhanced modules to verify improvements
 */

const { execSync } = require('child_process');

const testModules = [
  'DiscountPolicy',
  'Treasury',
  'CustomerCategory',
  'Tag',
  'CostCenter'
];

console.log('🧪 Quick Test Verification\n');
console.log('='.repeat(70));
console.log('\nTesting enhanced modules to verify improvements...\n');

const results = [];

for (const module of testModules) {
  process.stdout.write(`📦 Testing ${module.padEnd(25)} `);
  
  try {
    const output = execSync(
      `npm test -- tests/generated-modules/${module}.test.js --testNamePattern="CREATE" --silent`,
      { encoding: 'utf8', timeout: 60000 }
    );
    
    if (output.includes('PASS') || output.includes('1 passed')) {
      console.log('✅ PASSED');
      results.push({ module, status: 'PASSED' });
    } else if (output.includes('FAIL')) {
      console.log('❌ FAILED');
      results.push({ module, status: 'FAILED' });
    } else {
      console.log('⚠️  UNKNOWN');
      results.push({ module, status: 'UNKNOWN' });
    }
  } catch (error) {
    if (error.stdout && error.stdout.includes('500')) {
      console.log('❌ FAILED (500 error)');
      results.push({ module, status: 'FAILED_500' });
    } else if (error.stdout && error.stdout.includes('400')) {
      console.log('❌ FAILED (400 error)');
      results.push({ module, status: 'FAILED_400' });
    } else {
      console.log('❌ FAILED (error)');
      results.push({ module, status: 'FAILED_ERROR' });
    }
  }
}

console.log('\n' + '='.repeat(70));
console.log('\n📊 Verification Summary:\n');

const passed = results.filter(r => r.status === 'PASSED').length;
const failed = results.filter(r => r.status.includes('FAILED')).length;

console.log(`   ✅ Passed: ${passed}/${testModules.length}`);
console.log(`   ❌ Failed: ${failed}/${testModules.length}`);

if (passed > 0) {
  console.log('\n✨ Schema enhancement is working! Some tests are now passing.');
} else {
  console.log('\n⚠️  Tests may need additional API-specific adjustments.');
  console.log('   Check API logs for specific validation requirements.');
}

console.log('\n' + '='.repeat(70) + '\n');
