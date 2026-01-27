// jest.globalSetup.js - Global setup for all Jest test suites
const tokenValidator = require('./utils/token-validator');

/**
 * Jest Global Setup
 * 
 * This runs ONCE before all test suites execute.
 * Ensures a valid authentication token exists before any tests run.
 * 
 * If the token is expired or invalid, it will automatically fetch a new one.
 */
module.exports = async () => {
  console.log('\n🚀 JEST GLOBAL SETUP - Pre-Test Token Validation\n');

  try {
    const result = await tokenValidator.ensureValidToken();

    if (!result.success) {
      console.error('❌ CRITICAL: Token validation failed');
      console.error('   Tests cannot proceed without a valid token');
      throw new Error(`Token validation failed: ${result.error}`);
    }

    if (result.refreshed) {
      console.log('✅ Token was refreshed - all tests will use the new token');
    } else {
      console.log('✅ Existing token is valid - tests can proceed');
    }

    console.log(`🔐 Token valid for ${result.validation.minutesRemaining} minutes`);
    console.log('🎯 All test suites will use this validated token\n');

  } catch (error) {
    console.error('\n❌ FATAL ERROR: Cannot start tests without valid token');
    console.error(`   ${error.message}\n`);
    process.exit(1); // Exit with error code to prevent tests from running
  }
};
