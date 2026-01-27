#!/usr/bin/env node
// validate-token.js - Standalone token validation script
const tokenValidator = require('./utils/token-validator');

/**
 * Standalone Token Validation Script
 * 
 * Usage:
 *   node validate-token.js           - Validate and auto-refresh if needed
 *   node validate-token.js --status  - Check status only (no refresh)
 *   node validate-token.js --force   - Force refresh even if valid
 */

async function main() {
  const args = process.argv.slice(2);
  const statusOnly = args.includes('--status');
  const forceRefresh = args.includes('--force');

  try {
    if (statusOnly) {
      // Status check only
      console.log('\n🔍 TOKEN STATUS CHECK (No Refresh)\n');
      console.log('='.repeat(70));
      
      const status = tokenValidator.getTokenStatus();
      
      console.log(`📁 Token file: ${tokenValidator.tokenPath}`);
      console.log(`📄 Exists: ${status.exists ? '✅ YES' : '❌ NO'}`);
      
      if (status.exists) {
        console.log(`🔐 Token length: ${status.tokenLength} characters`);
        console.log(`✓  Valid: ${status.valid ? '✅ YES' : '❌ NO'}`);
        console.log(`⏰ Status: ${status.message}`);
        
        if (status.valid) {
          console.log(`⏱️  Time remaining: ${status.minutesRemaining} minutes`);
          console.log(`📅 Expires at: ${new Date(status.expiresAt).toLocaleString()}`);
        }
      }
      
      console.log('='.repeat(70) + '\n');
      
      process.exit(status.valid ? 0 : 1);
    } else if (forceRefresh) {
      // Force refresh
      console.log('\n🔄 FORCE TOKEN REFRESH\n');
      console.log('='.repeat(70));
      
      const token = await tokenValidator.fetchNewToken();
      const validation = tokenValidator.validateToken(token);
      
      console.log('\n✅ TOKEN REFRESHED');
      console.log(`   Valid for: ${validation.minutesRemaining} minutes`);
      console.log(`   Expires at: ${new Date(validation.expiresAt).toLocaleString()}`);
      console.log('='.repeat(70) + '\n');
      
      process.exit(0);
    } else {
      // Normal validation with auto-refresh
      const result = await tokenValidator.ensureValidToken();
      
      if (!result.success) {
        console.error('❌ Token validation failed');
        process.exit(1);
      }
      
      process.exit(0);
    }
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}\n`);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = main;
