// utils/token-validator.js - Professional Token Validation and Auto-Refresh System
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

/**
 * TokenValidator - Robust token management for test suites
 * 
 * Features:
 * - Automatic token validation before test execution
 * - Auto-refresh expired or invalid tokens
 * - Comprehensive error handling and logging
 * - Integration with existing token.txt file
 * 
 * @class TokenValidator
 */
class TokenValidator {
  constructor() {
    this.tokenPath = path.join(process.cwd(), 'token.txt');
    this.minValidityMinutes = 5; // Refresh if less than 5 minutes remaining
  }

  /**
   * Read token from token.txt file
   * @returns {string|null} Clean token without quotes or newlines
   */
  readToken() {
    try {
      if (!fs.existsSync(this.tokenPath)) {
        console.log('⚠️  Token file not found:', this.tokenPath);
        return null;
      }

      const rawToken = fs.readFileSync(this.tokenPath, 'utf8');
      const cleanToken = rawToken
        .replace(/[\r\n"']/g, '')
        .replace(/^Bearer\s+/i, '')
        .trim();

      if (!cleanToken) {
        console.log('⚠️  Token file is empty');
        return null;
      }

      return cleanToken;
    } catch (error) {
      console.error(`❌ Error reading token: ${error.message}`);
      return null;
    }
  }

  /**
   * Save token to token.txt file
   * @param {string} token - Token to save (will be cleaned)
   * @returns {boolean} Success status
   */
  saveToken(token) {
    try {
      const cleanToken = token
        .replace(/[\r\n"']/g, '')
        .replace(/^Bearer\s+/i, '')
        .trim();

      fs.writeFileSync(this.tokenPath, cleanToken, 'utf8');
      
      // Verify write
      const verification = fs.readFileSync(this.tokenPath, 'utf8').trim();
      if (verification !== cleanToken) {
        throw new Error('Token verification failed after write');
      }

      console.log(`✅ Token saved successfully (${cleanToken.length} characters)`);
      return true;
    } catch (error) {
      console.error(`❌ Error saving token: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate JWT token structure and expiration
   * @param {string} token - JWT token to validate
   * @returns {Object} Validation result with details
   */
  validateToken(token) {
    if (!token) {
      return {
        valid: false,
        reason: 'Token is empty or null',
        expired: false,
        minutesRemaining: 0
      };
    }

    try {
      // Check JWT structure
      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          valid: false,
          reason: 'Invalid JWT structure (expected 3 parts)',
          expired: false,
          minutesRemaining: 0
        };
      }

      // Decode payload
      const base64Url = parts[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(Buffer.from(base64, 'base64').toString());

      // Check expiration
      if (!payload.exp) {
        return {
          valid: false,
          reason: 'Token has no expiration claim',
          expired: false,
          minutesRemaining: 0
        };
      }

      const expiresAt = new Date(payload.exp * 1000);
      const now = new Date();
      const millisecondsRemaining = expiresAt - now;
      const minutesRemaining = Math.round(millisecondsRemaining / (1000 * 60));

      if (minutesRemaining < 0) {
        return {
          valid: false,
          reason: 'Token has expired',
          expired: true,
          minutesRemaining: minutesRemaining,
          expiresAt: expiresAt.toISOString()
        };
      }

      if (minutesRemaining < this.minValidityMinutes) {
        return {
          valid: false,
          reason: `Token expires soon (${minutesRemaining} minutes remaining)`,
          expired: false,
          minutesRemaining: minutesRemaining,
          expiresAt: expiresAt.toISOString()
        };
      }

      return {
        valid: true,
        reason: 'Token is valid',
        expired: false,
        minutesRemaining: minutesRemaining,
        expiresAt: expiresAt.toISOString(),
        payload: payload
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Token validation error: ${error.message}`,
        expired: false,
        minutesRemaining: 0
      };
    }
  }

  /**
   * Fetch new token using fetchToken.js script
   * @returns {Promise<string>} New token
   */
  async fetchNewToken() {
    console.log('🔄 Fetching new token from authentication server...');
    
    try {
      const { stdout, stderr } = await execAsync('node fetchToken.js', {
        cwd: process.cwd(),
        timeout: 60000 // 60 second timeout
      });

      // Log output for debugging (filter out dotenv warnings)
      if (stderr && !stderr.includes('dotenv')) {
        console.log('⚠️  Fetch stderr:', stderr);
      }

      // Read the token that was saved by fetchToken.js
      const token = this.readToken();

      if (!token) {
        throw new Error('Token file is empty after fetch operation');
      }

      // Validate the new token
      const validation = this.validateToken(token);
      if (!validation.valid) {
        throw new Error(`Fetched token is invalid: ${validation.reason}`);
      }

      console.log(`✅ New token fetched successfully (valid for ${validation.minutesRemaining} minutes)`);
      return token;
    } catch (error) {
      throw new Error(`Failed to fetch new token: ${error.message}`);
    }
  }

  /**
   * Ensure a valid token exists - main entry point
   * @returns {Promise<Object>} Token validation result
   */
  async ensureValidToken() {
    console.log('\n' + '='.repeat(70));
    console.log('🔐 TOKEN VALIDATION AND AUTO-REFRESH SYSTEM');
    console.log('='.repeat(70));
    console.log(`📁 Token file: ${this.tokenPath}`);
    console.log(`⏱️  Minimum validity: ${this.minValidityMinutes} minutes\n`);

    try {
      // Step 1: Check if token file exists
      let token = this.readToken();

      if (!token) {
        console.log('❌ No token file found or file is empty');
        console.log('🔄 Fetching new token...\n');
        
        token = await this.fetchNewToken();
        const validation = this.validateToken(token);

        console.log('\n✅ TOKEN READY');
        console.log(`   Status: NEW TOKEN FETCHED`);
        console.log(`   Valid for: ${validation.minutesRemaining} minutes`);
        console.log(`   Expires at: ${new Date(validation.expiresAt).toLocaleString()}`);
        console.log('='.repeat(70) + '\n');

        return {
          success: true,
          token: token,
          refreshed: true,
          validation: validation
        };
      }

      // Step 2: Validate existing token
      console.log(`📄 Token file found (${token.length} characters)`);
      const validation = this.validateToken(token);

      console.log(`🔍 Validation: ${validation.reason}`);
      if (validation.minutesRemaining > 0) {
        console.log(`⏰ Time remaining: ${validation.minutesRemaining} minutes`);
      }

      if (!validation.valid) {
        console.log(`\n❌ Token is ${validation.expired ? 'EXPIRED' : 'INVALID'}`);
        console.log('🔄 Fetching new token...\n');

        token = await this.fetchNewToken();
        const newValidation = this.validateToken(token);

        console.log('\n✅ TOKEN READY');
        console.log(`   Status: TOKEN REFRESHED`);
        console.log(`   Valid for: ${newValidation.minutesRemaining} minutes`);
        console.log(`   Expires at: ${new Date(newValidation.expiresAt).toLocaleString()}`);
        console.log('='.repeat(70) + '\n');

        return {
          success: true,
          token: token,
          refreshed: true,
          validation: newValidation
        };
      }

      // Step 3: Token is valid
      console.log('\n✅ TOKEN READY');
      console.log(`   Status: EXISTING TOKEN VALID`);
      console.log(`   Valid for: ${validation.minutesRemaining} minutes`);
      console.log(`   Expires at: ${new Date(validation.expiresAt).toLocaleString()}`);
      console.log('='.repeat(70) + '\n');

      return {
        success: true,
        token: token,
        refreshed: false,
        validation: validation
      };

    } catch (error) {
      console.error('\n' + '='.repeat(70));
      console.error('❌ TOKEN VALIDATION FAILED');
      console.error('='.repeat(70));
      console.error(`Error: ${error.message}\n`);
      console.error('💡 Troubleshooting steps:');
      console.error('   1. Check your internet connection');
      console.error('   2. Verify credentials in .env file');
      console.error('   3. Ensure fetchToken.js is working: node fetchToken.js');
      console.error('   4. Check if authentication server is accessible');
      console.error('='.repeat(70) + '\n');

      return {
        success: false,
        token: null,
        refreshed: false,
        error: error.message
      };
    }
  }

  /**
   * Quick token status check (no refresh)
   * @returns {Object} Token status
   */
  getTokenStatus() {
    const token = this.readToken();
    
    if (!token) {
      return {
        exists: false,
        valid: false,
        message: 'No token file found'
      };
    }

    const validation = this.validateToken(token);

    return {
      exists: true,
      valid: validation.valid,
      expired: validation.expired,
      minutesRemaining: validation.minutesRemaining,
      expiresAt: validation.expiresAt,
      message: validation.reason,
      tokenLength: token.length
    };
  }
}

// Export singleton instance
const tokenValidator = new TokenValidator();

module.exports = tokenValidator;
module.exports.TokenValidator = TokenValidator;
