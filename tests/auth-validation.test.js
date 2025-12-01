/**
 * Authentication Validation Test Suite
 * Ensures proper authentication before running main tests
 * 
 * Features:
 * - Token validation
 * - Token refresh
 * - API client authentication
 * - Comprehensive diagnostics
 */

const TokenManager = require('../utils/token-manager');
const apiClient = require('../utils/api-client');
const logger = require('../utils/logger');

describe('Authentication Validation Suite', () => {
  
  describe('Token Management', () => {
    
    test('should have valid token file', async () => {
      logger.info('🔐 Checking token file...');
      
      const tokenStatus = TokenManager.checkTokenStatus();
      
      expect(tokenStatus.exists).toBe(true);
      logger.info(`✅ Token file exists: ${tokenStatus.exists}`);
      
      if (!tokenStatus.valid) {
        logger.warn(`⚠️  Token invalid: ${tokenStatus.message}`);
        logger.info('🔄 Attempting to refresh token...');
        
        await TokenManager.refreshToken();
        
        const newStatus = TokenManager.checkTokenStatus();
        expect(newStatus.valid).toBe(true);
        logger.info(`✅ Token refreshed successfully`);
      } else {
        logger.info(`✅ Token is valid: ${tokenStatus.message}`);
      }
    }, 30000);

    test('should validate and refresh token if needed', async () => {
      logger.info('🔐 Validating token with auto-refresh...');
      
      const result = await TokenManager.validateAndRefreshTokenWithStatus();
      
      expect(result.success).toBe(true);
      
      logger.info(`✅ Token validation result: ${result.message}`);
      logger.info(`   Refreshed: ${result.refreshed ? 'Yes' : 'No'}`);
      
      if (result.tokenInfo) {
        logger.info(`   Token exists: ${result.tokenInfo.exists}`);
        logger.info(`   Token valid: ${result.tokenInfo.isValid}`);
        
        if (result.tokenInfo.expiresAt) {
          logger.info(`   Expires at: ${result.tokenInfo.expiresAt}`);
        }
      }
    }, 30000);

    test('should get valid token', async () => {
      logger.info('🔐 Getting valid token...');
      
      const token = await TokenManager.getValidToken();
      
      expect(token).toBeDefined();
      expect(token).not.toBeNull();
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(100);
      
      logger.info(`✅ Valid token obtained (length: ${token.length})`);
      
      // Verify token format
      const parts = token.split('.');
      expect(parts.length).toBe(3); // JWT format
      
      logger.info(`✅ Token format is valid JWT`);
    }, 30000);

    test('should format token for header correctly', () => {
      logger.info('🔐 Testing token formatting...');
      
      const token = TokenManager.readTokenFromFile();
      expect(token).toBeDefined();
      
      const formatted = TokenManager.formatTokenForHeader(token);
      
      expect(formatted).toMatch(/^Bearer /);
      expect(formatted.length).toBeGreaterThan(token.length);
      
      logger.info(`✅ Token formatted correctly: ${formatted.substring(0, 30)}...`);
    });

    test('should get token info', () => {
      logger.info('🔐 Getting token information...');
      
      const info = TokenManager.getTokenInfo();
      
      expect(info.exists).toBe(true);
      expect(info.isValid).toBe(true);
      expect(info.length).toBeGreaterThan(100);
      
      logger.info(`✅ Token info retrieved:`);
      logger.info(`   Exists: ${info.exists}`);
      logger.info(`   Valid: ${info.isValid}`);
      logger.info(`   Length: ${info.length}`);
      logger.info(`   Source: ${info.source}`);
      
      if (info.expiresAt) {
        logger.info(`   Expires: ${info.expiresAt}`);
      }
    });
  });

  describe('API Client Authentication', () => {
    
    test('should have API client configured', () => {
      logger.info('🌐 Checking API client configuration...');
      
      expect(apiClient).toBeDefined();
      expect(apiClient.client).toBeDefined();
      
      logger.info(`✅ API client is configured`);
    });

    test('should have authorization header in API client', () => {
      logger.info('🔐 Checking API client authorization header...');
      
      const headers = apiClient.client.defaults.headers;
      const authHeader = headers.Authorization || headers.common?.Authorization;
      
      expect(authHeader).toBeDefined();
      expect(authHeader).toMatch(/^Bearer /);
      
      logger.info(`✅ Authorization header present in API client`);
      logger.info(`   Header preview: ${authHeader.substring(0, 30)}...`);
    });

    test('should test token validity with API call', async () => {
      logger.info('🔐 Testing token with actual API call...');
      
      try {
        // Test with a simple GET endpoint
        const response = await apiClient.get('/erp-apis/Company/GetFirstCompany');
        
        expect(response.status).toBe(200);
        
        logger.info(`✅ Token is valid - API call successful`);
        logger.info(`   Status: ${response.status}`);
        
      } catch (error) {
        if (error.response?.status === 401) {
          logger.error(`❌ Token authentication failed (401)`);
          logger.error(`   This indicates the token is invalid or expired`);
          
          // Try to refresh and retry
          logger.info('🔄 Attempting to refresh token...');
          await TokenManager.refreshToken();
          
          const retryResponse = await apiClient.get('/erp-apis/Company/GetFirstCompany');
          expect(retryResponse.status).toBe(200);
          
          logger.info(`✅ Token refreshed and API call successful`);
        } else {
          throw error;
        }
      }
    }, 30000);
  });

  describe('Authentication Diagnostics', () => {
    
    test('should provide comprehensive token diagnostics', async () => {
      logger.info('🔍 Running comprehensive token diagnostics...');
      
      // Check token file
      const tokenStatus = TokenManager.checkTokenStatus();
      logger.info(`📊 Token Status:`);
      logger.info(`   Exists: ${tokenStatus.exists}`);
      logger.info(`   Valid: ${tokenStatus.valid}`);
      logger.info(`   Message: ${tokenStatus.message}`);
      
      // Get token info
      const tokenInfo = TokenManager.getTokenInfo();
      logger.info(`📊 Token Info:`);
      logger.info(`   Length: ${tokenInfo.length}`);
      logger.info(`   Source: ${tokenInfo.source}`);
      logger.info(`   Valid: ${tokenInfo.isValid}`);
      
      // Check API client
      const clientStatus = apiClient.getTokenStatus();
      logger.info(`📊 API Client Status:`);
      logger.info(`   Has Token: ${clientStatus.hasToken}`);
      logger.info(`   Token Length: ${clientStatus.tokenLength}`);
      logger.info(`   Is Ready: ${clientStatus.isReady}`);
      
      // Validate everything is working
      expect(tokenStatus.valid).toBe(true);
      expect(tokenInfo.isValid).toBe(true);
      expect(clientStatus.hasToken).toBe(true);
      expect(clientStatus.isReady).toBe(true);
      
      logger.info(`✅ All authentication diagnostics passed`);
    });
  });
});
