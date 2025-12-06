# 🔐 Authentication & Authorization Guide

## Complete Token Management System

**Version:** 3.0  
**Date:** December 1, 2025  
**Status:** ✅ **PRODUCTION READY**

---

## 🎯 Overview

The framework includes a comprehensive authentication system with:
- ✅ Automatic token management
- ✅ Token validation and refresh
- ✅ JWT token handling
- ✅ API client integration
- ✅ Comprehensive diagnostics

---

## 🔧 Components

### 1. Token Manager (`utils/token-manager.js`)

**Purpose:** Manages authentication tokens with automatic validation and refresh

**Key Features:**
- Read token from file
- Validate JWT tokens
- Auto-refresh expired tokens
- Token expiration monitoring
- Comprehensive diagnostics

### 2. API Client (`utils/api-client.js`)

**Purpose:** HTTP client with built-in authentication

**Key Features:**
- Automatic token injection
- Request/response interceptors
- Token validation logging
- Error handling for 401 responses

### 3. Authentication Tests (`tests/auth-validation.test.js`)

**Purpose:** Validate authentication before running tests

**Key Features:**
- Token file validation
- Token refresh testing
- API client authentication
- Comprehensive diagnostics

---

## 🚀 Quick Start

### Check Authentication Status

```bash
# Check token status
npm run debug-token-status

# Fetch new token
npm run fetch-token

# Run authentication tests
npm run test:auth
```

### Run Tests with Authentication

```bash
# Run auth validation + enhanced tests
npm run test:with:auth

# Run enhanced tests (auth auto-validated)
npm run test:enhanced
```

---

## 📊 Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Suite Starts                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Token Manager: Get Valid Token                  │
│  1. Check if token.txt exists                               │
│  2. Read token from file                                    │
│  3. Validate JWT format                                     │
│  4. Check expiration                                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
                  Token Valid?
                       │
        ┌──────────────┴──────────────┐
        │                             │
       Yes                           No
        │                             │
        ▼                             ▼
┌──────────────┐            ┌──────────────────┐
│  Use Token   │            │  Refresh Token   │
│              │            │  (fetchToken.js) │
└──────┬───────┘            └────────┬─────────┘
       │                             │
       │                             ▼
       │                    ┌──────────────────┐
       │                    │  Save New Token  │
       │                    │  to token.txt    │
       │                    └────────┬─────────┘
       │                             │
       └─────────────┬───────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              API Client: Inject Token                        │
│  Authorization: Bearer <token>                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Make API Request                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
                  Response 200?
                       │
        ┌──────────────┴──────────────┐
        │                             │
       Yes                           No (401)
        │                             │
        ▼                             ▼
┌──────────────┐            ┌──────────────────┐
│   Success    │            │  Token Invalid   │
│              │            │  Refresh & Retry │
└──────────────┘            └──────────────────┘
```

---

## 💡 Usage Examples

### Example 1: Manual Token Management

```javascript
const TokenManager = require('./utils/token-manager');

// Get valid token (auto-refresh if needed)
const token = await TokenManager.getValidToken();

// Check token status
const status = TokenManager.checkTokenStatus();
console.log(status);
// {
//   exists: true,
//   valid: true,
//   expiresIn: '45 minutes',
//   message: 'Token valid for 45 minutes'
// }

// Validate and refresh if needed
const result = await TokenManager.validateAndRefreshTokenWithStatus();
console.log(result);
// {
//   success: true,
//   refreshed: false,
//   message: 'Token is valid for 45 minutes',
//   tokenInfo: { ... }
// }
```

### Example 2: API Client with Authentication

```javascript
const apiClient = require('./utils/api-client');

// API client automatically uses token from TokenManager
const response = await apiClient.get('/erp-apis/Company/GetFirstCompany');

// Check if client is ready
console.log(apiClient.isReady()); // true

// Get token status
console.log(apiClient.getTokenStatus());
// {
//   hasToken: true,
//   tokenLength: 850,
//   tokenPreview: 'eyJhbGciOiJIUzI1NiIs...',
//   isReady: true
// }
```

### Example 3: Test Suite with Authentication

```javascript
describe('My Test Suite', () => {
  
  beforeAll(async () => {
    // Validate authentication before tests
    const tokenStatus = await TokenManager.validateAndRefreshTokenWithStatus();
    
    if (!tokenStatus.success) {
      throw new Error(`Authentication failed: ${tokenStatus.message}`);
    }
    
    console.log(`✅ Authentication successful: ${tokenStatus.message}`);
  });

  test('should make authenticated request', async () => {
    const response = await apiClient.get('/erp-apis/Bank');
    expect(response.status).toBe(200);
  });
});
```

---

## 🔍 Token Validation

### JWT Token Structure

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
│                                   │                                                                                                                    │
│          Header                   │                                      Payload                                                                        │                Signature
```

### Validation Checks

1. **Format Check** - Must be valid JWT (3 parts separated by dots)
2. **Expiration Check** - Token must not be expired
3. **Length Check** - Token must be > 100 characters
4. **Signature Check** - JWT signature validation

---

## 📊 Token Lifecycle

### Token States

| State | Description | Action |
|-------|-------------|--------|
| **Valid** | Token exists and not expired | Use token |
| **Expiring Soon** | < 5 minutes until expiration | Auto-refresh |
| **Expired** | Token has expired | Refresh required |
| **Missing** | No token file | Fetch new token |
| **Invalid** | Malformed or corrupted | Fetch new token |

### Auto-Refresh Triggers

- Token expires in < 5 minutes
- Token is expired
- Token validation fails
- 401 response from API

---

## 🛠️ Configuration

### Environment Variables (`.env`)

```properties
# Authentication
LOGIN_URL=https://happytesting.microtecdev.com:2050/erp/login
USEREMAIL=ot369268@gmail.com
PASSWORD=adomin0123

# API Configuration
API_BASE_URL=https://microtecsaudi.com:2032
ENDPOINT=https://microtecsaudi.com:2032
```

### Token Storage

**File:** `token.txt` (root directory)

**Format:** Plain JWT token (no "Bearer " prefix)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 🔧 Troubleshooting

### Issue 1: Token Not Found

**Symptoms:**
```
⚠️ Token file not found at: /path/to/token.txt
```

**Solution:**
```bash
npm run fetch-token
```

### Issue 2: Token Expired

**Symptoms:**
```
⚠️ Token is invalid: Token has expired
```

**Solution:**
```bash
# Auto-refresh
npm run test:auth

# Or manual refresh
npm run fetch-token
```

### Issue 3: 401 Unauthorized

**Symptoms:**
```
🔐 AUTH FAILED (401) for: /erp-apis/Bank
```

**Solution:**
```bash
# Check token status
npm run debug-token-status

# Refresh token
npm run fetch-token

# Validate
npm run test:auth
```

### Issue 4: Token Too Short

**Symptoms:**
```
⚠️ Warning: Token appears short (50 chars)
```

**Solution:**
```bash
# Delete corrupted token
rm token.txt

# Fetch new token
npm run fetch-token
```

---

## 📈 Diagnostics

### Check Token Status

```bash
npm run debug-token-status
```

**Output:**
```
🔐 Token Status:
   Exists: true
   Valid: true
   Expires in: 45 minutes
   Message: Token valid for 45 minutes
```

### Run Authentication Tests

```bash
npm run test:auth --verbose
```

**Output:**
```
Authentication Validation Suite
  Token Management
    ✓ should have valid token file (234ms)
    ✓ should validate and refresh token if needed (156ms)
    ✓ should get valid token (89ms)
    ✓ should format token for header correctly (12ms)
    ✓ should get token info (8ms)
  API Client Authentication
    ✓ should have API client configured (5ms)
    ✓ should have authorization header in API client (7ms)
    ✓ should test token validity with API call (567ms)
  Authentication Diagnostics
    ✓ should provide comprehensive token diagnostics (45ms)

Tests: 9 passed, 9 total
```

---

## 🎯 Best Practices

### 1. Always Validate Before Tests

```javascript
beforeAll(async () => {
  await TokenManager.validateAndRefreshTokenWithStatus();
});
```

### 2. Handle 401 Responses

```javascript
try {
  const response = await apiClient.get(url);
} catch (error) {
  if (error.response?.status === 401) {
    await TokenManager.refreshToken();
    // Retry request
  }
}
```

### 3. Monitor Token Expiration

```javascript
const status = TokenManager.checkTokenStatus();
if (status.expiresIn < '10 minutes') {
  await TokenManager.refreshToken();
}
```

### 4. Use Comprehensive Validation

```javascript
const result = await TokenManager.validateAndRefreshTokenWithStatus();
console.log(result.message);
console.log(result.tokenInfo);
```

---

## 📚 API Reference

### TokenManager Methods

```javascript
// Get valid token (auto-refresh if needed)
await TokenManager.getValidToken()

// Check token status (no refresh)
TokenManager.checkTokenStatus()

// Validate and refresh if needed
await TokenManager.validateAndRefreshToken()

// Comprehensive validation with status
await TokenManager.validateAndRefreshTokenWithStatus()

// Manual refresh
await TokenManager.refreshToken()

// Get token info
TokenManager.getTokenInfo()

// Format for HTTP header
TokenManager.formatTokenForHeader(token)

// Read from file
TokenManager.readTokenFromFile()

// Save to file
TokenManager.saveTokenToFile(token)

// Validate JWT
TokenManager.validateToken(token)
```

### API Client Methods

```javascript
// Check if ready
apiClient.isReady()

// Get token status
apiClient.getTokenStatus()

// Test token validity
await apiClient.testTokenValidity()

// HTTP methods (auto-authenticated)
await apiClient.get(url)
await apiClient.post(url, data)
await apiClient.put(url, data)
await apiClient.delete(url)
```

---

## 🎉 Summary

### What You Have

✅ **Automatic Token Management** - No manual intervention  
✅ **JWT Validation** - Complete token validation  
✅ **Auto-Refresh** - Tokens refresh automatically  
✅ **API Integration** - Seamless authentication  
✅ **Comprehensive Tests** - Full auth validation  
✅ **Diagnostics** - Detailed status information  

### Commands Summary

```bash
# Authentication
npm run fetch-token          # Fetch new token
npm run debug-token-status   # Check status
npm run test:auth            # Validate auth

# Testing with Auth
npm run test:with:auth       # Auth + tests
npm run test:enhanced        # Auto-validates
```

---

**Your authentication system is complete and production-ready!** 🔐✅

---

**Generated:** December 1, 2025  
**Version:** 3.0  
**Status:** Production Ready
