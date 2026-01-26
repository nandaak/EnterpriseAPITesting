// test-token-loading.js - Test if token is properly loaded in API client
const apiClient = require('./utils/api-client');
const TokenManager = require('./utils/token-manager');
const apiConfig = require('./config/api-config');

console.log('\n🔍 Testing Token Loading in API Client\n');
console.log('='.repeat(60));

// 1. Check token file
console.log('\n1️⃣ Token File Status:');
const tokenInfo = TokenManager.getTokenInfo();
console.log(`   Exists: ${tokenInfo.exists ? '✅' : '❌'}`);
console.log(`   Valid: ${tokenInfo.isValid ? '✅' : '❌'}`);
console.log(`   Length: ${tokenInfo.length || 0} characters`);
if (tokenInfo.expiresAt) {
  console.log(`   Expires: ${tokenInfo.expiresAt}`);
}

// 2. Check API config
console.log('\n2️⃣ API Config Status:');
console.log(`   Base URL: ${apiConfig.baseURL}`);
console.log(`   Has Auth Header: ${apiConfig.headers?.Authorization ? '✅' : '❌'}`);
if (apiConfig.headers?.Authorization) {
  const authHeader = apiConfig.headers.Authorization;
  console.log(`   Auth Header Length: ${authHeader.length} characters`);
  console.log(`   Starts with Bearer: ${authHeader.startsWith('Bearer ') ? '✅' : '❌'}`);
  console.log(`   Preview: ${authHeader.substring(0, 30)}...`);
}
console.log(`   Token Info:`, apiConfig.tokenInfo);

// 3. Check API client instance
console.log('\n3️⃣ API Client Instance Status:');
const clientStatus = apiClient.getTokenStatus();
console.log(`   Has Token: ${clientStatus.hasToken ? '✅' : '❌'}`);
console.log(`   Token Length: ${clientStatus.tokenLength} characters`);
console.log(`   Is Ready: ${clientStatus.isReady ? '✅' : '❌'}`);
console.log(`   Preview: ${clientStatus.tokenPreview}`);

// 4. Check actual headers in axios instance
console.log('\n4️⃣ Axios Instance Headers:');
const axiosHeaders = apiClient.client?.defaults?.headers;
if (axiosHeaders) {
  console.log(`   Common Headers:`, axiosHeaders.common);
  console.log(`   Authorization in common: ${axiosHeaders.common?.Authorization ? '✅' : '❌'}`);
  console.log(`   Authorization direct: ${axiosHeaders.Authorization ? '✅' : '❌'}`);
  
  const authHeader = axiosHeaders.Authorization || axiosHeaders.common?.Authorization;
  if (authHeader) {
    console.log(`   Actual Auth Header Length: ${authHeader.length}`);
    console.log(`   Actual Preview: ${authHeader.substring(0, 30)}...`);
  }
}

console.log('\n' + '='.repeat(60));
console.log('\n✅ Token loading test complete\n');
