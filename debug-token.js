// debug-token.js - Token diagnostic tool
const TokenManager = require("./utils/token-manager");
const apiClientFactory = require("./utils/api-client");

async function debugToken() {
  console.log("🔐 TOKEN DEBUG DIAGNOSTICS\n");
  
  // 1. Check token file
  const tokenPath = TokenManager.getTokenFilePath();
  console.log(`1. Token File: ${tokenPath}`);
  console.log(`   Exists: ${require("fs").existsSync(tokenPath) ? "✅ YES" : "❌ NO"}`);
  
  // 2. Read token
  const token = TokenManager.readTokenFromFile();
  console.log(`\n2. Token Reading:`);
  console.log(`   Token Present: ${token ? "✅ YES" : "❌ NO"}`);
  console.log(`   Raw Length: ${token ? token.length : 0} characters`);
  
  if (token) {
    // 3. Validate token
    const validation = TokenManager.validateToken(token);
    console.log(`\n3. Token Validation:`);
    console.log(`   Valid: ${validation.isValid ? "✅ YES" : "❌ NO"}`);
    console.log(`   Reason: ${validation.reason || "N/A"}`);
    console.log(`   Expired: ${validation.reason === "Token has expired" ? "✅ YES" : "❌ NO"}`);
    
    if (validation.expiresAt) {
      const now = new Date();
      const expiresIn = validation.expiresAt - now;
      console.log(`   Expires In: ${Math.round(expiresIn / (1000 * 60))} minutes`);
    }
    
    // 4. Format for header
    const headerToken = TokenManager.formatTokenForHeader(token);
    console.log(`\n4. Header Format:`);
    console.log(`   Formatted Length: ${headerToken.length} characters`);
    console.log(`   Has Bearer Prefix: ${headerToken.startsWith("Bearer ") ? "✅ YES" : "❌ NO"}`);
    
    // 5. Test with API
    console.log(`\n5. API Test:`);
    try {
      const client = apiClientFactory({
        headers: {
          Authorization: headerToken,
        },
      });
      
      const testResult = await client.testTokenValidity();
      console.log(`   Token Works: ${testResult ? "✅ YES" : "❌ NO"}`);
      
    } catch (error) {
      console.log(`   API Test Failed: ${error.message}`);
    }
  }
  
  console.log("\n🔍 DEBUG COMPLETE");
}

debugToken().catch(console.error);