const TokenManager = require("./utils/token-manager");
const logger = require("./utils/logger");

async function debugTokenStatus() {
  console.log("🔐 TOKEN STATUS DEBUG INFORMATION\n");

  // Basic token info
  const tokenInfo = TokenManager.getTokenInfo();
  console.log("📄 BASIC TOKEN INFO:");
  console.log(JSON.stringify(tokenInfo, null, 2));

  console.log("\n🔄 VALIDATION AND REFRESH TEST:");
  const validationResult =
    await TokenManager.validateAndRefreshTokenWithStatus();
  console.log(JSON.stringify(validationResult, null, 2));

  console.log("\n📋 QUICK STATUS CHECK:");
  const quickStatus = TokenManager.checkTokenStatus();
  console.log(JSON.stringify(quickStatus, null, 2));

  console.log("\n🔧 TROUBLESHOOTING INFO:");
  console.log(`   Token file: ${TokenManager.getTokenFilePath()}`);
  console.log(
    `   File exists: ${require("fs").existsSync(
      TokenManager.getTokenFilePath()
    )}`
  );
  console.log(`   TOKEN env: ${process.env.TOKEN ? "PRESENT" : "MISSING"}`);

  if (validationResult.success) {
    console.log("\n✅ TOKEN STATUS: HEALTHY");
  } else {
    console.log("\n❌ TOKEN STATUS: ISSUES DETECTED");
    console.log(`   Issue: ${validationResult.message}`);
  }
}

debugTokenStatus().catch(console.error);
