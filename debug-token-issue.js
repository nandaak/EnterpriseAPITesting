import fs from "fs";
import path from "path";

function diagnoseTokenIssue() {
  console.log("🔍 DIAGNOSING TOKEN ISSUE\n");

  const tokenFilePath = path.join(process.cwd(), "token.txt");

  // Check token file
  console.log("📁 TOKEN FILE ANALYSIS:");
  if (fs.existsSync(tokenFilePath)) {
    const fileContent = fs.readFileSync(tokenFilePath, "utf8").trim();
    console.log(`   File exists: ✅`);
    console.log(`   Content length: ${fileContent.length} characters`);
    console.log(
      `   Starts with "Bearer": ${
        fileContent.startsWith("Bearer ") ? "✅ YES" : "❌ NO"
      }`
    );
    console.log(`   First 50 chars: ${fileContent.substring(0, 50)}`);
    console.log(
      `   Last 30 chars: ${fileContent.substring(fileContent.length - 30)}`
    );
  } else {
    console.log("   File exists: ❌ NO");
  }

  // Check environment
  console.log("\n🌐 ENVIRONMENT ANALYSIS:");
  console.log(
    `   TOKEN env: ${
      process.env.TOKEN
        ? `PRESENT (${process.env.TOKEN.length} chars)`
        : "MISSING"
    }`
  );
  if (process.env.TOKEN) {
    console.log(
      `   TOKEN starts with "Bearer": ${
        process.env.TOKEN.startsWith("Bearer ") ? "✅ YES" : "❌ NO"
      }`
    );
  }

  // Simulate what API config does
  console.log("\n🔧 API CONFIG SIMULATION:");
  let rawToken = fs.existsSync(tokenFilePath)
    ? fs.readFileSync(tokenFilePath, "utf8").trim()
    : "";
  console.log(`   Raw token from file: ${rawToken.substring(0, 30)}...`);

  let authorizationHeader = "";
  if (rawToken) {
    if (rawToken.startsWith("Bearer ")) {
      authorizationHeader = rawToken;
    } else {
      authorizationHeader = `Bearer ${rawToken}`;
    }
  }
  console.log(
    `   Final Authorization header: ${authorizationHeader.substring(0, 40)}...`
  );
  console.log(`   Header length: ${authorizationHeader.length}`);
  console.log(
    `   Has double "Bearer": ${
      authorizationHeader.includes("Bearer Bearer ")
        ? "❌ YES - PROBLEM!"
        : "✅ NO"
    }`
  );
}

diagnoseTokenIssue();
