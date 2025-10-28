// utils/test-status-verifier.js
const fs = require("fs");
const path = require("path");

class TestStatusVerifier {
  static verifyAllureResults() {
    const resultsDir = path.join(process.cwd(), "allure-results");
    if (!fs.existsSync(resultsDir)) {
      console.log("❌ No allure-results directory found");
      return;
    }

    const resultFiles = fs
      .readdirSync(resultsDir)
      .filter((file) => file.endsWith("-result.json"));
    let passed = 0;
    let failed = 0;
    let broken = 0;

    console.log("\n📊 Allure Results Verification:");
    console.log("=".repeat(50));

    resultFiles.forEach((file) => {
      const filePath = path.join(resultsDir, file);
      const result = JSON.parse(fs.readFileSync(filePath, "utf8"));

      console.log(`${result.name} - ${result.status.toUpperCase()}`);

      if (result.status === "passed") passed++;
      else if (result.status === "failed") failed++;
      else if (result.status === "broken") broken++;
    });

    console.log("=".repeat(50));
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`⚠️  Broken: ${broken}`);
    console.log(`📈 Total: ${resultFiles.length}`);

    // Verify consistency with Jest output
    if (failed > 0) {
      console.log("\n🔍 Allure report should show failed tests correctly.");
    } else {
      console.log(
        "\n⚠️  Warning: Allure shows no failed tests, but Jest reported failures."
      );
    }
  }
}

module.exports = TestStatusVerifier;
