// utils/show-failures.js
const fs = require("fs");
const path = require("path");

function analyzeFailures() {
  try {
    const resultsPath = path.join(__dirname, "../test-results.json");

    if (!fs.existsSync(resultsPath)) {
      console.log("❌ No test results found. Run tests first.");
      return;
    }

    const results = JSON.parse(fs.readFileSync(resultsPath, "utf8"));

    const failedTests = results.testResults
      .map((suite) => ({
        file: suite.name,
        failures: suite.assertionResults.filter(
          (test) => test.status === "failed"
        ),
      }))
      .filter((suite) => suite.failures.length > 0);

    if (failedTests.length === 0) {
      console.log("🎉 All tests passed!");
      return;
    }

    console.log("🚨 FAILED TESTS ANALYSIS");
    console.log("=".repeat(60));

    failedTests.forEach((suite) => {
      console.log(`\n📁 Test File: ${path.basename(suite.file)}`);
      console.log("-".repeat(40));

      suite.failures.forEach((test, index) => {
        console.log(`\n${index + 1}. ${test.title}`);
        console.log(`   ❌ Status: ${test.status}`);

        if (test.failureMessages && test.failureMessages.length > 0) {
          console.log(`   📝 Failure Message:`);
          test.failureMessages.forEach((msg) => {
            // Clean up the failure message
            const cleanMsg = msg
              .split("\n")
              .filter((line) => !line.includes("at ")) // Remove stack traces
              .slice(0, 5) // Show first 5 lines
              .join("\n     ");
            console.log(`     ${cleanMsg}`);
          });
        }
      });
    });

    const totalFailures = failedTests.reduce(
      (sum, suite) => sum + suite.failures.length,
      0
    );
    console.log(
      `\n📊 SUMMARY: ${totalFailures} failed test(s) across ${failedTests.length} file(s)`
    );
  } catch (error) {
    console.error("❌ Error analyzing failures:", error.message);
  }
}

analyzeFailures();
