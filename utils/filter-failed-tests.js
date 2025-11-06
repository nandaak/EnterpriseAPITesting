// utils/filter-failed-tests.js
const fs = require("fs");
const path = require("path");

function filterFailedTests() {
  const reportPath = path.join(__dirname, "../html-report/test-report.html");

  if (!fs.existsSync(reportPath)) {
    console.log("❌ Test report not found. Run tests first.");
    return;
  }

  let reportContent = fs.readFileSync(reportPath, "utf8");

  // Extract failed tests from report
  const failedTestsMatch = reportContent.match(
    /<div class="test failed">[\s\S]*?<\/div>/g
  );

  if (failedTestsMatch) {
    console.log("🚨 FAILED TESTS SUMMARY:");
    console.log("=".repeat(50));

    failedTestsMatch.forEach((testHtml, index) => {
      // Extract test name
      const testNameMatch = testHtml.match(
        /<div class="test-title">(.*?)<\/div>/
      );
      const testName = testNameMatch ? testNameMatch[1] : `Test ${index + 1}`;

      // Extract failure message
      const failureMatch = testHtml.match(
        /<div class="failure-msg">([\s\S]*?)<\/div>/
      );
      const failureMsg = failureMatch
        ? failureMatch[1].replace(/<br\/>/g, "\n")
        : "No failure message";

      console.log(`\n${index + 1}. ${testName}`);
      console.log(`   Failure: ${failureMsg}`);
      console.log("-".repeat(50));
    });

    console.log(`\n📊 Total Failed Tests: ${failedTestsMatch.length}`);
  } else {
    console.log("✅ No failed tests found in the report!");
  }
}

filterFailedTests();
