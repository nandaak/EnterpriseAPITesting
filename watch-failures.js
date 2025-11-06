// utils/watch-failures.js
const { exec } = require("child_process");
const chalk = require("chalk");

console.log(chalk.yellow("🔍 Monitoring for test failures..."));

function runTests() {
  exec(
    "npx jest --silent --json --outputFile=test-results.json",
    (error, stdout, stderr) => {
      if (error) {
        console.log(chalk.red("❌ Tests failed! Analyzing..."));
        // Run our failure analysis
        require("./show-failures.js");
      } else {
        console.log(chalk.green("✅ All tests passed!"));
      }

      // Continue watching
      setTimeout(runTests, 5000);
    }
  );
}

runTests();
