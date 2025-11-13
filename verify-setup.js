// verify-setup.js
const fs = require("fs");
const path = require("path");

// Check if required files exist
const requiredFiles = ["jest.config.js", "jest.setup.js", "package.json"];

requiredFiles.forEach((file) => {
  const exists = fs.existsSync(path.join(__dirname, file));
  console.log(`${exists ? "✅" : "❌"} ${file}`);
});

// Check package.json for required dependencies
const packageJson = require("./package.json");

requiredDeps.forEach((dep) => {
  const hasDep =
    packageJson.devDependencies && packageJson.devDependencies[dep];
  console.log(`${hasDep ? "✅" : "❌"} ${dep} installed`);
});

console.log("\n📋 Setup Summary:");
console.log(
  `Jest Reporter: ${packageJson.jest ? "Configured" : "Not configured"}`
);
console.log(
  `Test Scripts: ${
    packageJson.scripts && packageJson.scripts.test ? "Available" : "Missing"
  }`
);

