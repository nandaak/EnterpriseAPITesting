// utils/debug-schema.js
const fs = require("fs");
const path = require("path");

function debugSchema() {
  const schemaPath = path.resolve(
    process.cwd(),
    "test-data/Input/JL-Backend-Api-Schema.json"
  );

  if (!fs.existsSync(schemaPath)) {
    console.log("❌ Schema file not found:", schemaPath);
    return;
  }

  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

  console.log("🔍 Schema Structure Analysis");
  console.log("=".repeat(50));

  function analyze(obj, depth = 0, path = []) {
    if (depth > 4) return; // Limit depth for large schemas

    if (obj && typeof obj === "object") {
      Object.keys(obj).forEach((key) => {
        const currentPath = [...path, key];
        const value = obj[key];

        // Check if this looks like an API operation
        const isOperation = ["Post", "PUT", "DELETE", "View", "GET"].includes(
          key
        );

        if (isOperation && Array.isArray(value) && value[0]) {
          console.log(`📍 API Operation: ${currentPath.join(".")}`);
          console.log(`   URL: ${value[0]}`);
          console.log(`   Has Payload: ${!!value[1]}`);
          console.log("");
        } else if (typeof value === "object" && value !== null) {
          analyze(value, depth + 1, currentPath);
        }
      });
    }
  }

  analyze(schema);
  console.log("✅ Schema analysis complete");
}

debugSchema();
