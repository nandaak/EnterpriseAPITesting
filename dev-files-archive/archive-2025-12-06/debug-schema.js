// debug-schema.js - Debug script to check schema structure
const fs = require("fs");
const path = require("path");

const schemaPath = path.join(
  __dirname,
  "test-data",
  "Input",
  "Main-Standarized-Backend-Api-Schema.json"
);

try {
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  console.log("🔍 SCHEMA DEBUG INFORMATION");
  console.log("==========================");

  // Check Journal Entry structure
  const journalEntry = schema.Accounting?.Transaction?.Journal_Entry;
  if (journalEntry) {
    console.log("✅ Journal Entry found in schema");
    console.log("Available operations:", Object.keys(journalEntry));

    // Check PUT operation structure
    if (journalEntry.PUT) {
      console.log("\n📝 PUT Operation Structure:");
      console.log("Endpoint:", journalEntry.PUT[0]);
      console.log("Payload keys:", Object.keys(journalEntry.PUT[1] || {}));

      // Show required fields for PUT
      const putPayload = journalEntry.PUT[1];
      if (putPayload) {
        console.log("\n🔑 PUT Payload Fields:");
        Object.keys(putPayload).forEach((key) => {
          const value = putPayload[key];
          console.log(
            `  - ${key}: ${typeof value} ${value === null ? "(null)" : ""}`
          );
        });
      }
    }
  } else {
    console.log("❌ Journal Entry not found in schema");
  }
} catch (error) {
  console.error("❌ Error reading schema:", error.message);
}
