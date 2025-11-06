// jest.setup.js
// =============================================================
// ✅ Global setup for Jest + Allure
// =============================================================
console.log("[JEST SETUP] Initializing Allure reporting...");

try {
  if (!global.allure) {
    global.allure = {
      label: (name, value) => console.log(`[ALLURE] Label: ${name}=${value}`),
      description: (text) => console.log(`[ALLURE] Description: ${text}`),
      link: (name, url) => console.log(`[ALLURE] Link: ${name} -> ${url}`),
      epic: (value) => console.log(`[ALLURE] Epic: ${value}`),
      feature: (value) => console.log(`[ALLURE] Feature: ${value}`),
      story: (value) => console.log(`[ALLURE] Story: ${value}`),
      severity: (value) => console.log(`[ALLURE] Severity: ${value}`)
    };
    console.log("[JEST SETUP] Created mock Allure reporter.");
  } else {
    console.log("[JEST SETUP] Allure reporter detected from environment.");
  }
} catch (err) {
  console.warn("[JEST SETUP] Allure setup failed:", err.message);
}

console.log("[JEST SETUP] Global setup complete.");
