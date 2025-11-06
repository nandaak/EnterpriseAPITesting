// custom-allure-environment.js
// =============================================================
// ✅ Stable Allure Environment for Jest ≥29
// Works with jest-circus-allure-environment and Allure 2.x
// =============================================================

const BaseEnvModule = require("jest-circus-allure-environment");
const NodeEnvironment = require("jest-environment-node"); // ✅ fixed import

// Handle both default/named exports for safety
const AllureBaseEnvironment = BaseEnvModule.default || BaseEnvModule;

class PatchedAllureEnvironment extends NodeEnvironment {
  constructor(config, maybeContext) {
    // Prepare safe context for Jest >=29+
    const safeContext = {
      ...(maybeContext || {}),
      testPath: maybeContext?.testPath || "unknown-test-path",
      docblockPragmas: maybeContext?.docblockPragmas || {},
      testEnvironmentOptions: maybeContext?.testEnvironmentOptions || {},
    };

    // Call NodeEnvironment constructor safely
    super(config, safeContext);

    // Try to initialize AllureBaseEnvironment inside
    try {
      this.allureEnv = new AllureBaseEnvironment(config, safeContext);
      this.allure = this.allureEnv.allure || null;
      console.log("[ALLURE-ENV] AllureBaseEnvironment initialized successfully");
    } catch (err) {
      console.warn(
        `[ALLURE-ENV] Non-fatal initialization issue: ${err.message}`
      );
      this.allureEnv = null;
    }
  }

  async handleTestEvent(event, state) {
    if (this.allureEnv?.handleTestEvent) {
      await this.allureEnv.handleTestEvent(event, state);
    }
    return super.handleTestEvent?.(event, state);
  }
}

module.exports = PatchedAllureEnvironment;
